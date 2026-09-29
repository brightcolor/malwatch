// Package fileview cuts out what a reader should see of a file with findings.
//
// Short files are shown whole: a 600 byte uploader is best judged by reading
// all of it. Of a long one the view keeps the lines around every mark, and of
// a long line the part around its first mark, because an obfuscated payload
// is often a single line of 80,000 characters.
//
// Everything the view shows is text that came from a customer's website and
// possibly from an attacker. The view only cuts; escaping is the job of
// whoever puts it on a page.
package fileview

import (
	"bytes"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/textpos"
)

// Options limit a view. Every value is a setting; Default holds the defaults
// and Limits the bounds a setting may take.
type Options struct {
	// MaxLines is the size up to which a file is shown whole, and the most
	// lines a view of a longer file shows. 0 switches the code view off; the
	// traits are still reported.
	MaxLines int
	// Context is the number of lines shown above and below a mark.
	Context int
	// LineLength is the most bytes shown of one line.
	LineLength int
	// MaxMarks is the most marks kept per rule and per trait.
	MaxMarks int
	// BudgetMiB is the most code, in MiB, all views of one report hold
	// together. A file past it keeps its traits and loses its lines, so a
	// badly infected server does not produce a report the panel cannot
	// load.
	BudgetMiB int
}

// Default are the values a scan uses when nobody set others.
var Default = Options{MaxLines: 400, Context: 5, LineLength: 300, MaxMarks: 20, BudgetMiB: 32}

// Bound is the range a setting may take.
type Bound struct{ Min, Max int }

// Limits are the bounds of the settings, checked by Validate and by the
// settings page of the addon (see check_wiring.sh).
var Limits = struct {
	MaxLines, Context, LineLength, MaxMarks, BudgetMiB Bound
}{
	MaxLines:   Bound{0, 2000},
	Context:    Bound{0, 50},
	LineLength: Bound{60, 2000},
	MaxMarks:   Bound{1, 200},
	BudgetMiB:  Bound{1, 512},
}

// Validate checks the options against Limits and names the flag that is off.
func (o Options) Validate() error {
	checks := []struct {
		flag  string
		value int
		bound Bound
	}{
		{"--view-lines", o.MaxLines, Limits.MaxLines},
		{"--view-context", o.Context, Limits.Context},
		{"--view-line-length", o.LineLength, Limits.LineLength},
		{"--view-marks", o.MaxMarks, Limits.MaxMarks},
		{"--view-budget", o.BudgetMiB, Limits.BudgetMiB},
	}
	for _, c := range checks {
		if c.value < c.bound.Min || c.value > c.bound.Max {
			return fmt.Errorf("%s=%d liegt außerhalb der Grenzen: erlaubt sind %d bis %d", c.flag, c.value, c.bound.Min, c.bound.Max)
		}
	}
	return nil
}

// Budget is BudgetMiB in bytes.
func (o Options) Budget() int64 { return int64(o.BudgetMiB) << 20 }

// binaryProbe is how much of the start decides whether a file is text.
const binaryProbe = 8192

// IsBinary reports whether content is no text: it holds a NUL byte near its
// start, which no source file does and every program does.
func IsBinary(content []byte) bool {
	head := content
	if len(head) > binaryProbe {
		head = head[:binaryProbe]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// Build makes the view of content. marks are the places to show, most
// important first: a view too short for all of them keeps the first ones.
func Build(content []byte, lines *textpos.Lines, marks []report.Mark, opt Options) *report.FileView {
	if IsBinary(content) {
		return &report.FileView{Kind: "binary"}
	}
	total := lines.Count()
	v := &report.FileView{Kind: "text", Lines: total}
	if opt.MaxLines <= 0 || total == 0 {
		return v
	}

	var show []int
	if total <= opt.MaxLines {
		v.Whole = true
		show = make([]int, total)
		for i := range show {
			show[i] = i + 1
		}
	} else {
		show = pickLines(marks, total, opt)
	}

	byLine := map[int][]report.Mark{}
	for _, m := range marks {
		byLine[m.Line] = append(byLine[m.Line], m)
	}
	for _, n := range show {
		v.Show = append(v.Show, cutLine(n, lines.Line(n), byLine[n], opt.LineLength))
	}
	return v
}

// pickLines chooses the lines of a long file: the windows around the marks
// in their order until MaxLines is reached, or the start of the file when
// there is no mark to show.
func pickLines(marks []report.Mark, total int, opt Options) []int {
	chosen := map[int]bool{}
	for _, m := range marks {
		from := m.Line - opt.Context
		if from < 1 {
			from = 1
		}
		to := m.Line + opt.Context
		if to > total {
			to = total
		}
		added := 0
		for n := from; n <= to; n++ {
			if !chosen[n] {
				added++
			}
		}
		if len(chosen)+added > opt.MaxLines {
			if len(chosen) > 0 {
				break
			}
			// Even the first window is too big: keep the marked line and
			// as much around it as fits.
			from, to = m.Line, m.Line
			for to-from+1 < opt.MaxLines && (from > 1 || to < total) {
				if from > 1 {
					from--
				}
				if to-from+1 < opt.MaxLines && to < total {
					to++
				}
			}
		}
		for n := from; n <= to; n++ {
			chosen[n] = true
		}
	}
	if len(chosen) == 0 {
		for n := 1; n <= total && n <= opt.MaxLines; n++ {
			chosen[n] = true
		}
	}
	out := make([]int, 0, len(chosen))
	for n := range chosen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// cutLine keeps at most max bytes of line, around the first mark on it, and
// makes the text safe to carry: invalid UTF-8 and control characters become
// one printable byte each, so the columns of the marks stay right.
func cutLine(n int, line []byte, marks []report.Mark, max int) report.ViewLine {
	off := 0
	end := len(line)
	if max > 0 && len(line) > max {
		first := -1
		for _, m := range marks {
			if first < 0 || m.Col < first {
				first = m.Col
			}
		}
		if first > max/4 {
			off = first - max/4
		}
		if off+max > len(line) {
			off = len(line) - max
		}
		off = runeStart(line, off)
		end = runeStart(line, off+max)
	}
	return report.ViewLine{N: n, Text: printable(line[off:end]), Off: off, Cut: end < len(line)}
}

// runeStart moves i back to the first byte of the character it points into.
func runeStart(b []byte, i int) int {
	if i >= len(b) {
		return len(b)
	}
	for i > 0 && !utf8.RuneStart(b[i]) {
		i--
	}
	return i
}

// printable returns b with every invalid UTF-8 byte replaced by '?' and every
// control character but the tab by '.'. The length in bytes stays the same.
func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			out = append(out, '?')
			i++
			continue
		case r < 0x20 && r != '\t', r == 0x7f:
			out = append(out, '.')
		default:
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return string(out)
}
