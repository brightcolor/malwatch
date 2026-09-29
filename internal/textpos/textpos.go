// Package textpos turns byte positions in a file into lines and marks.
//
// A rule finds a byte range; a reader looks for a line. The index here is
// built once per file and answers every question about lines after that,
// so a file with many marks is not walked once per mark.
package textpos

import (
	"sort"

	"github.com/brightcolor/malwatch/internal/report"
)

// Lines indexes where each line of a file starts.
type Lines struct {
	content []byte
	starts  []int
}

// New indexes content.
func New(content []byte) *Lines {
	starts := []int{0}
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &Lines{content: content, starts: starts}
}

// Count is the number of lines. A final line break does not open another
// line, the way an editor counts.
func (l *Lines) Count() int {
	if len(l.content) == 0 {
		return 0
	}
	n := len(l.starts)
	if l.starts[n-1] == len(l.content) {
		n--
	}
	return n
}

// LineOf is the 1-based line that holds byte offset off.
func (l *Lines) LineOf(off int) int {
	if off < 0 {
		off = 0
	}
	return sort.Search(len(l.starts), func(i int) bool { return l.starts[i] > off })
}

// Start is the byte offset where line n (1-based) begins.
func (l *Lines) Start(n int) int {
	if n < 1 || n > len(l.starts) {
		return len(l.content)
	}
	return l.starts[n-1]
}

// Line is line n without its line break and without a carriage return
// before it. Out of range gives nil.
func (l *Lines) Line(n int) []byte {
	if n < 1 || n > l.Count() {
		return nil
	}
	start := l.starts[n-1]
	end := len(l.content)
	if n < len(l.starts) {
		end = l.starts[n] - 1
	}
	if end > start && l.content[end-1] == '\r' {
		end--
	}
	return l.content[start:end]
}

// Marks turns the byte range [start, end) into one mark per line it touches,
// at most max of them. A match that spans three lines is three marks, each
// covering its part of the line.
func (l *Lines) Marks(start, end, max int) []report.Mark {
	if max <= 0 || start < 0 || end <= start || start >= len(l.content) {
		return nil
	}
	if end > len(l.content) {
		end = len(l.content)
	}
	var out []report.Mark
	for n := l.LineOf(start); n <= l.Count() && len(out) < max; n++ {
		lineStart := l.starts[n-1]
		if lineStart >= end {
			break
		}
		lineEnd := lineStart + len(l.Line(n))
		from := start
		if from < lineStart {
			from = lineStart
		}
		to := end
		if to > lineEnd {
			to = lineEnd
		}
		if to < from {
			to = from
		}
		out = append(out, report.Mark{Line: n, Col: from - lineStart, Len: to - from})
	}
	return out
}
