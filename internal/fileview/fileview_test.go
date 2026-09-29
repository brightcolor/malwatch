package fileview

import (
	"fmt"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/textpos"
)

func build(src string, marks []report.Mark, opt Options) *report.FileView {
	content := []byte(src)
	return Build(content, textpos.New(content), marks, opt)
}

func numbered(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func shown(v *report.FileView) []int {
	var out []int
	for _, l := range v.Show {
		out = append(out, l.N)
	}
	return out
}

func TestShortFileIsShownWhole(t *testing.T) {
	v := build("<?php\necho 1;\n", nil, Default)
	if v.Kind != "text" || !v.Whole || v.Lines != 2 || len(v.Show) != 2 {
		t.Fatalf("view = %+v", v)
	}
	if v.Show[1].N != 2 || v.Show[1].Text != "echo 1;" {
		t.Fatalf("second line = %+v", v.Show[1])
	}
}

func TestLongFileKeepsTheWindowsAroundTheMarks(t *testing.T) {
	opt := Options{MaxLines: 10, Context: 1, LineLength: 300, MaxMarks: 5}
	v := build(numbered(100), []report.Mark{{Line: 50}, {Line: 80}}, opt)
	want := []int{49, 50, 51, 79, 80, 81}
	if v.Whole || fmt.Sprint(shown(v)) != fmt.Sprint(want) {
		t.Fatalf("shown = %v, want %v", shown(v), want)
	}
}

func TestLongFileStopsAtMaxLinesWithTheFirstMarksFirst(t *testing.T) {
	opt := Options{MaxLines: 4, Context: 1, LineLength: 300, MaxMarks: 5}
	v := build(numbered(100), []report.Mark{{Line: 50}, {Line: 80}}, opt)
	if fmt.Sprint(shown(v)) != fmt.Sprint([]int{49, 50, 51}) {
		t.Fatalf("shown = %v: the second window does not fit and must stay out", shown(v))
	}
}

func TestLongFileWithoutMarksShowsItsStart(t *testing.T) {
	opt := Options{MaxLines: 3, Context: 2, LineLength: 300, MaxMarks: 5}
	if got := fmt.Sprint(shown(build(numbered(50), nil, opt))); got != "[1 2 3]" {
		t.Fatalf("shown = %s", got)
	}
}

func TestLongLineIsCutAroundItsMark(t *testing.T) {
	line := strings.Repeat("a", 1000) + "EVIL" + strings.Repeat("b", 1000)
	opt := Options{MaxLines: 10, Context: 0, LineLength: 100, MaxMarks: 5}
	v := build(line, []report.Mark{{Line: 1, Col: 1000, Len: 4}}, opt)
	l := v.Show[0]
	if len(l.Text) != 100 || !l.Cut || l.Off == 0 {
		t.Fatalf("line = off %d, len %d, cut %v", l.Off, len(l.Text), l.Cut)
	}
	if got := l.Text[1000-l.Off : 1000-l.Off+4]; got != "EVIL" {
		t.Fatalf("mark lands on %q, want EVIL: Off must count the same bytes as Col", got)
	}
}

func TestPrintableKeepsTheByteLength(t *testing.T) {
	in := []byte("a\x01b\xffc\tä")
	out := printable(in)
	if len(out) != len(in) {
		t.Fatalf("length %d, want %d", len(out), len(in))
	}
	if out != "a.b?c\tä" {
		t.Fatalf("printable = %q", out)
	}
}

func TestBinaryFileHasNoLines(t *testing.T) {
	v := build("\x7fELF\x02\x01\x01\x00\x00", nil, Default)
	if v.Kind != "binary" || len(v.Show) != 0 {
		t.Fatalf("view = %+v", v)
	}
}

func TestZeroLinesSwitchesTheCodeOff(t *testing.T) {
	opt := Default
	opt.MaxLines = 0
	v := build("<?php\necho 1;\n", nil, opt)
	if len(v.Show) != 0 || v.Lines != 2 {
		t.Fatalf("view = %+v", v)
	}
}

func TestValidateNamesTheFlag(t *testing.T) {
	if err := Default.Validate(); err != nil {
		t.Fatalf("the defaults fail their own check: %v", err)
	}
	bad := Default
	bad.Context = 51
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "--view-context=51") || !strings.Contains(err.Error(), "0 bis 50") {
		t.Fatalf("error = %v", err)
	}
}
