package textpos

import (
	"reflect"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

func TestCountFollowsTheEditor(t *testing.T) {
	cases := map[string]int{
		"":           0,
		"one":        1,
		"one\n":      1,
		"one\ntwo":   2,
		"one\ntwo\n": 2,
		"\n":         1,
		"a\n\nb":     3,
	}
	for in, want := range cases {
		if got := New([]byte(in)).Count(); got != want {
			t.Errorf("Count(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLineOfAndLine(t *testing.T) {
	l := New([]byte("first\r\nsecond\nthird"))
	if got := l.LineOf(0); got != 1 {
		t.Errorf("LineOf(0) = %d", got)
	}
	if got := l.LineOf(7); got != 2 {
		t.Errorf("LineOf(7) = %d, want 2", got)
	}
	if got := l.LineOf(14); got != 3 {
		t.Errorf("LineOf(14) = %d, want 3", got)
	}
	if got := string(l.Line(1)); got != "first" {
		t.Errorf("Line(1) = %q: the carriage return belongs to the break", got)
	}
	if got := string(l.Line(3)); got != "third" {
		t.Errorf("Line(3) = %q", got)
	}
	if l.Line(4) != nil || l.Line(0) != nil {
		t.Error("lines outside the file must be nil")
	}
}

func TestMarksSplitAtLineBreaks(t *testing.T) {
	content := []byte("abc\ndef eval(\nghi\n")
	l := New(content)
	// From "eval(" to the end of "gh".
	start := 8
	end := 16
	got := l.Marks(start, end, 10)
	want := []report.Mark{{Line: 2, Col: 4, Len: 5}, {Line: 3, Col: 0, Len: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Marks = %+v, want %+v", got, want)
	}
	if got := l.Marks(start, end, 1); len(got) != 1 {
		t.Fatalf("the limit of 1 gave %d marks", len(got))
	}
	if got := l.Marks(5, 5, 10); got != nil {
		t.Fatalf("an empty range gave %+v", got)
	}
}
