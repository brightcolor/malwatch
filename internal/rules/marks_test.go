package rules

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// Samples are assembled from pieces, see persistence_test.go.

func findRule(fs []report.Finding, id string) *report.Finding {
	for i := range fs {
		if fs[i].Rule == id {
			return &fs[i]
		}
	}
	return nil
}

func TestFindingsMarkEveryMatch(t *testing.T) {
	src := "<?php\n// head\n" +
		"$a = ev" + "al($_PO" + "ST['x']);\n" +
		"$b = ev" + "al($_PO" + "ST['y']);\n"
	e := NewEngine(nil)
	e.SetMarkLimit(10)
	f := findRule(e.Scan("x.php", "x.php", "php", []byte(src)), "php.eval.request")
	if f == nil {
		t.Fatal("php.eval.request did not match the sample")
	}
	if len(f.Marks) != 2 {
		t.Fatalf("marks = %+v, want one per match", f.Marks)
	}
	if f.Marks[0].Line != 3 || f.Marks[1].Line != 4 {
		t.Fatalf("marks on lines %d and %d, want 3 and 4", f.Marks[0].Line, f.Marks[1].Line)
	}
	line := strings.Split(src, "\n")[2]
	m := f.Marks[0]
	if got := line[m.Col : m.Col+m.Len]; !strings.HasPrefix(got, "ev"+"al(") {
		t.Fatalf("mark covers %q, want the call", got)
	}
}

func TestSupportingConditionsAreMarkedToo(t *testing.T) {
	src := "<?php\nerror_reporting(0);\n\n\nini_set('log_errors', 0);\n"
	e := NewEngine(nil)
	e.SetMarkLimit(10)
	f := findRule(e.Scan("x.php", "x.php", "php", []byte(src)), "php.silence.preamble")
	if f == nil {
		t.Fatal("php.silence.preamble did not match the sample")
	}
	lines := map[int]bool{}
	for _, m := range f.Marks {
		lines[m.Line] = true
	}
	if !lines[2] || !lines[5] {
		t.Fatalf("marks %+v: both the pattern (line 2) and its condition (line 5) belong to the reason", f.Marks)
	}
}

func TestNoMarksWithoutALimit(t *testing.T) {
	src := "<?php\n$a = ev" + "al($_PO" + "ST['x']);\n"
	f := findRule(NewEngine(nil).Scan("x.php", "x.php", "php", []byte(src)), "php.eval.request")
	if f == nil || len(f.Marks) != 0 {
		t.Fatalf("finding = %+v, want it without marks", f)
	}
}

func TestMarkLimitHolds(t *testing.T) {
	src := "<?php\n" + strings.Repeat("$a = ev"+"al($_PO"+"ST['x']);\n", 30)
	e := NewEngine(nil)
	e.SetMarkLimit(3)
	f := findRule(e.Scan("x.php", "x.php", "php", []byte(src)), "php.eval.request")
	if f == nil || len(f.Marks) != 3 {
		t.Fatalf("finding = %+v, want 3 marks", f)
	}
}
