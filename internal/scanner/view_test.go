package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/fileview"
	"github.com/brightcolor/malwatch/internal/report"
)

// The sample is put together from pieces, see rules/persistence_test.go.
func viewSample() string {
	return "<?php\n// tool\n" +
		"$c = $_PO" + "ST['c'];\n" +
		"$x = ev" + "al($_PO" + "ST['p']);\n" +
		"echo 'done';\n"
}

func scanDir(t *testing.T, files map[string]string, view fileview.Options) *report.Report {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Run(Options{
		Paths:         []string{dir},
		NoVersionScan: true,
		NoClamAV:      true,
		Offline:       true,
		SignatureDir:  filepath.Join(dir, "no-signatures"),
		View:          view,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestReportCarriesMarksTraitsAndCode(t *testing.T) {
	rep := scanDir(t, map[string]string{"tool.php": viewSample()}, fileview.Default)
	var hit *report.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Rule == "php.eval.request" {
			hit = &rep.Findings[i]
		}
	}
	if hit == nil {
		t.Fatalf("php.eval.request missing, findings: %+v", rep.Findings)
	}
	if len(hit.Marks) == 0 || hit.Marks[0].Line != 4 {
		t.Fatalf("marks = %+v, want line 4", hit.Marks)
	}
	v := rep.Files[hit.SHA256]
	if v == nil {
		t.Fatalf("no view for %s", hit.SHA256)
	}
	if !v.Whole || v.Lines != 5 || len(v.Show) != 5 {
		t.Fatalf("view = %+v, want the whole five-line file", v)
	}
	ids := map[string]bool{}
	for _, tr := range v.Traits {
		ids[tr.ID] = true
	}
	if !ids["eval.code"] || !ids["input.request"] {
		t.Fatalf("traits = %+v", v.Traits)
	}
}

func TestViewBudgetKeepsTraitsAndDropsCode(t *testing.T) {
	// Two files of 600 lines with 1,000 bytes each are shown whole: one view
	// weighs about 600 KB, so the first fits the budget of 1 MiB and the
	// second one does not, whichever of them a worker finishes first.
	opt := fileview.Default
	opt.BudgetMiB = 1
	opt.MaxLines = 2000
	opt.LineLength = 2000
	filler := "// " + strings.Repeat("w", 997) + "\n"
	big := strings.Repeat(filler, 600) + viewSample()
	rep := scanDir(t, map[string]string{"a/one.php": big, "b/two.php": big + "// other\n"}, opt)
	if len(rep.Files) != 2 {
		t.Fatalf("views = %d, want 2", len(rep.Files))
	}
	omitted := 0
	for _, v := range rep.Files {
		if v.Omitted {
			omitted++
			if len(v.Show) != 0 || len(v.Traits) == 0 {
				t.Fatalf("an omitted view must keep its traits and lose its lines: %+v", v)
			}
		}
	}
	if omitted != 1 {
		t.Fatalf("omitted views = %d, want exactly one past the budget", omitted)
	}
}

func TestZeroOptionsReportNoViewCode(t *testing.T) {
	rep := scanDir(t, map[string]string{"tool.php": viewSample()}, fileview.Options{})
	for _, f := range rep.Findings {
		if len(f.Marks) != 0 {
			t.Fatalf("marks without a limit: %+v", f)
		}
	}
	for _, v := range rep.Files {
		if len(v.Show) != 0 {
			t.Fatalf("code without a view: %+v", v)
		}
	}
}
