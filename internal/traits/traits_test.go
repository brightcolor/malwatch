package traits

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/textpos"
)

// The samples are put together from pieces: the virus scanner on the
// workstation deletes test files that spell out a webshell in one piece.

func detect(src string) map[string]report.Trait {
	content := []byte(src)
	got := map[string]report.Trait{}
	for _, t := range Detect(content, textpos.New(content), 5) {
		got[t.ID] = t
	}
	return got
}

func TestOldUploaderShowsItsProtections(t *testing.T) {
	src := "<?php\nrequire_once('admin.php');\n" +
		"if (isset($_POST['upload_theme']) && check_admin_referer('upload-theme')) {\n" +
		"  if (!current_user_can('edit_themes')) wp_die('no');\n" +
		"  $f = wp_handle_upload($_FILES['package'], array());\n" +
		"  $a = new PclZip($f['file']);\n}\n"
	got := detect(src)
	for _, id := range []string{"guard.login", "guard.nonce", "guard.capability", "file.upload", "archive.extract", "input.request"} {
		if _, ok := got[id]; !ok {
			t.Errorf("trait %s missing, got %v", id, keys(got))
		}
	}
	for _, id := range []string{"exec.shell", "eval.code"} {
		if _, ok := got[id]; ok {
			t.Errorf("trait %s reported for a file without it", id)
		}
	}
	if m := got["guard.login"].Marks; len(m) != 1 || m[0].Line != 2 {
		t.Errorf("guard.login marks = %+v, want line 2", m)
	}
}

func TestShellLikeFileShowsItsRisks(t *testing.T) {
	src := "<?php\n$c = $_GET['c'];\n" +
		"sys" + "tem($c);\n" +
		"ev" + "al(base" + "64_decode($_POST['p']));\n"
	got := detect(src)
	for _, id := range []string{"exec.shell", "eval.code", "decode.hidden", "input.request"} {
		if _, ok := got[id]; !ok {
			t.Errorf("trait %s missing, got %v", id, keys(got))
		}
	}
	shell := got["exec.shell"].Marks
	if len(shell) != 1 || shell[0].Line != 3 || shell[0].Col != 0 {
		t.Fatalf("exec.shell mark = %+v, want line 3 from column 0", shell)
	}
}

func TestMethodCallsAreOtherFunctions(t *testing.T) {
	src := "<?php\n$pdo->ex" + "ec('SELECT 1');\n$m = $re.ex" + "ec(s);\nFoo::ex" + "ec();\n"
	if _, ok := detect(src)["exec.shell"]; ok {
		t.Fatal("a method named exec counted as a shell call")
	}
}

func TestRiskComesFirst(t *testing.T) {
	src := "<?php\ndefined('ABSPATH') or die;\n" + "ev" + "al($x);\n"
	content := []byte(src)
	got := Detect(content, textpos.New(content), 5)
	if len(got) < 2 || got[0].Kind != report.TraitRisk || got[len(got)-1].Kind != report.TraitGuard {
		t.Fatalf("order = %+v", got)
	}
}

func TestMarkLimit(t *testing.T) {
	src := strings.Repeat("$_GET['a'];\n", 30)
	content := []byte(src)
	for _, tr := range Detect(content, textpos.New(content), 3) {
		if len(tr.Marks) > 3 {
			t.Fatalf("%s has %d marks, limit 3", tr.ID, len(tr.Marks))
		}
	}
}

func TestEveryTraitHasLabelAndKnownKind(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range detectors {
		if d.label == "" {
			t.Errorf("%s has no label", d.id)
		}
		if _, ok := kindOrder[d.kind]; !ok {
			t.Errorf("%s has unknown kind %q", d.id, d.kind)
		}
		if seen[d.id] {
			t.Errorf("%s twice", d.id)
		}
		seen[d.id] = true
	}
}

func keys(m map[string]report.Trait) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
