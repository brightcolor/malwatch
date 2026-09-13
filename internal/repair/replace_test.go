package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/quarantine"
)

// stagedTree writes files into a fresh directory outside the site, the way an
// unpacked vendor archive arrives.
func stagedTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "staged")
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReplaceDirFilesTheOldTreeUnderTheCallersLabel(t *testing.T) {
	root := fakeWordPress(t)
	plugin := filepath.Join(root, "wp-content", "plugins", "akismet")
	newTree := stagedTree(t, map[string]string{
		"akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.4\n*/",
	})
	store := t.TempDir()

	entry, files, err := ReplaceDir(Replacement{
		Root: root, QuarantineDir: store, Domain: "beispiel.de",
		Origin: "upgrade", Reason: "Vor dem Update abgelegt",
	}, plugin, newTree)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Errorf("files = %d, want 1", files)
	}
	raw, err := os.ReadFile(filepath.Join(plugin, "akismet.php"))
	if err != nil || !strings.Contains(string(raw), "5.3.4") {
		t.Fatalf("the new release is not in place: %q %v", raw, err)
	}
	stored, err := quarantine.Get(store, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Origin != "upgrade" || stored.Reason != "Vor dem Update abgelegt" {
		t.Errorf("entry labelled %q / %q", stored.Origin, stored.Reason)
	}

	// The entry brings the old release back over the new one.
	if err := quarantine.Restore(store, entry.ID, true); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(plugin, "akismet.php"))
	if !strings.Contains(string(raw), "5.3.3") {
		t.Errorf("the restore did not bring the old release back: %q", raw)
	}
}

func TestReplaceCoreLabelsEveryEntryItFiles(t *testing.T) {
	root := fakeWordPress(t)
	newCore := stagedTree(t, map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.6.3';\n",
		"wp-login.php":            "<?php // 6.6.3",
	})
	store := t.TempDir()

	n, ids, err := ReplaceCore(Replacement{
		Root: root, QuarantineDir: store, Domain: "beispiel.de",
		Origin: "upgrade", Reason: "Vor dem Update abgelegt",
	}, newCore)
	if err != nil {
		t.Fatal(err)
	}
	// wp-includes as a directory, wp-login.php as a loose file that differs.
	if n == 0 || len(ids) != 2 {
		t.Fatalf("n = %d, ids = %v; want files and two entries", n, ids)
	}
	for _, id := range ids {
		e, err := quarantine.Get(store, id)
		if err != nil {
			t.Fatal(err)
		}
		if e.Origin != "upgrade" || e.Reason != "Vor dem Update abgelegt" {
			t.Errorf("entry %s labelled %q / %q", id, e.Origin, e.Reason)
		}
	}
}
