package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brightcolor/malwatch/internal/quarantine"
)

// writeHarmlessFile creates a test fixture that reads like a PHP file
// without reading like a webshell. A prior version of this test wrote an
// actual eval($_POST) one-liner, and Windows Defender quarantined it out
// from under the test before the assertions ever ran.
func writeHarmlessFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php\n// nur ein Platzhalter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineOldStyleCallWithoutAnActionStoresTheFile(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "wp-content", "uploads", "shell.php")
	writeHarmlessFile(t, victim)
	store := t.TempDir()

	// No action word, and --backup-dir rather than --quarantine-dir: this
	// is the call every ISPConfig install made before quarantine grew the
	// other four actions, and it has to keep working unchanged.
	if code := cmdQuarantine([]string{
		"--path=" + root, "--file=wp-content/uploads/shell.php", "--backup-dir=" + store,
	}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}

	entries, _, err := quarantine.List(store)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 1 || entries[0].RelPath != "wp-content/uploads/shell.php" {
		t.Fatalf("List = %+v, want exactly the stored file", entries)
	}
}

func TestQuarantineAddRefusesAPathOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	outside := filepath.Join(other, "passwd")
	if err := os.WriteFile(outside, []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The path arrives from a form field by way of the job queue. The check
	// against malwatch_finding in the panel is one guard; this is the
	// second, independent one.
	rel := filepath.Join("..", filepath.Base(other), "passwd")
	code := cmdQuarantine([]string{
		"add", "--path=" + root, "--file=" + filepath.ToSlash(rel), "--quarantine-dir=" + t.TempDir(),
	})
	if code == 0 {
		t.Fatal("a path leaving the root was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("a file outside the root was removed")
	}
}

func TestQuarantineNeedsAQuarantineDir(t *testing.T) {
	if code := cmdQuarantine([]string{"--path=" + t.TempDir()}); code != 3 {
		t.Errorf("exit code %d without --quarantine-dir/--backup-dir and --file, want 3", code)
	}
}

func TestQuarantineListJSONOutWritesTheStoredEntry(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	writeHarmlessFile(t, filepath.Join(root, "note.txt"))

	entry, err := quarantine.Store(store, quarantine.Source{
		Root: root, RelPath: "note.txt", Domain: "beispiel.de",
		Origin: "manual", Reason: "Testaufbau",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	out := filepath.Join(t.TempDir(), "list.json")
	if code := cmdQuarantine([]string{
		"list", "--quarantine-dir=" + store, "--json", "--out=" + out,
	}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	var doc struct {
		Schema  int                `json:"schema"`
		Entries []quarantine.Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("list output is not valid JSON: %v\n%s", err, raw)
	}
	if doc.Schema != 1 {
		t.Errorf("schema = %d, want 1", doc.Schema)
	}
	found := false
	for _, e := range doc.Entries {
		if e.ID == entry.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("entries = %+v, missing the stored entry %s", doc.Entries, entry.ID)
	}
}

func TestQuarantineListWithoutJSONIsAnError(t *testing.T) {
	// list's only defined output is the JSON index; without --json it would
	// otherwise do nothing and exit 0, which looks like success.
	if code := cmdQuarantine([]string{"list", "--quarantine-dir=" + t.TempDir()}); code != 3 {
		t.Errorf("exit code %d for list without --json, want 3", code)
	}
}

func TestQuarantineRestoreThenDeleteEmptiesTheStore(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	target := filepath.Join(root, "note.txt")
	writeHarmlessFile(t, target)

	entry, err := quarantine.Store(store, quarantine.Source{
		Root: root, RelPath: "note.txt", Domain: "beispiel.de", Origin: "manual",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if code := cmdQuarantine([]string{
		"restore", "--quarantine-dir=" + store, "--id=" + entry.ID,
	}); code != 0 {
		t.Fatalf("restore exit code %d, want 0", code)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("restore did not bring the file back: %v", err)
	}

	if code := cmdQuarantine([]string{
		"delete", "--quarantine-dir=" + store, "--id=" + entry.ID,
	}); code != 0 {
		t.Fatalf("delete exit code %d, want 0", code)
	}

	entries, _, err := quarantine.List(store)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries after delete = %+v, want none", entries)
	}
}

func TestQuarantineRestoreContinuesPastAnUnknownID(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	target := filepath.Join(root, "note.txt")
	writeHarmlessFile(t, target)

	entry, err := quarantine.Store(store, quarantine.Source{
		Root: root, RelPath: "note.txt", Domain: "beispiel.de", Origin: "manual",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// One id that was never stored, one that was: the batch a collection
	// restore sends is not guaranteed to be clean, and one bad id must not
	// keep the good one from coming back.
	code := cmdQuarantine([]string{
		"restore", "--quarantine-dir=" + store,
		"--id=20260101T000000Z-00000000", "--id=" + entry.ID,
	})
	if code == 0 {
		t.Fatal("an unknown id among the batch was not reported as a failure")
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the entry that does exist was not restored: %v", err)
	}
}

func TestQuarantineExportBundlesMultipleIDsIntoOneZip(t *testing.T) {
	store := t.TempDir()

	rootA := t.TempDir()
	writeHarmlessFile(t, filepath.Join(rootA, "shell.php"))
	entryA, err := quarantine.Store(store, quarantine.Source{
		Root: rootA, RelPath: "shell.php", Domain: "eins.beispiel.de", Origin: "manual",
	})
	if err != nil {
		t.Fatalf("Store A failed: %v", err)
	}

	// Same relative path, a different website: the whole point of a
	// per-id directory in the archive is that this does not collide.
	rootB := t.TempDir()
	writeHarmlessFile(t, filepath.Join(rootB, "shell.php"))
	entryB, err := quarantine.Store(store, quarantine.Source{
		Root: rootB, RelPath: "shell.php", Domain: "zwei.beispiel.de", Origin: "manual",
	})
	if err != nil {
		t.Fatalf("Store B failed: %v", err)
	}

	zipOut := filepath.Join(t.TempDir(), "sammel.zip")
	code := cmdQuarantine([]string{
		"export", "--quarantine-dir=" + store,
		"--id=" + entryA.ID, "--id=" + entryB.ID,
		"--zip=" + zipOut,
	})
	if code != 0 {
		t.Fatalf("export exit code %d, want 0", code)
	}

	rc, err := zip.OpenReader(zipOut)
	if err != nil {
		t.Fatalf("result is not a valid zip: %v", err)
	}
	defer rc.Close()

	names := map[string]bool{}
	for _, f := range rc.File {
		names[f.Name] = true
		if f.Flags&0x1 == 0 {
			t.Errorf("%s: Flags = %#x, encrypted bit (0x1) not set", f.Name, f.Flags)
		}
	}
	for _, want := range []string{entryA.ID + "/shell.php", entryB.ID + "/shell.php"} {
		if !names[want] {
			t.Errorf("zip is missing %q; has %v", want, names)
		}
	}
}

func TestQuarantineJSONAfterAFailureStillReportsTheFullStore(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	writeHarmlessFile(t, filepath.Join(root, "note.txt"))

	entry, err := quarantine.Store(store, quarantine.Source{
		Root: root, RelPath: "note.txt", Domain: "beispiel.de", Origin: "manual",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	out := filepath.Join(t.TempDir(), "delete.json")
	// One id fails (never stored), so the action as a whole must report
	// failure - but the index it writes has to name the entry that is
	// genuinely still there, since that is exactly what lets the panel's
	// own copy resync after a partial failure instead of just after a
	// clean run.
	code := cmdQuarantine([]string{
		"delete", "--quarantine-dir=" + store,
		"--id=20260101T000000Z-00000000",
		"--json", "--out=" + out,
	})
	if code == 0 {
		t.Fatal("deleting an unknown id was not reported as a failure")
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report was written after the failed action: %v", err)
	}
	var doc struct {
		Entries []quarantine.Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	if len(doc.Entries) != 1 || doc.Entries[0].ID != entry.ID {
		t.Fatalf("entries = %+v, want exactly the untouched entry %s", doc.Entries, entry.ID)
	}
}
