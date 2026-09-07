package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Der Balken im Panel rechnet seine Breite aus done/total. Ohne total stand er
// auf festen fünf Prozent, und ein Scan sah minutenlang aus wie ein Absturz.
func TestScanReportsATotalWhenExpectIsGiven(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.php", "b.php", "c.php"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("<?php echo 1;"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	code := cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog, "--expect=3",
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})
	if code > 1 {
		t.Fatalf("Rückgabewert %d", code)
	}

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 3 {
		t.Errorf("files_total ist %d, erwartet 3", doc.FilesTotal)
	}
}

// Ohne den Schalter bleibt alles wie bisher: ein Zähler ohne Nenner ist eine
// ehrliche Aussage, eine erfundene Gesamtzahl wäre keine.
func TestScanLeavesTheTotalAtZeroWithoutExpect(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog,
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 0 {
		t.Errorf("files_total ist %d, erwartet 0", doc.FilesTotal)
	}
}
