package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// --upload-dirs names the directories the location rules go by, as the setting
// "Ordner für hochgeladene Dateien" of the addon passes them.
func TestScanTakesTheUploadDirs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "kundendateien")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	code := cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--upload-dirs=uploads, kundendateien", "--out=" + out, "--json",
	})
	if code != report.ExitFindings {
		t.Fatalf("Rückgabewert %d, erwartet %d", code, report.ExitFindings)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].Rule != "shell.in_uploads" {
		t.Errorf("Funde %+v, erwartet shell.in_uploads", doc.Findings)
	}
}

func TestScanRefusesABadUploadDir(t *testing.T) {
	for _, value := range []string{"../x", "", "wp-content/uploads"} {
		code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav",
			"--upload-dirs=" + value})
		if code != report.ExitError {
			t.Errorf("--upload-dirs=%q: Rückgabewert %d, erwartet %d", value, code, report.ExitError)
		}
	}
}

func TestUsageNamesTheUploadDirs(t *testing.T) {
	if !strings.Contains(usageText, "--upload-dirs=NAMEN") {
		t.Error("die Hilfe nennt --upload-dirs nicht")
	}
}
