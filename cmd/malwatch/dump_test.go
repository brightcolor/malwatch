package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdDumpNeedsPathAndArchive(t *testing.T) {
	if code := cmdDump(nil); code != 3 {
		t.Errorf("ohne Schalter: Code %d, erwartet 3", code)
	}
	if code := cmdDump([]string{"--path=" + t.TempDir()}); code != 3 {
		t.Errorf("ohne --archive: Code %d, erwartet 3", code)
	}
}

func TestCmdDumpWritesArchiveAndReport(t *testing.T) {
	web := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "index.php"), []byte("<?php // beispiel"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	archive := filepath.Join(out, "dump.tar.gz")
	report := filepath.Join(out, "job-1.json")

	code := cmdDump([]string{
		"--path=" + web,
		"--archive=" + archive,
		"--json",
		"--out=" + report,
	})
	if code != 0 {
		t.Fatalf("Code %d, erwartet 0", code)
	}

	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("das Archiv fehlt: %v", err)
	}
	if info.Size() == 0 {
		t.Error("das Archiv ist leer")
	}

	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("der Bericht fehlt: %v", err)
	}
	for _, want := range []string{"\"sha256\"", "\"archive_bytes\"", "\"files\""} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("der Bericht nennt %s nicht", want)
		}
	}
}
