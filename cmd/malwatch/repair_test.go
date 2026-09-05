package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepairRefusesWithoutAPath(t *testing.T) {
	if code := cmdRepair([]string{}); code != 3 {
		t.Errorf("exit code %d without --path, want 3", code)
	}
}

func TestRepairRefusesWithoutABackupDir(t *testing.T) {
	// Everything that is touched is kept, so a run that would touch something
	// needs somewhere to keep it.
	if code := cmdRepair([]string{"--path=" + t.TempDir()}); code != 3 {
		t.Errorf("exit code %d without --backup-dir, want 3", code)
	}
}

func TestRepairDryRunWritesAReportAndChangesNothing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.6.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")

	// No network in the test: an unreachable vendor address plus --dry-run has
	// to end in a report, not in a changed tree.
	code := cmdRepair([]string{
		"--path=" + root, "--dry-run", "--json", "--out=" + out,
		"--vendor-base=http://127.0.0.1:1/",
	})
	if code == 0 {
		t.Error("an unreachable vendor must not report success")
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	if !strings.Contains(string(raw), "\"schema\"") {
		t.Errorf("the report has no schema:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-includes", "version.php")); err != nil {
		t.Error("the tree was modified during a dry run")
	}
}
