package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineRemovesTheFileAndKeepsACopy(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "wp-content", "uploads", "shell.php")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("<?php @eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}
	backups := t.TempDir()

	if code := cmdQuarantine([]string{
		"--path=" + root, "--file=wp-content/uploads/shell.php", "--backup-dir=" + backups,
	}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}
	found := false
	_ = filepath.Walk(backups, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("nothing was kept - a false alarm would be unrecoverable")
	}
}

func TestQuarantineRefusesAPathOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	outside := filepath.Join(other, "passwd")
	if err := os.WriteFile(outside, []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The path arrives from a form field by way of the queue. The check against
	// the findings in the panel is one guard; this is the second, independent
	// one.
	rel := filepath.Join("..", filepath.Base(other), "passwd")
	if code := cmdQuarantine([]string{
		"--path=" + root, "--file=" + filepath.ToSlash(rel), "--backup-dir=" + t.TempDir(),
	}); code == 0 {
		t.Fatal("a path leaving the root was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("a file outside the root was removed")
	}
}

func TestQuarantineNeedsItsArguments(t *testing.T) {
	if code := cmdQuarantine([]string{"--path=/tmp"}); code != 3 {
		t.Errorf("exit code %d without --file and --backup-dir, want 3", code)
	}
}
