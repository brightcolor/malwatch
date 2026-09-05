package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSwapPutsTheNewTreeInPlace(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "shell.php"), []byte("<?php eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "plugin.php"), []byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Swap(root, old, staged); err != nil {
		t.Fatalf("swap failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(old, "shell.php")); !os.IsNotExist(err) {
		t.Error("the planted file survived the swap")
	}
	if _, err := os.Stat(filepath.Join(old, "plugin.php")); err != nil {
		t.Errorf("the original is not in place: %v", err)
	}
}

func TestSwapKeepsTheModeOfTheReplacedTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not exist on Windows")
	}
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o777); err != nil {
		t.Fatal(err)
	}

	// A hardened install must stay hardened: a fixed default would widen it.
	if err := Swap(root, old, staged); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(old)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode is %o, want 750", info.Mode().Perm())
	}
}

func TestSwapRefusesATargetOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Swap(root, outside, staged); err == nil {
		t.Fatal("a swap outside the root was accepted")
	}
}
