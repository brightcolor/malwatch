package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOverlayReplacesAKnownFileAndLeavesAForeignOneAlone(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "plugin.php"), []byte("<?php // stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A harmless placeholder standing in for whatever a customer, or an
	// attacker, added to the directory: overlay's whole point is to leave it
	// alone.
	if err := os.WriteFile(filepath.Join(old, "foreign.txt"), []byte("// nur ein Platzhalter"), 0o644); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "plugin.php"), []byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := Overlay(root, old, newDir)
	if err != nil {
		t.Fatalf("overlay failed: %v", err)
	}
	if n != 1 {
		t.Errorf("files written = %d, want 1", n)
	}

	got, err := os.ReadFile(filepath.Join(old, "plugin.php"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "<?php // original" {
		t.Errorf("plugin.php was not replaced: %q", got)
	}
	if _, err := os.Stat(filepath.Join(old, "foreign.txt")); err != nil {
		t.Error("overlay must leave what is not in newDir alone")
	}
}

func TestOverlayAddsAFileTheOldTreeDidNotHave(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(filepath.Join(newDir, "includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "includes", "new.php"), []byte("<?php // new"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Overlay(root, old, newDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(old, "includes", "new.php")); err != nil {
		t.Errorf("overlay did not add the new file: %v", err)
	}
}

func TestOverlayKeepsTheModeOfTheTreeItWritesInto(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not exist on Windows")
	}
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	newDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(newDir, 0o777); err != nil {
		t.Fatal(err)
	}
	// The archive's own, wide-open mode must not leak into a hardened site.
	if err := os.WriteFile(filepath.Join(newDir, "x.php"), []byte("<?php"), 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := Overlay(root, old, newDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(old, "x.php"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode is %o, want 640", info.Mode().Perm())
	}
}

func TestOverlayRefusesATargetOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	newDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Overlay(root, outside, newDir); err == nil {
		t.Fatal("an overlay outside the root was accepted")
	}
}
