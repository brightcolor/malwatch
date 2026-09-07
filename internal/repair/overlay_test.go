package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// symlinkOrSkip creates oldname -> newname and skips the test if this
// platform refuses - a plain symlink needs a privilege Windows only grants
// in Developer Mode. The write path this guards runs on Linux in the run
// that matters, so skipping here on a machine that cannot make the link
// narrows nothing that run would catch.
func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("cannot create a symlink on this platform: %v", err)
	}
}

// TestOverlayRefusesToWriteThroughAPlantedSymlink guards K1. Overlay checked
// containment once, for oldDir itself, and then wrote every file at
// oldDir/rel without asking whether that particular target was still inside
// the root - so a symlink planted inside a plugin directory, named after a
// subdirectory the vendor's own archive ships (e.g. plugins/akismet/assets),
// let a root-run repair follow the link and write vendor content, and a
// chown, wherever it pointed. Overlay mode leaves the old tree standing on
// purpose, so a planted link is still there while this runs - that is
// exactly the mode the finding was reported against.
func TestOverlayRefusesToWriteThroughAPlantedSymlink(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "wp-content", "plugins", "akismet")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.conf")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}

	// What a compromised site plants: a link inside the plugin directory
	// whose name matches a directory the vendor's own tree ships, so the
	// walk over the vendor tree steps right onto it.
	linkPath := filepath.Join(oldDir, "assets")
	symlinkOrSkip(t, outside, linkPath)

	newDir := filepath.Join(t.TempDir(), "akismet")
	if err := os.MkdirAll(filepath.Join(newDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "assets", "victim.conf"),
		[]byte("VENDOR CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := Overlay(root, oldDir, newDir)
	if err == nil {
		t.Fatal("Overlay wrote through a planted symlink instead of refusing")
	}
	if !strings.Contains(err.Error(), linkPath) {
		t.Errorf("error %q does not name the planted link %q", err, linkPath)
	}
	if n != 0 {
		t.Errorf("files written = %d, want 0 - the walk reaches the link before anything below it", n)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("victim file unreadable: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Errorf("Overlay wrote through the planted link: %s = %q", victim, got)
	}
}
