package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeFileTree writes a set of slash-separated relative paths with benign
// content below dir. It carries no malware sample, so it runs on a developer's
// machine where the scanner's own test probes are quarantined by the local
// antivirus.
func writeFileTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSwapCopiesTheStagedTreeThroughOsRoot is the benign check that the os.Root
// rewrite still does Swap's own job: the old tree goes, the staged one lands in
// its place, nested and all.
func TestSwapCopiesTheStagedTreeThroughOsRoot(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	writeFileTree(t, old, map[string]string{
		"stale.php":   "<?php // stale",
		"sub/old.php": "<?php // old",
	})
	staged := filepath.Join(t.TempDir(), "plugin")
	writeFileTree(t, staged, map[string]string{
		"plugin.php":  "<?php // original",
		"lib/new.php": "<?php // new",
	})

	if err := Swap(root, old, staged); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(old, "stale.php")); !os.IsNotExist(err) {
		t.Error("the old tree survived the swap")
	}
	for _, rel := range []string{"plugin.php", "lib/new.php"} {
		if _, err := os.Stat(filepath.Join(old, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s is not in place: %v", rel, err)
		}
	}
}

// TestSwapRefusesATreeReachedThroughAnEscapingSymlink turns the directory on
// the way to oldDir into a link out of the web root, the folder-for-a-link swap
// a website's user can do under a repair. Swap writes nothing behind it: every
// step goes through an os.Root on root, which refuses the one that leaves it.
func TestSwapRefusesATreeReachedThroughAnEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	root := filepath.Join(base, "web")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "plugins")); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "akismet")
	writeFileTree(t, staged, map[string]string{"akismet.php": "<?php // original"})

	if err := Swap(root, filepath.Join(root, "plugins", "akismet"), staged); err == nil {
		t.Fatal("Swap placed a tree behind a symlink out of the web root")
	}
	if _, err := os.Stat(filepath.Join(outside, "akismet")); !os.IsNotExist(err) {
		t.Error("Swap wrote the staged tree outside the web root")
	}
}

// TestSwapCorePlacesAFreshCoreDir exercises SwapCore's branch for a core
// directory that is not there yet - the normal case once a repair has
// quarantined it. The staged directory is written in through os.Root, the loose
// root files beside it, and wp-config.php is left where it is.
func TestSwapCorePlacesAFreshCoreDir(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php // keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "wordpress")
	writeFileTree(t, staged, map[string]string{
		"wp-admin/admin.php":      "<?php // admin",
		"wp-includes/version.php": "<?php\n$wp_version = '6.6.2';\n",
		"index.php":               "<?php // loose",
	})

	n, err := SwapCore(root, staged)
	if err != nil {
		t.Fatalf("SwapCore failed: %v", err)
	}
	if n == 0 {
		t.Error("SwapCore reported no files written")
	}
	for _, rel := range []string{"wp-admin/admin.php", "wp-includes/version.php", "index.php"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s was not placed: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "wp-config.php")); err != nil {
		t.Error("wp-config.php was removed")
	}
}

// TestOverlayRefusesAnEscapingIntermediateSymlink turns a directory the vendor
// tree also ships into a link out of the web root, then overlays. Overlay stops
// at that step with the link named and writes nothing past it - the os.Root
// walk refuses to descend through a link that leaves the root.
func TestOverlayRefusesAnEscapingIntermediateSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	root := filepath.Join(base, "web")
	oldDir := filepath.Join(root, "wp-content", "plugins", "akismet")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	// A subdirectory the vendor archive ships is a link out of the web root.
	if err := os.Symlink(outside, filepath.Join(oldDir, "lib")); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(t.TempDir(), "akismet")
	writeFileTree(t, newDir, map[string]string{"lib/engine.php": "<?php // vendor"})

	n, err := Overlay(root, oldDir, newDir)
	if err == nil {
		t.Fatal("Overlay wrote through an escaping symlink instead of refusing")
	}
	if n != 0 {
		t.Errorf("files written = %d, want 0", n)
	}
	if _, err := os.Stat(filepath.Join(outside, "engine.php")); !os.IsNotExist(err) {
		t.Error("Overlay wrote a vendor file outside the web root")
	}
}
