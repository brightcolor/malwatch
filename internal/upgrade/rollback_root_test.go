package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestRemoveAddedDeletesWhatTheReleaseAdded is the normal rollback path: the
// directories and loose files a release put in place go again, through os.Root,
// and what the site already had is left alone.
func TestRemoveAddedDeletesWhatTheReleaseAdded(t *testing.T) {
	install := t.TempDir()
	if err := os.MkdirAll(filepath.Join(install, "wp-admin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "wp-admin", "admin.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "readme.html"), []byte("neu"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "wp-config.php"), []byte("<?php // bleibt"), 0o644); err != nil {
		t.Fatal(err)
	}

	if problems := removeAdded(install, []string{"wp-admin", "readme.html"}); len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if _, err := os.Stat(filepath.Join(install, "wp-admin")); !os.IsNotExist(err) {
		t.Error("wp-admin was not removed")
	}
	if _, err := os.Stat(filepath.Join(install, "readme.html")); !os.IsNotExist(err) {
		t.Error("readme.html was not removed")
	}
	if _, err := os.Stat(filepath.Join(install, "wp-config.php")); err != nil {
		t.Error("wp-config.php was removed")
	}
}

// TestRemoveAddedLeavesAFileBehindAnEscapingSymlink turns an added name into a
// link out of the installation, the swap a website's user can do between the
// exchange and the rollback. removeAdded reports it and deletes nothing out
// there: every step goes through an os.Root on the installation.
func TestRemoveAddedLeavesAFileBehindAnEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	install := filepath.Join(base, "wp")
	outside := filepath.Join(base, "outside")
	victim := filepath.Join(outside, "victim.txt")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("bleibt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(install, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(install, "added")); err != nil {
		t.Fatal(err)
	}

	problems := removeAdded(install, []string{"added/victim.txt"})
	if len(problems) == 0 {
		t.Error("removeAdded followed a symlink out of the installation")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("a file outside the installation was removed: %v", err)
	}
}
