package repair

import (
	"os"
	"path/filepath"
	"testing"
)

func stagedCore(t *testing.T) string {
	t.Helper()
	staged := filepath.Join(t.TempDir(), "wordpress")
	if err := os.MkdirAll(filepath.Join(staged, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.6.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-login.php"),
		[]byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}
	return staged
}

func TestSwapCoreRemovesWhatHidesInsideCoreDirectories(t *testing.T) {
	root := fakeWordPress(t)
	planted := filepath.Join(root, "wp-includes", "2mOnl635P1W.php")
	if err := os.WriteFile(planted, []byte("<?php @eval($_GET[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := SwapCore(root, stagedCore(t)); err != nil {
		t.Fatal(err)
	}
	// wp-includes goes as a whole: a dropped file only disappears with the
	// directory it hides in.
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Error("the dropped file inside wp-includes survived")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-includes", "version.php")); err != nil {
		t.Errorf("the original wp-includes is not in place: %v", err)
	}
}

func TestSwapCoreKeepsContentAndConfig(t *testing.T) {
	root := fakeWordPress(t)
	if _, err := SwapCore(root, stagedCore(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-config.php")); err != nil {
		t.Error("wp-config.php was removed")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "uploads", "2026", "06", "photo.jpg")); err != nil {
		t.Error("uploads were removed")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php")); err != nil {
		t.Error("wp-content was taken along with the core")
	}
}

func TestSwapCoreLeavesAForeignRootFileWhereItIs(t *testing.T) {
	root := fakeWordPress(t)
	foreign := filepath.Join(root, "2q7ajgCOGou.php")
	if err := os.WriteFile(foreign, []byte("<?php @eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Root files are replaced by name, so anything foreign stays. That is the
	// point: the scan after the repair is what has to report it.
	if _, err := SwapCore(root, stagedCore(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("a foreign root file was removed - the following scan can no longer report it")
	}
}

func TestSwapCoreRefusesStagingInsideTheRoot(t *testing.T) {
	root := fakeWordPress(t)
	inside := filepath.Join(root, "staging")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SwapCore(root, inside); err == nil {
		t.Fatal("staging inside the web root was accepted")
	}
}
