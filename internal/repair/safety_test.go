package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInsideRootAcceptsAPathBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InsideRoot(root, filepath.Join(root, "wp-includes")); err != nil {
		t.Fatalf("a directory inside the root was rejected: %v", err)
	}
}

func TestInsideRootRefusesDotDot(t *testing.T) {
	root := t.TempDir()
	if err := InsideRoot(root, filepath.Join(root, "..", "etc")); err == nil {
		t.Fatal("a path leaving the root through .. was accepted")
	}
}

func TestInsideRootRefusesASymlinkOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	// The link resolves outside: refusing it is the whole point, because a
	// planted symlink would otherwise turn a repair into a way to delete
	// anything the scanner may write to.
	if err := InsideRoot(root, link); err == nil {
		t.Fatal("a symlink pointing out of the root was accepted")
	}
}
