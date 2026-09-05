package repair

import (
	"os"
	"path/filepath"
)

// Swap replaces oldDir with newDir and carries over what the old tree was.
//
// Owner, group and mode are read off the tree being replaced rather than set
// to a default: a tree owned by root leaves the site on 500 or hands it the
// wrong write rights, and a fixed default would soften a hardened install.
func Swap(root, oldDir, newDir string) error {
	if err := InsideRoot(root, oldDir); err != nil {
		return err
	}

	info, err := os.Stat(oldDir)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	uid, gid := ownerOf(info)

	if err := os.RemoveAll(oldDir); err != nil {
		return err
	}
	if err := os.Rename(newDir, oldDir); err != nil {
		// Rename fails across devices, and the staging area may well live on
		// another filesystem than the customer tree.
		if err := copyTree(newDir, oldDir); err != nil {
			return err
		}
		_ = os.RemoveAll(newDir)
	}
	return applyOwnership(oldDir, uid, gid, mode)
}

// applyOwnership gives every entry of the new tree the identity of the one it
// replaced. Directories keep the directory mode; files lose the execute bits
// an archive may carry.
func applyOwnership(dir string, uid, gid int, mode os.FileMode) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return chownLink(path, uid, gid)
		}
		want := mode &^ 0o111
		if info.IsDir() {
			want = mode
		}
		if err := os.Chmod(path, want); err != nil {
			return err
		}
		return chownPath(path, uid, gid)
	})
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}
