package repair

import (
	"os"
	"path/filepath"
)

// Overlay copies newDir over oldDir, adding and replacing, leaving everything
// else in place. Ownership and mode come from the tree being written into: a
// plugin overlaid onto a hardened install must not loosen it just because the
// vendor's own archive carries different permissions, and a file that is not
// part of the vendor's tree - a customer addition, or exactly the kind of
// planted file overlay mode is trusted to leave visible - is never touched.
func Overlay(root, oldDir, newDir string) (int, error) {
	if err := InsideRoot(root, oldDir); err != nil {
		return 0, err
	}

	// oldDir's own mode governs every file this writes, in place of whatever
	// the vendor's archive extracted with. When oldDir does not exist yet
	// there is nothing to inherit, so a plain default takes over.
	dirMode := os.FileMode(0o755)
	uid, gid := -1, -1
	if info, err := os.Stat(oldDir); err == nil {
		dirMode = info.Mode().Perm()
		uid, gid = ownerOf(info)
	}
	fileMode := dirMode &^ 0o111

	if err := os.MkdirAll(oldDir, dirMode); err != nil {
		return 0, err
	}

	written := 0
	err := filepath.Walk(newDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(newDir, path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(oldDir, rel)

		if info.IsDir() {
			if err := os.MkdirAll(target, dirMode); err != nil {
				return err
			}
			return chownPath(target, uid, gid)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, raw, fileMode); err != nil {
			return err
		}
		written++
		return chownPath(target, uid, gid)
	})
	if err != nil {
		return written, err
	}
	return written, nil
}
