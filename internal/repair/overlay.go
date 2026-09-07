package repair

import (
	"fmt"
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

		// Overlay mode is the one that leaves the old tree standing, so
		// whatever the attacker put there is still there while this writes -
		// including a symlink. os.WriteFile and os.MkdirAll follow one, and
		// this runs as root: plugins/akismet/assets pointed at /etc/cron.d
		// would have vendor files, and a chown, land outside the web root.
		// A link at this position is not something to write through and fix
		// up afterwards; it is a finding, and the repair says so and stops.
		if lst, err := os.Lstat(target); err == nil && lst.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s ist eine Verknüpfung und wird nicht überschrieben - "+
				"sie gehört nicht in ein Herstellerverzeichnis", target)
		}
		if err := InsideRoot(root, target); err != nil {
			return err
		}

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
