//go:build !linux

package quarantine

import (
	"os"
	"path/filepath"
	"time"
)

// The scanner restores on Linux, where restore_linux.go takes these two steps
// through descriptors. Elsewhere - a developer's machine - they go by name.

func symlinkIn(root *os.Root, oldname, name string, uid, gid int) error {
	path := filepath.Join(root.Name(), name)
	if err := os.Symlink(oldname, path); err != nil {
		return err
	}
	return chownLink(path, uid, gid)
}

func setTimes(f *os.File, atime, mtime time.Time) error {
	return os.Chtimes(f.Name(), atime, mtime)
}
