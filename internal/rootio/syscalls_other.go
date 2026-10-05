//go:build !linux

package rootio

import (
	"os"
	"path/filepath"
	"time"
)

// The scanner restores and repairs on Linux, where syscalls_linux.go takes
// these three steps through descriptors. Elsewhere - a developer's machine -
// they go by name.

func SymlinkIn(root *os.Root, oldname, name string, uid, gid int) error {
	path := filepath.Join(root.Name(), name)
	if err := os.Symlink(oldname, path); err != nil {
		return err
	}
	return ChownLink(path, uid, gid)
}

func SetTimes(f *os.File, atime, mtime time.Time) error {
	return os.Chtimes(f.Name(), atime, mtime)
}

func ReadlinkIn(root *os.Root, name string) (string, error) {
	return os.Readlink(filepath.Join(root.Name(), name))
}
