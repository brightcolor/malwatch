//go:build !windows

package repair

import (
	"os"
	"syscall"
)

func ownerOf(info os.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// chownPath tolerates a permission error. Not being root is normal in tests
// and during a dry run; the report says the ownership could not be set rather
// than failing the whole repair over it.
func chownPath(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}

func chownLink(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := os.Lchown(path, uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}
