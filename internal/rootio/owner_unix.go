//go:build !windows

package rootio

import "os"

// ChownFile sets the owner of the open file and tolerates a permission error,
// the same way repair does: restoring the exact original owner needs a
// privilege the run may not have, and that must not turn an otherwise
// successful change into a failure. A uid or gid below zero leaves it alone.
func ChownFile(f *os.File, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := f.Chown(uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}

// ChownLink sets the owner of the symlink at path without following it, with
// the same tolerance for a missing privilege.
func ChownLink(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := os.Lchown(path, uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}
