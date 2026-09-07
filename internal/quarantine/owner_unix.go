//go:build !windows

package quarantine

import "os"

// chownPath tolerates a permission error, the same way repair.applyOwnership
// does: restoring the exact original owner needs a privilege quarantine may
// not run with, and that must not turn a successful restore into a failure.
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
