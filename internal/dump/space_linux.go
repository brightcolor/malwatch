//go:build linux

package dump

import "syscall"

// FreeSpace is what is still available on the filesystem that holds path.
//
// Bavail rather than Bfree: the blocks a filesystem reserves belong to root,
// and a dump runs as root. Counting them would let one dump take the reserve
// that keeps the machine able to write at all.
func FreeSpace(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
