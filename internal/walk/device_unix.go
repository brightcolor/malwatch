//go:build unix

package walk

import (
	"io/fs"
	"syscall"
)

// deviceID returns the file system device of the entry, so the walk can stop
// at a mount point.
func deviceID(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}
