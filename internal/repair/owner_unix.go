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
