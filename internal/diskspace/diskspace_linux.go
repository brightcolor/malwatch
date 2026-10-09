//go:build linux

package diskspace

import (
	"io/fs"
	"syscall"
)

// Stat measures the filesystem that holds path. The path has to exist.
//
// Free counts Bavail rather than Bfree: the blocks a filesystem reserves
// belong to root, and the scanner runs as root. Counting them would let it
// take the reserve that keeps the machine able to write at all.
func Stat(path string) (Usage, error) {
	var vfs syscall.Statfs_t
	if err := syscall.Statfs(path, &vfs); err != nil {
		return Usage{}, &fs.PathError{Op: "statfs", Path: path, Err: err}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return Usage{}, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	return Usage{
		Free:   int64(vfs.Bavail) * int64(vfs.Bsize),
		Block:  int64(vfs.Bsize),
		Device: uint64(st.Dev),
	}, nil
}

// Allocated is the room the file behind info takes up and gives back once it
// is removed. A file with a second hard link gives back nothing, because the
// other name keeps its blocks; a sparse file gives back only the blocks it
// has.
func Allocated(info fs.FileInfo) int64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	if info.Mode().IsRegular() && st.Nlink > 1 {
		return 0
	}
	return int64(st.Blocks) * 512
}
