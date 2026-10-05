//go:build !linux

package diskspace

import (
	"io/fs"
	"math"
	"os"
)

// Stat outside Linux has no portable answer, and the scanner ships for Linux.
// It keeps the packages that measure building and testable on a workstation:
// the path has to exist, Free has no limit and every path shares one
// filesystem, so a check passes. A test that measures on purpose brings its
// own Stat.
func Stat(path string) (Usage, error) {
	if _, err := os.Stat(path); err != nil {
		return Usage{}, err
	}
	return Usage{Free: math.MaxInt64}, nil
}

// Allocated counts a regular file at its size; nothing else counts.
func Allocated(info fs.FileInfo) int64 {
	if info.Mode().IsRegular() {
		return info.Size()
	}
	return 0
}
