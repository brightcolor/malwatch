//go:build windows

package quarantine

import "os"

// Windows has no Unix owner. These exist so the package still builds on a
// developer's machine; the scanner itself runs on Linux.
func chownFile(f *os.File, uid, gid int) error { return nil }

func chownLink(path string, uid, gid int) error { return nil }
