//go:build windows

package rootio

import "os"

// Windows has no Unix owner. These exist so the package still builds on a
// developer's machine; the scanner itself runs on Linux.
func ChownFile(f *os.File, uid, gid int) error { return nil }

func ChownLink(path string, uid, gid int) error { return nil }
