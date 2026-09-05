//go:build windows

package repair

import "os"

// Windows has no Unix owner. The scanner runs on Linux; these exist so the
// package still builds on a developer's machine.
func ownerOf(info os.FileInfo) (int, int) { return -1, -1 }

func chownPath(path string, uid, gid int) error { return nil }

func chownLink(path string, uid, gid int) error { return nil }
