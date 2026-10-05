//go:build windows

package repair

import "os"

// Windows has no Unix owner. The scanner runs on Linux; this exists so the
// package still builds on a developer's machine.
func ownerOf(info os.FileInfo) (int, int) { return -1, -1 }
