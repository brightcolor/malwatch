//go:build !unix

package walk

import "io/fs"

// deviceID has no meaning outside unix; the walk then simply does not stop at
// mount points. malwatch ships for Linux, this keeps the tests buildable
// on a developer machine.
func deviceID(fs.FileInfo) (uint64, bool) { return 0, false }
