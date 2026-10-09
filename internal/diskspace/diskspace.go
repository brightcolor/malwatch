// Package diskspace measures the filesystem behind a path: the room still free
// for the scanner to write, the block size files take up space in, and which
// filesystem it is, so that two paths on one filesystem count against the
// same free space.
package diskspace

// Usage is what Stat reports about the filesystem that holds one path.
type Usage struct {
	// Free is the room left for an unprivileged writer, in bytes.
	Free int64
	// Block is the unit a file takes up space in, in bytes; 0 when the
	// platform does not say.
	Block int64
	// Device tells filesystems apart: paths with the same Device share Free.
	Device uint64
}
