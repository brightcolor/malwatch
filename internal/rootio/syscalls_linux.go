//go:build linux

package rootio

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// The three steps os.Root in Go 1.24 does not offer, taken through
// descriptors so none can be redirected by a directory the website's user
// swaps for a symlink in the meantime.

// SymlinkIn creates name below root as a link to oldname and gives the link
// itself uid and gid. The parent is opened through root; the link is created
// in that open directory, wherever it sits by now.
func SymlinkIn(root *os.Root, oldname, name string, uid, gid int) error {
	dir, err := root.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	conn, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var linkErr error
	if err := conn.Control(func(fd uintptr) {
		// /proc/self/fd/N stands for the open directory itself: the kernel
		// does not walk its old path again. Go's own syscall.Futimes relies
		// on the same.
		at := "/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10) + "/" + filepath.Base(name)
		if err := syscall.Symlink(oldname, at); err != nil {
			linkErr = &os.LinkError{Op: "symlink", Old: oldname, New: name, Err: err}
			return
		}
		linkErr = ChownLink(at, uid, gid)
	}); err != nil {
		return err
	}
	return linkErr
}

// SetTimes sets the access and modification time of f through its descriptor.
// A tar header carries whole seconds, so the microseconds of a Timeval lose
// nothing.
func SetTimes(f *os.File, atime, mtime time.Time) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	tv := []syscall.Timeval{
		syscall.NsecToTimeval(atime.UnixNano()),
		syscall.NsecToTimeval(mtime.UnixNano()),
	}
	var timesErr error
	if err := conn.Control(func(fd uintptr) {
		timesErr = syscall.Futimes(int(fd), tv)
	}); err != nil {
		return err
	}
	if timesErr != nil {
		return &os.PathError{Op: "futimes", Path: f.Name(), Err: timesErr}
	}
	return nil
}

// ReadlinkIn reads the target of the symlink at name below root, without
// following any symlink on the way: the parent is opened through root, and the
// final component is read from that open directory through /proc/self/fd, the
// same path SymlinkIn writes through, so the parent's old path is never walked
// again.
func ReadlinkIn(root *os.Root, name string) (string, error) {
	dir, err := root.Open(filepath.Dir(name))
	if err != nil {
		return "", err
	}
	defer dir.Close()
	conn, err := dir.SyscallConn()
	if err != nil {
		return "", err
	}
	var link string
	var readErr error
	if err := conn.Control(func(fd uintptr) {
		at := "/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10) + "/" + filepath.Base(name)
		link, readErr = os.Readlink(at)
	}); err != nil {
		return "", err
	}
	return link, readErr
}
