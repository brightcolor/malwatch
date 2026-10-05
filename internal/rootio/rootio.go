// Package rootio changes files inside a directory tree that keeps belonging to
// a website's user while a root process works in it.
//
// Quarantine restore, repair and the upgrade rollback all run as root in a
// tree the site's user owns. Every step here goes through an *os.Root
// (Go 1.24): it resolves one path element at a time, at the moment of the
// access, and refuses any element that leads out of the root, including a
// symlink into the void or a directory that becomes a link while the walk
// runs. The helpers are the shared mechanism behind the three callers, so the
// same reasoning holds in one place instead of three.
//
// os.Root in Go 1.24 has no Symlink, Lchown or Readlink of its own; those
// three steps run through a descriptor of the open parent directory, in the
// platform files next to this one.
package rootio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// EscapesRoot reports whether err is os.Root refusing a step out of its root.
// Go names that case "path escapes from parent" and keeps the error value to
// itself, so its text is the only way to tell it apart.
func EscapesRoot(err error) bool {
	return err != nil && strings.Contains(err.Error(), "path escapes from parent")
}

// RemoveAllIn removes name below root with everything in it. Like os.RemoveAll
// it removes a symlink itself and leaves its target alone. In addition, every
// step goes through root, so the removal stays below root.
func RemoveAllIn(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		dir, err := root.Open(name)
		if err != nil {
			return err
		}
		children, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := RemoveAllIn(root, filepath.Join(name, child.Name())); err != nil {
				return err
			}
		}
	}
	return root.Remove(name)
}

// MkdirAllIn creates name and every missing parent below root, one step at a
// time through root. Whatever already stands at one of these names has to be a
// directory.
func MkdirAllIn(root *os.Root, name string) error {
	if name == "." || name == "" {
		return nil
	}
	err := isDirIn(root, name)
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := MkdirAllIn(root, filepath.Dir(name)); err != nil {
		return err
	}
	if err := root.Mkdir(name, 0o750); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		// Created in the meantime: fine, as long as it is a directory.
		return isDirIn(root, name)
	}
	return nil
}

// isDirIn returns nil when name below root is a directory.
func isDirIn(root *os.Root, name string) error {
	info, err := root.Stat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return &os.PathError{Op: "mkdir", Path: name, Err: syscall.ENOTDIR}
	}
	return nil
}

// FinishEntry gives a restored file or directory its mode, times and owner,
// all three through f.
func FinishEntry(f *os.File, perm fs.FileMode, atime, mtime time.Time, uid, gid int) error {
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := SetTimes(f, atime, mtime); err != nil {
		return err
	}
	return ChownFile(f, uid, gid)
}

// SetModeOwner gives f its mode and owner through the descriptor, leaving its
// times alone. A repair carries over the identity of the tree it replaced and
// has no archived timestamp to set.
func SetModeOwner(f *os.File, perm fs.FileMode, uid, gid int) error {
	if err := f.Chmod(perm); err != nil {
		return err
	}
	return ChownFile(f, uid, gid)
}

// CopyTreeInto copies the tree at srcDir to destRel below root, every
// directory and file created through root so nothing lands outside it.
//
// srcDir is read by its own path: a repair stages the vendor's own files in a
// root-owned directory outside the web root, so reading them needs no guard;
// only the destination sits in the tree the website's user can change under
// the run. Directories take dirMode, files fileMode, both the given owner
// (uid or gid below zero leaves the owner alone). A symlink in the staged tree
// is refused - a vendor archive holds none, and following one here would put a
// file wherever it pointed. It returns the number of regular files written.
func CopyTreeInto(root *os.Root, destRel, srcDir string, dirMode, fileMode fs.FileMode, uid, gid int) (int, error) {
	written := 0
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		name := destRel
		if rel != "." {
			name = filepath.Join(destRel, rel)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unerwartete Verknüpfung %s im bereitgestellten Baum", path)
		}
		if info.IsDir() {
			if err := MkdirAllIn(root, name); err != nil {
				return err
			}
			d, err := root.Open(name)
			if err != nil {
				return err
			}
			err = SetModeOwner(d, dirMode, uid, gid)
			if cerr := d.Close(); err == nil {
				err = cerr
			}
			return err
		}

		if err := MkdirAllIn(root, filepath.Dir(name)); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := SetModeOwner(out, fileMode, uid, gid); err != nil {
			out.Close()
			return err
		}
		written++
		return out.Close()
	})
	return written, err
}

// ApplyOwnershipIn gives every entry of the tree at dir the owner and mode of
// the tree it replaced, each through its own descriptor. dir is opened as its
// own root, so every step stays inside the tree just written into place: a
// directory the website's user swaps for a symlink cannot steer a chmod or
// chown out of it. Directories keep mode, files lose the execute bits an
// archive may carry. The mode of a directory is set after its children, so a
// tightened parent never blocks reaching them.
func ApplyOwnershipIn(dir string, uid, gid int, mode fs.FileMode) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return applyOwnershipWalk(root, ".", uid, gid, mode)
}

func applyOwnershipWalk(root *os.Root, name string, uid, gid int, mode fs.FileMode) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A tree this package wrote holds no symlinks; a stray one is left as
		// it stands rather than followed by a chown.
		return nil
	}
	if !info.IsDir() {
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		err = SetModeOwner(f, mode&^0o111, uid, gid)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}

	d, err := root.Open(name)
	if err != nil {
		return err
	}
	children, err := d.ReadDir(-1)
	if err != nil {
		d.Close()
		return err
	}
	for _, c := range children {
		if err := applyOwnershipWalk(root, filepath.Join(name, c.Name()), uid, gid, mode); err != nil {
			d.Close()
			return err
		}
	}
	err = SetModeOwner(d, mode, uid, gid)
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
