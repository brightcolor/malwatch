package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"time"
)

// writeArchive packs whatever sits at root+rel - a single file or a whole
// directory - into a gzipped tar at dst. Every entry's name is computed
// relative to root rather than to the packed item itself, so rel is part of
// the name: unpacking the result against root reproduces root+rel exactly,
// which is the layout Restore needs back.
//
// Symlinks are stored as links and never followed, the same as
// repair.Backup: following one would pull whatever it points at into the
// archive instead of the link that was actually planted.
func writeArchive(dst string, root, rel string) (files int, bytes int64, err error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return 0, 0, err
	}
	fh, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, 0, err
	}
	defer fh.Close()

	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)

	start := filepath.Join(root, filepath.FromSlash(rel))
	walkErr := filepath.Walk(start, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(name)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		bytes += info.Size()
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	if walkErr != nil {
		return 0, 0, walkErr
	}
	if err := tw.Close(); err != nil {
		return 0, 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, 0, err
	}
	return files, bytes, nil
}

// pendingDir is a directory whose mode and timestamp are applied only after
// everything below it has been written - setting them any earlier could
// leave the walk unable to create the directory's own children, or would
// have that creation immediately overwrite the restored mtime.
type pendingDir struct {
	path string
	mode os.FileMode
	mod  time.Time
	uid  int
	gid  int
}

// readArchive unpacks src below destRoot, recreating the entries exactly as
// writeArchive named them - so destRoot is the root an entry was packed
// with, not the entry's own target path.
func readArchive(src string, destRoot string) error {
	fh, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var dirs []pendingDir

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destRoot, filepath.FromSlash(hdr.Name))
		mode := hdr.FileInfo().Mode()

		switch hdr.Typeflag {
		case tar.TypeDir:
			// A permissive mode for now: the walk that produced this
			// archive may still need to create files below it.
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			dirs = append(dirs, pendingDir{
				path: target, mode: mode.Perm(), mod: hdr.ModTime,
				uid: hdr.Uid, gid: hdr.Gid,
			})

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
			// Neither Chmod nor Chtimes has a portable, symlink-specific
			// form in the standard library; only ownership follows.
			if err := chownLink(target, hdr.Uid, hdr.Gid); err != nil {
				return err
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			if err := os.Chmod(target, mode.Perm()); err != nil {
				return err
			}
			if err := os.Chtimes(target, modTimeOrFallback(hdr), hdr.ModTime); err != nil {
				return err
			}
			if err := chownPath(target, hdr.Uid, hdr.Gid); err != nil {
				return err
			}

		default:
			return &UnsupportedEntryError{Name: hdr.Name, Type: hdr.Typeflag}
		}
	}

	// Deepest first, so a parent's tightened mode never blocks setting a
	// child's - Chmod only needs to reach the child, not write into it.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chtimes(d.path, d.mod, d.mod); err != nil {
			return err
		}
		if err := chownPath(d.path, d.uid, d.gid); err != nil {
			return err
		}
	}
	return nil
}

// modTimeOrFallback covers archives written on a platform that never filled
// in AccessTime (Windows, notably): Chtimes needs both times, and the zero
// value would set the access time to the Unix epoch instead of leaving it
// close to correct.
func modTimeOrFallback(hdr *tar.Header) time.Time {
	if hdr.AccessTime.IsZero() {
		return hdr.ModTime
	}
	return hdr.AccessTime
}

// UnsupportedEntryError means the tar held something that is neither a
// plain file, a directory nor a symlink - none of which writeArchive ever
// produces, so seeing one means the archive was not written by this package.
type UnsupportedEntryError struct {
	Name string
	Type byte
}

func (e *UnsupportedEntryError) Error() string {
	return "quarantine: " + e.Name + " hat einen nicht unterstützten Tar-Eintragstyp"
}
