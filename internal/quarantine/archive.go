package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/brightcolor/malwatch/internal/rootio"
)

// writeArchive packs whatever sits at root+rel - a single file or a whole
// directory - into a gzipped tar at dst. Every entry's name is computed
// relative to root rather than to the packed item itself, so rel is part of
// the name: unpacking the result against root reproduces root+rel exactly,
// which is the layout Restore needs back.
//
// Every step reads through an os.Root opened on root, which resolves each step
// at the moment it is read and refuses one that leaves root, so the walk stays
// inside the web root even if the tree changes while it runs. A symlink is
// stored as the link it is and never followed, the same as before: a shared
// upload folder comes back as the link it was.
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

	src, err := os.OpenRoot(root)
	if err != nil {
		return 0, 0, err
	}
	defer src.Close()

	name := filepath.Clean(filepath.FromSlash(rel))
	files, bytes, err = packEntry(tw, src, name)
	if err != nil {
		return 0, 0, err
	}
	if err := tw.Close(); err != nil {
		return 0, 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, 0, err
	}
	return files, bytes, nil
}

// packEntry writes name below src into the tar and, when name is a directory,
// everything under it. It counts regular files and their bytes, the same
// figures the old filepath.Walk returned. Children are sorted by name, so an
// archive of the same tree comes out byte for byte the same.
func packEntry(tw *tar.Writer, src *os.Root, name string) (files int, bytes int64, err error) {
	info, err := src.Lstat(name)
	if err != nil {
		return 0, 0, err
	}

	link := ""
	if info.Mode()&os.ModeSymlink != 0 {
		if link, err = rootio.ReadlinkIn(src, name); err != nil {
			return 0, 0, err
		}
	}
	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return 0, 0, err
	}
	hdr.Name = filepath.ToSlash(name)
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, 0, err
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return 0, 0, nil

	case info.IsDir():
		d, err := src.Open(name)
		if err != nil {
			return 0, 0, err
		}
		children, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return 0, 0, err
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, c := range children {
			f, b, err := packEntry(tw, src, filepath.Join(name, c.Name()))
			if err != nil {
				return files, bytes, err
			}
			files += f
			bytes += b
		}
		return files, bytes, nil

	case info.Mode().IsRegular():
		in, err := src.Open(name)
		if err != nil {
			return 0, 0, err
		}
		defer in.Close()
		if _, err := io.Copy(tw, in); err != nil {
			return 0, 0, err
		}
		return 1, info.Size(), nil

	default:
		// A socket, device or pipe: its header is written, like the old walk
		// did, and nothing is read from it.
		return 0, 0, nil
	}
}

// pendingDir is a directory whose mode and timestamp are applied only after
// everything below it has been written - setting them any earlier could
// leave the walk unable to create the directory's own children, or would
// have that creation immediately overwrite the restored mtime.
type pendingDir struct {
	entry string // the name in the archive, for messages
	name  string // the same name below destRoot
	mode  os.FileMode
	mod   time.Time
	uid   int
	gid   int
}

// readArchive unpacks src below destRoot, recreating the entries exactly as
// writeArchive named them - so destRoot is the root an entry was packed
// with, not the entry's own target path.
//
// Every write goes through an os.Root opened on destRoot, which resolves a
// name one step at a time at the moment of the write and refuses every step
// that leaves destRoot. Mode, times and owner are set through the open file,
// so they apply to exactly the file that was written. The steps os.Root in
// Go 1.24 does not offer (a symlink, its owner, a file's times) run through a
// descriptor in internal/rootio.
func readArchive(src string, destRoot string) error {
	// os.OpenRoot needs destRoot to exist. It does for a real restore - it is
	// the web root - but not for the scratch directory StoreCopy verifies a
	// fresh archive through.
	if err := os.MkdirAll(destRoot, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(destRoot)
	if err != nil {
		return err
	}
	defer root.Close()

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
		// Names are judged before they are used: IsLocal refuses "..", an
		// absolute name and an empty one, so every entry stays below destRoot.
		name := filepath.FromSlash(hdr.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("archiveintrag %q zeigt aus %s heraus", hdr.Name, destRoot)
		}
		name = filepath.Clean(name)
		if name == "." {
			return fmt.Errorf("archiveintrag %q benennt %s selbst, nicht einen Eintrag darin", hdr.Name, destRoot)
		}
		mode := hdr.FileInfo().Mode()

		switch hdr.Typeflag {
		case tar.TypeDir:
			// A permissive mode for now: the walk that produced this
			// archive may still need to create files below it.
			if err := rootio.MkdirAllIn(root, name); err != nil {
				return rootError(hdr.Name, destRoot, err)
			}
			dirs = append(dirs, pendingDir{
				entry: hdr.Name, name: name, mode: mode.Perm(), mod: hdr.ModTime,
				uid: hdr.Uid, gid: hdr.Gid,
			})

		case tar.TypeSymlink:
			if err := rootio.MkdirAllIn(root, filepath.Dir(name)); err != nil {
				return rootError(hdr.Name, destRoot, err)
			}
			// The link comes back pointing wherever it pointed when it was
			// quarantined, into the website or out of it: quarantine returns
			// what was there, and a shared upload folder is a link out of the
			// web root as well. It cannot carry a later entry out of
			// destRoot, because os.Root never follows a link there. Neither
			// Chmod nor Chtimes has a portable, symlink-specific form in the
			// standard library; only ownership follows.
			if err := rootio.SymlinkIn(root, hdr.Linkname, name, hdr.Uid, hdr.Gid); err != nil {
				return rootError(hdr.Name, destRoot, err)
			}

		case tar.TypeReg:
			if err := rootio.MkdirAllIn(root, filepath.Dir(name)); err != nil {
				return rootError(hdr.Name, destRoot, err)
			}
			out, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
			if err != nil {
				return rootError(hdr.Name, destRoot, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := rootio.FinishEntry(out, mode.Perm(), modTimeOrFallback(hdr), hdr.ModTime, hdr.Uid, hdr.Gid); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}

		default:
			return &UnsupportedEntryError{Name: hdr.Name, Type: hdr.Typeflag}
		}
	}

	// Deepest first, so a parent's tightened mode never blocks setting a
	// child's: opening the child only needs to pass through its parents.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		dir, err := root.Open(d.name)
		if err != nil {
			return rootError(d.entry, destRoot, err)
		}
		err = rootio.FinishEntry(dir, d.mode, d.mod, d.mod, d.uid, d.gid)
		if closeErr := dir.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// rootError says why an entry could not be written below destRoot; any cause
// other than a step out of the root comes with Go's own description.
func rootError(entry, destRoot string, err error) error {
	if rootio.EscapesRoot(err) {
		return fmt.Errorf("archiveintrag %q führt über einen symbolischen Link aus %s heraus und wurde nicht geschrieben (%v). "+
			"Den Link prüfen und entfernen, danach den Auftrag erneut starten", entry, destRoot, err)
	}
	return fmt.Errorf("archiveintrag %q lässt sich unter %s nicht anlegen: %w", entry, destRoot, err)
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
