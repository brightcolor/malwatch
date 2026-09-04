// Package walk traverses a directory tree and hands out candidate files.
// It never follows symlinks and never leaves the starting file system.
package walk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// File is one candidate handed to the scanners.
type File struct {
	Path  string
	Size  int64
	Mode  fs.FileMode
	MTime time.Time
	// Ext is the lower-case extension without the dot.
	Ext string
	// Rel is the slash separated path below the scanned root, with a leading
	// slash. Rules that judge a file by where it sits must use this and not
	// the absolute path: a site living under a directory called "uploads"
	// would otherwise have every one of its files flagged.
	Rel string
}

// Options steer the traversal.
type Options struct {
	// Excludes are glob patterns; "*" does not cross a slash, "**" does.
	Excludes []string
	// MaxAge skips files older than this. Zero means no age limit.
	MaxAge time.Duration
	// MaxSize skips files larger than this. Zero means no size limit.
	MaxSize int64
	// IgnoreChmod0 skips files with mode 000.
	IgnoreChmod0 bool
	// FollowSymlinks is deliberately absent: a symlinked path could point
	// outside the customer directory being scanned.
	Now time.Time
}

// Counters records what the walk did. Fields are updated atomically.
type Counters struct {
	Files       atomic.Int64
	Skipped     atomic.Int64
	Directories atomic.Int64
	Bytes       atomic.Int64
}

// Walker traverses trees under the given options.
type Walker struct {
	opts     Options
	counters *Counters
	errs     []string
}

// New returns a walker.
func New(opts Options, c *Counters) *Walker {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	return &Walker{opts: opts, counters: c}
}

// Errors returns non-fatal problems encountered during the walk.
func (w *Walker) Errors() []string { return w.errs }

// Walk visits root and calls fn for every candidate file. Directories that
// cannot be read are recorded as errors and skipped, so one unreadable
// customer directory does not abort the whole run.
func (w *Walker) Walk(root string, fn func(File) error) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Startpfad ist ein Symlink: " + root)
	}
	if !info.IsDir() {
		f, ok := w.candidate(root, root, info)
		if !ok {
			return nil
		}
		return fn(f)
	}

	var rootDev uint64
	if dev, ok := deviceID(info); ok {
		rootDev = dev
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			w.errs = append(w.errs, "nicht lesbar: "+path+" ("+err.Error()+")")
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path != root && w.excluded(path, root, true) {
				return fs.SkipDir
			}
			// Do not cross into another file system: a bind mount or a network
			// share below a web root would otherwise be scanned as if it were
			// part of the site, which can mean scanning it once per site.
			if path != root && rootDev != 0 {
				if di, err := d.Info(); err == nil {
					if dev, ok := deviceID(di); ok && dev != rootDev {
						return fs.SkipDir
					}
				}
			}
			w.counters.Directories.Add(1)
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if w.excluded(path, root, false) {
			w.counters.Skipped.Add(1)
			return nil
		}
		f, ok := w.candidate(root, path, info)
		if !ok {
			return nil
		}
		return fn(f)
	})
}

func (w *Walker) candidate(root, path string, info fs.FileInfo) (File, bool) {
	if w.opts.IgnoreChmod0 && info.Mode().Perm() == 0 {
		w.counters.Skipped.Add(1)
		return File{}, false
	}
	if w.opts.MaxAge > 0 && w.opts.Now.Sub(info.ModTime()) > w.opts.MaxAge {
		w.counters.Skipped.Add(1)
		return File{}, false
	}
	if w.opts.MaxSize > 0 && info.Size() > w.opts.MaxSize {
		w.counters.Skipped.Add(1)
		return File{}, false
	}
	ext := filepath.Ext(path)
	if len(ext) > 0 {
		ext = lower(ext[1:])
	}
	return File{
		Path:  path,
		Size:  info.Size(),
		Mode:  info.Mode(),
		MTime: info.ModTime(),
		Ext:   ext,
		Rel:   relPath(root, path),
	}, true
}

// relPath returns the slash separated path below root, always with a leading
// slash so a rule can anchor on "/uploads/" without matching "myuploads/".
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	return "/" + filepath.ToSlash(rel)
}

func (w *Walker) excluded(path, root string, isDir bool) bool {
	if len(w.opts.Excludes) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)
	full := filepath.ToSlash(path)
	for _, pat := range w.opts.Excludes {
		if Match(pat, rel) || Match(pat, full) || Match(pat, base) {
			return true
		}
		// A directory pattern such as "cache" or "**/cache" also excludes
		// everything below it, which is what an operator means by it.
		if isDir && Match(pat+"/**", rel) {
			return true
		}
	}
	return false
}

func lower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}
