// Package dump packs the web directory of one website, its logs and its
// databases into a single tar.gz the panel hands out.
//
// The layout is the one an operator expects to find after unpacking:
//
//	web/…                  the web directory, names relative to its root
//	protokolle/…           the log directory, when one was named
//	datenbanken/<name>.sql one file per database
//	dump.json              the report of this run
//
// Symlinks are stored as links and never followed, the same as
// internal/quarantine/archive.go: following one would pull whatever it points
// at into the archive instead of the link that actually sits there.
package dump

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/version"
)

// Schema is the version of the report below. The panel reads it before it
// trusts the fields.
const Schema = 1

// reservePart is the share of the source size a run keeps free on top of what
// it writes: a tenth, so a dump never fills the last block of a disk that
// other services write to at the same time.
const reservePart = 10

// prefixWeb and prefixLogs are the two directories inside the archive.
const (
	prefixWeb  = "web"
	prefixLogs = "protokolle"
	prefixDB   = "datenbanken"
)

// Dumper writes one database as SQL. The production dumper runs mysqldump;
// tests put their own in, so they need no database.
type Dumper interface {
	Dump(name string, out io.Writer) error
}

// Options describes one run. WebRoot and Archive are required, everything else
// is optional.
type Options struct {
	WebRoot   string
	LogRoot   string
	Databases []string
	Archive   string
	// MinFree is space the run leaves untouched on top of its own estimate,
	// for example the size the panel knows the databases will add.
	MinFree int64
	Dumper  Dumper
	// Free measures the free space; nil means FreeSpace. A test puts its own
	// in, so the gate answers the same on every machine.
	Free     func(path string) (int64, error)
	Progress *progress.Writer
}

// DatabaseReport is one database as it landed in the archive.
type DatabaseReport struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// Report is what the run leaves behind, both inside the archive and in the
// file the caller names with --out.
type Report struct {
	Schema    int              `json:"schema"`
	Version   string           `json:"malwatch_version"`
	WebRoot   string           `json:"web_root"`
	LogRoot   string           `json:"log_root,omitempty"`
	Files     int              `json:"files"`
	Bytes     int64            `json:"bytes"`
	Databases []DatabaseReport `json:"databases"`
	// ArchiveBytes and SHA256 describe the finished archive. The copy inside
	// the archive leaves them empty: a file cannot carry its own size and
	// checksum. The caller writes the complete report next to the archive.
	ArchiveBytes int64     `json:"archive_bytes"`
	SHA256       string    `json:"sha256"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	// Reason is space, database or files when the run ended early, and names
	// which of the three steps refused; Message carries the detail.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Run packs one website. It returns the report in every case, so a caller can
// tell the panel what happened even when the error stopped the run.
func Run(opts Options) (*Report, error) {
	rep := &Report{
		Schema:    Schema,
		Version:   version.Version,
		WebRoot:   opts.WebRoot,
		LogRoot:   opts.LogRoot,
		Databases: []DatabaseReport{},
		StartedAt: time.Now().UTC(),
	}

	if opts.WebRoot == "" || opts.Archive == "" {
		return fail(rep, "files", errors.New("Webverzeichnis und Zieldatei sind Pflicht"))
	}
	if len(opts.Databases) > 0 && opts.Dumper == nil {
		return fail(rep, "database", errors.New("kein Weg, die Datenbanken zu holen"))
	}

	dir := filepath.Dir(opts.Archive)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fail(rep, "files", err)
	}
	if err := checkSpace(opts, dir); err != nil {
		return fail(rep, "space", err)
	}

	fh, err := os.OpenFile(opts.Archive, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fail(rep, "files", err)
	}

	sum := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(fh, sum))
	tw := tar.NewWriter(gz)

	reason, err := pack(tw, opts, rep)
	if err == nil {
		err = closeAll(tw, gz, fh)
		if err != nil {
			reason = "files"
		}
	} else {
		// The half archive goes: it would unpack into something that looks
		// like a backup and is missing a part nobody named.
		_ = tw.Close()
		_ = gz.Close()
		_ = fh.Close()
	}
	if err != nil {
		_ = os.Remove(opts.Archive)
		return fail(rep, reason, err)
	}

	info, err := os.Stat(opts.Archive)
	if err != nil {
		_ = os.Remove(opts.Archive)
		return fail(rep, "files", err)
	}
	rep.ArchiveBytes = info.Size()
	rep.SHA256 = hex.EncodeToString(sum.Sum(nil))
	rep.FinishedAt = time.Now().UTC()
	return rep, nil
}

// pack writes every part in order and names the step that refused.
func pack(tw *tar.Writer, opts Options, rep *Report) (string, error) {
	phases := 2
	if len(opts.Databases) > 0 {
		phases = 3
	}

	step(opts.Progress, 1, phases, "Dateien")
	if err := packTree(tw, opts.WebRoot, prefixWeb, rep, opts.Progress); err != nil {
		return "files", err
	}

	if opts.LogRoot != "" {
		step(opts.Progress, 2, phases, "Protokolle")
		if err := packTree(tw, opts.LogRoot, prefixLogs, rep, opts.Progress); err != nil {
			return "files", err
		}
	}

	for i, name := range opts.Databases {
		step(opts.Progress, 3, phases, "Datenbanken")
		logf(opts.Progress, "info", "Datenbank %s (%d von %d)", name, i+1, len(opts.Databases))
		bytes, err := packDatabase(tw, opts, name)
		if err != nil {
			return "database", fmt.Errorf("Datenbank %s: %w", name, err)
		}
		rep.Databases = append(rep.Databases, DatabaseReport{Name: name, Bytes: bytes})
	}

	if err := packReport(tw, rep); err != nil {
		return "files", err
	}
	return "", nil
}

// packTree walks one directory into the archive under prefix.
func packTree(tw *tar.Writer, root, prefix string, rep *Report, pw *progress.Writer) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := prefix
		if rel != "." {
			name = prefix + "/" + filepath.ToSlash(rel)
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
		hdr.Name = name
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		rep.Files++
		rep.Bytes += info.Size()
		if pw != nil {
			pw.File(name, rep.Files, 0)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
}

// packDatabase exports one database and puts it into the archive.
//
// tar carries the size in the header, so the export lands next to the archive
// first and streams in from there. The file sits in the same directory as the
// archive, which the space check already measured, and it goes as soon as it
// is in.
func packDatabase(tw *tar.Writer, opts Options, name string) (int64, error) {
	scratch := opts.Archive + "." + name + ".part"
	fh, err := os.OpenFile(scratch, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer os.Remove(scratch)

	dumpErr := opts.Dumper.Dump(name, fh)
	closeErr := fh.Close()
	if dumpErr != nil {
		return 0, dumpErr
	}
	if closeErr != nil {
		return 0, closeErr
	}

	info, err := os.Stat(scratch)
	if err != nil {
		return 0, err
	}
	hdr := &tar.Header{
		Name:     prefixDB + "/" + name + ".sql",
		Mode:     0o600,
		Size:     info.Size(),
		ModTime:  info.ModTime(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, err
	}
	in, err := os.Open(scratch)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if _, err := io.Copy(tw, in); err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// packReport puts the report into the archive, as the last entry: it counts
// the files above it.
func packReport(tw *tar.Writer, rep *Report) error {
	inside := *rep
	inside.FinishedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(inside, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	hdr := &tar.Header{
		Name:     "dump.json",
		Mode:     0o600,
		Size:     int64(len(raw)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write(raw)
	return err
}

// checkSpace refuses before the first byte: a dump that fills the disk takes
// every website on the machine with it.
func checkSpace(opts Options, dir string) error {
	size, err := SourceSize(opts.WebRoot, opts.LogRoot)
	if err != nil {
		return err
	}
	free := opts.Free
	if free == nil {
		free = FreeSpace
	}
	have, err := free(dir)
	if err != nil {
		return err
	}
	need := size + size/reservePart + opts.MinFree
	if have < need {
		return fmt.Errorf("frei sind %d Bytes, gebraucht werden %d", have, need)
	}
	return nil
}

func closeAll(tw *tar.Writer, gz *gzip.Writer, fh *os.File) error {
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = fh.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

func fail(rep *Report, reason string, err error) (*Report, error) {
	rep.Reason = reason
	rep.Message = err.Error()
	rep.FinishedAt = time.Now().UTC()
	return rep, err
}

func step(pw *progress.Writer, index, total int, name string) {
	if pw != nil {
		pw.Phase(index, total, name)
	}
}

func logf(pw *progress.Writer, level, format string, args ...any) {
	if pw != nil {
		pw.Log(level, format, args...)
	}
}
