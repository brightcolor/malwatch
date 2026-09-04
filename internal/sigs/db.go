package sigs

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/brightcolor/malwatch/internal/report"
)

// Pattern is one byte signature. Parts must occur in order; between two
// parts any number of bytes may stand, which is how the "*" wildcard of the
// signature format is expressed.
type Pattern struct {
	Name  string
	Parts [][]byte
}

// DB holds the loaded signatures.
type DB struct {
	// bySize maps a file size to the known hashes of that size. Checking the
	// size first means the MD5 of a file is only computed when some signature
	// could match it at all.
	bySize map[int64]map[string]string

	patterns []Pattern
	m        *matcher

	Version     string
	HashCount   int
	PatternMax  int
	Unsupported int
}

// Empty reports whether the database holds nothing to match against.
func (d *DB) Empty() bool {
	return d == nil || (d.HashCount == 0 && len(d.patterns) == 0)
}

// Describe returns a short version string for the report.
func (d *DB) Describe() string {
	if d.Empty() {
		return "keine"
	}
	v := d.Version
	if v == "" {
		v = "unbekannt"
	}
	return fmt.Sprintf("%s (%d Hashes, %d Muster)", v, d.HashCount, len(d.patterns))
}

// Load reads the signature files from dir. A missing directory is not an
// error: the scan then runs on heuristics alone and says so in the report.
func Load(dir string) (*DB, error) {
	db := &DB{bySize: map[int64]map[string]string{}}

	if v, err := os.ReadFile(filepath.Join(dir, "version")); err == nil {
		db.Version = strings.TrimSpace(string(v))
	}

	if err := db.loadHashes(filepath.Join(dir, "rfxn.hdb")); err != nil && !os.IsNotExist(err) {
		return db, err
	}
	if err := db.loadPatterns(filepath.Join(dir, "rfxn.ndb")); err != nil && !os.IsNotExist(err) {
		return db, err
	}

	b := newBuilder()
	for i := range db.patterns {
		b.add(db.patterns[i].Parts[0], int32(i))
		if n := len(db.patterns[i].Parts[0]); n > db.PatternMax {
			db.PatternMax = n
		}
	}
	db.m = b.build()
	return db, nil
}

// loadHashes reads the "md5:size:name" hash database.
func (d *DB) loadHashes(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		size, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		sum := strings.ToLower(parts[0])
		if len(sum) != 32 {
			continue
		}
		if d.bySize[size] == nil {
			d.bySize[size] = map[string]string{}
		}
		d.bySize[size][sum] = parts[2]
		d.HashCount++
	}
	return sc.Err()
}

// loadPatterns reads the "name:target:offset:hex" pattern database.
//
// Only the plain hex form and the "*" gap are supported. Signatures using
// single-byte wildcards or alternatives are counted and skipped rather than
// loaded half-understood - a pattern parsed wrongly would either never match
// or match everything.
func (d *DB) loadPatterns(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		body := fields[3]

		if strings.ContainsAny(body, "?(){}[]") {
			d.Unsupported++
			continue
		}
		var parts [][]byte
		ok := true
		for _, chunk := range strings.Split(body, "*") {
			if chunk == "" {
				continue
			}
			raw, err := hex.DecodeString(chunk)
			if err != nil || len(raw) < 4 {
				ok = false
				break
			}
			parts = append(parts, raw)
		}
		if !ok || len(parts) == 0 {
			d.Unsupported++
			continue
		}
		d.patterns = append(d.patterns, Pattern{Name: name, Parts: parts})
	}
	return sc.Err()
}

// MatchHash returns the signature name if the file's size and MD5 are known
// bad. The size is checked first so most files never get hashed.
func (d *DB) MatchHash(size int64, content []byte) (string, bool) {
	if d == nil || d.HashCount == 0 {
		return "", false
	}
	byHash, ok := d.bySize[size]
	if !ok {
		return "", false
	}
	sum := md5.Sum(content)
	name, ok := byHash[hex.EncodeToString(sum[:])]
	return name, ok
}

// MatchPatterns returns the names of all byte signatures found in content.
func (d *DB) MatchPatterns(content []byte) []string {
	if d == nil || d.m == nil {
		return nil
	}
	var out []string
	for _, h := range d.m.findAll(content) {
		p := d.patterns[h.index]
		if len(p.Parts) == 1 {
			out = append(out, p.Name)
			continue
		}
		// The remaining parts must follow, in order, somewhere after the
		// first one - that is what "*" between two parts means.
		pos := h.end
		matched := true
		for _, part := range p.Parts[1:] {
			idx := bytes.Index(content[pos:], part)
			if idx < 0 {
				matched = false
				break
			}
			pos += idx + len(part)
		}
		if matched {
			out = append(out, p.Name)
		}
	}
	return out
}

// Scan runs both signature stages over one file.
func (d *DB) Scan(path string, size int64, content []byte) []report.Finding {
	if d.Empty() {
		return nil
	}
	var out []report.Finding
	if name, ok := d.MatchHash(size, content); ok {
		out = append(out, report.Finding{
			Path:     path,
			Rule:     name,
			Severity: report.SeverityCritical,
			Engine:   "signature",
			Size:     size,
		})
		// A file whose whole hash is known bad needs no pattern hits on top.
		return out
	}
	for _, name := range d.MatchPatterns(content) {
		out = append(out, report.Finding{
			Path:     path,
			Rule:     name,
			Severity: report.SeverityCritical,
			Engine:   "signature",
			Size:     size,
		})
	}
	return out
}
