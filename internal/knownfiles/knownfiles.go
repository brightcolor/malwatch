// Package knownfiles keeps the checksums of unmodified vendor files. It
// serves two purposes: an untouched original never becomes a false positive,
// and an original that no longer matches is itself worth reporting.
package knownfiles

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Status is the verdict for one file.
type Status int

const (
	// Unknown means no vendor checksum covers this file.
	Unknown Status = iota
	// Original means the file is byte for byte the vendor's.
	Original
	// Modified means a vendor file exists under this name but differs.
	Modified
)

// Index answers checksum questions for a set of installations.
type Index struct {
	mu sync.RWMutex

	// entries are sorted by descending root length, so the most specific
	// installation wins when a plugin lives inside a WordPress tree.
	entries []*entry

	// generic holds SHA-256 sums of vendor files whose location does not
	// matter, built from the release archives of the other CMS.
	generic map[string]bool
}

type entry struct {
	root  string
	label string
	// files maps a slash separated relative path to a lower case MD5.
	files map[string]string
}

// New returns an empty index.
func New() *Index {
	return &Index{generic: map[string]bool{}}
}

// AddInstall registers the checksum list of one installation. root is the
// directory the relative paths are based on.
func (i *Index) AddInstall(root, label string, files map[string]string) {
	if len(files) == 0 {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.entries = append(i.entries, &entry{
		root:  filepath.Clean(root),
		label: label,
		files: files,
	})
	sort.SliceStable(i.entries, func(a, b int) bool {
		return len(i.entries[a].root) > len(i.entries[b].root)
	})
}

// AddGeneric registers SHA-256 sums of vendor files.
func (i *Index) AddGeneric(sums []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, s := range sums {
		s = strings.ToLower(strings.TrimSpace(s))
		if len(s) == 64 {
			i.generic[s] = true
		}
	}
}

// Empty reports whether the index knows nothing.
func (i *Index) Empty() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.entries) == 0 && len(i.generic) == 0
}

// Counts returns how many installs and generic sums are loaded.
func (i *Index) Counts() (installs, sums int) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	total := 0
	for _, e := range i.entries {
		total += len(e.files)
	}
	return len(i.entries), total + len(i.generic)
}

// Check classifies one file. label names the installation the file belongs
// to, for the report.
func (i *Index) Check(path string, content []byte) (Status, string) {
	i.mu.RLock()
	entries := i.entries
	generic := i.generic
	i.mu.RUnlock()

	clean := filepath.Clean(path)
	for _, e := range entries {
		rel, ok := relativeTo(e.root, clean)
		if !ok {
			continue
		}
		want, ok := e.files[rel]
		if !ok {
			// The file is inside a known installation but not part of it -
			// an upload, a cache file, a plugin. Nothing is claimed about it.
			continue
		}
		sum := md5.Sum(content)
		if hex.EncodeToString(sum[:]) == want {
			return Original, e.label
		}
		return Modified, e.label
	}

	if len(generic) > 0 {
		sum := sha256.Sum256(content)
		if generic[hex.EncodeToString(sum[:])] {
			return Original, ""
		}
	}
	return Unknown, ""
}

// relativeTo returns the slash separated path of file below root.
func relativeTo(root, file string) (string, bool) {
	if !strings.HasPrefix(file, root) {
		return "", false
	}
	rest := file[len(root):]
	if rest == "" {
		return "", false
	}
	if rest[0] != filepath.Separator && rest[0] != '/' {
		// root "/var/www/web" must not swallow "/var/www/website".
		return "", false
	}
	return filepath.ToSlash(strings.TrimLeft(rest, `/\`)), true
}
