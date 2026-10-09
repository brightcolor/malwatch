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
	// Foreign means the file sits inside a tree the vendor ships whole and
	// is not part of it. Only trees registered through AddVendorTree can
	// produce this: a WordPress core install is full of files the checksum
	// list does not cover - wp-config.php, uploads, every plugin - and
	// calling those foreign would report the entire website.
	Foreign
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

	// copies maps every listed sum of a registered list - SHA-256 or MD5 - to
	// where the file comes from, so a copy elsewhere is known by its content
	// (see Copy).
	copies map[string]string
}

type entry struct {
	root  string
	label string
	// files maps a slash separated relative path to one or more lower case
	// hex sums, separated by commas: SHA-256 where the vendor publishes it,
	// MD5 otherwise (see Matches).
	files map[string]string
	// complete says the list covers everything the vendor puts in this
	// directory, so anything else below it does not come from the vendor.
	complete bool
	// confirmOnly says the list may only confirm a file: one that differs or
	// is missing from it says nothing, see AddVerified.
	confirmOnly bool
	// origin is where a single file of the release can be read, the path
	// below root appended; empty when unknown. See OriginOf.
	origin string
}

// New returns an empty index.
func New() *Index {
	return &Index{generic: map[string]bool{}, copies: map[string]string{}}
}

// AddInstall registers the checksum list of one installation. root is the
// directory the relative paths are based on.
//
// The list is treated as partial: a file below root that it does not mention
// is simply unknown. That is the right reading for a CMS core, whose
// directory also holds the configuration, the uploads and every plugin.
func (i *Index) AddInstall(root, label string, files map[string]string) {
	i.add(root, label, files, false, false)
}

// AddVendorTree registers a directory the vendor ships as a whole - a plugin
// or a theme.
//
// The difference to AddInstall is what an unlisted file means. A plugin
// directory contains the plugin and nothing else; a PHP file in it that the
// vendor does not ship got there some other way. That question - does this
// belong here - needs no pattern and cannot produce a false positive from a
// clever disguise, which is what makes it worth asking.
func (i *Index) AddVendorTree(root, label string, files map[string]string) {
	i.add(root, label, files, true, false)
}

// AddVerified registers a list that may only confirm a file as the vendor's.
// A theme is often adapted to its site - functions.php edited, a template
// added - so a file that differs from the release or is not part of it says
// nothing there; one that matches needs no further look.
func (i *Index) AddVerified(root, label string, files map[string]string) {
	i.add(root, label, files, false, true)
}

// AddCore registers the checksum list of a CMS core whose directories
// wholeDirs belong to the core alone.
//
// The install as a whole stays partial, as with AddInstall: its root holds
// the configuration and the site's own content. A directory in wholeDirs is
// different - WordPress keeps nothing of the site in wp-admin or
// wp-includes, so a file there that the release does not contain came in
// some other way. wp-cli verify-checksums asks the same question of the same
// two directories.
func (i *Index) AddCore(root, label string, files map[string]string, wholeDirs ...string) {
	i.add(root, label, files, false, false)
	for _, dir := range wholeDirs {
		prefix := strings.Trim(dir, "/") + "/"
		below := make(map[string]string)
		for path, sum := range files {
			if strings.HasPrefix(path, prefix) {
				below[path[len(prefix):]] = sum
			}
		}
		i.add(filepath.Join(root, filepath.FromSlash(dir)), label, below, true, false)
	}
}

func (i *Index) add(root, label string, files map[string]string, complete, confirmOnly bool) {
	if len(files) == 0 {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	for path, sums := range files {
		for _, sum := range strings.Split(sums, ",") {
			if sum != "" {
				if _, seen := i.copies[sum]; !seen {
					i.copies[sum] = label + ": " + path
				}
			}
		}
	}
	i.entries = append(i.entries, &entry{
		root:        filepath.Clean(root),
		label:       label,
		files:       files,
		complete:    complete,
		confirmOnly: confirmOnly,
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
			if e.confirmOnly {
				continue
			}
			if e.complete {
				// Inside a directory the vendor ships whole, and not part of
				// it. The caller decides what to make of that; the index only
				// says that the vendor did not put it there.
				return Foreign, e.label
			}
			// The file is inside a known installation but not part of it -
			// an upload, a cache file, a plugin. Nothing is claimed about it.
			continue
		}
		if Matches(want, content) {
			return Original, e.label
		}
		if e.confirmOnly {
			continue
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

// Lengths of a sum in hex digits; the length of a listed value names its kind.
const (
	md5Hex    = 2 * md5.Size
	sha256Hex = 2 * sha256.Size
)

// Matches reports whether content is one of the files a checksum list entry
// allows. A value of 64 hex digits is a SHA-256, one of 32 an MD5: wordpress.org
// publishes SHA-256 for plugin files and only MD5 for the core.
func Matches(entry string, content []byte) bool {
	var withSHA256, withMD5 bool
	for _, want := range strings.Split(entry, ",") {
		switch len(want) {
		case sha256Hex:
			withSHA256 = true
		case md5Hex:
			withMD5 = true
		}
	}
	if withSHA256 {
		sum := sha256.Sum256(content)
		if SumMatches(entry, hex.EncodeToString(sum[:])) {
			return true
		}
	}
	if withMD5 {
		sum := md5.Sum(content)
		if SumMatches(entry, hex.EncodeToString(sum[:])) {
			return true
		}
	}
	return false
}

// SetOrigin names where single files of the release registered for root can
// be read: base with the path below root appended, such as a tag of a plugin
// on plugins.svn.wordpress.org. It applies to the entries registered under
// label; one below root - wp-admin of a core install - gets its directory
// added to base.
func (i *Index) SetOrigin(root, label, base string) {
	root = filepath.Clean(root)
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, e := range i.entries {
		if e.label != label {
			continue
		}
		if e.root == root {
			e.origin = base
		} else if sub, ok := relativeTo(root, e.root); ok {
			e.origin = base + sub + "/"
		}
	}
}

// OriginOf returns where the release's own version of a listed file can be
// read, for a file below a root with a known origin.
func (i *Index) OriginOf(path string) (string, bool) {
	i.mu.RLock()
	entries := i.entries
	i.mu.RUnlock()
	clean := filepath.Clean(path)
	for _, e := range entries {
		rel, ok := relativeTo(e.root, clean)
		if !ok {
			continue
		}
		if _, listed := e.files[rel]; listed && e.origin != "" {
			return e.origin + rel, true
		}
	}
	return "", false
}

// Copy reports whether content is byte for byte a file of one of the
// registered lists, wherever it lies now, and names that file. A plugin that
// copies its own bundled files elsewhere at run time - EWWW Image Optimizer
// puts its programs into wp-content/ewww - leaves copies the vendor shipped.
// Where a copy lies can still be a question of its own; Copy only answers
// what it is.
func (i *Index) Copy(content []byte) (string, bool) {
	sum5 := md5.Sum(content)
	sum256 := sha256.Sum256(content)
	return i.CopySum(hex.EncodeToString(sum5[:]), hex.EncodeToString(sum256[:]))
}

// CopySum is Copy for a file whose sums are known already, as lower case hex:
// the lists hold SHA-256 where the vendor publishes it and MD5 otherwise (see
// Matches), so a caller passes every sum it has.
func (i *Index) CopySum(sums ...string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	for _, sum := range sums {
		if label, ok := i.copies[sum]; ok {
			return label, true
		}
	}
	return "", false
}

// SumMatches reports whether sum is one of the values of a checksum list
// entry. wordpress.org lists several for a plugin file that changed between
// two builds of the same release; the entry holds them separated by commas.
func SumMatches(entry, sum string) bool {
	for _, want := range strings.Split(entry, ",") {
		if want != "" && want == sum {
			return true
		}
	}
	return false
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
