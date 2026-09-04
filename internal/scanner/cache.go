package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cleanCache remembers files that were found clean, so a nightly run only
// looks at what changed.
//
// The cache is keyed by a fingerprint of everything that could change the
// verdict: the malwatch version, the rule count and the signature version.
// Without that a new rule would never be applied to old files - the scan
// would look fast and be blind.
type cleanCache struct {
	mu     sync.Mutex
	path   string
	print  string
	seen   map[string]cacheItem
	next   map[string]cacheItem
	loaded bool
}

type cacheItem struct {
	Size  int64 `json:"s"`
	MTime int64 `json:"m"`
}

type cacheFile struct {
	Fingerprint string               `json:"fingerprint"`
	SavedAt     time.Time            `json:"saved_at"`
	Files       map[string]cacheItem `json:"files"`
}

func newCleanCache(path, fingerprint string) *cleanCache {
	c := &cleanCache{
		path:  path,
		print: fingerprint,
		seen:  map[string]cacheItem{},
		next:  map[string]cacheItem{},
	}
	if path == "" {
		return c
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var loaded cacheFile
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return c
	}
	if loaded.Fingerprint != fingerprint {
		// Rules or signatures changed: everything is looked at again.
		return c
	}
	c.seen = loaded.Files
	c.loaded = true
	return c
}

// Enabled reports whether a cache path was configured.
func (c *cleanCache) Enabled() bool { return c != nil && c.path != "" }

// IsClean reports whether the file was clean last time and has not changed.
func (c *cleanCache) IsClean(path string, size int64, mtime time.Time) bool {
	if !c.Enabled() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.seen[path]
	return ok && item.Size == size && item.MTime == mtime.UnixNano()
}

// MarkClean records a file as clean for the next run.
func (c *cleanCache) MarkClean(path string, size int64, mtime time.Time) {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next[path] = cacheItem{Size: size, MTime: mtime.UnixNano()}
}

// Keep carries a still valid entry over into the next generation, so files
// skipped by the cache do not fall out of it on the following run.
func (c *cleanCache) Keep(path string) {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.seen[path]; ok {
		c.next[path] = item
	}
}

// Save writes the cache. A failure is silent: the next run just does more work.
func (c *cleanCache) Save() {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return
	}
	raw, err := json.Marshal(cacheFile{
		Fingerprint: c.print,
		SavedAt:     time.Now(),
		Files:       c.next,
	})
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}
