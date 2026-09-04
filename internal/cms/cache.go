package cms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache remembers version lookups between runs, so a nightly scan over
// fifty sites asks each vendor once a day rather than once per site.
type Cache struct {
	mu      sync.Mutex
	path    string
	ttl     time.Duration
	entries map[string]cacheEntry
	dirty   bool
}

type cacheEntry struct {
	Versions  []string  `json:"versions"`
	FetchedAt time.Time `json:"fetched_at"`
}

// NewCache loads the cache from path. A missing or broken file yields an
// empty cache rather than an error: a stale cache must never stop a scan.
func NewCache(path string, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	c := &Cache{path: path, ttl: ttl, entries: map[string]cacheEntry{}}
	if path == "" {
		return c
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var loaded map[string]cacheEntry
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return c
	}
	for k, v := range loaded {
		c.entries[k] = v
	}
	return c
}

// Get returns the cached versions if the entry is still fresh.
func (c *Cache) Get(key string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Since(e.FetchedAt) > c.ttl {
		return nil, false
	}
	return e.Versions, true
}

// Set stores a lookup result.
func (c *Cache) Set(key string, versions []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{Versions: versions, FetchedAt: time.Now()}
	c.dirty = true
}

// Save writes the cache back to disk. Failure is not reported as a scan
// error: the next run simply asks the vendors again.
func (c *Cache) Save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty || c.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return
	}
	raw, err := json.Marshal(c.entries)
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
	c.dirty = false
}
