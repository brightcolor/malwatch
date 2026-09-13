package vulns

import (
	"os"
	"path/filepath"
	"time"
)

// diskCache keeps the answers of the vulnerability sources between runs.
//
// A nightly pass over sixty websites asks about the same few hundred plugins
// sixty times. The sources are run by small teams or sit behind a daily
// quota, and each question should reach them once a day at most. Freshness
// is the modification time of the file, so the directory can be deleted at
// any moment and the only cost is a round of requests.
type diskCache struct {
	dir string
}

// get returns what is stored under key and its age. ok is false when nothing
// is stored.
func (d diskCache) get(key string) (body []byte, age time.Duration, ok bool) {
	if d.dir == "" {
		return nil, 0, false
	}
	path := filepath.Join(d.dir, key)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, 0, false
	}
	body, err = os.ReadFile(path)
	if err != nil {
		return nil, 0, false
	}
	return body, time.Since(info.ModTime()), true
}

// put stores body under key. A failed write costs a request on the next run
// and nothing else, so it is not reported.
//
// The temporary file gets a name of its own: two scans running side by side
// may store the same answer at the same moment, and a shared temporary name
// would let the one interleave its bytes with the other's.
func (d diskCache) put(key string, body []byte) {
	if d.dir == "" {
		return
	}
	if err := os.MkdirAll(d.dir, 0o750); err != nil {
		return
	}
	f, err := os.CreateTemp(d.dir, key+".*.tmp")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		return
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, filepath.Join(d.dir, key)); err != nil {
		os.Remove(tmp)
	}
}

// touch marks a stored answer as fresh without rewriting it, for a source
// that answered "unchanged since you last asked".
func (d diskCache) touch(key string) {
	if d.dir == "" {
		return
	}
	now := time.Now()
	_ = os.Chtimes(filepath.Join(d.dir, key), now, now)
}

// path returns where key is stored, empty without a cache directory.
func (d diskCache) path(key string) string {
	if d.dir == "" {
		return ""
	}
	return filepath.Join(d.dir, key)
}
