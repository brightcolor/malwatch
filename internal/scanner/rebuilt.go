package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/brightcolor/malwatch/internal/knownfiles"
)

// verifiedRebuild is the source of script files that differ from the release
// the way a rebuild by the vendor does.
const verifiedRebuild = "Neubau einer Skriptdatei des Herstellers"

// scriptExts are the extensions of files a browser reads, whose deviation
// from the release is weighed by what changed rather than reported as such.
var scriptExts = map[string]bool{"js": true, "mjs": true, "cjs": true, "html": true, "htm": true, "svg": true, "css": true}

// localized is how much of the original a changed file has to keep, from its
// start and its end, for the change to count as one place. Below that the
// file differs throughout, as a new build with another bundler does.
const localized = 0.9

// harmlessDeviation reports whether a script file that differs from the
// vendor's release differs the way a rebuild does. A file that keeps the
// original whole or all but one place is judged by what came in there:
// code that loads or runs a script is what an injection adds, a changed data
// block is not. A file that differs throughout is a rebuild; code injected
// into it is left to the rules that read scripts.
func harmlessDeviation(local, orig []byte) bool {
	if len(orig) > 0 {
		if i := bytes.Index(local, orig); i >= 0 {
			added := append(append([]byte{}, local[:i]...), local[i+len(orig):]...)
			return !loadsOrRuns(added)
		}
	}
	p := 0
	for p < len(local) && p < len(orig) && local[p] == orig[p] {
		p++
	}
	s := 0
	for s < len(local)-p && s < len(orig)-p && local[len(local)-1-s] == orig[len(orig)-1-s] {
		s++
	}
	if float64(p+s) >= localized*float64(len(orig)) {
		return !loadsOrRuns(local[p : len(local)-s])
	}
	return true
}

// runners are what code that loads or runs a script contains, lower case.
var runners = [][]byte{
	[]byte("<script"), []byte("<iframe"), []byte("createelement("), []byte("eval("), []byte("new function("),
	[]byte("atob("), []byte("fromcharcode"), []byte("unescape("), []byte("document.write"), []byte("document.cookie"),
	[]byte("location."), []byte("location="), []byte(".src="), []byte(".src ="), []byte("fetch("),
	[]byte("xmlhttprequest"), []byte("import("), []byte("settimeout(\""), []byte("settimeout('"),
	[]byte("setinterval(\""), []byte("setinterval('"), []byte("window["),
}

func loadsOrRuns(b []byte) bool {
	lower := bytes.ToLower(b)
	for _, r := range runners {
		if bytes.Contains(lower, r) {
			return true
		}
	}
	return false
}

// originFetcher loads single files of a vendor's release, such as one file
// of a plugin tag on plugins.svn.wordpress.org, and keeps them.
type originFetcher struct {
	client   *http.Client
	cacheDir string
	maxBytes int64
	budget   int64
}

func newOriginFetcher(opts *Options) *originFetcher {
	if opts.Offline || !opts.Verify.Originals {
		return nil
	}
	return &originFetcher{
		client:   &http.Client{Timeout: time.Duration(opts.Verify.TimeoutSeconds) * time.Second, Transport: opts.verifyTransport},
		cacheDir: stateFile(opts.StateDir, "originals"),
		maxBytes: int64(opts.Verify.MaxMB) * 1024 * 1024,
		budget:   int64(opts.Verify.MaxDownloads),
	}
}

func (f *originFetcher) get(u string) ([]byte, error) {
	h := sha256.Sum256([]byte(u))
	key := hex.EncodeToString(h[:16])
	var cachePath string
	if f.cacheDir != "" {
		cachePath = filepath.Join(f.cacheDir, key)
		if raw, err := os.ReadFile(cachePath); err == nil {
			return raw, nil
		}
	}
	if atomic.AddInt64(&f.budget, -1) < 0 {
		return nil, errors.New("die Grenze der Abrufe je Lauf ist erreicht")
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "malwatch")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > f.maxBytes {
		return nil, errors.New("Datei zu groß")
	}
	if cachePath != "" && os.MkdirAll(f.cacheDir, 0o750) == nil {
		tmp := cachePath + ".tmp"
		if os.WriteFile(tmp, raw, 0o640) == nil {
			_ = os.Rename(tmp, cachePath)
		}
	}
	return raw, nil
}

// rebuilt reports whether a script file that differs from its vendor list
// differs the way a rebuild does, judged against the original from the
// vendor's repository.
func (o *Options) rebuilt(path, ext string, content []byte, known *knownfiles.Index) bool {
	if o.originals == nil || !scriptExts[ext] {
		return false
	}
	u, ok := known.OriginOf(path)
	if !ok {
		return false
	}
	orig, err := o.originals.get(u)
	if err != nil || !harmlessDeviation(content, orig) {
		return false
	}
	o.count(verifiedRebuild)
	return true
}
