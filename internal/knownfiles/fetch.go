package knownfiles

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fetcher loads vendor checksum lists over the network and keeps them on
// disk, so a nightly run over many sites downloads each list once.
type Fetcher struct {
	client   *http.Client
	cacheDir string
	// failures records lists that could not be loaded. Without them the
	// scanner would treat every file of that install as unknown, which is
	// safe but noisier - the report says so instead of hiding it.
	failures []string
}

// NewFetcher returns a fetcher writing its cache below cacheDir.
func NewFetcher(cacheDir string, timeout time.Duration) *Fetcher {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Fetcher{
		client:   &http.Client{Timeout: timeout},
		cacheDir: cacheDir,
	}
}

// Failures returns the lists that could not be loaded.
func (f *Fetcher) Failures() []string { return f.failures }

// WordPressCore returns path to MD5 for one WordPress release.
//
// locale selects the localised build; empty means the international one. A
// German install compared against the en_US list reports the files that carry
// translated comments as modified.
func (f *Fetcher) WordPressCore(version, locale string) (map[string]string, error) {
	if !safeVersion(version) {
		return nil, fmt.Errorf("unplausible Version %q", version)
	}
	if locale == "" {
		locale = "en_US"
	}
	if !safeSlug(locale) {
		locale = "en_US"
	}

	key := "wordpress-core-" + version + "-" + locale + ".json"
	u := "https://api.wordpress.org/core/checksums/1.0/?version=" +
		url.QueryEscape(version) + "&locale=" + url.QueryEscape(locale)

	raw, err := f.load(key, u)
	if err != nil {
		f.note("WordPress %s (%s): Prüfsummen nicht ladbar (%v)", version, locale, err)
		return nil, err
	}
	var payload struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		f.note("WordPress %s (%s): Prüfsummen nicht lesbar", version, locale)
		return nil, err
	}
	if len(payload.Checksums) == 0 {
		// The API answers 200 with an empty body for an unknown version.
		f.note("WordPress %s (%s): keine Prüfsummen veröffentlicht", version, locale)
		return nil, fmt.Errorf("leere Prüfsummenliste")
	}

	return coreOnly(lowerValues(payload.Checksums)), nil
}

// coreOnly drops everything below wp-content.
//
// The core checksum list covers the bundled themes, which WordPress updates
// on their own schedule. A site whose Twenty Twenty theme is newer than its
// core then reports every one of that theme's files as a modified core file -
// fifty findings on one site, none of them real. What remains is wp-admin,
// wp-includes and the root files, which is what wp-cli verifies too.
func coreOnly(files map[string]string) map[string]string {
	out := make(map[string]string, len(files))
	for path, sum := range files {
		if strings.HasPrefix(path, "wp-content/") {
			continue
		}
		out[path] = sum
	}
	return out
}

// WordPressPlugin returns path to MD5 for one plugin release.
func (f *Fetcher) WordPressPlugin(slug, version string) (map[string]string, error) {
	if !safeSlug(slug) || !safeVersion(version) {
		return nil, fmt.Errorf("unplausibler Name oder Version")
	}
	key := "wordpress-plugin-" + slug + "-" + version + ".json"
	u := "https://downloads.wordpress.org/plugin-checksums/" + slug + "/" + version + ".json"

	raw, err := f.load(key, u)
	if err != nil {
		// Paid and custom plugins are simply not published. That is normal
		// and must not show up as a problem in the report.
		return nil, err
	}
	var payload struct {
		Files map[string]struct {
			MD5 string `json:"md5"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(payload.Files))
	for path, sums := range payload.Files {
		if sums.MD5 != "" {
			out[path] = strings.ToLower(sums.MD5)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("leere Prüfsummenliste")
	}
	return out, nil
}

// load returns the cached body or fetches and caches it.
func (f *Fetcher) load(key, rawURL string) ([]byte, error) {
	var cachePath string
	if f.cacheDir != "" {
		cachePath = filepath.Join(f.cacheDir, key)
		if raw, err := os.ReadFile(cachePath); err == nil && len(raw) > 0 {
			return raw, nil
		}
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, err
	}

	if cachePath != "" && len(raw) > 0 {
		if err := os.MkdirAll(f.cacheDir, 0o750); err == nil {
			tmp := cachePath + ".tmp"
			if os.WriteFile(tmp, raw, 0o640) == nil {
				_ = os.Rename(tmp, cachePath)
			}
		}
	}
	return raw, nil
}

func (f *Fetcher) note(format string, args ...any) {
	f.failures = append(f.failures, fmt.Sprintf(format, args...))
}

func lowerValues(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = strings.ToLower(v)
	}
	return out
}

// safeSlug and safeVersion keep a version string read off a customer's disk
// out of a URL path. The value comes from a file an attacker may control.
func safeSlug(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func safeVersion(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || c == '_'
		if !ok {
			return false
		}
	}
	return !strings.Contains(s, "..")
}
