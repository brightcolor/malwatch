// Package vendorfiles fetches the original archives a repair puts back.
package vendorfiles

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotPublished says the version does not exist at the vendor. That is a
// fact about the element, not a failure of the run: a paid plugin and a
// withdrawn release both look like this, and both have to be reported rather
// than abort a repair that has not touched anything yet.
var ErrNotPublished = errors.New("beim Hersteller nicht veröffentlicht")

// BaseURLs lets the tests point at a local server. Empty fields mean the real
// vendor addresses. LocalisedCore carries one %s for the language part.
type BaseURLs struct {
	Core          string
	LocalisedCore string
	Plugin        string
	Theme         string
}

// Fetcher downloads and unpacks vendor archives.
type Fetcher struct {
	client *http.Client
	base   BaseURLs
}

// NewFetcher returns a fetcher for the given addresses.
func NewFetcher(base BaseURLs, timeout time.Duration) *Fetcher {
	if base.Core == "" {
		base.Core = "https://wordpress.org/"
	}
	if base.LocalisedCore == "" {
		base.LocalisedCore = "https://%s.wordpress.org/"
	}
	if base.Plugin == "" {
		base.Plugin = "https://downloads.wordpress.org/plugin/"
	}
	if base.Theme == "" {
		base.Theme = "https://downloads.wordpress.org/theme/"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Fetcher{client: &http.Client{Timeout: timeout}, base: base}
}

// Core fetches one WordPress release and returns the unpacked directory.
//
// A localised install has to come from the localised build: comparing a German
// installation against the international files reports everything carrying a
// translated comment as modified.
func (f *Fetcher) Core(version, locale, dest string) (string, error) {
	if !safe(version) {
		return "", fmt.Errorf("unplausible Version %q", version)
	}
	u := f.base.Core + "wordpress-" + url.PathEscape(version) + ".zip"
	if locale != "" && locale != "en_US" {
		if !safe(locale) {
			return "", fmt.Errorf("unplausible Sprache %q", locale)
		}
		lang := strings.SplitN(locale, "_", 2)[0]
		u = fmt.Sprintf(f.base.LocalisedCore, lang) +
			"wordpress-" + url.PathEscape(version) + "-" + url.PathEscape(locale) + ".zip"
	}
	if err := f.download(u, dest); err != nil {
		return "", err
	}
	return filepath.Join(dest, "wordpress"), nil
}

// Plugin fetches one plugin release and returns the unpacked directory.
func (f *Fetcher) Plugin(slug, version, dest string) (string, error) {
	return f.slugged(f.base.Plugin, slug, version, dest)
}

// Theme fetches one theme release and returns the unpacked directory.
//
// wordpress.org publishes no checksums for themes, so a theme can only be
// verified as far as the archive being complete and unpackable. The report
// says so rather than implying a certainty that does not exist.
func (f *Fetcher) Theme(slug, version, dest string) (string, error) {
	return f.slugged(f.base.Theme, slug, version, dest)
}

func (f *Fetcher) slugged(base, slug, version, dest string) (string, error) {
	if !safe(slug) || !safe(version) {
		return "", fmt.Errorf("unplausibler Name %q oder Version %q", slug, version)
	}
	u := base + url.PathEscape(slug) + "." + url.PathEscape(version) + ".zip"
	if err := f.download(u, dest); err != nil {
		return "", err
	}
	return filepath.Join(dest, slug), nil
}

func (f *Fetcher) download(rawURL, dest string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "malwatch")
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s: %w", rawURL, ErrNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", rawURL, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dest, "archive-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 512*1024*1024)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return unzip(tmp.Name(), dest)
}

// unzip refuses an entry whose name leaves the destination. A crafted archive
// would otherwise write wherever the process can.
func unzip(archive, dest string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()

	root := filepath.Clean(dest)
	for _, entry := range zr.File {
		target := filepath.Join(root, filepath.FromSlash(entry.Name))
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return fmt.Errorf("Eintrag %q zeigt aus dem Zielverzeichnis heraus", entry.Name)
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeEntry(entry, target); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(entry *zip.File, target string) error {
	rc, err := entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(rc, 256*1024*1024))
	return err
}

// safe keeps a version or slug read off a customer's disk out of a URL path.
// The value comes from a file an attacker may control.
func safe(s string) bool {
	if s == "" || len(s) > 100 || strings.Contains(s, "..") {
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
	return true
}
