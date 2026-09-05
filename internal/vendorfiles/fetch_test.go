package vendorfiles

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// zipOf builds an archive in memory, so the tests need no network and no
// fixture files.
func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPluginIsFetchedAndUnpacked(t *testing.T) {
	archive := zipOf(t, map[string]string{
		"akismet/akismet.php": "<?php // akismet",
		"akismet/readme.txt":  "= Akismet =",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plugin/akismet.5.3.3.zip" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	f := NewFetcher(BaseURLs{Plugin: srv.URL + "/plugin/"}, 10*time.Second)
	dir, err := f.Plugin("akismet", "5.3.3", t.TempDir())
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "akismet.php"))
	if err != nil || string(raw) != "<?php // akismet" {
		t.Fatalf("the unpacked plugin is wrong: %v %q", err, raw)
	}
}

func TestCoreUsesTheLocalisedAddressForALocale(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write(zipOf(t, map[string]string{"wordpress/wp-login.php": "<?php"}))
	}))
	defer srv.Close()

	// A German install has to come from the German build, or every file
	// carrying a translated comment would count as modified afterwards.
	f := NewFetcher(BaseURLs{Core: srv.URL + "/", LocalisedCore: srv.URL + "/%s/"}, 10*time.Second)
	if _, err := f.Core("6.6.2", "de_DE", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if asked != "/de/wordpress-6.6.2-de_DE.zip" {
		t.Errorf("asked for %q, want the localised archive", asked)
	}
}

func TestAMissingVersionIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// 404 means the version was never published - a fact about the element,
	// not a failure of the run. Everything else has to stop the run before
	// anything on the site is touched.
	f := NewFetcher(BaseURLs{Plugin: srv.URL + "/plugin/"}, 10*time.Second)
	_, err := f.Plugin("elementor-pro", "3.21.0", t.TempDir())
	if !errors.Is(err, ErrNotPublished) {
		t.Fatalf("a 404 has to be ErrNotPublished, got %v", err)
	}
}

func TestAServerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := NewFetcher(BaseURLs{Plugin: srv.URL + "/plugin/"}, 10*time.Second)
	_, err := f.Plugin("akismet", "5.3.3", t.TempDir())
	if err == nil || errors.Is(err, ErrNotPublished) {
		t.Fatalf("a 500 must be a plain error, got %v", err)
	}
}

func TestAnArchiveCannotEscapeItsDestination(t *testing.T) {
	archive := zipOf(t, map[string]string{"../../etc/passwd": "root:x:0:0"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	f := NewFetcher(BaseURLs{Plugin: srv.URL + "/plugin/"}, 10*time.Second)
	if _, err := f.Plugin("evil", "1.0", t.TempDir()); err == nil {
		t.Fatal("an entry pointing out of the destination was unpacked")
	}
}

func TestAVersionReadOffDiskCannotShapeTheURL(t *testing.T) {
	// The version comes out of a file an attacker may control.
	f := NewFetcher(BaseURLs{}, time.Second)
	if _, err := f.Plugin("akismet", "../../evil", t.TempDir()); err == nil {
		t.Fatal("a traversing version was accepted")
	}
	if _, err := f.Plugin("../evil", "1.0", t.TempDir()); err == nil {
		t.Fatal("a traversing slug was accepted")
	}
}
