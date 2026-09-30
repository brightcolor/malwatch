package knownfiles

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func md5Of(s string) string {
	m := md5.Sum([]byte(s))
	return hex.EncodeToString(m[:])
}

// themeServer serves the archive of theme twentyx 1.2 the way
// downloads.wordpress.org does - every file below the slug - and 404 for
// anything else.
func themeServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"style.css": "/* Theme Name: X */", "functions.php": "<?php // x"} {
		w, err := zw.Create("twentyx/" + name)
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
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if !strings.HasSuffix(r.URL.Path, "/twentyx.1.2.zip") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// A theme from wordpress.org has no checksum list; its archive is. The sums
// are computed from it once and kept.
func TestWordPressThemeSumsComeFromTheArchive(t *testing.T) {
	srv, hits := themeServer(t)
	cache := t.TempDir()
	f := NewFetcher(cache, 5*time.Second)
	f.client = srv.Client()
	f.themeBase = srv.URL + "/theme/"
	files, err := f.WordPressTheme("twentyx", "1.2")
	if err != nil {
		t.Fatal(err)
	}
	if files["functions.php"] != md5Of("<?php // x") || files["style.css"] != md5Of("/* Theme Name: X */") {
		t.Fatalf("Prüfsummen %v", files)
	}
	g := NewFetcher(cache, 5*time.Second)
	g.client = srv.Client()
	g.themeBase = srv.URL + "/theme/"
	if _, err := g.WordPressTheme("twentyx", "1.2"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("%d Abrufe, erwartet 1", n)
	}
	if _, err := g.WordPressTheme("premium", "3.0"); !errors.Is(err, ErrNotPublished) {
		t.Errorf("Theme ohne Archiv: %v, erwartet ErrNotPublished", err)
	}
}

// A theme is often adapted to the site: a file that differs from the archive
// or is not in it says nothing, only one that matches is confirmed.
func TestVerifiedTreesOnlyConfirm(t *testing.T) {
	idx := New()
	idx.AddVerified("/web/wp-content/themes/twentyx", "Theme twentyx 1.2", map[string]string{"functions.php": md5Of("<?php // x")})
	if st, _ := idx.Check("/web/wp-content/themes/twentyx/functions.php", []byte("<?php // x")); st != Original {
		t.Errorf("gleiche Datei: %v, erwartet Original", st)
	}
	if st, _ := idx.Check("/web/wp-content/themes/twentyx/functions.php", []byte("<?php // angepasst")); st != Unknown {
		t.Errorf("angepasste Datei: %v, erwartet Unknown", st)
	}
	if st, _ := idx.Check("/web/wp-content/themes/twentyx/custom.php", []byte("<?php echo 1;")); st != Unknown {
		t.Errorf("zusätzliche Datei: %v, erwartet Unknown", st)
	}
}
