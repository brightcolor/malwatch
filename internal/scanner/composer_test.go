package scanner

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/brightcolor/malwatch/internal/composer"
	"github.com/brightcolor/malwatch/internal/fileview"
)

// A file of a Composer package that is byte for byte the one in the package's
// archive is the package's own: PHP_CodeSniffer's test files, Zend's PHAR,
// the CA bundle of composer/ca-bundle. Its content findings drop. A changed
// copy and a file outside the package stay findings.
func TestFilesOfComposerPackagesAreConfirmedAgainstTheirArchive(t *testing.T) {
	ev := "ev" + "al"
	original := "<?php\n$code = load_rule();\n" + ev + "($code);\n"

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("acme-lib-1a2b3c/src/Rule.inc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write(buf.Bytes())
	}))
	defer srv.Close()
	host := func() string { u, _ := url.Parse(srv.URL); return u.Hostname() }()

	root := t.TempDir()
	installed := `{"packages":[{"name":"acme/lib","version":"1.0.0","dist":{"type":"zip","url":"` + srv.URL +
		`/zip/1a2b3c","reference":"1a2b3c"},"install-path":"../acme/lib"}]}`
	files := map[string]string{
		"vendor/composer/installed.json":    installed,
		"vendor/acme/lib/src/Rule.inc":      original,
		"vendor/acme/lib/src/Changed.inc":   original + "// changed\n",
		"wp-content/themes/x/functions.php": original,
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := Run(Options{
		Paths:         []string{root},
		NoVersionScan: true,
		NoClamAV:      true,
		SignatureDir:  filepath.Join(root, "no-signatures"),
		StateDir:      t.TempDir(),
		View:          fileview.Default,
		Verify: VerifyOptions{
			Composer: true, Hosts: []string{host}, MaxDownloads: composer.DefaultMaxDownloads,
			MaxMB: composer.DefaultMaxMB, TimeoutSeconds: 5, RetryHours: 1,
		},
		verifyTransport: srv.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range rep.Findings {
		rel, _ := filepath.Rel(root, f.Path)
		reported[filepath.ToSlash(rel)] = true
	}
	if reported["vendor/acme/lib/src/Rule.inc"] {
		t.Error("Datei des Pakets gemeldet, obwohl sie dem Archiv gleicht")
	}
	for _, rel := range []string{"vendor/acme/lib/src/Changed.inc", "wp-content/themes/x/functions.php"} {
		if !reported[rel] {
			t.Errorf("%s nicht mehr gemeldet", rel)
		}
	}
	if rep.Verified[verifiedComposer] != 1 {
		t.Errorf("Verified = %v, erwartet eine Datei bei %q", rep.Verified, verifiedComposer)
	}
}
