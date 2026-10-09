package scanner

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/fileview"
)

// A file the database of known files has as part of published software loses
// its content findings; the database only ever sees the sums.
func TestFilesTheHashDatabaseKnowsAreConfirmed(t *testing.T) {
	ev := "ev" + "al"
	known := "<?php // test fixture of a library\n$code = load();\n" + ev + "($code);\n"
	other := known + "// something else\n"
	s1 := sha1.Sum([]byte(known))
	s2 := sha256.Sum256([]byte(known))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"FileName":"usr/share/php/tests/EvalUnitTest.inc","SHA-1":"` +
			strings.ToUpper(hex.EncodeToString(s1[:])) + `","SHA-256":"` + strings.ToUpper(hex.EncodeToString(s2[:])) + `"}]`))
	}))
	defer srv.Close()

	root := t.TempDir()
	for rel, body := range map[string]string{"lib/Tests/EvalUnitTest.inc": known, "lib/Other.inc": other} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Run(Options{
		Paths: []string{root}, NoVersionScan: true, NoClamAV: true,
		SignatureDir: filepath.Join(root, "none"), StateDir: t.TempDir(), View: fileview.Default,
		Verify:          VerifyOptions{HashlookupURL: srv.URL, TimeoutSeconds: 5, MaxDownloads: 5, MaxMB: 5},
		verifyTransport: srv.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range rep.Findings {
		reported[filepath.Base(f.Path)] = true
	}
	if reported["EvalUnitTest.inc"] {
		t.Error("bekannte Datei trotzdem gemeldet")
	}
	if !reported["Other.inc"] {
		t.Error("unbekannte Datei nicht mehr gemeldet")
	}
	if rep.Verified[verifiedHashlookup] != 1 {
		t.Errorf("Verified = %v", rep.Verified)
	}
}
