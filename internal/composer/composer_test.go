package composer

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// zipOf builds an archive the way GitHub serves one: every file below a single
// top directory named after the repository and the commit.
func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create("shardj-zf1-future-1a2b3c4/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// server serves archive under any path and counts the requests.
func server(t *testing.T, archive []byte) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// tr is the transport that trusts the certificate of the test server.
func tr(srv *httptest.Server) http.RoundTripper { return srv.Client().Transport }

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func TestFilesHashesTheArchiveBelowItsTopDirectory(t *testing.T) {
	srv, hits := server(t, zipOf(t, map[string]string{
		"library/Zend/Tool.phar": "phar body",
		"README.md":              "# zf1",
	}))
	cache := t.TempDir()
	f := NewFetcher(Options{CacheDir: cache, Hosts: []string{hostOf(t, srv.URL)}, MaxDownloads: 5, MaxMB: 5, Timeout: 5 * time.Second, Transport: tr(srv)})
	files, err := f.Files(srv.URL+"/zip/abc", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if files["library/Zend/Tool.phar"] != sum("phar body") || files["README.md"] != sum("# zf1") {
		t.Fatalf("Prüfsummen %v", files)
	}
	// A second fetcher reads the cache: the reference names one commit for
	// good, and the archive is not loaded again.
	g := NewFetcher(Options{CacheDir: cache, Hosts: []string{hostOf(t, srv.URL)}, MaxDownloads: 5, MaxMB: 5, Timeout: 5 * time.Second, Transport: tr(srv)})
	if _, err := g.Files(srv.URL+"/zip/abc", "abc"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("%d Abrufe, erwartet 1", n)
	}
}

func TestFilesRefusesHostsOffTheList(t *testing.T) {
	srv, hits := server(t, zipOf(t, map[string]string{"a.php": "x"}))
	f := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{"codeload.github.com"}, MaxDownloads: 5, MaxMB: 5, Timeout: time.Second})
	if _, err := f.Files(srv.URL+"/zip/abc", "abc"); err == nil {
		t.Fatal("Host außerhalb der Liste geladen")
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Error("Anfrage an einen Host außerhalb der Liste gestellt")
	}
}

func TestFilesKeepsToTheLimits(t *testing.T) {
	// Data that does not pack: the archive itself is over the limit.
	noise := make([]byte, 3*1024*1024/2)
	rand.New(rand.NewSource(1)).Read(noise)
	srv, _ := server(t, zipOf(t, map[string]string{"big.bin": string(noise)}))
	f := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{hostOf(t, srv.URL)}, MaxDownloads: 5, MaxMB: 1, Timeout: 5 * time.Second, Transport: tr(srv)})
	if _, err := f.Files(srv.URL+"/zip/big", "big"); err == nil {
		t.Error("Archiv über der Größengrenze angenommen")
	}
	// Data that packs well: small archive, too much unpacked.
	bomb, _ := server(t, zipOf(t, map[string]string{"bomb.txt": strings.Repeat("x", 12*1024*1024)}))
	b := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{hostOf(t, bomb.URL)}, MaxDownloads: 5, MaxMB: 1, Timeout: 5 * time.Second, Transport: tr(bomb)})
	if _, err := b.Files(bomb.URL+"/zip/bomb", "bomb"); err == nil {
		t.Error("Archiv, das entpackt zu groß ist, angenommen")
	}
	small, _ := server(t, zipOf(t, map[string]string{"a.php": "x"}))
	g := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{hostOf(t, small.URL)}, MaxDownloads: 1, MaxMB: 5, Timeout: 5 * time.Second, Transport: tr(small)})
	if _, err := g.Files(small.URL+"/zip/one", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Files(small.URL+"/zip/two", "two"); err == nil {
		t.Error("mehr Abrufe als erlaubt")
	}
}

// register serves the metadata of acme/lib the way repo.packagist.org does:
// minified, every entry lists what changed against the one before.
func register(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.URL.Path {
		case "/p2/acme/lib.json":
			_, _ = w.Write([]byte(`{"minified":"composer/2.0","packages":{"acme/lib":[` +
				`{"name":"acme/lib","version":"1.1.0","license":["MIT"],"dist":{"type":"zip","url":"` + srv.URL + `/zip/bbb","reference":"bbb"}},` +
				`{"version":"1.0.0","dist":{"type":"zip","url":"` + srv.URL + `/zip/aaa","reference":"aaa"}},` +
				`{"version":"0.9.0","license":"__unset","dist":"__unset"}]}}`))
		case "/p2/acme/lib~dev.json":
			_, _ = w.Write([]byte(`{"minified":"composer/2.0","packages":{"acme/lib":[` +
				`{"name":"acme/lib","version":"dev-main","dist":{"type":"zip","url":"` + srv.URL + `/zip/ccc","reference":"ccc"}}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The address of an archive in vendor/composer/installed.json is the website's
// own word: whoever can write a file there can point it at an archive of their
// own making, and their code would pass as the package's. The register the
// maintainers publish to names the archive of each commit instead.
func TestPublishedTakesTheArchiveFromTheRegister(t *testing.T) {
	srv, hits := register(t)
	f := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{hostOf(t, srv.URL)}, MaxDownloads: 5, MaxMB: 5,
		Timeout: 5 * time.Second, Transport: tr(srv), PackagistURL: srv.URL})
	for _, c := range []struct{ name, version, reference, want string }{
		{"Version aus dem Register", "1.0.0", "aaa", srv.URL + "/zip/aaa"},
		{"neueste Version", "v1.1.0", "BBB", srv.URL + "/zip/bbb"},
		{"Entwicklungsstand", "dev-main", "ccc", srv.URL + "/zip/ccc"},
	} {
		got, err := f.Published("acme/lib", c.version, c.reference)
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v, erwartet %q", c.name, got, err, c.want)
		}
	}
	for _, c := range []struct{ name, pkg, version, reference string }{
		{"Stand, den das Register nicht kennt", "acme/lib", "1.0.0", "evil"},
		{"Eintrag ohne Archiv", "acme/lib", "0.9.0", ""},
		{"Paket, das das Register nicht kennt", "evil/lib", "1.0.0", "aaa"},
	} {
		if got, err := f.Published(c.pkg, c.version, c.reference); err == nil {
			t.Errorf("%s: bestätigt mit %q", c.name, got)
		}
	}
	before := atomic.LoadInt32(hits)
	if _, err := f.Published("acme/lib", "1.0.0", "aaa"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(hits) != before {
		t.Error("das Register wurde für einen bekannten Stand erneut gefragt")
	}
	g := NewFetcher(Options{CacheDir: t.TempDir(), Hosts: []string{hostOf(t, srv.URL)}, MaxDownloads: 5, MaxMB: 5,
		Timeout: 5 * time.Second, Transport: tr(srv)})
	if _, err := g.Published("acme/lib", "1.0.0", "aaa"); err == nil {
		t.Error("ohne Register bestätigt")
	}
}

func TestCheckPackagistURL(t *testing.T) {
	for _, raw := range []string{"http://repo.packagist.org", "repo.packagist.org", "https://user:secret@repo.packagist.org", ""} {
		if err := CheckPackagistURL(raw); err == nil {
			t.Errorf("%q angenommen", raw)
		}
	}
	if err := CheckPackagistURL(DefaultPackagistURL); err != nil {
		t.Errorf("Vorgabe abgelehnt: %v", err)
	}
}

func TestGitHubArchivesComeFromCodeload(t *testing.T) {
	got := downloadURL("https://api.github.com/repos/Shardj/zf1-future/zipball/1a2b3c4d")
	if got != "https://codeload.github.com/Shardj/zf1-future/legacy.zip/1a2b3c4d" {
		t.Errorf("%q", got)
	}
	if got := downloadURL("https://gitlab.com/x/y/-/archive/v1/y-v1.zip"); got != "https://gitlab.com/x/y/-/archive/v1/y-v1.zip" {
		t.Errorf("%q", got)
	}
}

func TestInstalledReadsBothFormats(t *testing.T) {
	vendor := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vendor, "composer"), 0o755); err != nil {
		t.Fatal(err)
	}
	two := `{"packages":[{"name":"shardj/zf1-future","version":"1.21.0","dist":{"type":"zip","url":"https://api.github.com/repos/Shardj/zf1-future/zipball/abc","reference":"abc"},"install-path":"../shardj/zf1-future"}],"dev":false}`
	if err := os.WriteFile(filepath.Join(vendor, "composer", "installed.json"), []byte(two), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := Installed(vendor)
	if err != nil || len(pkgs) != 1 || pkgs[0].Dir != filepath.Join(vendor, "shardj", "zf1-future") || pkgs[0].Reference != "abc" {
		t.Fatalf("Composer 2: %+v %v", pkgs, err)
	}
	one := `[{"name":"yiisoft/yii","version":"1.1.29","dist":{"type":"zip","url":"https://api.github.com/repos/yiisoft/yii/zipball/def","reference":"def"}}]`
	if err := os.WriteFile(filepath.Join(vendor, "composer", "installed.json"), []byte(one), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err = Installed(vendor)
	if err != nil || len(pkgs) != 1 || pkgs[0].Dir != filepath.Join(vendor, "yiisoft", "yii") {
		t.Fatalf("Composer 1: %+v %v", pkgs, err)
	}
	// An install path that leaves the vendor directory is not followed.
	bad := `{"packages":[{"name":"x/y","dist":{"type":"zip","url":"https://api.github.com/repos/x/y/zipball/1","reference":"1"},"install-path":"../../../etc"}]}`
	if err := os.WriteFile(filepath.Join(vendor, "composer", "installed.json"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if pkgs, _ = Installed(vendor); len(pkgs) != 0 {
		t.Errorf("Pfad außerhalb von vendor angenommen: %+v", pkgs)
	}
}

func TestCheckOptions(t *testing.T) {
	if err := CheckHosts(DefaultHosts); err != nil {
		t.Errorf("Vorgabe abgelehnt: %v", err)
	}
	for _, h := range [][]string{{"https://github.com"}, {"github.com/x"}, {""}} {
		if err := CheckHosts(h); err == nil {
			t.Errorf("%v angenommen", h)
		}
	}
}
