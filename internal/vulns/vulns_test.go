package vulns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// fakeSources stands in for WPVulnerability, WPScan and wordpress.org on one
// test server. Their paths do not collide: /plugin/ against /plugins/.
type fakeSources struct {
	mu        sync.Mutex
	hits      map[string]int
	down      bool // every source answers 503
	wpscanErr int  // WPScan answers with this status instead
	authSeen  map[string]string
}

func newFakeSources(t *testing.T) (*fakeSources, *httptest.Server) {
	f := &fakeSources{hits: map[string]int{}, authSeen: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeSources) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.authSeen[r.URL.Path] = r.Header.Get("Authorization")
	down, wpscanErr := f.down, f.wpscanErr
	f.mu.Unlock()

	if down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.URL.Path == "/core/stable-check/1.0/":
		_ = json.NewEncoder(w).Encode(sampleStatuses)
	case r.URL.Path == "/core/6.4.2/":
		w.Write([]byte(wpvCoreAnswer))
	case r.URL.Path == "/plugin/sample-forms/":
		w.Write([]byte(wpvPluginAnswer))
	case strings.HasPrefix(r.URL.Path, "/plugin/"):
		w.Write([]byte(wpvUnknownAnswer))
	case strings.HasPrefix(r.URL.Path, "/plugins/") || strings.HasPrefix(r.URL.Path, "/wordpresses/"):
		if wpscanErr != 0 {
			w.WriteHeader(wpscanErr)
			return
		}
		if r.Header.Get("Authorization") != "Token token=secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/plugins/sample-forms" {
			w.Write([]byte(wpscanPluginAnswer))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeSources) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func fakeChecker(srv *httptest.Server, dir, token string) *Checker {
	return New(Options{
		CacheDir:    dir,
		WPScanToken: token,
		Timeout:     5 * time.Second,
		Base: BaseURLs{
			WPVulnerability: srv.URL,
			WPScan:          srv.URL,
			WordPressOrg:    srv.URL,
			OSV:             srv.URL,
			Joomla:          srv.URL,
		},
	})
}

func TestCheckerAsksOnceAndRemembers(t *testing.T) {
	f, srv := newFakeSources(t)
	dir := t.TempDir()
	inst := plugin("sample-forms", "5.3.1")

	first := fakeChecker(srv, dir, "secret")
	list, checked := first.Check(inst)
	if !checked || len(list) != 4 {
		t.Fatalf("first run: checked=%v, %d flaws, want 4: %+v", checked, len(list), list)
	}
	if got := first.Describe(); got != "WPVulnerability, WPScan" {
		t.Errorf("Describe() = %q", got)
	}

	// A second scan the same night: everything from disk.
	second := fakeChecker(srv, dir, "secret")
	again, _ := second.Check(inst)
	if len(again) != 4 {
		t.Errorf("second run: %d flaws, want the same 4", len(again))
	}
	if n := f.count("/plugin/sample-forms/"); n != 1 {
		t.Errorf("WPVulnerability was asked %d times, want once", n)
	}
	if n := f.count("/plugins/sample-forms"); n != 1 {
		t.Errorf("WPScan was asked %d times, want once", n)
	}
}

func TestTheTokenGoesToWPScanOnly(t *testing.T) {
	f, srv := newFakeSources(t)
	fakeChecker(srv, t.TempDir(), "secret").Check(plugin("sample-forms", "5.3.1"))

	f.mu.Lock()
	defer f.mu.Unlock()
	if auth := f.authSeen["/plugin/sample-forms/"]; auth != "" {
		t.Errorf("WPVulnerability received an Authorization header: %q", auth)
	}
	if auth := f.authSeen["/plugins/sample-forms"]; auth != "Token token=secret" {
		t.Errorf("WPScan received %q", auth)
	}
}

func TestCheckerFallsBackToStoredAnswers(t *testing.T) {
	f, srv := newFakeSources(t)
	dir := t.TempDir()
	inst := plugin("sample-forms", "5.3.1")
	fakeChecker(srv, dir, "").Check(inst)

	// Two days later the source is down.
	old := time.Now().Add(-48 * time.Hour)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		_ = os.Chtimes(filepath.Join(dir, e.Name()), old, old)
	}
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()

	c := fakeChecker(srv, dir, "")
	list, checked := c.Check(inst)
	if !checked || len(list) != 3 {
		t.Fatalf("with the source down: checked=%v, %d flaws, want the 3 stored ones", checked, len(list))
	}
	if notes := strings.Join(c.Notes(), "\n"); !strings.Contains(notes, "ältere Daten") {
		t.Errorf("the report does not say old data was used: %q", notes)
	}
}

func TestCheckerStopsAskingADeadSource(t *testing.T) {
	f, srv := newFakeSources(t)
	f.down = true
	c := fakeChecker(srv, t.TempDir(), "")

	for _, slug := range []string{"a", "b", "c", "d", "e"} {
		if _, checked := c.Check(plugin(slug, "1.0")); checked {
			t.Errorf("%s counts as checked although nothing answered", slug)
		}
	}
	asked := 0
	for _, slug := range []string{"a", "b", "c", "d", "e"} {
		asked += f.count("/plugin/" + slug + "/")
	}
	if asked != maxFailures {
		t.Errorf("a dead source was asked %d times, want %d", asked, maxFailures)
	}
	if notes := strings.Join(c.Notes(), "\n"); !strings.Contains(notes, "5 Abfrage(n) bei WPVulnerability ohne Antwort") {
		t.Errorf("notes: %q", notes)
	}
}

func TestRefusedTokenSwitchesWPScanOff(t *testing.T) {
	f, srv := newFakeSources(t)
	c := fakeChecker(srv, t.TempDir(), "wrong")

	list, checked := c.Check(plugin("sample-forms", "5.3.1"))
	if !checked || len(list) != 3 {
		t.Fatalf("WPVulnerability still answers: checked=%v, %d flaws", checked, len(list))
	}
	c.Check(plugin("another", "1.0"))
	if n := f.count("/plugins/another"); n != 0 {
		t.Errorf("WPScan was asked again after refusing the token (%d)", n)
	}
	if notes := strings.Join(c.Notes(), "\n"); !strings.Contains(notes, "lehnt den API-Schlüssel ab") {
		t.Errorf("notes: %q", notes)
	}
}

func TestUsedUpQuotaIsRememberedAcrossRuns(t *testing.T) {
	f, srv := newFakeSources(t)
	f.wpscanErr = http.StatusTooManyRequests
	dir := t.TempDir()

	fakeChecker(srv, dir, "secret").Check(plugin("sample-forms", "5.3.1"))
	f.mu.Lock()
	f.wpscanErr = 0
	f.mu.Unlock()

	fakeChecker(srv, dir, "secret").Check(plugin("another", "1.0"))
	if n := f.count("/plugins/another"); n != 0 {
		t.Errorf("the next run asked WPScan although the quota was used up (%d)", n)
	}
}

func TestWPScanNotFoundIsStored(t *testing.T) {
	f, srv := newFakeSources(t)
	dir := t.TempDir()
	fakeChecker(srv, dir, "secret").Check(plugin("custom-plugin", "1.0"))
	fakeChecker(srv, dir, "secret").Check(plugin("custom-plugin", "1.0"))
	if n := f.count("/plugins/custom-plugin"); n != 1 {
		t.Errorf("a plugin WPScan does not know cost %d requests, want 1", n)
	}
}

func TestWordPressCoreEndToEnd(t *testing.T) {
	_, srv := newFakeSources(t)
	c := fakeChecker(srv, t.TempDir(), "")
	list, checked := c.Check(cms.Install{Product: "wordpress", Kind: "core", Version: "6.4.2"})
	if !checked || len(list) != 1 {
		t.Fatalf("checked=%v, %+v", checked, list)
	}
	if list[0].FixedIn != "6.4.10" || UpdateTo(list) != "6.4.10" {
		t.Errorf("the insecure release should point at the branch release: %+v", list[0])
	}
	if got := c.Describe(); got != "WPVulnerability, wordpress.org" {
		t.Errorf("Describe() = %q", got)
	}
}

func TestImplausibleNamesAreNeverRequested(t *testing.T) {
	f, srv := newFakeSources(t)
	c := fakeChecker(srv, t.TempDir(), "secret")
	c.Check(plugin("../../etc", "1.0"))
	c.Check(cms.Install{Product: "wordpress", Kind: "core", Version: "6.4/../../x"})

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) != 0 {
		t.Errorf("requests were made for implausible names: %v", f.hits)
	}
}
