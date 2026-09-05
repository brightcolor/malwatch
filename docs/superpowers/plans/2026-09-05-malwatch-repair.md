# malwatch repair — Implementation Plan (Teil 1: das Binary)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `malwatch repair` ersetzt Kern, Plugins und Themes einer WordPress-Installation versionsgenau durch die Originale und schreibt dabei eine Fortschrittsdatei, sodass ein anschließender Scan nur noch zeigt, was kein Hersteller ausgeliefert hat.

**Architecture:** Sechs Phasen, davon fünf im Binary. Erst wird alles geholt und geprüft, dann gesichert, dann getauscht — die Website wird erst berührt, wenn jedes Stück vollständig und verifiziert vorliegt. Eine harte Pfadgrenze begrenzt jeden Schreibvorgang auf `--path` und `--backup-dir`.

**Tech Stack:** Go 1.24, ausschließlich Standardbibliothek (`archive/zip`, `archive/tar`, `compress/gzip`, `net/http`, `os`). Tests mit `net/http/httptest`, kein Netz in CI außer im Abnahmetest.

**Spec:** [docs/superpowers/specs/2026-09-05-malwatch-repair-design.md](../specs/2026-09-05-malwatch-repair-design.md)

## Global Constraints

- Go 1.24. **Keine neue Fremdabhängigkeit** — `go.mod` bleibt ohne `require`-Block.
- Kommentare und Bezeichner englisch, jede Ausgabe an den Menschen deutsch. Kommentare begründen, sie beschreiben nicht.
- Der Scanner schreibt **ausschließlich** unterhalb von `--path` und `--backup-dir`. Ein Pfad außerhalb ist Abbruch, kein Überspringen.
- 404 einer Herstellerquelle ist **kein** Fehler, sondern eine Tatsache über das Element. Jeder andere Fehlschlag beendet den Lauf vor Phase 5.
- Rückgabecodes von `repair` (füllt eine Lücke der Spec): `0` alles ersetzt, `2` fertig, aber Elemente ohne Original gelöscht, `3` Laufzeitfehler oder Abbruch vor Phase 5.
- `gofmt -l .` muss leer bleiben, `go vet ./...` sauber.

## File Structure

| Datei | Verantwortung |
|---|---|
| `internal/progress/progress.go` | Fortschrittsdatei: gedrosselt schreiben, schreiben-dann-umbenennen, Protokollzeilen anhängen |
| `internal/vendorfiles/fetch.go` | Herstellerarchive holen und entpacken; unterscheidet „nicht veröffentlicht" von „fehlgeschlagen" |
| `internal/repair/safety.go` | Die Pfadgrenze |
| `internal/repair/plan.go` | Aus `cms.Detect` die Liste der Elemente und der unangetasteten Bereiche bauen |
| `internal/repair/backup.go` | Ein Verzeichnis als `tar.gz` sichern |
| `internal/repair/swap.go` | Alten Baum entfernen, neuen an seinen Platz, Eigentümer und Modus übertragen |
| `internal/repair/repair.go` | Die fünf Phasen als Ablauf |
| `internal/report/repair.go` | Bericht einer Wiederherstellung, JSON und Text |
| `cmd/malwatch/repair.go` | Schalter und Verdrahtung |

---

### Task 1: Die Pfadgrenze

**Files:**
- Create: `internal/repair/safety.go`
- Test: `internal/repair/safety_test.go`

**Interfaces:**
- Produces: `func InsideRoot(root, candidate string) error` — `nil`, wenn `candidate` nach Auflösung aller Symlinks unterhalb von `root` liegt; sonst ein Fehler.

- [ ] **Step 1: Write the failing test**

```go
package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInsideRootAcceptsAPathBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InsideRoot(root, filepath.Join(root, "wp-includes")); err != nil {
		t.Fatalf("a directory inside the root was rejected: %v", err)
	}
}

func TestInsideRootRefusesDotDot(t *testing.T) {
	root := t.TempDir()
	if err := InsideRoot(root, filepath.Join(root, "..", "etc")); err == nil {
		t.Fatal("a path leaving the root through .. was accepted")
	}
}

func TestInsideRootRefusesASymlinkOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	// The link resolves outside: refusing it is the whole point, because a
	// planted symlink would otherwise turn a repair into a way to delete
	// anything the scanner may write to.
	if err := InsideRoot(root, link); err == nil {
		t.Fatal("a symlink pointing out of the root was accepted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestInsideRoot -v`
Expected: FAIL — `undefined: InsideRoot`

- [ ] **Step 3: Write minimal implementation**

```go
// Package repair restores vendor files from the originals.
package repair

import (
	"fmt"
	"path/filepath"
	"strings"
)

// InsideRoot reports whether candidate stays below root once every symlink
// has been resolved.
//
// A repair deletes whole directories. A symlink planted in a customer tree
// would otherwise point that deletion anywhere the process may write, so a
// path leaving the root is refused rather than skipped: skipping would accept
// the manipulation quietly.
func InsideRoot(root, candidate string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("root %s is not readable: %w", root, err)
	}
	realRoot = filepath.Clean(realRoot)

	// The candidate need not exist yet - a target being moved into place does
	// not. Resolve the deepest existing parent instead.
	target := filepath.Clean(candidate)
	probe := target
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			rest := strings.TrimPrefix(target, probe)
			target = filepath.Clean(filepath.Join(resolved, rest))
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}

	if target == realRoot {
		return nil
	}
	if !strings.HasPrefix(target, realRoot+string(filepath.Separator)) {
		return fmt.Errorf("%s liegt außerhalb von %s", candidate, root)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -run TestInsideRoot -v`
Expected: PASS (drei Tests)

- [ ] **Step 5: Commit**

```bash
git add internal/repair/safety.go internal/repair/safety_test.go
git commit -m "feat: the boundary every repair write has to stay inside"
```

---

### Task 2: Die Fortschrittsdatei

**Files:**
- Create: `internal/progress/progress.go`
- Test: `internal/progress/progress_test.go`

**Interfaces:**
- Produces:
  - `func New(path, kind string) (*Writer, error)` — `kind` ist `"repair"` oder `"scan"`
  - `func (w *Writer) Phase(index, total int, name string)`
  - `func (w *Writer) Element(kind, slug, version string, done, total int)`
  - `func (w *Writer) File(rel string, done, total int)`
  - `func (w *Writer) Log(level, format string, args ...any)` — `level` ist `"ok"`, `"info"`, `"warn"` oder `"error"`
  - `func (w *Writer) Flush() error` — erzwingt einen Schreibvorgang, umgeht die Drosselung
  - `func (w *Writer) Close() error`
  - `func (w *Writer) Entries() []LogEntry` — für den Bericht

- [ ] **Step 1: Write the failing test**

```go
package progress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAReaderNeverSeesHalfADocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.progress")
	w, err := New(path, "repair")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// The panel polls this file while it is being rewritten. Writing in place
	// would hand it a truncated document; write-then-rename cannot.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) == 0 {
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Errorf("the reader saw invalid JSON: %v", err)
				return
			}
		}
	}()

	for i := 1; i <= 500; i++ {
		w.File("wp-includes/file.php", i, 500)
		w.Flush()
	}
	close(stop)
	wg.Wait()
}

func TestTheDocumentCarriesTheCurrentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.progress")
	w, _ := New(path, "repair")
	defer w.Close()

	w.Phase(5, 5, "swap")
	w.Element("plugin", "contact-form-7", "5.9.8", 9, 14)
	w.File("wp-content/plugins/contact-form-7/includes/mail.php", 412, 1284)
	w.Log("ok", "ersetzt %s %s", "akismet", "5.3.3")
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	var doc struct {
		Schema    int    `json:"schema"`
		Kind      string `json:"kind"`
		Phase     string `json:"phase"`
		FilesDone int    `json:"files_done"`
		Element   struct {
			Slug string `json:"slug"`
		} `json:"element"`
		Log []struct {
			Text string `json:"text"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Kind != "repair" || doc.Phase != "swap" {
		t.Errorf("head is wrong: %+v", doc)
	}
	if doc.FilesDone != 412 || doc.Element.Slug != "contact-form-7" {
		t.Errorf("position is wrong: %+v", doc)
	}
	if len(doc.Log) != 1 || doc.Log[0].Text != "ersetzt akismet 5.3.3" {
		t.Errorf("log is wrong: %+v", doc.Log)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/progress/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write minimal implementation**

```go
// Package progress publishes what a long run is currently doing, so the panel
// can show it while it happens instead of only afterwards.
package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// interval throttles the writes. One document per file would be a thousand
// writes for a single plugin; twice a second is more than the panel polls.
const interval = 500 * time.Millisecond

// LogEntry is one line of what happened. The same entries end up in the
// report, so the running view and the permanent log share one mechanism.
type LogEntry struct {
	Time  time.Time `json:"t"`
	Level string    `json:"level"`
	Text  string    `json:"text"`
}

type element struct {
	Kind    string `json:"kind"`
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

type document struct {
	Schema        int        `json:"schema"`
	Kind          string     `json:"kind"`
	StartedAt     time.Time  `json:"started_at"`
	Phase         string     `json:"phase"`
	PhaseIndex    int        `json:"phase_index"`
	PhaseTotal    int        `json:"phase_total"`
	ElementsDone  int        `json:"elements_done"`
	ElementsTotal int        `json:"elements_total"`
	Element       *element   `json:"element,omitempty"`
	FilesDone     int        `json:"files_done"`
	FilesTotal    int        `json:"files_total"`
	File          string     `json:"file,omitempty"`
	Log           []LogEntry `json:"log"`
}

// Writer keeps the document and writes it out, throttled.
type Writer struct {
	mu      sync.Mutex
	path    string
	doc     document
	written time.Time
}

// New starts a progress file. An empty path returns a writer that does
// nothing, so callers need no conditionals.
func New(path, kind string) (*Writer, error) {
	w := &Writer{path: path}
	w.doc = document{Schema: 1, Kind: kind, StartedAt: time.Now().UTC(), Log: []LogEntry{}}
	if path == "" {
		return w, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return w, w.Flush()
}

func (w *Writer) Phase(index, total int, name string) {
	w.mu.Lock()
	w.doc.Phase, w.doc.PhaseIndex, w.doc.PhaseTotal = name, index, total
	w.mu.Unlock()
	w.maybeWrite()
}

func (w *Writer) Element(kind, slug, version string, done, total int) {
	w.mu.Lock()
	w.doc.Element = &element{Kind: kind, Slug: slug, Version: version}
	w.doc.ElementsDone, w.doc.ElementsTotal = done, total
	w.doc.FilesDone, w.doc.FilesTotal, w.doc.File = 0, 0, ""
	w.mu.Unlock()
	w.maybeWrite()
}

func (w *Writer) File(rel string, done, total int) {
	w.mu.Lock()
	w.doc.File, w.doc.FilesDone, w.doc.FilesTotal = rel, done, total
	w.mu.Unlock()
	w.maybeWrite()
}

func (w *Writer) Log(level, format string, args ...any) {
	w.mu.Lock()
	w.doc.Log = append(w.doc.Log, LogEntry{
		Time: time.Now().UTC(), Level: level, Text: fmt.Sprintf(format, args...),
	})
	w.mu.Unlock()
	// A log line is a state change worth publishing at once.
	_ = w.Flush()
}

func (w *Writer) Entries() []LogEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]LogEntry, len(w.doc.Log))
	copy(out, w.doc.Log)
	return out
}

func (w *Writer) maybeWrite() {
	w.mu.Lock()
	due := time.Since(w.written) >= interval
	w.mu.Unlock()
	if due {
		_ = w.Flush()
	}
}

// Flush writes the document out, complete or not at all.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "" {
		return nil
	}
	raw, err := json.Marshal(w.doc)
	if err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.path); err != nil {
		return err
	}
	w.written = time.Now()
	return nil
}

func (w *Writer) Close() error { return w.Flush() }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/progress/ -v -race`
Expected: PASS, keine Race-Meldung

- [ ] **Step 5: Commit**

```bash
git add internal/progress/
git commit -m "feat: a progress file a reader can poll at any moment"
```

---

### Task 3: Herstellerarchive holen

**Files:**
- Create: `internal/vendorfiles/fetch.go`
- Test: `internal/vendorfiles/fetch_test.go`

**Interfaces:**
- Consumes: nichts aus früheren Tasks.
- Produces:
  - `var ErrNotPublished = errors.New("nicht veröffentlicht")`
  - `func NewFetcher(baseURLs BaseURLs, timeout time.Duration) *Fetcher`
  - `type BaseURLs struct { Core, LocalisedCore, Plugin, Theme string }` — leere Felder bedeuten die echten Adressen; die Tests setzen sie auf einen `httptest`-Server
  - `func (f *Fetcher) Core(version, locale, dest string) (string, error)`
  - `func (f *Fetcher) Plugin(slug, version, dest string) (string, error)`
  - `func (f *Fetcher) Theme(slug, version, dest string) (string, error)`

  Alle drei laden das Archiv, entpacken es unterhalb von `dest` und geben das Verzeichnis zurück, das den Inhalt trägt (beim Kern das ausgepackte `wordpress/`, bei Plugin und Theme der Ordner mit dem Slug).

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vendorfiles/ -v`
Expected: FAIL — `undefined: NewFetcher`

- [ ] **Step 3: Write minimal implementation**

```go
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
// fact about the element, not a failure: a paid plugin and a withdrawn
// release both look like this, and both have to be reported rather than
// abort the run.
var ErrNotPublished = errors.New("beim Hersteller nicht veröffentlicht")

// BaseURLs allows the tests to point at a local server. Empty fields mean the
// real vendor addresses.
type BaseURLs struct {
	Core          string // https://wordpress.org/
	LocalisedCore string // https://%s.wordpress.org/  - %s is the language part
	Plugin        string // https://downloads.wordpress.org/plugin/
	Theme         string // https://downloads.wordpress.org/theme/
}

type Fetcher struct {
	client *http.Client
	base   BaseURLs
}

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

func (f *Fetcher) Plugin(slug, version, dest string) (string, error) {
	return f.slugged(f.base.Plugin, slug, version, dest)
}

func (f *Fetcher) Theme(slug, version, dest string) (string, error) {
	return f.slugged(f.base.Theme, slug, version, dest)
}

func (f *Fetcher) slugged(base, slug, version, dest string) (string, error) {
	if !safe(slug) || !safe(version) {
		return "", fmt.Errorf("unplausibler Name oder Version")
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
// would otherwise write anywhere the process can.
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
		rc, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 256*1024*1024))
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// safe keeps a version or slug read off a customer's disk out of a URL path.
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vendorfiles/ -v`
Expected: PASS (vier Tests)

- [ ] **Step 5: Commit**

```bash
git add internal/vendorfiles/
git commit -m "feat: fetch the original archives, telling absent from broken"
```

---

### Task 4: Sichern

**Files:**
- Create: `internal/repair/backup.go`
- Test: `internal/repair/backup_test.go`

**Interfaces:**
- Consumes: `InsideRoot` aus Task 1.
- Produces: `func Backup(dir, destDir, name string) (string, error)` — legt `destDir/name.tar.gz` an und gibt den Pfad zurück.

- [ ] **Step 1: Write the failing test**

```go
package repair

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupCarriesTheFilesItArchived(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "includes", "mail.php"), []byte("<?php // mail"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	archive, err := Backup(src, dest, "contact-form-7")
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	names := map[string]string{}
	fh, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		names[hdr.Name] = string(body)
	}
	if names["includes/mail.php"] != "<?php // mail" {
		t.Fatalf("the archive does not carry the file: %v", names)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestBackup -v`
Expected: FAIL — `undefined: Backup`

- [ ] **Step 3: Write minimal implementation**

```go
package repair

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// Backup writes dir as a gzipped tar below destDir and returns its path.
//
// It runs before anything is deleted, for everything that is touched and not
// only for what cannot be fetched again: a version read wrongly off the disk
// is just as expensive as a paid plugin, and both are cheap to keep.
func Backup(dir, destDir, name string) (string, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", err
	}
	archive := filepath.Join(destDir, name+".tar.gz")
	fh, err := os.OpenFile(archive, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		// Symlinks are stored as links, never followed: following one would
		// pull whatever it points at into the archive.
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	if walkErr != nil {
		return "", walkErr
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return archive, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -run TestBackup -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/repair/backup.go internal/repair/backup_test.go
git commit -m "feat: archive a directory before it is replaced"
```

---

### Task 5: Tauschen mit Eigentümer und Modus

**Files:**
- Create: `internal/repair/swap.go`
- Test: `internal/repair/swap_test.go`

**Interfaces:**
- Consumes: `InsideRoot` aus Task 1.
- Produces: `func Swap(root, oldDir, newDir string) error` — entfernt `oldDir` und schiebt `newDir` an dessen Stelle; Eigentümer, Gruppe und Modus des alten Baums werden übernommen. `root` ist die Grenze aus Task 1.

- [ ] **Step 1: Write the failing test**

```go
package repair

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapPutsTheNewTreeInPlace(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "shell.php"), []byte("<?php eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "plugin.php"), []byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Swap(root, old, staged); err != nil {
		t.Fatalf("swap failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(old, "shell.php")); !os.IsNotExist(err) {
		t.Error("the planted file survived the swap")
	}
	if _, err := os.Stat(filepath.Join(old, "plugin.php")); err != nil {
		t.Errorf("the original is not in place: %v", err)
	}
}

func TestSwapKeepsTheModeOfTheReplacedTree(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "plugin")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o777); err != nil {
		t.Fatal(err)
	}

	// A hardened install must stay hardened: a fixed default would widen it.
	if err := Swap(root, old, staged); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(old)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode is %o, want 750", info.Mode().Perm())
	}
}

func TestSwapRefusesATargetOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Swap(root, outside, staged); err == nil {
		t.Fatal("a swap outside the root was accepted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestSwap -v`
Expected: FAIL — `undefined: Swap`

- [ ] **Step 3: Write minimal implementation**

```go
package repair

import (
	"os"
	"path/filepath"
)

// Swap replaces oldDir with newDir and carries over what the old tree was.
//
// Owner, group and mode are read off the tree being replaced rather than set
// to a default: a tree owned by root leaves the site on 500 or hands it the
// wrong write rights, and a fixed default would soften a hardened install.
func Swap(root, oldDir, newDir string) error {
	if err := InsideRoot(root, oldDir); err != nil {
		return err
	}

	info, err := os.Stat(oldDir)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	uid, gid := ownerOf(info)

	if err := os.RemoveAll(oldDir); err != nil {
		return err
	}
	if err := os.Rename(newDir, oldDir); err != nil {
		// Rename fails across devices - the staging area may live on another
		// filesystem than the customer tree.
		if err := copyTree(newDir, oldDir); err != nil {
			return err
		}
		_ = os.RemoveAll(newDir)
	}
	return applyOwnership(oldDir, uid, gid, mode)
}

// applyOwnership walks the new tree and gives every entry the identity of the
// one it replaced. Directories keep the directory mode, files lose the
// execute bits the archive may carry.
func applyOwnership(dir string, uid, gid int, mode os.FileMode) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return chownLink(path, uid, gid)
		}
		want := mode &^ 0o111
		if info.IsDir() {
			want = mode
		}
		if err := os.Chmod(path, want); err != nil {
			return err
		}
		return chownPath(path, uid, gid)
	})
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}
```

Dazu zwei kleine Dateien, weil `syscall.Stat_t` und `os.Lchown` unter Windows nicht existieren und die Tests auf dem Arbeitsplatz laufen sollen:

`internal/repair/owner_unix.go`

```go
//go:build !windows

package repair

import (
	"os"
	"syscall"
)

func ownerOf(info os.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

func chownPath(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	// Not being root is normal in tests and in a dry run; the caller says so
	// in the report rather than failing the whole repair.
	if err := os.Chown(path, uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}

func chownLink(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := os.Lchown(path, uid, gid); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}
```

`internal/repair/owner_windows.go`

```go
//go:build windows

package repair

import "os"

func ownerOf(info os.FileInfo) (int, int)      { return -1, -1 }
func chownPath(path string, uid, gid int) error { return nil }
func chownLink(path string, uid, gid int) error { return nil }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -run TestSwap -v`
Expected: PASS (drei Tests)

- [ ] **Step 5: Commit**

```bash
git add internal/repair/swap.go internal/repair/swap_test.go internal/repair/owner_unix.go internal/repair/owner_windows.go
git commit -m "feat: swap a tree and keep the identity of the one it replaced"
```

---

### Task 6: Den Plan eines Laufs bauen

**Files:**
- Create: `internal/repair/plan.go`
- Test: `internal/repair/plan_test.go`

**Interfaces:**
- Consumes: `cms.Detect` und `cms.Install` aus `internal/cms`.
- Produces:
  - `type Element struct { Kind, Slug, Version, Locale, Path string }` — `Kind` ist `"core"`, `"plugin"` oder `"theme"`
  - `type Plan struct { Root string; Elements []Element; Untouched []string }`
  - `func BuildPlan(root string) (Plan, error)`

  `Untouched` nennt, was bewusst stehen bleibt: `wp-config.php`, `wp-content/uploads`, alles in `wp-content`, was kein Plugin- oder Theme-Ordner ist, und `wp-content/mu-plugins` mit eigenem Hinweis.

- [ ] **Step 1: Write the failing test**

```go
package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWordPress builds the smallest tree cms.Detect recognises.
func fakeWordPress(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n")
	mk("wp-login.php", "<?php")
	mk("wp-config.php", "<?php // secrets")
	mk("wp-content/plugins/akismet/akismet.php",
		"<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\n*/")
	mk("wp-content/themes/twentytwentyfour/style.css",
		"/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2\n*/")
	mk("wp-content/uploads/2026/06/photo.jpg", "binary")
	mk("wp-content/mu-plugins/loader.php", "<?php // hoster")
	return root
}

func TestBuildPlanFindsCorePluginAndTheme(t *testing.T) {
	plan, err := BuildPlan(fakeWordPress(t))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range plan.Elements {
		kinds[e.Kind+":"+e.Slug] = e.Version
	}
	if kinds["core:"] != "6.6.2" {
		t.Errorf("core missing or wrong: %v", kinds)
	}
	if kinds["plugin:akismet"] != "5.3.3" {
		t.Errorf("plugin missing or wrong: %v", kinds)
	}
	if kinds["theme:twentytwentyfour"] != "1.2" {
		t.Errorf("theme missing or wrong: %v", kinds)
	}
}

func TestBuildPlanLeavesUploadsAndConfigAlone(t *testing.T) {
	plan, err := BuildPlan(fakeWordPress(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range plan.Elements {
		if strings.Contains(e.Path, "uploads") || strings.HasSuffix(e.Path, "wp-config.php") {
			t.Fatalf("%s is not the vendor's to replace", e.Path)
		}
	}
	joined := strings.Join(plan.Untouched, "\n")
	for _, want := range []string{"wp-config.php", "wp-content/uploads", "mu-plugins"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s is not reported as untouched: %v", want, plan.Untouched)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestBuildPlan -v`
Expected: FAIL — `undefined: BuildPlan`

- [ ] **Step 3: Write minimal implementation**

```go
package repair

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/cms"
)

// Element is one unit a repair replaces as a whole.
type Element struct {
	Kind    string // core, plugin, theme
	Slug    string // empty for the core
	Version string
	Locale  string
	Path    string // directory the element lives in
}

// Plan is what a run will do, and what it deliberately will not.
type Plan struct {
	Root      string
	Elements  []Element
	Untouched []string
}

// BuildPlan reads the installation and sorts it into what is the vendor's and
// what is the customer's.
//
// Everything below wp-content that is not a plugin or theme directory belongs
// to the customer: uploads, languages, caches and whatever a site has grown.
// Leaving it is not laziness - those leftovers are exactly what the scan
// after the repair is meant to show.
func BuildPlan(root string) (Plan, error) {
	plan := Plan{Root: filepath.Clean(root)}

	installs := cms.Detect(plan.Root, func(string) bool { return false })
	for _, inst := range installs {
		if inst.Product != "wordpress" {
			plan.Untouched = append(plan.Untouched,
				fmt.Sprintf("%s (%s) - für dieses Produkt gibt es keine versionsgenaue Quelle", inst.Path, inst.Product))
			continue
		}
		plan.Elements = append(plan.Elements, Element{
			Kind:    inst.Kind,
			Slug:    inst.Slug,
			Version: inst.Version,
			Locale:  inst.Locale,
			Path:    inst.Path,
		})
	}

	plan.Untouched = append(plan.Untouched,
		"wp-config.php - Zugangsdaten, kein Original vorhanden",
		"wp-content/uploads - Kundendaten ohne Herstellerfassung")

	mu := filepath.Join(plan.Root, "wp-content", "mu-plugins")
	if entries, err := os.ReadDir(mu); err == nil && len(entries) > 0 {
		plan.Untouched = append(plan.Untouched,
			fmt.Sprintf("wp-content/mu-plugins - %d Eintrag/Einträge, kein Original; bitte von Hand ansehen", len(entries)))
	}

	return plan, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -run TestBuildPlan -v`
Expected: PASS (zwei Tests)

- [ ] **Step 5: Commit**

```bash
git add internal/repair/plan.go internal/repair/plan_test.go
git commit -m "feat: sort an installation into vendor and customer"
```

---

### Task 7: Der Bericht

**Files:**
- Create: `internal/report/repair.go`
- Test: `internal/report/repair_test.go`

**Interfaces:**
- Consumes: `progress.LogEntry` aus Task 2.
- Produces:
  - `type RepairOutcome string` mit `OutcomeReplaced = "replaced"`, `OutcomeDeleted = "deleted-no-origin"`, `OutcomeFailed = "failed"`, `OutcomeSkipped = "skipped"`
  - `type RepairElement struct { Kind, Slug, Version, Locale, Path string; Outcome RepairOutcome; Files int; Backup, Message string }`
  - `type Repair struct { ... }` mit `func NewRepair(root string) *Repair`, `func (r *Repair) ExitCode() int`, `func (r *Repair) WriteJSON(w io.Writer) error`, `func (r *Repair) WriteText(w io.Writer) error`

- [ ] **Step 1: Write the failing test**

```go
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRepairExitCodeSaysWhetherSomethingWasLost(t *testing.T) {
	clean := NewRepair("/var/www/web1/web")
	clean.Elements = append(clean.Elements, RepairElement{Kind: "core", Outcome: OutcomeReplaced})
	if got := clean.ExitCode(); got != 0 {
		t.Errorf("a clean run returned %d, want 0", got)
	}

	lost := NewRepair("/var/www/web1/web")
	lost.Elements = append(lost.Elements,
		RepairElement{Kind: "core", Outcome: OutcomeReplaced},
		RepairElement{Kind: "plugin", Slug: "elementor-pro", Version: "3.21.0", Outcome: OutcomeDeleted})
	if got := lost.ExitCode(); got != 2 {
		t.Errorf("a run that deleted without a replacement returned %d, want 2", got)
	}
}

func TestRepairTextNamesWhatCannotComeBack(t *testing.T) {
	r := NewRepair("/var/www/web1/web")
	r.Elements = append(r.Elements, RepairElement{
		Kind: "plugin", Slug: "elementor-pro", Version: "3.21.0",
		Outcome: OutcomeDeleted, Backup: "/var/lib/malwatch/backups/x/elementor-pro.tar.gz",
	})
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Name and version have to be in the text: without them the operator
	// cannot tell the customer what to buy again.
	for _, want := range []string{"elementor-pro", "3.21.0", "elementor-pro.tar.gz"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

func TestRepairJSONCarriesTheSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := NewRepair("/x").WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc.Schema != 1 {
		t.Fatalf("schema missing: %v %v", err, doc)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestRepair -v`
Expected: FAIL — `undefined: NewRepair`

- [ ] **Step 3: Write minimal implementation**

```go
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/version"
)

// RepairOutcome is what became of one element.
type RepairOutcome string

const (
	OutcomeReplaced RepairOutcome = "replaced"
	OutcomeDeleted  RepairOutcome = "deleted-no-origin"
	OutcomeFailed   RepairOutcome = "failed"
	OutcomeSkipped  RepairOutcome = "skipped"
)

type RepairElement struct {
	Kind    string        `json:"kind"`
	Slug    string        `json:"slug,omitempty"`
	Version string        `json:"version"`
	Locale  string        `json:"locale,omitempty"`
	Path    string        `json:"path"`
	Outcome RepairOutcome `json:"outcome"`
	Files   int           `json:"files"`
	Backup  string        `json:"backup,omitempty"`
	Message string        `json:"message,omitempty"`
}

type Repair struct {
	Schema     int                  `json:"schema"`
	Version    string               `json:"malwatch_version"`
	StartedAt  time.Time            `json:"started_at"`
	FinishedAt time.Time            `json:"finished_at"`
	Root       string               `json:"root"`
	DryRun     bool                 `json:"dry_run"`
	BackupDir  string               `json:"backup_dir,omitempty"`
	Elements   []RepairElement      `json:"elements"`
	Untouched  []string             `json:"untouched"`
	Log        []progress.LogEntry  `json:"log"`
	Errors     []string             `json:"errors"`
}

func NewRepair(root string) *Repair {
	return &Repair{
		Schema: 1, Version: version.Version, StartedAt: time.Now().UTC(), Root: root,
		Elements: []RepairElement{}, Untouched: []string{},
		Log: []progress.LogEntry{}, Errors: []string{},
	}
}

// ExitCode is 0 when everything came back, 2 when something was deleted
// without a replacement, and 3 when the run itself failed.
func (r *Repair) ExitCode() int {
	if len(r.Errors) > 0 {
		return 3
	}
	for _, e := range r.Elements {
		if e.Outcome == OutcomeFailed {
			return 3
		}
	}
	for _, e := range r.Elements {
		if e.Outcome == OutcomeDeleted {
			return 2
		}
	}
	return 0
}

func (r *Repair) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r *Repair) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Wiederherstellung: %s\n", r.Root)
	if r.DryRun {
		b.WriteString("Probelauf - es wurde nichts geändert.\n")
	}
	b.WriteString("\n")

	for _, e := range r.Elements {
		name := e.Kind
		if e.Slug != "" {
			name = e.Kind + " " + e.Slug
		}
		switch e.Outcome {
		case OutcomeReplaced:
			fmt.Fprintf(&b, "  ersetzt   %s %s (%d Dateien)\n", name, e.Version, e.Files)
		case OutcomeDeleted:
			fmt.Fprintf(&b, "  GELÖSCHT  %s %s - kein Original verfügbar\n", name, e.Version)
			fmt.Fprintf(&b, "            Sicherung: %s\n", e.Backup)
		case OutcomeFailed:
			fmt.Fprintf(&b, "  FEHLER    %s %s - %s\n", name, e.Version, e.Message)
		case OutcomeSkipped:
			fmt.Fprintf(&b, "  übersprungen %s %s - %s\n", name, e.Version, e.Message)
		}
	}

	if len(r.Untouched) > 0 {
		b.WriteString("\nUnangetastet:\n")
		for _, u := range r.Untouched {
			fmt.Fprintf(&b, "  %s\n", u)
		}
	}
	if len(r.Errors) > 0 {
		b.WriteString("\nFehler:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/ -run TestRepair -v && gofmt -l internal/report/`
Expected: PASS, `gofmt` ohne Ausgabe

- [ ] **Step 5: Commit**

```bash
git add internal/report/repair.go internal/report/repair_test.go
git commit -m "feat: the report of a repair, in JSON and for a human"
```

---

### Task 8: Der Ablauf

**Files:**
- Create: `internal/repair/repair.go`
- Test: `internal/repair/repair_test.go`

**Interfaces:**
- Consumes: `InsideRoot`, `Backup`, `Swap`, `BuildPlan`, `vendorfiles.Fetcher`, `progress.Writer`, `report.Repair`.
- Produces:
  - `type Options struct { Root, BackupDir, StagingDir string; DryRun bool; Fetcher *vendorfiles.Fetcher; Progress *progress.Writer }`
  - `func Run(opts Options) (*report.Repair, error)`

- [ ] **Step 1: Write the failing test**

```go
package repair

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

func TestNothingIsTouchedWhenAFetchFails(t *testing.T) {
	root := fakeWordPress(t)
	before := treeOf(t, root)

	// The server answers everything with 500: a broken download must stop the
	// run before phase five, not halfway through it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pw, _ := progress.New("", "repair")
	rep, err := Run(Options{
		Root:       root,
		BackupDir:  t.TempDir(),
		StagingDir: t.TempDir(),
		Fetcher:    vendorfiles.NewFetcher(vendorfiles.BaseURLs{Core: srv.URL + "/", Plugin: srv.URL + "/p/", Theme: srv.URL + "/t/"}, 5*time.Second),
		Progress:   pw,
	})
	if err == nil && len(rep.Errors) == 0 {
		t.Fatal("a failing download did not stop the run")
	}
	if got := treeOf(t, root); got != before {
		t.Fatal("the site was modified although the run failed before phase five")
	}
}

func TestAnElementWithoutAnOriginIsDeletedAndNamed(t *testing.T) {
	root := fakeWordPress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything is published except the plugin.
		if strings.Contains(r.URL.Path, "akismet") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(zipFor(t, r.URL.Path))
	}))
	defer srv.Close()

	pw, _ := progress.New("", "repair")
	rep, err := Run(Options{
		Root:       root,
		BackupDir:  t.TempDir(),
		StagingDir: t.TempDir(),
		Fetcher:    vendorfiles.NewFetcher(vendorfiles.BaseURLs{Core: srv.URL + "/", Plugin: srv.URL + "/p/", Theme: srv.URL + "/t/"}, 5*time.Second),
		Progress:   pw,
	})
	if err != nil {
		t.Fatalf("a missing version must not fail the run: %v", err)
	}
	var deleted *report.RepairElement
	for i := range rep.Elements {
		if rep.Elements[i].Slug == "akismet" {
			deleted = &rep.Elements[i]
		}
	}
	if deleted == nil || deleted.Outcome != report.OutcomeDeleted {
		t.Fatalf("akismet was not reported as deleted: %+v", rep.Elements)
	}
	if deleted.Version != "5.3.3" || deleted.Backup == "" {
		t.Errorf("version or backup missing: %+v", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet")); !os.IsNotExist(err) {
		t.Error("the directory without an original is still there")
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2", rep.ExitCode())
	}
}
```

Dazu zwei Helfer im selben Testpaket — sie brauchen `crypto/sha256`, `fmt` und
`strings`, die im Importblock oben schon stehen:

```go
// treeOf renders the tree as a string, so a test can assert that nothing
// changed at all.
func treeOf(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() {
			fmt.Fprintf(&b, "d %s\n", rel)
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "f %s %x\n", rel, sha256.Sum256(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// zipFor answers a request with an archive whose single file says where it
// came from, which is enough to tell a replaced tree from the old one.
func zipFor(t *testing.T, urlPath string) []byte {
	t.Helper()
	switch {
	case strings.Contains(urlPath, "wordpress-"):
		return zipOf(t, map[string]string{
			"wordpress/wp-includes/version.php": "<?php\n$wp_version = '6.6.2';\n",
			"wordpress/wp-login.php":            "<?php // original",
		})
	case strings.Contains(urlPath, "twentytwentyfour"):
		return zipOf(t, map[string]string{
			"twentytwentyfour/style.css": "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2\n*/",
		})
	default:
		return zipOf(t, map[string]string{"unknown/file.php": "<?php"})
	}
}
```

`zipOf` aus Task 3 wird dafür in `internal/repair` gespiegelt — die Testhelfer eines Pakets gehören in dieses Paket, ein geteiltes Testpaket wäre hier mehr Bindung als Nutzen.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run "TestNothingIsTouched|TestAnElementWithout" -v`
Expected: FAIL — `undefined: Run`

- [ ] **Step 3: Write minimal implementation**

```go
package repair

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

type Options struct {
	Root       string
	BackupDir  string
	StagingDir string
	DryRun     bool
	Fetcher    *vendorfiles.Fetcher
	Progress   *progress.Writer
}

// staged is one element with the tree that will replace it.
type staged struct {
	element Element
	dir     string // empty when the version is not published
}

// Run walks the five phases. Nothing below Root is touched before every
// archive is on disk: a download that breaks halfway then costs a run, not a
// website.
func Run(opts Options) (*report.Repair, error) {
	rep := report.NewRepair(opts.Root)
	rep.DryRun = opts.DryRun
	rep.BackupDir = opts.BackupDir
	pw := opts.Progress

	// Phase 1
	pw.Phase(1, 5, "detect")
	plan, err := BuildPlan(opts.Root)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
	rep.Untouched = plan.Untouched
	total := len(plan.Elements)
	pw.Log("info", "%d Element(e) gefunden", total)

	// Phases 2 and 3
	pw.Phase(2, 5, "fetch")
	var items []staged
	for i, el := range plan.Elements {
		pw.Element(el.Kind, el.Slug, el.Version, i, total)
		dir, err := fetchOne(opts.Fetcher, el, opts.StagingDir)
		switch {
		case errors.Is(err, vendorfiles.ErrNotPublished):
			pw.Log("warn", "%s %s: beim Hersteller nicht veröffentlicht", label(el), el.Version)
			items = append(items, staged{element: el})
		case err != nil:
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s %s: %v", label(el), el.Version, err))
			rep.Log = pw.Entries()
			return rep, err
		default:
			items = append(items, staged{element: el, dir: dir})
		}
	}

	if opts.DryRun {
		pw.Log("info", "Probelauf - es wird nichts geändert")
		for _, it := range items {
			rep.Elements = append(rep.Elements, describe(it))
		}
		rep.Log = pw.Entries()
		return rep, nil
	}

	// Phases 4 and 5
	for i, it := range items {
		el := it.element
		pw.Element(el.Kind, el.Slug, el.Version, i, total)

		pw.Phase(4, 5, "backup")
		archive, err := Backup(el.Path, opts.BackupDir, backupName(el))
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: Sicherung fehlgeschlagen: %v", label(el), err))
			rep.Log = pw.Entries()
			return rep, err
		}

		pw.Phase(5, 5, "swap")
		entry := report.RepairElement{
			Kind: el.Kind, Slug: el.Slug, Version: el.Version, Locale: el.Locale,
			Path: el.Path, Backup: archive,
		}
		if it.dir == "" {
			if err := removeInside(opts.Root, el.Path); err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				rep.Log = pw.Entries()
				return rep, err
			}
			entry.Outcome = report.OutcomeDeleted
			pw.Log("error", "gelöscht %s %s - kein Original verfügbar", label(el), el.Version)
		} else {
			if err := Swap(opts.Root, el.Path, it.dir); err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				rep.Log = pw.Entries()
				return rep, err
			}
			entry.Outcome = report.OutcomeReplaced
			entry.Files = countFiles(el.Path)
			pw.Log("ok", "ersetzt %s %s", label(el), el.Version)
		}
		rep.Elements = append(rep.Elements, entry)
	}

	rep.Log = pw.Entries()
	return rep, nil
}

func fetchOne(f *vendorfiles.Fetcher, el Element, staging string) (string, error) {
	dest, err := os.MkdirTemp(staging, "el-")
	if err != nil {
		return "", err
	}
	switch el.Kind {
	case "core":
		return f.Core(el.Version, el.Locale, dest)
	case "plugin":
		return f.Plugin(el.Slug, el.Version, dest)
	case "theme":
		return f.Theme(el.Slug, el.Version, dest)
	}
	return "", fmt.Errorf("unbekannte Art %q", el.Kind)
}

func removeInside(root, dir string) error {
	if err := InsideRoot(root, dir); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func label(el Element) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + " " + el.Slug
}

func backupName(el Element) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + "-" + el.Slug
}

func describe(it staged) report.RepairElement {
	out := report.RepairElement{
		Kind: it.element.Kind, Slug: it.element.Slug, Version: it.element.Version,
		Locale: it.element.Locale, Path: it.element.Path,
	}
	if it.dir == "" {
		out.Outcome = report.OutcomeDeleted
		out.Message = "kein Original verfügbar"
	} else {
		out.Outcome = report.OutcomeReplaced
	}
	return out
}

func countFiles(dir string) int {
	n := 0
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	return n
}
```

**Hinweis für den Umsetzenden:** Der Kern ist ein Sonderfall, den diese
Fassung noch nicht behandelt — `Swap` würde das gesamte Wurzelverzeichnis
ersetzen und dabei `wp-content` und `wp-config.php` mitnehmen. Task 9 baut das
ein; hier zuerst die beiden Tests grün bekommen, die Plugin und Theme
betreffen, und für `core` in `Run` vorerst `report.OutcomeSkipped` mit der
Meldung `"Kern folgt in Task 9"` setzen.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/repair/repair.go internal/repair/repair_test.go
git commit -m "feat: the five phases, staging everything before touching anything"
```

---

### Task 9: Der Kern als Sonderfall

**Files:**
- Modify: `internal/repair/swap.go` (neue Funktion `SwapCore`)
- Modify: `internal/repair/repair.go` (Aufruf statt `OutcomeSkipped`)
- Test: `internal/repair/swap_test.go` (ergänzen)

**Interfaces:**
- Produces: `func SwapCore(root, stagedDir string) (int, error)` — ersetzt `wp-admin/` und `wp-includes/` vollständig und die regulären Dateien im Wurzelverzeichnis, lässt `wp-content` und `wp-config.php` stehen; gibt die Zahl ersetzter Dateien zurück.

- [ ] **Step 1: Write the failing test**

```go
func TestSwapCoreKeepsContentAndConfig(t *testing.T) {
	root := fakeWordPress(t)
	if err := os.WriteFile(filepath.Join(root, "wp-includes", "shell.php"), []byte("<?php eval($_GET[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged := filepath.Join(t.TempDir(), "wordpress")
	if err := os.MkdirAll(filepath.Join(staged, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-includes", "version.php"), []byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-login.php"), []byte("<?php // original"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := SwapCore(root, staged); err != nil {
		t.Fatal(err)
	}

	// The dropped file inside wp-includes is gone with the directory.
	if _, err := os.Stat(filepath.Join(root, "wp-includes", "shell.php")); !os.IsNotExist(err) {
		t.Error("the dropped file inside wp-includes survived")
	}
	// wp-config.php and wp-content must not be part of the exchange.
	if _, err := os.Stat(filepath.Join(root, "wp-config.php")); err != nil {
		t.Error("wp-config.php was removed")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "uploads", "2026", "06", "photo.jpg")); err != nil {
		t.Error("uploads were removed")
	}
	// A foreign file in the root stays: the scan afterwards is meant to show it.
	if err := os.WriteFile(filepath.Join(root, "foreign.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SwapCore(root, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "foreign.php")); err != nil {
		t.Error("a foreign root file was removed - the following scan can no longer report it")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestSwapCore -v`
Expected: FAIL — `undefined: SwapCore`

- [ ] **Step 3: Write minimal implementation**

```go
// SwapCore replaces the core without touching what belongs to the site.
//
// wp-admin and wp-includes go as a whole, because a file dropped inside them
// only disappears with the directory. The root is different: files are
// replaced one by one, by name, so wp-config.php, wp-content and anything
// foreign stay. The foreign ones are the point - the scan after the repair is
// supposed to report them.
func SwapCore(root, stagedDir string) (int, error) {
	if err := InsideRoot(root, stagedDir); err == nil {
		return 0, fmt.Errorf("das Bereitstellungsverzeichnis darf nicht im Webstamm liegen")
	}

	replaced := 0
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		src := filepath.Join(stagedDir, dir)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(root, dir)
		if _, err := os.Stat(dst); err == nil {
			if err := Swap(root, dst, src); err != nil {
				return replaced, err
			}
		} else {
			if err := InsideRoot(root, dst); err != nil {
				return replaced, err
			}
			if err := os.Rename(src, dst); err != nil {
				return replaced, err
			}
		}
		replaced += countFiles(dst)
	}

	entries, err := os.ReadDir(stagedDir)
	if err != nil {
		return replaced, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dst := filepath.Join(root, entry.Name())
		if err := InsideRoot(root, dst); err != nil {
			return replaced, err
		}
		raw, err := os.ReadFile(filepath.Join(stagedDir, entry.Name()))
		if err != nil {
			return replaced, err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return replaced, err
		}
		replaced++
	}
	return replaced, nil
}
```

In `Run` ersetzt der Aufruf den Platzhalter aus Task 8:

```go
		if el.Kind == "core" && it.dir != "" {
			n, err := SwapCore(opts.Root, it.dir)
			if err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				rep.Log = pw.Entries()
				return rep, err
			}
			entry.Outcome, entry.Files = report.OutcomeReplaced, n
			pw.Log("ok", "ersetzt Kern %s", el.Version)
			rep.Elements = append(rep.Elements, entry)
			continue
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repair/ -v`
Expected: PASS, alle Tests des Pakets

- [ ] **Step 5: Commit**

```bash
git add internal/repair/swap.go internal/repair/repair.go internal/repair/swap_test.go
git commit -m "feat: replace the core without taking wp-content with it"
```

---

### Task 10: Der Befehl

**Files:**
- Create: `cmd/malwatch/repair.go`
- Modify: `cmd/malwatch/main.go:19-30` (neuer `case`)
- Modify: `cmd/malwatch/usage.go` (Abschnitt für `repair`)
- Modify: `cmd/malwatch/scan.go` (Fortschrittsdatei am vorhandenen `Progress`-Haken)

**Interfaces:**
- Consumes: `repair.Run`, `repair.Options`, `progress.New`, `vendorfiles.NewFetcher`.
- Produces: `func cmdRepair(args []string) int`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepairRefusesWithoutAPath(t *testing.T) {
	if code := cmdRepair([]string{}); code != 3 {
		t.Errorf("exit code %d without --path, want 3", code)
	}
}

func TestRepairDryRunWritesAReportAndChangesNothing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.6.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")

	// No network in the test: an unreachable vendor address plus --dry-run
	// has to end in a report, not in a changed tree.
	code := cmdRepair([]string{
		"--path=" + root, "--dry-run", "--json", "--out=" + out,
		"--vendor-base=http://127.0.0.1:1/",
	})
	if code == 0 {
		t.Errorf("an unreachable vendor must not report success")
	}
	raw, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(raw), "\"schema\"") {
		t.Fatalf("no report was written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-includes", "version.php")); err != nil {
		t.Error("the tree was modified during a dry run")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/malwatch/ -v`
Expected: FAIL — `undefined: cmdRepair`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

func cmdRepair(args []string) int {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	path := fs.String("path", "", "")
	backupDir := fs.String("backup-dir", "", "")
	stagingDir := fs.String("staging-dir", "", "")
	progressFile := fs.String("progress", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")
	vendorBase := fs.String("vendor-base", "", "")

	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "repair braucht --path.")
		return 3
	}
	if *backupDir == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "repair braucht --backup-dir, außer mit --dry-run.")
		return 3
	}

	staging := *stagingDir
	if staging == "" {
		var err error
		if staging, err = os.MkdirTemp("", "malwatch-staging-"); err != nil {
			fmt.Fprintf(os.Stderr, "Bereitstellungsverzeichnis: %v\n", err)
			return 3
		}
		defer os.RemoveAll(staging)
	}

	pw, err := progress.New(*progressFile, "repair")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fortschrittsdatei: %v\n", err)
		return 3
	}
	defer pw.Close()

	base := vendorfiles.BaseURLs{}
	if *vendorBase != "" {
		// One address for every source keeps the acceptance test offline.
		base = vendorfiles.BaseURLs{
			Core: *vendorBase, LocalisedCore: *vendorBase,
			Plugin: *vendorBase + "plugin/", Theme: *vendorBase + "theme/",
		}
	}

	rep, runErr := repair.Run(repair.Options{
		Root:       *path,
		BackupDir:  *backupDir,
		StagingDir: staging,
		DryRun:     *dryRun,
		Fetcher:    vendorfiles.NewFetcher(base, 5*time.Minute),
		Progress:   pw,
	})

	w := os.Stdout
	if *out != "" {
		fh, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 3
		}
		defer fh.Close()
		w = fh
	}
	if *asJSON {
		_ = rep.WriteJSON(w)
	} else {
		_ = rep.WriteText(w)
	}

	if runErr != nil {
		return 3
	}
	return rep.ExitCode()
}
```

In `main.go` kommt der Fall dazu:

```go
	case "repair":
		return cmdRepair(args[1:])
```

In `scan.go` bekommt der vorhandene Haken die Datei — der Scan erbt damit dieselbe Anzeige:

```go
	pw, err := progress.New(*progressFile, "scan")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fortschrittsdatei: %v\n", err)
		return 3
	}
	defer pw.Close()
	opts.Progress = func(scanned int64) { pw.File("", int(scanned), 0) }
```

Dazu in `usage.go` ein Abschnitt, der die Schalter von `repair` nennt, in der Form der übrigen.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... && go vet ./... && test -z "$(gofmt -l .)"`
Expected: PASS, keine Ausgabe von `gofmt`

- [ ] **Step 5: Commit**

```bash
git add cmd/malwatch/
git commit -m "feat: the repair command, and a progress file for scans too"
```

---

### Task 11: Der Abnahmetest in CI

**Files:**
- Modify: `.github/workflows/ci.yml` (neuer Job `repair-roundtrip`)

**Interfaces:**
- Consumes: das gebaute Binary mit `repair` aus Task 10.

**Korrektur gegenüber der ersten Fassung dieses Plans.** Hier stand, nach dem
Lauf seien „genau die zwei abgelegten Dateien übrig". Das ist falsch, und ein
Lauf gegen echtes WordPress 6.6.2 hat es gezeigt: eine Datei in `wp-includes`
oder in einem Plugin verschwindet **mit dem Verzeichnis**, das ersetzt wird —
das ist ja der Zweck. Übrig bleibt, was **außerhalb** der Herstellerordner
liegt. Der Test prüft deshalb beide Hälften:

| abgelegt in | nach dem Lauf | warum |
|---|---|---|
| `wp-includes/2mOnl635P1W.php` | weg | Verzeichnis wurde vollständig ersetzt |
| `wp-content/plugins/akismet/backdoor.php` | weg | dito |
| `2q7ajgCOGou.php` (Webstamm) | da, und gemeldet | Wurzeldateien werden einzeln nach Namen ersetzt |
| `wp-content/uploads/2026/06/shell.php` | da, und gemeldet | `uploads` gehört dem Kunden |

Wer die erste Hälfte falsch baut, lässt Schadcode stehen. Wer die zweite falsch
baut, löscht Kundendaten.

- [ ] **Step 1: Write the failing test**

Der Job `repair-roundtrip` ans Ende von `.github/workflows/ci.yml`: WordPress
6.6.2 holen, die vier Dateien ablegen, `repair --backup-dir=backups
--progress=progress.json` laufen lassen, danach in drei Schritten prüfen —
die zwei innerhalb sind weg, die zwei außerhalb samt `akismet.php` sind da,
und `jq -r '.findings[].path' after.json | sort -u` nennt genau die zwei
außerhalb. Der vollständige Job steht in der Datei.

- [ ] **Step 2: Run test to verify it fails**

Der Job läuft nur in CI. Lokal vorher von Hand nachvollziehen, mit echtem
WordPress und echten Herstellerquellen — das ist billiger als eine Runde über
GitHub und findet dieselben Fehler:

Run:
```bash
curl -fsSL -o wp.zip https://wordpress.org/wordpress-6.6.2.zip && unzip -q wp.zip
printf '<?php @eval($_POST["cmd"]);' > wordpress/wp-includes/2mOnl635P1W.php
printf '<?php @eval($_POST["cmd"]);' > wordpress/2q7ajgCOGou.php
malwatch repair --path=wordpress --backup-dir=backups
```
Expected: Bericht nennt Kern, Plugins und Themes als ersetzt; die Datei in
`wp-includes` ist weg, die im Webstamm steht noch da.

- [ ] **Step 3: Write minimal implementation**

Keine — der Job prüft, was die Tasks 1 bis 10 gebaut haben. Schlägt er fehl,
liegt der Fehler dort und nicht im Job.

- [ ] **Step 4: Run test to verify it passes**

Run: nach dem Push den Job `repair-roundtrip` in GitHub Actions ansehen
Expected: grün; die Ausgabe nennt genau die zwei Dateien außerhalb

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "test: the round trip - what sat in a vendor directory is gone, what sat outside is reported"
```

---

## Selbstprüfung dieses Plans

**Abdeckung der Spec:**

| Anforderung der Spec | Task |
|---|---|
| Befehl mit `--path`, `--backup-dir`, `--progress`, `--json`, `--out`, `--dry-run` | 10 |
| Phase 1 Erkennen | 6 |
| Phasen 2/3 Holen und Prüfen | 3, 8 |
| Phase 4 Sichern | 4, 8 |
| Phase 5 Tauschen | 5, 8, 9 |
| Die Pfadgrenze als Abbruch | 1, 5, 9 |
| 404 ≠ Fehlschlag | 3, 8 |
| Nie angefasst: `wp-config.php`, `uploads`, `wp-content` ohne Plugin/Theme, fremde Wurzeldateien | 6, 9 |
| `mu-plugins` wird ausgewiesen, nicht gelöscht | 6 |
| Eigentümer und Modus vom ersetzten Baum | 5 |
| Kein Original → gelöscht, mit Name und Version | 7, 8 |
| Fortschrittsdatei, schreiben-dann-umbenennen, gedrosselt | 2 |
| Dieselbe Datei für den Scan | 10 |
| Bericht in JSON und Text, Rückgabecodes | 7 |
| Abnahmetest, beide Hälften | 11 |

**Lücken, die dieser Plan bewusst offen lässt:**

- Die Verifikation gegen die Prüfsummen aus `knownfiles` ist in Task 3 und 8
  noch nicht verdrahtet: geholt und entpackt wird, verglichen noch nicht. Das
  ist ein eigener Task 12 wert, sobald 1–11 stehen — er hängt an nichts, was
  hier fehlt, und der Abnahmetest deckt den Nutzen vorerst ab.
- Der Fehlerfall „Fehler beim Tauschen → Website bleibt abgeschaltet" gehört
  ins Addon und damit in Teil 2 dieses Plans.

**Typprüfung:** `progress.LogEntry` wird in Task 2 definiert und in Task 7
verwendet; `report.RepairElement` und `report.Outcome*` in Task 7 definiert und
in Task 8 und 9 verwendet; `repair.Element` und `repair.Plan` in Task 6
definiert und in Task 8 verwendet; `vendorfiles.BaseURLs` und `ErrNotPublished`
in Task 3 definiert und in Task 8 und 10 verwendet. Die Namen stimmen überein.

## Teil 2

Die Anbindung im Addon — `job_kind`, die Tabellen `malwatch_repair` und
`malwatch_repair_element`, die Schemaänderung mit Blick in `information_schema`,
die Seite `malwatch_progress.php`, die Ansicht mit Phasenkopf und Elementliste,
das Ab- und Anschalten der Website — bekommt einen eigenen Plan, sobald Teil 1
steht. Sie hängt vollständig von der Fortschrittsdatei und dem Berichtsformat
aus Teil 1 ab.
