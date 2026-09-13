# WordPress-Updates, Teil A: der Befehl `malwatch upgrade` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Der Scanner bekommt den Befehl `malwatch upgrade`, der WordPress-Kern, Plugins und Themes aus einer Plandatei auf eine Zielversion von wordpress.org bringt, die Website danach prüft und bei einem Fehler den alten Stand zurückholt; dazu liefern Scan und Abgleich die Angaben, aus denen das Panel Zielversionen anbietet.

**Architecture:** Ein neues Paket `internal/upgrade` ordnet den Lauf in vier Phasen (Erkennen, Holen, Prüfen, Aktualisieren). Es nutzt die vorhandenen Bausteine: `vendorfiles` lädt die Archive, `knownfiles` liefert Prüfsummen, `repair` tauscht Bäume und legt den alten Stand in die Quarantäne, `progress` veröffentlicht den Zustand. WP-CLI läuft über eine Executor-Schnittstelle, die Nachprüfung über eine Prober-Schnittstelle; beide lassen sich in Tests ersetzen.

**Tech Stack:** Go 1.24, ausschließlich Standardbibliothek; GitHub Actions mit MySQL-Dienst und WP-CLI für den Abnahmetest.

**Spec:** `docs/superpowers/specs/2026-09-13-wordpress-updates-design.md` (Teil 1 und Teil 2). Teil B dieses Plans (`2026-09-14-wordpress-upgrade-teil-b.md`) setzt Teil 3, das Addon, um und baut auf den Schnittstellen hier auf.

## Global Constraints

- Go 1.24, keine Abhängigkeit außerhalb der Standardbibliothek.
- Der Befehl heißt `malwatch upgrade`; `malwatch update` lädt weiter die Signaturen.
- Rückgabecodes von `upgrade`: 0 jedes Element aktualisiert oder Probelauf ohne Einwand, 2 mindestens ein Element `refused`, `rolled_back` oder `failed`, 3 Fehler des Laufs oder `rollback_failed`.
- Der JSON-Bericht trägt `"schema": 1`; die Fortschrittsdatei `"kind": "upgrade"`.
- Geschrieben wird allein unterhalb der Installation, des Quarantäne- und des Bereitstellungsverzeichnisses; ein Pfad, der nach Auflösung der Symlinks außerhalb liegt, beendet den Lauf.
- WP-CLI läuft nie als root; `--run-as=root` und UID 0 werden abgewiesen.
- Meldungen an Bediener auf Deutsch, Code-Kommentare im Stil der umgebenden Datei.
- Texte ohne Negativabgrenzungen („X, nicht Y“, „statt“, „kein X, sondern Y“) und ohne Zeitschätzungen (globale Vorgabe des Nutzers).
- Keine echten Daten in Tests und Doku: Beispiele heißen `beispiel.de`, `web12`, `client3`.
- Die zwei Produktnamen, die aus der Git-Historie entfernt wurden, kommen im Repository nicht vor. Prüfung vor jedem Commit: `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` liefert nichts.
- `gofmt -l .` bleibt leer, `go vet ./...` sauber.
- Tests dieser Pakete laufen lokal mit `go test ./internal/<paket>/`. Pakete mit Schadcode-Mustern (`internal/scanner`) laufen als Linux-Testbinaries auf dem Server (`GOOS=linux go test -c`, danach `chmod +x`).
- Jeder Commit endet mit der Zeile `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`; die Schritte unten nennen nur die erste Zeile.

## Entscheidungen gegenüber der Spezifikation

| # | Entscheidung | Grund | Preis, falls falsch |
|---|---|---|---|
| 1 | Befehl `malwatch upgrade`, Paket `internal/upgrade`, Addon-Kennungen `upgrade` (Teil B); Beschriftung im Panel bleibt „Updates“ | `malwatch update` lädt seit Anfang die Signaturen | mechanisches Umbenennen |
| 2 | Rückgabecode 3 für `rollback_failed` und Laufehler | alle Befehle nutzen 3 für „gescheitert“, das Addon wertet 0 und 2 als geordnetes Ende | eine Zeile im Runner |
| 3 | Bericht als flache Liste `elements`, je Element `install` | das Addon liest Elemente, eine Ebene weniger zu durchlaufen | Umbau des Einlesens |
| 4 | Fortschritt: `steps` je Element mit `from`, `to`, `state`; `element.version` trägt die Zielversion | Schritte zeigen alle Elemente zugleich, das laufende Element bleibt wie bei der Reparatur | Anpassung der Anzeige |
| 5 | Prüfsummen über `knownfiles`; ein Plugin ohne veröffentlichte Liste (404) gilt als `unverified` und läuft weiter, wie ein Theme | `repair.Run` prüft bisher keine Prüfsummen; kostenlose Plugins ohne Liste wären sonst nie aktualisierbar | ein Plugin läuft ohne Prüfsummenbeleg |
| 6 | Der Datenbank-Export liegt als Quarantäne-Eintrag mit dem Bereitstellungsverzeichnis als Wurzel; das Archiv trägt die Rechte der Quarantäne (0640 in einem Verzeichnis, das allein root betreten darf) | `quarantine.StoreCopy` bleibt unverändert, und der Export ist trotzdem allein für root lesbar | ein eigener Speicherweg für Exporte |

## File Structure

| Datei | Verantwortung |
|---|---|
| `internal/repair/replace.go` (neu) | `Replacement`, `ReplaceDir`, `ReplaceCore`: Tausch mit Quarantäne für andere Aufrufer |
| `internal/repair/repair.go` | `Options.Origin`, `Options.Reason` als Beschriftung der Quarantäne-Einträge |
| `internal/progress/progress.go` | `Step`, `SetSteps`, `StepState` |
| `internal/report/upgrade.go` (neu) | Bericht eines Upgrade-Laufs, Rückgabecode, Text- und JSON-Ausgabe |
| `internal/phpinfo/phpinfo.go` (neu) | PHP-Version eines Binaries |
| `internal/vendorfiles/fetch.go` | `Safe` exportiert |
| `internal/knownfiles/fetch.go` | `ErrNotPublished` für eine fehlende Prüfsummenliste |
| `internal/cms/wordpress.go` | `WordPressExtras` exportiert |
| `internal/upgrade/plan.go` (neu) | Plandatei lesen und prüfen |
| `internal/upgrade/wordpress.go` (neu) | Kern-Angaben, Anforderungen, Multisite, Wartungsmodus |
| `internal/upgrade/health.go` (neu) | Seiten abrufen und vorher/nachher bewerten |
| `internal/upgrade/exec.go` (neu) | Executor, WP-CLI-Aufrufe, `--run-as` prüfen |
| `internal/upgrade/verify.go` (neu) | geladenes Archiv gegen Prüfsummen halten |
| `internal/upgrade/upgrade.go` (neu) | der Lauf: Phasen, Tausch, Nachprüfung, Zurückholen |
| `cmd/malwatch/upgrade.go` (neu), `main.go`, `usage.go` | Befehl und Hilfe |
| `internal/cms/latest.go`, `internal/report/report.go`, `internal/scanner/scanner.go`, `cmd/malwatch/scan.go` | Anforderungen der neuesten Version, neueste Version im Zweig, PHP-Version im Scan-Bericht |
| `.github/workflows/ci.yml` | Abnahmetest `upgrade-roundtrip` |

---

### Task 1: Tauschen für andere Aufrufer

**Files:**
- Modify: `internal/repair/repair.go` (Options, `repairSource`, `repairCore`, `quarantineLooseRootFiles`)
- Create: `internal/repair/replace.go`
- Test: `internal/repair/replace_test.go`

**Interfaces:**
- Consumes: `quarantineElement`, `captureMode`, `Swap`, `applyOwnership`, `countFiles`, `repairCore` (alle im Paket `repair`)
- Produces:
  - `type Replacement struct { Root, QuarantineDir, Domain, Origin, Reason string }`
  - `func ReplaceDir(r Replacement, dir, stagedDir string) (quarantine.Entry, int, error)`
  - `func ReplaceCore(r Replacement, stagedDir string) (int, []string, error)`

- [ ] **Step 1: Write the failing test**

`internal/repair/replace_test.go`:

```go
package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/quarantine"
)

// stagedTree writes files into a fresh directory outside the site, the way an
// unpacked vendor archive arrives.
func stagedTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "staged")
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReplaceDirFilesTheOldTreeUnderTheCallersLabel(t *testing.T) {
	root := fakeWordPress(t)
	plugin := filepath.Join(root, "wp-content", "plugins", "akismet")
	newTree := stagedTree(t, map[string]string{
		"akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.4\n*/",
	})
	store := t.TempDir()

	entry, files, err := ReplaceDir(Replacement{
		Root: root, QuarantineDir: store, Domain: "beispiel.de",
		Origin: "upgrade", Reason: "Vor dem Update abgelegt",
	}, plugin, newTree)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Errorf("files = %d, want 1", files)
	}
	raw, err := os.ReadFile(filepath.Join(plugin, "akismet.php"))
	if err != nil || !strings.Contains(string(raw), "5.3.4") {
		t.Fatalf("the new release is not in place: %q %v", raw, err)
	}
	stored, err := quarantine.Get(store, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Origin != "upgrade" || stored.Reason != "Vor dem Update abgelegt" {
		t.Errorf("entry labelled %q / %q", stored.Origin, stored.Reason)
	}

	// The entry brings the old release back over the new one.
	if err := quarantine.Restore(store, entry.ID, true); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(plugin, "akismet.php"))
	if !strings.Contains(string(raw), "5.3.3") {
		t.Errorf("the restore did not bring the old release back: %q", raw)
	}
}

func TestReplaceCoreLabelsEveryEntryItFiles(t *testing.T) {
	root := fakeWordPress(t)
	newCore := stagedTree(t, map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.6.3';\n",
		"wp-login.php":            "<?php // 6.6.3",
	})
	store := t.TempDir()

	n, ids, err := ReplaceCore(Replacement{
		Root: root, QuarantineDir: store, Domain: "beispiel.de",
		Origin: "upgrade", Reason: "Vor dem Update abgelegt",
	}, newCore)
	if err != nil {
		t.Fatal(err)
	}
	// wp-includes as a directory, wp-login.php as a loose file that differs.
	if n == 0 || len(ids) != 2 {
		t.Fatalf("n = %d, ids = %v; want files and two entries", n, ids)
	}
	for _, id := range ids {
		e, err := quarantine.Get(store, id)
		if err != nil {
			t.Fatal(err)
		}
		if e.Origin != "upgrade" || e.Reason != "Vor dem Update abgelegt" {
			t.Errorf("entry %s labelled %q / %q", id, e.Origin, e.Reason)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repair/ -run TestReplace -v`
Expected: FAIL, `undefined: ReplaceDir` und `undefined: Replacement`

- [ ] **Step 3: Label the entries in `repair.go`**

In `type Options struct` nach `Domain string` einfügen:

```go
	// Origin and Reason label the quarantine entries. Empty means the
	// repair's own labels; an upgrade passes its own, so the quarantine list
	// says why a tree left the site.
	Origin string
	Reason string
```

Nach `ParseNoOriginal` einfügen:

```go
// origin is the quarantine origin of this run.
func (o Options) origin() string {
	if o.Origin != "" {
		return o.Origin
	}
	return "repair"
}

// reason is the caller's quarantine reason, or the repair's own text.
func (o Options) reason(own string) string {
	if o.Reason != "" {
		return o.Reason
	}
	return own
}
```

In `repairSource` die beiden Felder ersetzen:

```go
		Origin:  opts.origin(),
		Reason:  opts.reason(reason),
```

In `repairCore` die Quelle so bauen:

```go
		reason := opts.reason("Beim Ersetzen durch das Original abgelegt")
		src := quarantine.Source{
			Root: opts.Root, RelPath: dir, Domain: opts.Domain,
			Origin: opts.origin(), Reason: reason,
		}
		var qEntry quarantine.Entry
		var err error
		if mode == "overlay" {
			src.Reason = opts.reason("Vor dem Darüberschreiben abgelegt")
```

In `quarantineLooseRootFiles` den Aufruf so beschriften:

```go
		qEntry, err := quarantine.StoreCopy(opts.QuarantineDir, quarantine.Source{
			Root: opts.Root, RelPath: name, Domain: opts.Domain,
			Origin: opts.origin(),
			Reason: opts.reason("Vom Original abweichende Kerndatei, vor dem Überschreiben abgelegt"),
		})
```

- [ ] **Step 4: Create `internal/repair/replace.go`**

```go
package repair

import "github.com/brightcolor/malwatch/internal/quarantine"

// Replacement is what ReplaceDir and ReplaceCore need from a caller outside
// this package. An upgrade exchanges a plugin for a newer release the same
// way a repair exchanges it for the original of the installed one.
type Replacement struct {
	Root          string // the installation; nothing outside it is written
	QuarantineDir string
	Domain        string
	Origin        string // quarantine origin, e.g. "upgrade"
	Reason        string // quarantine reason of every entry filed
}

func (r Replacement) options() Options {
	return Options{
		Root: r.Root, QuarantineDir: r.QuarantineDir, Domain: r.Domain,
		Origin: r.Origin, Reason: r.Reason,
	}
}

// ReplaceDir files dir into quarantine and moves stagedDir into its place,
// with the owner, group and mode dir had. It returns the entry and the number
// of files now in dir.
//
// A failure after the entry was written still returns the entry: the old tree
// sits in the store then, and the caller needs its id to bring it back.
func ReplaceDir(r Replacement, dir, stagedDir string) (quarantine.Entry, int, error) {
	opts := r.options()
	mode, uid, gid, hadMode := captureMode(dir)
	entry, err := quarantineElement(opts, "replace", Element{Path: dir}, "Beim Ersetzen abgelegt")
	if err != nil {
		return quarantine.Entry{}, 0, err
	}
	if err := Swap(r.Root, dir, stagedDir); err != nil {
		return entry, 0, err
	}
	if hadMode {
		_ = applyOwnership(dir, uid, gid, mode)
	}
	return entry, countFiles(dir), nil
}

// ReplaceCore exchanges wp-admin, wp-includes and the loose root files of the
// installation at r.Root for the staged core, filing what it replaces into
// quarantine first. The ids come back in the order they were filed, after a
// failure as well.
func ReplaceCore(r Replacement, stagedDir string) (int, []string, error) {
	return repairCore(r.options(), "replace", stagedDir)
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/repair/`
Expected: PASS, die vorhandenen Reparatur-Tests eingeschlossen

- [ ] **Step 6: Commit**

```bash
git add internal/repair/repair.go internal/repair/replace.go internal/repair/replace_test.go
git commit -m "feat(repair): exchange a tree for another caller, under its own quarantine label"
```

---

### Task 2: Schritte in der Fortschrittsdatei

**Files:**
- Modify: `internal/progress/progress.go`
- Test: `internal/progress/progress_test.go`

**Interfaces:**
- Produces:
  - `type Step struct { Kind, Slug, Path, From, To, State string }` mit JSON-Namen `kind`, `slug`, `path`, `from`, `to`, `state`
  - `func (w *Writer) SetSteps(steps []Step)`
  - `func (w *Writer) StepState(index int, state string)`

- [ ] **Step 1: Write the failing tests**

An `internal/progress/progress_test.go` anhängen:

```go
func TestStepsCarryTheirStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.progress")
	w, err := New(path, "upgrade")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	w.SetSteps([]Step{
		{Kind: "core", Path: "/w", From: "6.4.2", To: "6.4.5", State: "waiting"},
		{Kind: "plugin", Slug: "akismet", Path: "/w/wp-content/plugins/akismet", From: "5.3.0", To: "5.3.3", State: "waiting"},
	})
	w.StepState(1, "swapped")
	w.StepState(7, "updated") // outside the list: ignored

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind  string `json:"kind"`
		Steps []Step `json:"steps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "upgrade" || len(doc.Steps) != 2 {
		t.Fatalf("document is wrong: %+v", doc)
	}
	if doc.Steps[0].State != "waiting" || doc.Steps[1].State != "swapped" || doc.Steps[1].To != "5.3.3" {
		t.Errorf("steps are wrong: %+v", doc.Steps)
	}
}

func TestADocumentWithoutStepsLeavesThemOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.progress")
	w, err := New(path, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"steps"`) {
		t.Errorf("a scan document carries steps: %s", raw)
	}
}
```

Im Importblock `"strings"` ergänzen.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/progress/ -run 'TestSteps|TestADocumentWithoutSteps' -v`
Expected: FAIL, `undefined: Step`

- [ ] **Step 3: Write minimal implementation**

In `progress.go` nach `type element struct` einfügen:

```go
// Step is one element of a run that goes through several states, such as an
// upgrade: the panel shows a line per step.
type Step struct {
	Kind  string `json:"kind"`
	Slug  string `json:"slug,omitempty"`
	Path  string `json:"path,omitempty"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	State string `json:"state"`
}
```

In `type document struct` nach `Log` einfügen:

```go
	Steps         []Step     `json:"steps,omitempty"`
```

Nach `File` einfügen:

```go
// SetSteps publishes the elements of the run with their first state.
func (w *Writer) SetSteps(steps []Step) {
	w.mu.Lock()
	w.doc.Steps = append([]Step(nil), steps...)
	w.mu.Unlock()
	_ = w.Flush()
}

// StepState moves one step to a new state and publishes it at once: a state
// change is what the panel waits for. An index outside the list is ignored.
func (w *Writer) StepState(index int, state string) {
	w.mu.Lock()
	if index >= 0 && index < len(w.doc.Steps) {
		w.doc.Steps[index].State = state
	}
	w.mu.Unlock()
	_ = w.Flush()
}
```

- [ ] **Step 4: Run the package tests**

Run: `go test ./internal/progress/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/progress/progress.go internal/progress/progress_test.go
git commit -m "feat(progress): steps with their own state, for runs that go element by element"
```

---

### Task 3: Der Bericht eines Upgrade-Laufs

**Files:**
- Create: `internal/report/upgrade.go`
- Test: `internal/report/upgrade_test.go`

**Interfaces:**
- Consumes: `progress.LogEntry`, `version.Version`, `ExitError` (report.go)
- Produces:
  - `type UpgradeOutcome string` mit `UpgradeUpdated` ("updated"), `UpgradeWould` ("would_update"), `UpgradeRefused` ("refused"), `UpgradeRolledBack` ("rolled_back"), `UpgradeFailed` ("failed"), `UpgradeRollbackFailed` ("rollback_failed"), `UpgradeSkipped` ("skipped")
  - `type PageCheck struct { URL string; Before, After, AfterRollback int }`
  - `type UpgradeElement struct { Kind, Slug, Install, Path, From, To string; Outcome UpgradeOutcome; Message string; Files int; Unverified bool; QuarantineIDs []string; DBExportID string; Checks []PageCheck }`
  - `type Upgrade struct { Schema int; Version string; StartedAt, FinishedAt time.Time; Root string; DryRun bool; PHPVersion string; Elements []UpgradeElement; Log []progress.LogEntry; Errors []string }`
  - `func NewUpgrade(root string, dryRun bool) *Upgrade`
  - `func (u *Upgrade) ExitCode() int`, `WriteJSON(io.Writer) error`, `WriteText(io.Writer) error`

JSON-Namen, auf die sich Teil B verlässt: `schema`, `malwatch_version`, `started_at`, `finished_at`, `root`, `dry_run`, `php_version`, `elements[].kind`, `slug`, `install`, `path`, `from`, `to`, `outcome`, `message`, `files`, `unverified`, `quarantine_ids`, `db_export_id`, `checks[].url`, `before`, `after`, `after_rollback`, `log`, `errors`.

- [ ] **Step 1: Write the failing tests**

`internal/report/upgrade_test.go`:

```go
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestUpgradeExitCode(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []UpgradeOutcome
		errs     []string
		want     int
	}{
		{"all updated", []UpgradeOutcome{UpgradeUpdated, UpgradeUpdated}, nil, 0},
		{"dry run", []UpgradeOutcome{UpgradeWould}, nil, 0},
		{"one refused", []UpgradeOutcome{UpgradeUpdated, UpgradeRefused}, nil, 2},
		{"one rolled back", []UpgradeOutcome{UpgradeRolledBack}, nil, 2},
		{"one failed", []UpgradeOutcome{UpgradeFailed}, nil, 2},
		{"rollback failed", []UpgradeOutcome{UpgradeRollbackFailed, UpgradeSkipped}, nil, 3},
		{"run error", []UpgradeOutcome{UpgradeSkipped}, []string{"Prüfsumme weicht ab"}, 3},
	}
	for _, c := range cases {
		u := NewUpgrade("/w", false)
		for _, o := range c.outcomes {
			u.Elements = append(u.Elements, UpgradeElement{Kind: "plugin", Outcome: o})
		}
		u.Errors = append(u.Errors, c.errs...)
		if got := u.ExitCode(); got != c.want {
			t.Errorf("%s: exit code %d, want %d", c.name, got, c.want)
		}
	}
}

func TestUpgradeTextNamesOutcomeVersionsAndReason(t *testing.T) {
	u := NewUpgrade("/var/www/clients/client3/web12/web", false)
	u.Elements = append(u.Elements, UpgradeElement{
		Kind: "plugin", Slug: "akismet", From: "5.3.0", To: "5.3.3",
		Outcome: UpgradeRolledBack, Message: "Startseite: Antwort 500",
		QuarantineIDs: []string{"20260914T101500Z-0a1b2c3d"},
	})
	var buf bytes.Buffer
	if err := u.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"zurückgeholt", "plugin akismet 5.3.0 → 5.3.3",
		"Startseite: Antwort 500", "20260914T101500Z-0a1b2c3d"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
}

func TestUpgradeJSONCarriesTheContract(t *testing.T) {
	u := NewUpgrade("/w", true)
	u.PHPVersion = "8.2.10"
	u.Elements = append(u.Elements, UpgradeElement{
		Kind: "core", Install: "/w", Path: "/w", From: "6.4.2", To: "6.4.5",
		Outcome: UpgradeWould, Checks: []PageCheck{{URL: "https://beispiel.de/", Before: 200}},
	})
	var buf bytes.Buffer
	if err := u.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != float64(1) || doc["dry_run"] != true || doc["php_version"] != "8.2.10" {
		t.Errorf("head is wrong: %v", doc)
	}
	el := doc["elements"].([]any)[0].(map[string]any)
	if el["install"] != "/w" || el["outcome"] != "would_update" || el["to"] != "6.4.5" {
		t.Errorf("element is wrong: %v", el)
	}
	check := el["checks"].([]any)[0].(map[string]any)
	if check["before"] != float64(200) {
		t.Errorf("check is wrong: %v", check)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestUpgrade -v`
Expected: FAIL, `undefined: NewUpgrade`

- [ ] **Step 3: Write `internal/report/upgrade.go`**

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

// UpgradeOutcome is what became of one element of an upgrade.
type UpgradeOutcome string

const (
	// UpgradeUpdated means the new release is in place and the site answered.
	UpgradeUpdated UpgradeOutcome = "updated"
	// UpgradeWould is a dry run's verdict on an element it found nothing against.
	UpgradeWould UpgradeOutcome = "would_update"
	// UpgradeRefused means the element was turned down before anything changed.
	UpgradeRefused UpgradeOutcome = "refused"
	// UpgradeRolledBack means the site broke after the exchange and the old
	// release is back, with the site answering as before.
	UpgradeRolledBack UpgradeOutcome = "rolled_back"
	// UpgradeFailed means the exchange or the database step broke off and the
	// old release is back, with the site answering as before.
	UpgradeFailed UpgradeOutcome = "failed"
	// UpgradeRollbackFailed means the old release is back and the site still
	// answers worse than before. The run stops there.
	UpgradeRollbackFailed UpgradeOutcome = "rollback_failed"
	// UpgradeSkipped means the element was never started.
	UpgradeSkipped UpgradeOutcome = "skipped"
)

// PageCheck is what one page of the site answered around an element. A status
// of 0 means no answer, or no check at that point.
type PageCheck struct {
	URL           string `json:"url"`
	Before        int    `json:"before"`
	After         int    `json:"after,omitempty"`
	AfterRollback int    `json:"after_rollback,omitempty"`
}

// UpgradeElement is one core, plugin or theme of an upgrade.
type UpgradeElement struct {
	Kind    string         `json:"kind"`
	Slug    string         `json:"slug,omitempty"`
	Install string         `json:"install"`
	Path    string         `json:"path"`
	From    string         `json:"from"`
	To      string         `json:"to"`
	Outcome UpgradeOutcome `json:"outcome"`
	Message string         `json:"message,omitempty"`
	Files   int            `json:"files,omitempty"`
	// Unverified marks an archive no checksum list covered: a theme, or a
	// plugin wordpress.org keeps no list for. It was unpacked in full.
	Unverified    bool        `json:"unverified,omitempty"`
	QuarantineIDs []string    `json:"quarantine_ids,omitempty"`
	DBExportID    string      `json:"db_export_id,omitempty"`
	Checks        []PageCheck `json:"checks,omitempty"`
}

// Upgrade is the report of one upgrade run.
type Upgrade struct {
	Schema     int                 `json:"schema"`
	Version    string              `json:"malwatch_version"`
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
	Root       string              `json:"root"`
	DryRun     bool                `json:"dry_run"`
	PHPVersion string              `json:"php_version,omitempty"`
	Elements   []UpgradeElement    `json:"elements"`
	Log        []progress.LogEntry `json:"log"`
	Errors     []string            `json:"errors"`
}

// NewUpgrade starts a report for the web root.
func NewUpgrade(root string, dryRun bool) *Upgrade {
	return &Upgrade{
		Schema:    1,
		Version:   version.Version,
		StartedAt: time.Now().UTC(),
		Root:      root,
		DryRun:    dryRun,
		Elements:  []UpgradeElement{},
		Log:       []progress.LogEntry{},
		Errors:    []string{},
	}
}

// ExitCode is 0 when every element was updated or a dry run found nothing
// against it, 2 when an element was refused, rolled back or failed with the
// old release back in place, and 3 when the run failed or a site stayed
// broken after the rollback.
func (u *Upgrade) ExitCode() int {
	if len(u.Errors) > 0 {
		return ExitError
	}
	code := 0
	for _, e := range u.Elements {
		switch e.Outcome {
		case UpgradeRollbackFailed:
			return ExitError
		case UpgradeRefused, UpgradeRolledBack, UpgradeFailed, UpgradeSkipped:
			code = 2
		}
	}
	return code
}

// WriteJSON writes the report for machines.
func (u *Upgrade) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(u)
}

var upgradeLabels = map[UpgradeOutcome]string{
	UpgradeUpdated:        "aktualisiert",
	UpgradeWould:          "würde aktualisieren",
	UpgradeRefused:        "abgelehnt",
	UpgradeRolledBack:     "zurückgeholt",
	UpgradeFailed:         "FEHLER, zurückgeholt",
	UpgradeRollbackFailed: "WEBSITE FEHLERHAFT",
	UpgradeSkipped:        "übersprungen",
}

// WriteText writes the report for a person.
func (u *Upgrade) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Update: %s\n", u.Root)
	if u.PHPVersion != "" {
		fmt.Fprintf(&b, "PHP %s\n", u.PHPVersion)
	}
	if u.DryRun {
		b.WriteString("Probelauf - es wurde nichts geändert.\n")
	}
	b.WriteString("\n")

	for _, e := range u.Elements {
		name := e.Kind
		if e.Slug != "" {
			name += " " + e.Slug
		}
		label := upgradeLabels[e.Outcome]
		if label == "" {
			label = string(e.Outcome)
		}
		fmt.Fprintf(&b, "  %-22s %s %s → %s", label, name, e.From, e.To)
		if e.Message != "" {
			fmt.Fprintf(&b, " - %s", e.Message)
		}
		b.WriteString("\n")
		if e.Unverified {
			b.WriteString("      ohne Prüfsummenliste; geprüft wurde, dass das Archiv vollständig ist\n")
		}
		if len(e.QuarantineIDs) > 0 {
			fmt.Fprintf(&b, "      Quarantäne: %s\n", strings.Join(e.QuarantineIDs, ", "))
		}
		if e.DBExportID != "" {
			fmt.Fprintf(&b, "      Datenbank-Export: %s\n", e.DBExportID)
		}
	}

	if len(u.Errors) > 0 {
		b.WriteString("\nFehler:\n")
		for _, msg := range u.Errors {
			fmt.Fprintf(&b, "  %s\n", msg)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
```

- [ ] **Step 4: Run the package tests**

Run: `go test ./internal/report/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/report/upgrade.go internal/report/upgrade_test.go
git commit -m "feat(report): the report of an upgrade run"
```

---

### Task 4: PHP-Version eines Binaries

**Files:**
- Create: `internal/phpinfo/phpinfo.go`
- Test: `internal/phpinfo/phpinfo_test.go`

**Interfaces:**
- Produces: `func Version(binary string, timeout time.Duration) (string, error)`; Rückgabe ohne Distributionsanhang, etwa `8.3.6`

- [ ] **Step 1: Write the failing tests**

`internal/phpinfo/phpinfo_test.go`:

```go
package phpinfo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fakePHP makes Version start this test binary, which prints what the test
// asks for instead of running PHP.
func fakePHP(t *testing.T, output string) {
	t.Helper()
	command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperPHP", "--")
		cmd.Env = append(os.Environ(), "MALWATCH_FAKE_PHP=1", "MALWATCH_FAKE_PHP_OUTPUT="+output)
		return cmd
	}
	t.Cleanup(func() { command = exec.CommandContext })
}

// TestHelperPHP is the fake binary itself. Outside fakePHP it does nothing.
func TestHelperPHP(t *testing.T) {
	if os.Getenv("MALWATCH_FAKE_PHP") != "1" {
		return
	}
	fmt.Print(os.Getenv("MALWATCH_FAKE_PHP_OUTPUT"))
	os.Exit(0)
}

func TestVersionReadsWhatPHPPrints(t *testing.T) {
	fakePHP(t, "8.2.10")
	v, err := Version("/usr/bin/php8.2", 5*time.Second)
	if err != nil || v != "8.2.10" {
		t.Fatalf("Version = %q, %v; want 8.2.10", v, err)
	}
}

func TestVersionDropsADistributionSuffix(t *testing.T) {
	fakePHP(t, "8.3.6-1+ubuntu22.04.1+deb.sury.org+1")
	v, err := Version("/usr/bin/php8.3", 5*time.Second)
	if err != nil || v != "8.3.6" {
		t.Fatalf("Version = %q, %v; want 8.3.6", v, err)
	}
}

func TestVersionRefusesOutputWithoutAVersion(t *testing.T) {
	fakePHP(t, "PHP Parse error: syntax error")
	_, err := Version("/usr/bin/php", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "nannte keine PHP-Version") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestVersionNeedsABinary(t *testing.T) {
	if _, err := Version("", 0); err == nil {
		t.Fatal("an empty binary was accepted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/phpinfo/ -v`
Expected: FAIL, `undefined: command` und `undefined: Version`

- [ ] **Step 3: Write `internal/phpinfo/phpinfo.go`**

```go
// Package phpinfo asks a PHP binary which version it is. The binary runs with
// -r and no script, so no code of a website runs.
package phpinfo

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// command starts the binary. The tests replace it with a helper process.
var command = exec.CommandContext

var versionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?`)

// Version runs "<binary> -r 'echo PHP_VERSION;'" and returns the version
// without a distribution suffix such as "-1+ubuntu22.04".
func Version(binary string, timeout time.Duration) (string, error) {
	if binary == "" {
		return "", fmt.Errorf("kein PHP-Binary angegeben")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := command(ctx, binary, "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", binary, err)
	}
	text := strings.TrimSpace(string(out))
	v := versionRe.FindString(text)
	if v == "" {
		if len(text) > 80 {
			text = text[:80]
		}
		return "", fmt.Errorf("%s nannte keine PHP-Version: %q", binary, text)
	}
	return v, nil
}
```

- [ ] **Step 4: Run the package tests**

Run: `go test ./internal/phpinfo/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/phpinfo
git commit -m "feat(phpinfo): the PHP version of a binary, without running site code"
```

---

### Task 5: Die Plandatei

**Files:**
- Modify: `internal/vendorfiles/fetch.go` (`safe` wird `Safe`), dazu jede Verwendung in `internal/vendorfiles/*_test.go`
- Create: `internal/upgrade/plan.go`
- Test: `internal/upgrade/plan_test.go`

**Interfaces:**
- Consumes: `safepath.InsideRoot(root, candidate string) error`
- Produces:
  - `func vendorfiles.Safe(s string) bool`
  - `type PlanElement struct { Kind, Slug, Version string }` (JSON `kind`, `slug`, `version`)
  - `type PlanInstall struct { Path, URL string; Elements []PlanElement }` (JSON `path`, `url`, `elements`)
  - `type Plan struct { Schema int; Installs []PlanInstall }` (JSON `schema`, `installs`)
  - `func LoadPlan(path, webRoot string) (Plan, error)`: Elemente je Installation sortiert (core, plugin, theme, dann Slug), `URL` mit abschließendem `/`
  - `func label(el PlanElement) string` (paketintern)
- Test-Helfer für spätere Tasks: `writeFile`, `jsonString`

- [ ] **Step 1: Export `Safe` in vendorfiles**

Run: `grep -rn "safe(" internal/vendorfiles`
In jeder Fundstelle `safe(` durch `Safe(` ersetzen. Die Funktion selbst:

```go
// Safe keeps a version or slug read off a customer's disk, or out of a plan
// file, out of a URL path. The value may come from a file an attacker controls.
func Safe(s string) bool {
```

Run: `go test ./internal/vendorfiles/`
Expected: PASS

- [ ] **Step 2: Write the failing tests**

`internal/upgrade/plan_test.go`:

```go
package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a file with its directories.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// jsonString quotes a path for a plan written by hand; a Windows path needs
// its backslashes escaped.
func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// planFile writes a plan into a fresh directory and returns its path.
func planFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "job.plan.json")
	writeFile(t, p, body)
	return p
}

// webRootWithTwoInstalls lays out a web root holding WordPress at its top and
// a second one in blog/.
func webRootWithTwoInstalls(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.2';\n")
	writeFile(t, filepath.Join(root, "blog", "wp-includes", "version.php"), "<?php\n$wp_version = '6.5.3';\n")
	return root
}

func TestLoadPlanAcceptsAValidPlanAndOrdersItsElements(t *testing.T) {
	root := webRootWithTwoInstalls(t)
	body := `{"schema":1,"installs":[
		{"path":` + jsonString(root) + `,"url":"https://beispiel.de","elements":[
			{"kind":"theme","slug":"twentytwentyfour","version":"1.2"},
			{"kind":"plugin","slug":"zzz","version":"2.0"},
			{"kind":"core","version":"6.4.5"},
			{"kind":"plugin","slug":"akismet","version":"5.3.3"}]},
		{"path":` + jsonString(filepath.Join(root, "blog")) + `,"url":"https://beispiel.de/blog","elements":[
			{"kind":"plugin","slug":"akismet","version":"5.3.3"}]}]}`

	plan, err := LoadPlan(planFile(t, body), root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, el := range plan.Installs[0].Elements {
		got = append(got, label(el))
	}
	if want := "core,plugin akismet,plugin zzz,theme twentytwentyfour"; strings.Join(got, ",") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
	if plan.Installs[0].URL != "https://beispiel.de/" || plan.Installs[1].URL != "https://beispiel.de/blog/" {
		t.Errorf("addresses not normalised: %q %q", plan.Installs[0].URL, plan.Installs[1].URL)
	}
}

func TestLoadPlanRefusesWhatItCannotVouchFor(t *testing.T) {
	root := webRootWithTwoInstalls(t)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.2';\n")
	empty := filepath.Join(root, "leer")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}

	install := func(path, url, elements string) string {
		return `{"schema":1,"installs":[{"path":` + jsonString(path) + `,"url":"` + url +
			`","elements":[` + elements + `]}]}`
	}
	core := `{"kind":"core","version":"6.4.5"}`
	cases := map[string]string{
		"schema 2":             `{"schema":2,"installs":[]}`,
		"no install":           `{"schema":1,"installs":[]}`,
		"outside the root":     install(outside, "https://beispiel.de/", core),
		"no WordPress":         install(empty, "https://beispiel.de/", core),
		"relative path":        install("web", "https://beispiel.de/", core),
		"ftp address":          install(root, "ftp://beispiel.de/", core),
		"unknown kind":         install(root, "https://beispiel.de/", `{"kind":"widget","slug":"x","version":"1"}`),
		"slug leaving a path":  install(root, "https://beispiel.de/", `{"kind":"plugin","slug":"../evil","version":"1.0"}`),
		"version with a slash": install(root, "https://beispiel.de/", `{"kind":"plugin","slug":"akismet","version":"5.3/3"}`),
		"core with a slug":     install(root, "https://beispiel.de/", `{"kind":"core","slug":"x","version":"6.4.5"}`),
		"twice the same": install(root, "https://beispiel.de/",
			`{"kind":"plugin","slug":"akismet","version":"5.3.3"},{"kind":"plugin","slug":"akismet","version":"5.3.4"}`),
		"no element": install(root, "https://beispiel.de/", ``),
	}
	for name, body := range cases {
		if _, err := LoadPlan(planFile(t, body), root); err == nil {
			t.Errorf("%s: the plan was accepted", name)
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/upgrade/ -v`
Expected: FAIL, `undefined: LoadPlan`

- [ ] **Step 4: Write `internal/upgrade/plan.go`**

```go
// Package upgrade brings WordPress core, plugins and themes to a newer release
// from wordpress.org: fetch and verify the archive, check what the release
// asks of the site, file the old tree into quarantine, exchange it, check the
// site, and bring the old tree back when the site broke.
package upgrade

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brightcolor/malwatch/internal/safepath"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// PlanElement is one element the plan asks for.
type PlanElement struct {
	Kind    string `json:"kind"`           // core, plugin, theme
	Slug    string `json:"slug,omitempty"` // empty for the core
	Version string `json:"version"`        // the target release
}

// PlanInstall is one WordPress installation of the website.
type PlanInstall struct {
	Path     string        `json:"path"`
	URL      string        `json:"url"`
	Elements []PlanElement `json:"elements"`
}

// Plan is what the panel asks the run to do.
type Plan struct {
	Schema   int           `json:"schema"`
	Installs []PlanInstall `json:"installs"`
}

var kindOrder = map[string]int{"core": 0, "plugin": 1, "theme": 2}

// LoadPlan reads a plan file and checks it against the web root.
//
// Every installation has to lie below webRoot, carry wp-includes/version.php
// and an http or https address. Every element needs a known kind, a slug and
// a version that may go into a URL, and may appear once. A plan that fails
// any of this is refused as a whole: half a plan would upgrade something
// nobody chose.
//
// The elements of each installation come back sorted: the core first, then
// plugins, then themes, each kind by slug.
func LoadPlan(path, webRoot string) (Plan, error) {
	f, err := os.Open(path)
	if err != nil {
		return Plan{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return Plan{}, err
	}

	var plan Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return Plan{}, fmt.Errorf("Plandatei %s ist unlesbar: %w", path, err)
	}
	if plan.Schema != 1 {
		return Plan{}, fmt.Errorf("Plandatei %s hat Format %d, erwartet wird 1", path, plan.Schema)
	}
	if len(plan.Installs) == 0 {
		return Plan{}, fmt.Errorf("Plandatei %s nennt keine Installation", path)
	}

	seen := map[string]bool{}
	for i := range plan.Installs {
		inst := &plan.Installs[i]
		if err := checkInstall(inst, webRoot); err != nil {
			return Plan{}, err
		}
		if seen[inst.Path] {
			return Plan{}, fmt.Errorf("die Installation %s steht zweimal im Plan", inst.Path)
		}
		seen[inst.Path] = true
		if err := checkElements(inst); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}

func checkInstall(inst *PlanInstall, webRoot string) error {
	if !filepath.IsAbs(inst.Path) {
		return fmt.Errorf("der Pfad %q ist kein absoluter Pfad", inst.Path)
	}
	inst.Path = filepath.Clean(inst.Path)
	if err := safepath.InsideRoot(webRoot, inst.Path); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(inst.Path, "wp-includes", "version.php"))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("unter %s liegt keine WordPress-Installation", inst.Path)
	}

	u, err := url.Parse(inst.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("die Adresse %q der Installation %s ist unbrauchbar", inst.URL, inst.Path)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery, u.Fragment = "", ""
	inst.URL = u.String()
	return nil
}

func checkElements(inst *PlanInstall) error {
	if len(inst.Elements) == 0 {
		return fmt.Errorf("für die Installation %s nennt der Plan kein Element", inst.Path)
	}
	seen := map[string]bool{}
	for _, el := range inst.Elements {
		if _, ok := kindOrder[el.Kind]; !ok {
			return fmt.Errorf("unbekannte Art %q in %s", el.Kind, inst.Path)
		}
		if el.Kind == "core" && el.Slug != "" {
			return fmt.Errorf("der Kern in %s trägt einen Slug", inst.Path)
		}
		if el.Kind != "core" && !vendorfiles.Safe(el.Slug) {
			return fmt.Errorf("unplausibler Slug %q in %s", el.Slug, inst.Path)
		}
		if !vendorfiles.Safe(el.Version) {
			return fmt.Errorf("unplausible Version %q in %s", el.Version, inst.Path)
		}
		key := el.Kind + ":" + el.Slug
		if seen[key] {
			return fmt.Errorf("%s steht zweimal in %s", label(el), inst.Path)
		}
		seen[key] = true
	}
	sort.SliceStable(inst.Elements, func(a, b int) bool {
		x, y := inst.Elements[a], inst.Elements[b]
		if kindOrder[x.Kind] != kindOrder[y.Kind] {
			return kindOrder[x.Kind] < kindOrder[y.Kind]
		}
		return x.Slug < y.Slug
	})
	return nil
}

// label names an element for messages: "core", "plugin akismet".
func label(el PlanElement) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + " " + el.Slug
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/upgrade/ ./internal/vendorfiles/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/vendorfiles internal/upgrade/plan.go internal/upgrade/plan_test.go
git commit -m "feat(upgrade): read and check the plan an upgrade runs from"
```

---

### Task 6: Was WordPress-Dateien über sich sagen

**Files:**
- Modify: `internal/cms/wordpress.go` (`WordPressExtras` exportiert)
- Create: `internal/upgrade/wordpress.go`
- Test: `internal/upgrade/wordpress_test.go`

**Interfaces:**
- Consumes: `cms.Compare(a, b string) int`, `writeFile` (Task 5)
- Produces:
  - `func cms.WordPressExtras(root string) []cms.Install`
  - `type CoreFacts struct { Version, DBVersion, RequiredPHP, Locale string }`
  - `type Requirements struct { WordPress, PHP string }` und `func (r Requirements) Check(label, wordpress, php string) string`
  - `func ReadCore(dir string) (CoreFacts, error)`
  - `func PluginRequirements(dir string) (Requirements, error)`, `func ThemeRequirements(dir string) (Requirements, error)`
  - `func Multisite(root string) bool`
  - `func MaintenanceActive(root string, now time.Time) bool`, `func EnterMaintenance(root string, now time.Time) error`, `func LeaveMaintenance(root string) error`

- [ ] **Step 1: Export the extras in cms**

An `internal/cms/wordpress.go` anhängen:

```go
// WordPressExtras lists the plugins and themes of the WordPress installation
// at root. An installation below root is a call of its own.
func WordPressExtras(root string) []Install { return wordpressExtras(root) }
```

- [ ] **Step 2: Write the failing tests**

`internal/upgrade/wordpress_test.go`:

```go
package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReadCoreReadsTheFourFacts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "wp-includes", "version.php"),
		"<?php\n$wp_version = '6.4.5';\n$wp_db_version = 56657;\n"+
			"$required_php_version = '7.0.0';\n$wp_local_package = 'de_DE';\n")
	facts, err := ReadCore(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := CoreFacts{Version: "6.4.5", DBVersion: "56657", RequiredPHP: "7.0.0", Locale: "de_DE"}
	if facts != want {
		t.Errorf("facts = %+v, want %+v", facts, want)
	}
}

func TestPluginRequirementsPreferTheHeaderAndFallBackToTheReadme(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kontakt")
	writeFile(t, filepath.Join(dir, "helpers.php"), "<?php // no header")
	writeFile(t, filepath.Join(dir, "kontakt.php"),
		"<?php\n/*\nPlugin Name: Kontakt\nVersion: 2.0\nRequires PHP: 8.1\n*/")
	writeFile(t, filepath.Join(dir, "readme.txt"),
		"=== Kontakt ===\nRequires at least: 6.5\nRequires PHP: 7.4\n")
	req, err := PluginRequirements(dir)
	if err != nil {
		t.Fatal(err)
	}
	if req.PHP != "8.1" || req.WordPress != "6.5" {
		t.Errorf("requirements = %+v, want PHP 8.1 from the header, WordPress 6.5 from the readme", req)
	}
}

func TestThemeRequirementsComeFromStyleCSS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "style.css"),
		"/*\nTheme Name: Vier\nRequires at least: 6.4\nRequires PHP: 7.0\n*/")
	req, err := ThemeRequirements(dir)
	if err != nil || req.WordPress != "6.4" || req.PHP != "7.0" {
		t.Fatalf("requirements = %+v, %v", req, err)
	}
}

func TestRequirementsCheckNamesWhatIsMissing(t *testing.T) {
	req := Requirements{WordPress: "6.6", PHP: "8.1"}
	if got := req.Check("3.25.1", "6.6.2", "7.4.33"); got != "3.25.1 braucht PHP 8.1, die Website läuft mit 7.4.33" {
		t.Errorf("php: %q", got)
	}
	if got := req.Check("3.25.1", "6.4.5", "8.2.10"); got != "3.25.1 braucht WordPress 6.6, installiert ist 6.4.5" {
		t.Errorf("wordpress: %q", got)
	}
	if got := req.Check("3.25.1", "6.6", "8.1"); got != "" {
		t.Errorf("met requirements refused: %q", got)
	}
}

func TestMultisiteReadsTheConfigOrTheOneAbove(t *testing.T) {
	root := t.TempDir()
	inst := filepath.Join(root, "web")
	writeFile(t, filepath.Join(inst, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.5';\n")
	if Multisite(inst) {
		t.Fatal("an installation without wp-config.php counts as multisite")
	}
	writeFile(t, filepath.Join(root, "wp-config.php"), "<?php\ndefine( 'MULTISITE', true );\n")
	if !Multisite(inst) {
		t.Error("wp-config.php one directory up was not read")
	}
	writeFile(t, filepath.Join(inst, "wp-config.php"), "<?php\ndefine('WP_DEBUG', false);\n")
	if Multisite(inst) {
		t.Error("the installation's own wp-config.php has to win")
	}
}

func TestMaintenanceFollowsTheRulesOfWordPress(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_790_000_000, 0)
	if MaintenanceActive(root, now) {
		t.Fatal("no file, yet active")
	}
	if err := EnterMaintenance(root, now); err != nil {
		t.Fatal(err)
	}
	if !MaintenanceActive(root, now.Add(time.Minute)) {
		t.Error("a fresh file is not active")
	}
	if MaintenanceActive(root, now.Add(11*time.Minute)) {
		t.Error("a file WordPress ignores counts as active")
	}
	if err := LeaveMaintenance(root); err != nil {
		t.Fatal(err)
	}
	if err := LeaveMaintenance(root); err != nil {
		t.Errorf("leaving twice: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}
}

func TestEnterMaintenanceRefusesALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra rights on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(root, ".maintenance")); err != nil {
		t.Fatal(err)
	}
	if err := EnterMaintenance(root, time.Now()); err == nil {
		t.Fatal("a link was written through")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("the link target was created")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/upgrade/ -run 'ReadCore|Requirements|Multisite|Maintenance' -v`
Expected: FAIL, `undefined: ReadCore`

- [ ] **Step 4: Write `internal/upgrade/wordpress.go`**

```go
package upgrade

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// CoreFacts is what wp-includes/version.php says about a core tree.
type CoreFacts struct {
	Version     string // $wp_version
	DBVersion   string // $wp_db_version
	RequiredPHP string // $required_php_version
	Locale      string // $wp_local_package; empty for the international build
}

// Requirements are what a release asks of the site. An empty field asks
// nothing.
type Requirements struct {
	WordPress string // "Requires at least"
	PHP       string // "Requires PHP"
}

var (
	wpVersionRe   = regexp.MustCompile(`(?m)^\s*\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	dbVersionRe   = regexp.MustCompile(`(?m)^\s*\$wp_db_version\s*=\s*(\d+)`)
	requiredPHPRe = regexp.MustCompile(`(?m)^\s*\$required_php_version\s*=\s*['"]([^'"]+)['"]`)
	localeRe      = regexp.MustCompile(`(?m)^\s*\$wp_local_package\s*=\s*['"]([A-Za-z_]{2,10})['"]`)

	requiresWPRe  = regexp.MustCompile(`(?im)^[ \t/*#@]*Requires at least\s*:\s*([0-9][0-9.]*)`)
	requiresPHPRe = regexp.MustCompile(`(?im)^[ \t/*#@]*Requires PHP\s*:\s*([0-9][0-9.]*)`)
	pluginNameRe  = regexp.MustCompile(`(?im)^[ \t/*#@]*Plugin Name\s*:\s*\S`)
	themeNameRe   = regexp.MustCompile(`(?im)^[ \t/*#@]*Theme Name\s*:\s*\S`)

	multisiteRe = regexp.MustCompile(`(?i)define\s*\(\s*['"]MULTISITE['"]\s*,\s*(true|1|'1'|"1")\s*\)`)
	upgradingRe = regexp.MustCompile(`\$upgrading\s*=\s*(\d+)`)
)

// headBytes is how much of a header file WordPress reads, and so do we.
const headBytes = 8192

// ReadCore reads wp-includes/version.php below dir.
func ReadCore(dir string) (CoreFacts, error) {
	path := filepath.Join(dir, "wp-includes", "version.php")
	raw, err := readHead(path, 512*1024)
	if err != nil {
		return CoreFacts{}, err
	}
	facts := CoreFacts{
		Version:     group(wpVersionRe, raw),
		DBVersion:   group(dbVersionRe, raw),
		RequiredPHP: group(requiredPHPRe, raw),
		Locale:      group(localeRe, raw),
	}
	if facts.Version == "" {
		return facts, fmt.Errorf("%s nennt keine WordPress-Version", path)
	}
	return facts, nil
}

// PluginRequirements reads the requirements of the plugin in dir from the
// header of its main file: the PHP file directly in dir that carries "Plugin
// Name", the one named after the directory first. A value the header leaves
// out comes from readme.txt, the order WordPress itself reads them in.
func PluginRequirements(dir string) (Requirements, error) {
	head, err := pluginHeader(dir)
	if err != nil {
		return Requirements{}, err
	}
	req := Requirements{WordPress: group(requiresWPRe, head), PHP: group(requiresPHPRe, head)}
	if req.WordPress == "" || req.PHP == "" {
		if readme, err := readHead(filepath.Join(dir, "readme.txt"), 16384); err == nil {
			if req.WordPress == "" {
				req.WordPress = group(requiresWPRe, readme)
			}
			if req.PHP == "" {
				req.PHP = group(requiresPHPRe, readme)
			}
		}
	}
	return req, nil
}

func pluginHeader(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	preferred := filepath.Base(dir) + ".php"
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
			names = append(names, e.Name())
		}
	}
	sort.SliceStable(names, func(a, b int) bool {
		return names[a] == preferred && names[b] != preferred
	})
	for _, name := range names {
		head, err := readHead(filepath.Join(dir, name), headBytes)
		if err == nil && pluginNameRe.Match(head) {
			return head, nil
		}
	}
	return nil, fmt.Errorf("in %s liegt keine Plugin-Hauptdatei", dir)
}

// ThemeRequirements reads the requirements of the theme in dir from style.css.
func ThemeRequirements(dir string) (Requirements, error) {
	path := filepath.Join(dir, "style.css")
	head, err := readHead(path, headBytes)
	if err != nil {
		return Requirements{}, err
	}
	if !themeNameRe.Match(head) {
		return Requirements{}, fmt.Errorf("%s trägt keinen Theme-Kopf", path)
	}
	return Requirements{WordPress: group(requiresWPRe, head), PHP: group(requiresPHPRe, head)}, nil
}

// Check returns why the release named label cannot go into a site running
// wordpress and php, or "" when it can. An empty site version checks nothing.
func (r Requirements) Check(label, wordpress, php string) string {
	if r.PHP != "" && php != "" && cms.Compare(php, r.PHP) < 0 {
		return fmt.Sprintf("%s braucht PHP %s, die Website läuft mit %s", label, r.PHP, php)
	}
	if r.WordPress != "" && wordpress != "" && cms.Compare(wordpress, r.WordPress) < 0 {
		return fmt.Sprintf("%s braucht WordPress %s, installiert ist %s", label, r.WordPress, wordpress)
	}
	return ""
}

// Multisite reports whether wp-config.php switches a network on. WordPress
// also takes wp-config.php from the directory above, when that directory
// holds no WordPress of its own.
func Multisite(root string) bool {
	candidates := []string{filepath.Join(root, "wp-config.php")}
	parent := filepath.Dir(root)
	if _, err := os.Stat(filepath.Join(parent, "wp-settings.php")); os.IsNotExist(err) {
		candidates = append(candidates, filepath.Join(parent, "wp-config.php"))
	}
	for _, path := range candidates {
		if raw, err := readHead(path, 512*1024); err == nil {
			return multisiteRe.Match(raw)
		}
	}
	return false
}

const maintenanceFile = ".maintenance"

// maintenanceWindow is how long WordPress honours a .maintenance file.
const maintenanceWindow = 10 * time.Minute

// MaintenanceActive reports whether root carries a .maintenance file that
// WordPress still honours at now.
func MaintenanceActive(root string, now time.Time) bool {
	raw, err := readHead(filepath.Join(root, maintenanceFile), 64*1024)
	if err != nil {
		return false
	}
	m := upgradingRe.FindSubmatch(raw)
	if m == nil {
		return false
	}
	sec, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return false
	}
	return now.Sub(time.Unix(sec, 0)) < maintenanceWindow
}

// EnterMaintenance writes the file the updater of WordPress writes. A link in
// its place is refused: this file is written as root.
func EnterMaintenance(root string, now time.Time) error {
	path := filepath.Join(root, maintenanceFile)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s ist eine Verknüpfung und wird nicht beschrieben", path)
	}
	body := fmt.Sprintf("<?php $upgrading = %d; ?>", now.Unix())
	return os.WriteFile(path, []byte(body), 0o644)
}

// LeaveMaintenance removes the file. A file that is already gone is fine.
func LeaveMaintenance(root string) error {
	err := os.Remove(filepath.Join(root, maintenanceFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// readHead reads at most n bytes of a regular file.
func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s ist keine Datei", path)
	}
	return io.ReadAll(io.LimitReader(f, n))
}

func group(re *regexp.Regexp, raw []byte) string {
	m := re.FindSubmatch(raw)
	if m == nil || len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/upgrade/ ./internal/cms/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cms/wordpress.go internal/upgrade/wordpress.go internal/upgrade/wordpress_test.go
git commit -m "feat(upgrade): read versions, requirements, multisite and maintenance state"
```

---

### Task 7: Die Nachprüfung

**Files:**
- Create: `internal/upgrade/health.go`
- Test: `internal/upgrade/health_test.go`

**Interfaces:**
- Produces:
  - `type Probe struct { Status int; Empty bool; Err string }`
  - `type PageProber interface { Get(url string) Probe }`
  - `func NewProber(connect string, timeout time.Duration) *Prober` und `func (p *Prober) Get(url string) Probe`
  - `func Broken(before, after Probe) string`, `func Judgeable(before Probe) bool`
  - paketintern: `pageNames` (`Startseite`, `Anmeldeseite`), `pageURLs(base string) []string`, `probeSite(p PageProber, base string) []Probe`, `siteBroken(before, after []Probe) string`

- [ ] **Step 1: Write the failing tests**

`internal/upgrade/health_test.go`:

```go
package upgrade

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// connectTo is the host:port an httptest server listens on.
func connectTo(srv *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
}

func TestProberConnectsToTheGivenAddressUnderTheSiteName(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	got := NewProber(connectTo(srv), 5*time.Second).Get("http://beispiel.de/")
	if got.Status != 200 || got.Empty {
		t.Fatalf("probe = %+v", got)
	}
	if host != "beispiel.de" {
		t.Errorf("Host = %q, want beispiel.de", host)
	}
}

func TestProberSendsTheSiteNameOverTLSWithoutVerifying(t *testing.T) {
	var sni string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni = r.TLS.ServerName
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	got := NewProber(connectTo(srv), 5*time.Second).Get("https://beispiel.de/")
	if got.Status != 200 {
		t.Fatalf("probe = %+v", got)
	}
	if sni != "beispiel.de" {
		t.Errorf("SNI = %q, want beispiel.de", sni)
	}
}

func TestProberFollowsItsOwnSiteAndStopsAtAnother(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "beispiel.de":
			http.Redirect(w, r, "http://www.beispiel.de/", http.StatusMovedPermanently)
		case r.Host == "www.beispiel.de" && r.URL.Path == "/":
			_, _ = w.Write([]byte("ok"))
		default:
			http.Redirect(w, r, "http://anderswo.example/", http.StatusFound)
		}
	}))
	defer srv.Close()
	p := NewProber(connectTo(srv), 5*time.Second)

	if got := p.Get("http://beispiel.de/"); got.Status != 200 {
		t.Errorf("the redirect to the www name was not followed: %+v", got)
	}
	if got := p.Get("http://www.beispiel.de/wp-login.php"); got.Status != 302 {
		t.Errorf("a redirect to another site has to be the answer: %+v", got)
	}
}

func TestProberWithoutAnAnswerReportsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	got := NewProber(connectTo(srv), 100*time.Millisecond).Get("http://beispiel.de/")
	if got.Status != 0 || got.Err == "" {
		t.Errorf("probe = %+v, want no answer", got)
	}
}

func TestProberCallsAWhitespacePageEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("\n  \n"))
	}))
	defer srv.Close()
	if got := NewProber(connectTo(srv), 5*time.Second).Get("http://beispiel.de/"); !got.Empty {
		t.Errorf("probe = %+v, want empty", got)
	}
}

func TestBrokenJudgesOnlyWhatAnsweredBefore(t *testing.T) {
	ok := Probe{Status: 200}
	cases := []struct {
		name          string
		before, after Probe
		broken        bool
	}{
		{"500 after 200", ok, Probe{Status: 500}, true},
		{"no answer after 200", ok, Probe{Err: "Zeitüberschreitung"}, true},
		{"empty after content", ok, Probe{Status: 200, Empty: true}, true},
		{"redirect after 200", ok, Probe{Status: 302}, false},
		{"403 after 200", ok, Probe{Status: 403}, false},
		{"500 after 500", Probe{Status: 500}, Probe{Status: 500}, false},
		{"500 after no answer", Probe{Err: "x"}, Probe{Status: 500}, false},
		{"empty after empty", Probe{Status: 200, Empty: true}, Probe{Status: 200, Empty: true}, false},
	}
	for _, c := range cases {
		if got := Broken(c.before, c.after) != ""; got != c.broken {
			t.Errorf("%s: broken = %v, want %v", c.name, got, c.broken)
		}
	}
}

func TestSiteBrokenNamesThePage(t *testing.T) {
	before := []Probe{{Status: 200}, {Status: 200}}
	after := []Probe{{Status: 200}, {Status: 500}}
	if got := siteBroken(before, after); got != "Anmeldeseite: Antwort 500" {
		t.Errorf("siteBroken = %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/upgrade/ -run 'Prober|Broken' -v`
Expected: FAIL, `undefined: NewProber`

- [ ] **Step 3: Write `internal/upgrade/health.go`**

```go
package upgrade

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Probe is what one page answered.
type Probe struct {
	Status int    // 0 without an answer
	Empty  bool   // a 200 whose body held nothing but whitespace
	Err    string // why there was no answer
}

// PageProber fetches a page of the site. *Prober is the real one; the tests
// script the answers.
type PageProber interface {
	Get(url string) Probe
}

// Prober asks the web server on this machine for a page of the website.
type Prober struct {
	client *http.Client
}

// NewProber returns a prober that connects to connect - "host" or
// "host:port" - whatever name an address carries, and sends that name as Host
// and SNI. An empty connect means 127.0.0.1. The certificate stays unverified:
// the check judges the answer of the site.
func NewProber(connect string, timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if connect == "" {
		connect = "127.0.0.1"
	}
	host, port, err := net.SplitHostPort(connect)
	if err != nil {
		host, port = strings.Trim(connect, "[]"), ""
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, addrPort, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if port != "" {
				addrPort = port
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, addrPort))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &Prober{client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: sameSite}}
}

// sameSite follows a redirect to the same name or its www variant, up to five
// times. Anything else ends the check, with the redirect as the answer.
func sameSite(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return http.ErrUseLastResponse
	}
	first := strings.TrimPrefix(strings.ToLower(via[0].URL.Hostname()), "www.")
	next := strings.TrimPrefix(strings.ToLower(req.URL.Hostname()), "www.")
	if first != next {
		return http.ErrUseLastResponse
	}
	return nil
}

// Get fetches url and reads at most 2 MB of the answer.
func (p *Prober) Get(url string) Probe {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Probe{Err: err.Error()}
	}
	req.Header.Set("User-Agent", "malwatch-upgrade")
	resp, err := p.client.Do(req)
	if err != nil {
		return Probe{Err: shortError(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return Probe{
		Status: resp.StatusCode,
		Empty:  resp.StatusCode == http.StatusOK && len(bytes.TrimSpace(body)) == 0,
	}
}

// shortError keeps the part of a transport error a person can act on.
func shortError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "Zeitüberschreitung"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

// Broken compares one page before and after an exchange and returns why the
// page counts as broken, or "". A page that answered with 500 or more before,
// or gave no answer at all, says nothing afterwards.
func Broken(before, after Probe) string {
	if !Judgeable(before) {
		return ""
	}
	switch {
	case after.Status == 0:
		return "keine Antwort (" + after.Err + ")"
	case after.Status >= 500:
		return fmt.Sprintf("Antwort %d", after.Status)
	case after.Empty && !before.Empty:
		return "leere Seite"
	}
	return ""
}

// Judgeable reports whether the answer of a page before an exchange lets a
// check afterwards mean something.
func Judgeable(before Probe) bool {
	return before.Status > 0 && before.Status < 500
}

// pageNames are the two pages every check looks at, in this order.
var pageNames = []string{"Startseite", "Anmeldeseite"}

// pageURLs returns the addresses of both pages below the URL of an
// installation, which ends in a slash (LoadPlan sees to that).
func pageURLs(base string) []string {
	return []string{base, base + "wp-login.php"}
}

// probeSite fetches both pages.
func probeSite(p PageProber, base string) []Probe {
	urls := pageURLs(base)
	out := make([]Probe, len(urls))
	for i, u := range urls {
		out[i] = p.Get(u)
	}
	return out
}

// siteBroken returns why the site counts as broken after an exchange, naming
// the page, or "" when neither page does.
func siteBroken(before, after []Probe) string {
	for i := range before {
		if i >= len(after) || i >= len(pageNames) {
			break
		}
		if reason := Broken(before[i], after[i]); reason != "" {
			return pageNames[i] + ": " + reason
		}
	}
	return ""
}
```

- [ ] **Step 4: Run the package tests**

Run: `go test ./internal/upgrade/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/upgrade/health.go internal/upgrade/health_test.go
git commit -m "feat(upgrade): check a site on this machine under its own name"
```

---

### Task 8: WP-CLI als Benutzer der Website

**Files:**
- Create: `internal/upgrade/exec.go`
- Test: `internal/upgrade/exec_test.go`

**Interfaces:**
- Produces:
  - `type Command struct { User, Group, Binary string; Args, Env []string; Stdin io.Reader; Stdout io.Writer }`
  - `type Executor interface { Run(ctx context.Context, cmd Command) error }`, `type SystemExecutor struct{}`
  - `type WPCLI struct { Exec Executor; User, Group, PHP, Binary string }` mit `ExportDB(ctx, install string, out io.Writer) error`, `ImportDB(ctx, install string, in io.Reader) error`, `UpdateDB(ctx, install string) error`
  - `func ParseRunAs(spec string, lookup func(string) (*user.User, error)) (name, group string, err error)`
- Test-Helfer für Task 10: `recorder` (Executor mit Mitschrift), `subcommand(c Command) string`

- [ ] **Step 1: Write the failing tests**

`internal/upgrade/exec_test.go`:

```go
package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"sync"
	"testing"
)

// recorder is an Executor that writes down every command and answers from a
// script: what a subcommand prints, and the error a subcommand returns.
type recorder struct {
	mu       sync.Mutex
	commands []Command
	stdins   []string
	stdout   map[string]string // "db export" -> printed text
	fail     map[string]error  // "core update-db" -> returned error
}

func (r *recorder) Run(ctx context.Context, c Command) error {
	in := ""
	if c.Stdin != nil {
		raw, _ := io.ReadAll(c.Stdin)
		in = string(raw)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, c)
	r.stdins = append(r.stdins, in)
	sub := subcommand(c)
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, r.stdout[sub])
	}
	return r.fail[sub]
}

// subcommand is "db export" for the arguments of a WP-CLI command.
func subcommand(c Command) string {
	var words []string
	for _, a := range c.Args[1:] {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(words) > 2 {
		words = words[:2]
	}
	return strings.Join(words, " ")
}

func (r *recorder) subcommands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.commands {
		out = append(out, subcommand(c))
	}
	return out
}

func TestWPCLIRunsAsTheSiteUserWithItsPHP(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"db export": "-- dump"}}
	cli := WPCLI{Exec: rec, User: "web12", Group: "client3", PHP: "/usr/bin/php8.2", Binary: "/usr/local/bin/wp"}
	install := "/var/www/clients/client3/web12/web"
	ctx := context.Background()

	var dump bytes.Buffer
	if err := cli.ExportDB(ctx, install, &dump); err != nil {
		t.Fatal(err)
	}
	if err := cli.UpdateDB(ctx, install); err != nil {
		t.Fatal(err)
	}
	if err := cli.ImportDB(ctx, install, strings.NewReader("-- dump")); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(rec.subcommands(), ","); got != "db export,core update-db,db import" {
		t.Errorf("commands = %s", got)
	}
	c := rec.commands[0]
	if c.User != "web12" || c.Group != "client3" || c.Binary != "/usr/bin/php8.2" || c.Args[0] != "/usr/local/bin/wp" {
		t.Errorf("command = %+v", c)
	}
	joined := strings.Join(c.Args, " ")
	for _, want := range []string{"--path=" + install, "--skip-plugins", "--skip-themes"} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments lack %s: %s", want, joined)
		}
	}
	if dump.String() != "-- dump" || rec.stdins[2] != "-- dump" {
		t.Errorf("export %q, import read %q", dump.String(), rec.stdins[2])
	}
}

func TestParseRunAsRefusesRoot(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		switch name {
		case "web12":
			return &user.User{Username: "web12", Uid: "5012"}, nil
		case "toor":
			return &user.User{Username: "toor", Uid: "0"}, nil
		}
		return nil, errors.New("unknown user")
	}
	if name, group, err := ParseRunAs("web12:client3", lookup); err != nil || name != "web12" || group != "client3" {
		t.Errorf("web12:client3 = %q %q %v", name, group, err)
	}
	for _, spec := range []string{"", "root", "root:root", "toor:toor", "web12;rm", "niemand:client3"} {
		if _, _, err := ParseRunAs(spec, lookup); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

// TestHelperEcho copies stdin to stdout and writes a line to stderr, standing
// in for a program the SystemExecutor starts. Outside that test it does nothing.
func TestHelperEcho(t *testing.T) {
	if os.Getenv("MALWATCH_HELPER_ECHO") != "1" {
		return
	}
	raw, _ := io.ReadAll(os.Stdin)
	fmt.Print(string(raw))
	fmt.Fprintln(os.Stderr, "letzte Zeile")
	if os.Getenv("MALWATCH_HELPER_FAIL") == "1" {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestSystemExecutorConnectsStdinStdoutAndNamesTheError(t *testing.T) {
	var out bytes.Buffer
	err := SystemExecutor{}.Run(context.Background(), Command{
		Binary: os.Args[0], Args: []string{"-test.run=TestHelperEcho", "--"},
		Env: []string{"MALWATCH_HELPER_ECHO=1"}, Stdin: strings.NewReader("hallo"), Stdout: &out,
	})
	if err != nil || out.String() != "hallo" {
		t.Fatalf("out = %q, err = %v", out.String(), err)
	}

	err = SystemExecutor{}.Run(context.Background(), Command{
		Binary: os.Args[0], Args: []string{"-test.run=TestHelperEcho", "--"},
		Env: []string{"MALWATCH_HELPER_ECHO=1", "MALWATCH_HELPER_FAIL=1"},
	})
	if err == nil || !strings.Contains(err.Error(), "letzte Zeile") {
		t.Errorf("err = %v, want the last line of stderr", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/upgrade/ -run 'WPCLI|ParseRunAs|SystemExecutor' -v`
Expected: FAIL, `undefined: Command`

- [ ] **Step 3: Write `internal/upgrade/exec.go`**

```go
package upgrade

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
)

// Command is one program the upgrade runs for a website.
type Command struct {
	User   string // run as this user; empty runs as the caller
	Group  string // with this group; empty takes the user's own
	Binary string
	Args   []string
	Env    []string  // added to a small environment of its own
	Stdin  io.Reader // nil reads nothing
	Stdout io.Writer // nil discards
}

// Executor runs a command. SystemExecutor is the real one; the tests record.
type Executor interface {
	Run(ctx context.Context, cmd Command) error
}

// SystemExecutor runs commands on this machine, through runuser when the
// command names another user than the one running malwatch.
type SystemExecutor struct{}

// Run starts the command and waits for it. An error names the last line the
// program wrote to stderr.
func (SystemExecutor) Run(ctx context.Context, c Command) error {
	name, args := c.Binary, c.Args
	if c.User != "" && !isCurrentUser(c.User) {
		name = "runuser"
		args = []string{"-u", c.User}
		if c.Group != "" {
			args = append(args, "-g", c.Group)
		}
		args = append(args, "--", c.Binary)
		args = append(args, c.Args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(baseEnv(), c.Env...)
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	stderr := &tailBuffer{max: 8192}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if line := lastLine(stderr.buf.String()); line != "" {
			return fmt.Errorf("%s: %w: %s", c.Binary, err, line)
		}
		return fmt.Errorf("%s: %w", c.Binary, err)
	}
	return nil
}

// baseEnv is the environment a website command starts from. The environment
// of the root process stays behind: WP-CLI loads the mu-plugins of the site,
// and whatever sits in root's environment would be theirs to read.
func baseEnv() []string {
	if runtime.GOOS == "windows" {
		return os.Environ() // tests only; the upgrade runs on Linux
	}
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
}

func isCurrentUser(name string) bool {
	u, err := user.Current()
	return err == nil && u.Username == name
}

// tailBuffer keeps the last max bytes a program writes.
type tailBuffer struct {
	buf bytes.Buffer
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf.Write(p)
	if over := t.buf.Len() - t.max; over > 0 {
		t.buf.Next(over)
	}
	return len(p), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// WPCLI runs WP-CLI for an installation as the user of the website and with
// its PHP. Plugins and themes stay unloaded; WP-CLI loads the mu-plugins of
// the installation all the same, it has no switch for them.
type WPCLI struct {
	Exec   Executor
	User   string
	Group  string
	PHP    string
	Binary string
}

func (w WPCLI) command(install string, stdin io.Reader, stdout io.Writer, args ...string) Command {
	full := append([]string{w.Binary, "--path=" + install, "--skip-plugins", "--skip-themes", "--skip-packages"}, args...)
	return Command{
		User: w.User, Group: w.Group, Binary: w.PHP, Args: full,
		Env: []string{
			"HOME=/tmp",
			"WP_CLI_CACHE_DIR=/tmp/malwatch-wp-cli-" + w.User,
			"WP_CLI_CONFIG_PATH=/dev/null",
			"WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		},
		Stdin:  stdin,
		Stdout: stdout,
	}
}

// ExportDB writes the database of the installation to out.
func (w WPCLI) ExportDB(ctx context.Context, install string, out io.Writer) error {
	return w.Exec.Run(ctx, w.command(install, nil, out, "db", "export", "-"))
}

// ImportDB loads in into the database of the installation.
func (w WPCLI) ImportDB(ctx context.Context, install string, in io.Reader) error {
	return w.Exec.Run(ctx, w.command(install, in, nil, "db", "import", "-"))
}

// UpdateDB raises the database to the core that is now in the installation.
func (w WPCLI) UpdateDB(ctx context.Context, install string) error {
	return w.Exec.Run(ctx, w.command(install, nil, nil, "core", "update-db"))
}

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ParseRunAs splits "user:group" and refuses root and every account with UID
// 0. lookup is user.Lookup outside the tests.
func ParseRunAs(spec string, lookup func(string) (*user.User, error)) (name, group string, err error) {
	name, group, _ = strings.Cut(strings.TrimSpace(spec), ":")
	if name == "" {
		return "", "", fmt.Errorf("--run-as braucht den Benutzer der Website, etwa web12:client3")
	}
	if !accountRe.MatchString(name) || (group != "" && !accountRe.MatchString(group)) {
		return "", "", fmt.Errorf("--run-as=%q nennt keinen gültigen Benutzer", spec)
	}
	if name == "root" {
		return "", "", fmt.Errorf("--run-as=root wird abgewiesen: WP-CLI führt Code der Website aus")
	}
	u, err := lookup(name)
	if err != nil {
		return "", "", fmt.Errorf("Benutzer %s ist unbekannt: %w", name, err)
	}
	if u.Uid == "0" {
		return "", "", fmt.Errorf("--run-as=%s hat die UID 0 und wird abgewiesen", name)
	}
	return name, group, nil
}
```

- [ ] **Step 4: Run the package tests**

Run: `go test ./internal/upgrade/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/upgrade/exec.go internal/upgrade/exec_test.go
git commit -m "feat(upgrade): run WP-CLI as the site user, never as root"
```

---

### Task 9: Das geladene Archiv gegen die Prüfsummen

**Files:**
- Modify: `internal/knownfiles/fetch.go` (`ErrNotPublished`)
- Test: `internal/knownfiles/notpublished_test.go` (neu)
- Create: `internal/upgrade/verify.go`
- Test: `internal/upgrade/verify_test.go`

**Interfaces:**
- Consumes: `label(el PlanElement) string` (Task 5), `writeFile` (Task 5)
- Produces:
  - `var knownfiles.ErrNotPublished error`: eine Antwort 404 und eine leere Plugin-Liste wickeln sie ein
  - `type Checksums interface { WordPressCore(version, locale string) (map[string]string, error); WordPressPlugin(slug, version string) (map[string]string, error) }`
  - `func VerifyTree(dir string, sums map[string]string) error`
  - paketintern: `func verifyStaged(cs Checksums, el PlanElement, locale, dir string) (unverified bool, err error)`
- Test-Helfer für Task 10: `md5Of(s string) string`, `fakeChecksums`

- [ ] **Step 1: Write the failing test for knownfiles**

`internal/knownfiles/notpublished_test.go`:

```go
package knownfiles

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestA404SaysTheListIsNotPublished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	f := NewFetcher("", 5*time.Second)

	if _, err := f.load("plugin-x", srv.URL+"/x.json"); !errors.Is(err, ErrNotPublished) {
		t.Fatalf("err = %v, want ErrNotPublished", err)
	}
	if _, err := f.load("plugin-y", "http://127.0.0.1:1/y.json"); err == nil || errors.Is(err, ErrNotPublished) {
		t.Errorf("an unreachable server reads as not published: %v", err)
	}
}
```

Run: `go test ./internal/knownfiles/ -run TestA404 -v`
Expected: FAIL, `undefined: ErrNotPublished`

- [ ] **Step 2: Add the sentinel to `internal/knownfiles/fetch.go`**

Im Importblock `"errors"` ergänzen. Nach dem Importblock:

```go
// ErrNotPublished says wordpress.org keeps no checksum list for a release. A
// paid plugin is the usual case; what that means is the caller's decision.
var ErrNotPublished = errors.New("keine Prüfsummen veröffentlicht")
```

In `load` vor `if resp.StatusCode != http.StatusOK {`:

```go
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("HTTP 404: %w", ErrNotPublished)
	}
```

In `WordPressPlugin` die leere Liste so melden:

```go
	if len(out) == 0 {
		return nil, fmt.Errorf("leere Prüfsummenliste: %w", ErrNotPublished)
	}
```

Run: `go test ./internal/knownfiles/`
Expected: PASS

- [ ] **Step 3: Write the failing tests for the verification**

`internal/upgrade/verify_test.go`:

```go
package upgrade

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/knownfiles"
)

func md5Of(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fakeChecksums answers from maps keyed "6.4.5" and "akismet@5.3.3". A plugin
// without a list is ErrNotPublished, a core without a list a server error.
type fakeChecksums struct {
	core    map[string]map[string]string
	plugins map[string]map[string]string
}

func (f fakeChecksums) WordPressCore(version, locale string) (map[string]string, error) {
	if sums, ok := f.core[version]; ok {
		return sums, nil
	}
	return nil, fmt.Errorf("HTTP 500")
}

func (f fakeChecksums) WordPressPlugin(slug, version string) (map[string]string, error) {
	if sums, ok := f.plugins[slug+"@"+version]; ok {
		return sums, nil
	}
	return nil, fmt.Errorf("HTTP 404: %w", knownfiles.ErrNotPublished)
}

func TestVerifyTreeChecksEveryListedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "akismet.php"), "<?php // 5.3.3")
	writeFile(t, filepath.Join(dir, "readme.txt"), "=== Akismet ===")

	good := map[string]string{
		"akismet.php": md5Of("<?php // 5.3.3"),
		"readme.txt":  md5Of("=== Akismet ==="),
	}
	if err := VerifyTree(dir, good); err != nil {
		t.Fatalf("a matching tree failed: %v", err)
	}
	cases := map[string]map[string]string{
		"changed file": {"akismet.php": md5Of("<?php // anders")},
		"missing file": {"class.akismet.php": md5Of("x")},
		"path with ..": {"../etc/passwd": md5Of("x")},
	}
	for name, sums := range cases {
		if err := VerifyTree(dir, sums); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestVerifyStagedTellsAMissingListFromABrokenOne(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "akismet.php"), "<?php // 5.3.3")
	cs := fakeChecksums{
		core:    map[string]map[string]string{},
		plugins: map[string]map[string]string{"akismet@5.3.3": {"akismet.php": md5Of("<?php // 5.3.3")}},
	}

	if unverified, err := verifyStaged(cs, PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.3.3"}, "", dir); err != nil || unverified {
		t.Errorf("listed plugin: unverified=%v err=%v", unverified, err)
	}
	if unverified, err := verifyStaged(cs, PlanElement{Kind: "plugin", Slug: "bezahlt", Version: "1.0"}, "", dir); err != nil || !unverified {
		t.Errorf("plugin without a list: unverified=%v err=%v", unverified, err)
	}
	if unverified, err := verifyStaged(cs, PlanElement{Kind: "theme", Slug: "vier", Version: "1.0"}, "", dir); err != nil || !unverified {
		t.Errorf("theme: unverified=%v err=%v", unverified, err)
	}
	if _, err := verifyStaged(cs, PlanElement{Kind: "core", Version: "6.4.5"}, "", dir); err == nil || !strings.Contains(err.Error(), "6.4.5") {
		t.Errorf("a core without a list has to fail: %v", err)
	}
}
```

Run: `go test ./internal/upgrade/ -run Verify -v`
Expected: FAIL, `undefined: VerifyTree`

- [ ] **Step 4: Write `internal/upgrade/verify.go`**

```go
package upgrade

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brightcolor/malwatch/internal/knownfiles"
)

// Checksums is where the verification takes its lists from: a
// *knownfiles.Fetcher, or a fake in the tests.
type Checksums interface {
	WordPressCore(version, locale string) (map[string]string, error)
	WordPressPlugin(slug, version string) (map[string]string, error)
}

// VerifyTree holds a staged tree against a checksum list: every file the list
// names has to be there with that MD5. The list decides what it covers; the
// core list leaves out wp-content, for instance.
func VerifyTree(dir string, sums map[string]string) error {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		clean := path.Clean("/" + name)
		if strings.Contains(name, "..") || clean == "/" {
			return fmt.Errorf("die Prüfsummenliste nennt den Pfad %q", name)
		}
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(clean, "/"))))
		if err != nil {
			return fmt.Errorf("%s fehlt im geladenen Archiv", name)
		}
		sum := md5.Sum(raw)
		if hex.EncodeToString(sum[:]) != strings.ToLower(sums[name]) {
			return fmt.Errorf("%s weicht von der Prüfsumme ab", name)
		}
	}
	return nil
}

// verifyStaged verifies the staged tree of one element. unverified is true
// when no list covers it: a theme, or a plugin wordpress.org keeps no list
// for. Every other failure to get a list is an error: a release that cannot
// be verified for a reason nobody knows stays out.
func verifyStaged(cs Checksums, el PlanElement, locale, dir string) (unverified bool, err error) {
	switch el.Kind {
	case "core":
		sums, err := cs.WordPressCore(el.Version, locale)
		if err != nil {
			return false, fmt.Errorf("Prüfsummen für WordPress %s nicht ladbar: %w", el.Version, err)
		}
		return false, VerifyTree(dir, sums)
	case "plugin":
		sums, err := cs.WordPressPlugin(el.Slug, el.Version)
		if errors.Is(err, knownfiles.ErrNotPublished) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("Prüfsummen für %s %s nicht ladbar: %w", label(el), el.Version, err)
		}
		return false, VerifyTree(dir, sums)
	}
	return true, nil
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/upgrade/ ./internal/knownfiles/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/knownfiles/fetch.go internal/knownfiles/notpublished_test.go internal/upgrade/verify.go internal/upgrade/verify_test.go
git commit -m "feat(upgrade): verify a fetched release against the checksums of wordpress.org"
```

---

### Task 10: Der Lauf

**Files:**
- Create: `internal/upgrade/upgrade.go`
- Test: `internal/upgrade/upgrade_test.go`

**Interfaces:**
- Consumes: `Plan`, `PlanInstall`, `PlanElement`, `label` (Task 5); `ReadCore`, `PluginRequirements`, `ThemeRequirements`, `Requirements.Check`, `Multisite`, `MaintenanceActive`, `EnterMaintenance`, `LeaveMaintenance` (Task 6); `PageProber`, `Probe`, `Judgeable`, `pageURLs`, `probeSite`, `siteBroken` (Task 7); `WPCLI` (Task 8); `Checksums`, `verifyStaged` (Task 9); `repair.Replacement`, `repair.ReplaceDir`, `repair.ReplaceCore` (Task 1); `progress.Step`, `SetSteps`, `StepState` (Task 2); `report.Upgrade` und Ausgänge (Task 3); `cms.WordPressExtras`, `cms.Compare`; `quarantine.StoreCopy`, `quarantine.Restore`; `safepath.InsideRoot`; `vendorfiles.Fetcher`, `vendorfiles.ErrNotPublished`
- Produces:
  - `type Options struct { WebRoot string; Plan Plan; QuarantineDir, StagingDir, Domain string; DryRun bool; PHPVersion string; WPCLI WPCLI; HasWPCLI bool; Fetcher *vendorfiles.Fetcher; Checksums Checksums; Prober PageProber; Progress *progress.Writer; Now func() time.Time; DBTimeout time.Duration }`
  - `func Run(opts Options) (*report.Upgrade, error)`
  - Zustände der Schritte in der Fortschrittsdatei, auf die Teil B die Anzeige baut: `waiting`, `fetched`, `verified`, `refused`, `swapped`, `database`, `updated`, `would_update`, `rolled_back`, `failed`, `rollback_failed`, `skipped`
  - Quarantäne-Einträge eines Laufs tragen `origin` `upgrade` (Teil B nimmt den Wert in die Aufzählung auf)

- [ ] **Step 1: Write the failing tests**

`internal/upgrade/upgrade_test.go`:

```go
package upgrade

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

const siteURL = "https://beispiel.de/"

var (
	planAkismet = PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.3.3"}
	planCore    = PlanElement{Kind: "core", Version: "6.4.5"}

	// Release contents the fake vendor hands out.
	akismet533 = map[string]string{
		"akismet/akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\nRequires PHP: 7.2\n*/",
	}
	core645 = map[string]string{
		"wordpress/wp-includes/version.php": "<?php\n$wp_version = '6.4.5';\n$wp_db_version = 56657;\n$required_php_version = '7.0.0';\n",
		"wordpress/wp-login.php":            "<?php // 6.4.5",
		"wordpress/wp-admin/index.php":      "<?php // admin 6.4.5",
	}
)

// site lays out WordPress 6.4.2 with akismet 5.3.0 at the web root.
func site(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"),
		"<?php\n$wp_version = '6.4.2';\n$wp_db_version = 56657;\n$required_php_version = '7.0.0';\n")
	writeFile(t, filepath.Join(root, "wp-login.php"), "<?php // 6.4.2")
	writeFile(t, filepath.Join(root, "wp-config.php"), "<?php // secrets")
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php"),
		"<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.0\n*/")
	return root
}

// treeOf renders a tree, so a test can assert that nothing changed at all.
func treeOf(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() {
			fmt.Fprintf(&b, "d %s\n", filepath.ToSlash(rel))
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "f %s %x\n", filepath.ToSlash(rel), sha256.Sum256(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// zipOf builds an archive in memory.
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

// vendor serves archives by URL path and 404 for everything else.
func vendor(t *testing.T, archives map[string]map[string]string) *vendorfiles.Fetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files, ok := archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zipOf(t, files))
	}))
	t.Cleanup(srv.Close)
	return vendorfiles.NewFetcher(vendorfiles.BaseURLs{
		Core: srv.URL + "/", LocalisedCore: srv.URL + "/%s/",
		Plugin: srv.URL + "/p/", Theme: srv.URL + "/t/",
	}, 10*time.Second)
}

// sumsOf is the checksum list wordpress.org would publish for release
// contents, relative to the unpacked directory.
func sumsOf(files map[string]string) map[string]string {
	out := map[string]string{}
	for name, body := range files {
		_, rel, _ := strings.Cut(name, "/")
		out[rel] = md5Of(body)
	}
	return out
}

// copyOf returns release contents with one file replaced.
func copyOf(files map[string]string, name, body string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	out[name] = body
	return out
}

// scripted answers each URL from a queue whose last answer repeats. A URL
// without a queue answers 200.
type scripted struct {
	mu      sync.Mutex
	answers map[string][]Probe
}

func (s *scripted) Get(url string) Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.answers[url]
	if len(queue) == 0 {
		return Probe{Status: 200}
	}
	answer := queue[0]
	if len(queue) > 1 {
		s.answers[url] = queue[1:]
	}
	return answer
}

func healthy() *scripted { return &scripted{answers: map[string][]Probe{}} }

func onePlan(root string, elements ...PlanElement) Plan {
	return Plan{Schema: 1, Installs: []PlanInstall{{Path: root, URL: siteURL, Elements: elements}}}
}

// options assembles a run against the fake vendor.
func options(t *testing.T, root string, plan Plan, prober PageProber, rec *recorder) Options {
	t.Helper()
	pw, err := progress.New("", "upgrade")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		WebRoot: root, Plan: plan,
		QuarantineDir: t.TempDir(), StagingDir: t.TempDir(), Domain: "beispiel.de",
		PHPVersion: "8.2.10",
		WPCLI: WPCLI{Exec: rec, User: "web12", Group: "client3",
			PHP: "/usr/bin/php8.2", Binary: "/usr/local/bin/wp"},
		HasWPCLI: true,
		Fetcher: vendor(t, map[string]map[string]string{
			"/p/akismet.5.3.3.zip": akismet533,
			"/wordpress-6.4.5.zip": core645,
		}),
		Checksums: fakeChecksums{
			core:    map[string]map[string]string{"6.4.5": sumsOf(core645)},
			plugins: map[string]map[string]string{"akismet@5.3.3": sumsOf(akismet533)},
		},
		Prober:   prober,
		Progress: pw,
	}
}

func TestAPluginIsUpdatedAndChecked(t *testing.T) {
	root := site(t)
	rec := &recorder{}
	rep, err := Run(options(t, root, onePlan(root, planAkismet), healthy(), rec))
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeUpdated || el.From != "5.3.0" || el.To != "5.3.3" || len(el.QuarantineIDs) != 1 {
		t.Fatalf("element = %+v", el)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php"))
	if !strings.Contains(string(raw), "5.3.3") {
		t.Errorf("the new release is not in place: %s", raw)
	}
	if len(rec.commands) != 0 {
		t.Errorf("a plugin update ran WP-CLI: %v", rec.subcommands())
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error(".maintenance is left behind")
	}
	if rep.ExitCode() != 0 {
		t.Errorf("exit code %d", rep.ExitCode())
	}
}

func TestABrokenSiteBringsTheOldPluginBack(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	prober := &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 200}}}}

	rep, err := Run(options(t, root, onePlan(root, planAkismet), prober, &recorder{}))
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRolledBack || !strings.Contains(el.Message, "Startseite: Antwort 500") {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before {
		t.Error("the site is not byte for byte what it was")
	}
	if c := el.Checks[0]; c.Before != 200 || c.After != 500 || c.AfterRollback != 200 {
		t.Errorf("checks = %+v", el.Checks)
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2", rep.ExitCode())
	}
}

func TestARequirementRefusesBeforeAnythingChanges(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	opts.PHPVersion = "7.1.33" // akismet 5.3.3 asks for 7.2

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRefused || el.Message != "5.3.3 braucht PHP 7.2, die Website läuft mit 7.1.33" {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before {
		t.Error("a refused element changed the site")
	}
	if entries, _, _ := quarantine.List(opts.QuarantineDir); len(entries) != 0 {
		t.Errorf("a refused element filed %d entries", len(entries))
	}
}

func TestAManipulatedArchiveStopsTheRun(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	opts.Checksums = fakeChecksums{plugins: map[string]map[string]string{
		"akismet@5.3.3": {"akismet.php": md5Of("<?php // the real 5.3.3")},
	}}

	rep, err := Run(opts)
	if err == nil || len(rep.Errors) == 0 {
		t.Fatal("a checksum mismatch did not stop the run")
	}
	if rep.Elements[0].Outcome != report.UpgradeSkipped || rep.ExitCode() != 3 {
		t.Errorf("element = %+v, exit code %d", rep.Elements[0], rep.ExitCode())
	}
	if got := treeOf(t, root); got != before {
		t.Error("the site changed although the run stopped before phase four")
	}
}

func TestTheCoreRaisesTheDatabaseOnlyWhenItsVersionChanges(t *testing.T) {
	for _, tc := range []struct{ name, dbVersion, want string }{
		{"same database", "56657", ""},
		{"new database", "57155", "db export,core update-db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := site(t)
			release := copyOf(core645, "wordpress/wp-includes/version.php",
				"<?php\n$wp_version = '6.4.5';\n$wp_db_version = "+tc.dbVersion+";\n$required_php_version = '7.0.0';\n")
			rec := &recorder{stdout: map[string]string{"db export": "-- dump 6.4.2"}}
			opts := options(t, root, onePlan(root, planCore), healthy(), rec)
			opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
			opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

			rep, err := Run(opts)
			if err != nil {
				t.Fatal(err)
			}
			el := rep.Elements[0]
			if el.Outcome != report.UpgradeUpdated {
				t.Fatalf("element = %+v", el)
			}
			if got := strings.Join(rec.subcommands(), ","); got != tc.want {
				t.Errorf("WP-CLI = %q, want %q", got, tc.want)
			}
			if (tc.want != "") != (el.DBExportID != "") {
				t.Errorf("db export id = %q", el.DBExportID)
			}
			if raw, _ := os.ReadFile(filepath.Join(root, "wp-includes", "version.php")); !strings.Contains(string(raw), "6.4.5") {
				t.Error("the new core is not in place")
			}
			if stray, _ := filepath.Glob(filepath.Join(opts.StagingDir, "datenbank-*.sql")); len(stray) != 0 {
				t.Errorf("the export stayed in the staging directory: %v", stray)
			}
		})
	}
}

func TestARollbackAfterTheDatabaseUpdateImportsTheExport(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	release := copyOf(core645, "wordpress/wp-includes/version.php",
		"<?php\n$wp_version = '6.4.5';\n$wp_db_version = 57155;\n$required_php_version = '7.0.0';\n")
	rec := &recorder{stdout: map[string]string{"db export": "-- dump 6.4.2"}}
	prober := &scripted{answers: map[string][]Probe{
		siteURL + "wp-login.php": {{Status: 200}, {Status: 500}, {Status: 200}},
	}}
	opts := options(t, root, onePlan(root, planCore), prober, rec)
	opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
	opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRolledBack || !strings.Contains(el.Message, "Anmeldeseite") || el.DBExportID == "" {
		t.Fatalf("element = %+v", el)
	}
	if got := strings.Join(rec.subcommands(), ","); got != "db export,core update-db,db import" {
		t.Errorf("WP-CLI = %s", got)
	}
	if rec.stdins[2] != "-- dump 6.4.2" {
		t.Errorf("the import read %q", rec.stdins[2])
	}
	if got := treeOf(t, root); got != before {
		t.Error("the core is not byte for byte what it was; wp-admin, added by the release, has to go too")
	}
}

func TestMaintenanceIsGoneAfterAFailedExchange(t *testing.T) {
	root := site(t)
	writeFile(t, filepath.Join(root, "wp-admin", "index.php"), "<?php // admin 6.4.2")
	before := treeOf(t, root)
	// A release without wp-admin: ReplaceCore refuses it before it touches anything.
	release := map[string]string{
		"wordpress/wp-includes/version.php": core645["wordpress/wp-includes/version.php"],
		"wordpress/wp-login.php":            core645["wordpress/wp-login.php"],
	}
	opts := options(t, root, onePlan(root, planCore), healthy(), &recorder{})
	opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
	opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeFailed || !strings.Contains(el.Message, "Tausch gescheitert") {
		t.Fatalf("element = %+v", el)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error(".maintenance is left behind")
	}
	if got := treeOf(t, root); got != before {
		t.Error("a failed exchange changed the site")
	}
}

func TestAFreshMaintenanceFileRefusesTheInstallAndStays(t *testing.T) {
	root := site(t)
	if err := EnterMaintenance(root, time.Now()); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(options(t, root, onePlan(root, planAkismet), healthy(), &recorder{}))
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeRefused || !strings.Contains(el.Message, ".maintenance") {
		t.Fatalf("element = %+v", el)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); err != nil {
		t.Error("the .maintenance of WordPress itself was removed")
	}
}

func TestASiteThatStaysBrokenStopsTheRun(t *testing.T) {
	root := site(t)
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "kontakt", "kontakt.php"),
		"<?php\n/*\nPlugin Name: Kontakt\nVersion: 1.0\n*/")
	kontakt := map[string]string{"kontakt/kontakt.php": "<?php\n/*\nPlugin Name: Kontakt\nVersion: 2.0\n*/"}
	prober := &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 500}}}}
	plan := onePlan(root, planAkismet, PlanElement{Kind: "plugin", Slug: "kontakt", Version: "2.0"})
	opts := options(t, root, plan, prober, &recorder{})
	opts.Fetcher = vendor(t, map[string]map[string]string{
		"/p/akismet.5.3.3.zip": akismet533,
		"/p/kontakt.2.0.zip":   kontakt,
	})

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Elements[0].Outcome != report.UpgradeRollbackFailed || rep.Elements[1].Outcome != report.UpgradeSkipped {
		t.Fatalf("elements = %+v", rep.Elements)
	}
	if rep.ExitCode() != 3 {
		t.Errorf("exit code %d, want 3", rep.ExitCode())
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "kontakt", "kontakt.php")); !strings.Contains(string(raw), "1.0") {
		t.Error("the skipped plugin was touched")
	}
}

func TestADryRunChangesNothingAndReportsWhatItWould(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	rec := &recorder{}
	prober := &scripted{answers: map[string][]Probe{siteURL + "wp-login.php": {{Status: 403}}}}
	opts := options(t, root, onePlan(root, planAkismet), prober, rec)
	opts.DryRun = true

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeWould || el.Checks[1].Before != 403 {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before || len(rec.commands) != 0 {
		t.Error("a dry run changed something")
	}
}

func TestWhatCannotGoAheadIsRefusedWithItsReason(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(root string)
		element PlanElement
		want    string
	}{
		{"lower target", func(string) {}, PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.2.0"}, "nicht höher"},
		{"unpublished release", func(string) {}, PlanElement{Kind: "plugin", Slug: "akismet", Version: "9.9.9"}, "nicht veröffentlicht"},
		{"missing plugin", func(string) {}, PlanElement{Kind: "plugin", Slug: "fehlt", Version: "1.0"}, "nicht vorhanden"},
		{"multisite", func(root string) {
			writeFile(t, filepath.Join(root, "wp-config.php"), "<?php\ndefine('MULTISITE', true);\n")
		}, planAkismet, "Multisite"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := site(t)
			c.prepare(root)
			rep, err := Run(options(t, root, onePlan(root, c.element), healthy(), &recorder{}))
			if err != nil {
				t.Fatal(err)
			}
			if el := rep.Elements[0]; el.Outcome != report.UpgradeRefused || !strings.Contains(el.Message, c.want) {
				t.Errorf("element = %+v, want a refusal naming %q", el, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/upgrade/ -run 'TestAPlugin|TestABroken|TestARequirement|TestAManipulated|TestTheCore|TestARollback|TestMaintenanceIsGone|TestAFresh|TestASite|TestADryRun|TestWhatCannot' -v`
Expected: FAIL, `undefined: Run` und `undefined: Options`

- [ ] **Step 3: Write `internal/upgrade/upgrade.go`**

```go
package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/safepath"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// phaseTotal is the number of phases a run goes through.
const phaseTotal = 4

// The states a step goes through in the progress file.
const (
	stateWaiting        = "waiting"
	stateFetched        = "fetched"
	stateVerified       = "verified"
	stateRefused        = "refused"
	stateSwapped        = "swapped"
	stateDatabase       = "database"
	stateUpdated        = "updated"
	stateWould          = "would_update"
	stateRolledBack     = "rolled_back"
	stateFailed         = "failed"
	stateRollbackFailed = "rollback_failed"
	stateSkipped        = "skipped"
)

// Options is one upgrade run. Fetcher and Checksums are required; the
// staging directory has to exist and lie outside the web root.
type Options struct {
	WebRoot       string // --path; the plan was checked against it
	Plan          Plan
	QuarantineDir string
	StagingDir    string
	Domain        string
	DryRun        bool

	PHPVersion string // what the PHP of the website says it is
	WPCLI      WPCLI  // runs the database steps
	HasWPCLI   bool   // the WP-CLI binary exists

	Fetcher   *vendorfiles.Fetcher
	Checksums Checksums
	Prober    PageProber
	Progress  *progress.Writer

	Now       func() time.Time // nil means time.Now
	DBTimeout time.Duration    // bound of each WP-CLI call; zero means an hour
}

// item is one element on its way through the run.
type item struct {
	index    int
	install  PlanInstall
	el       PlanElement
	path     string // element directory; the installation for the core
	from     string
	locale   string
	staged   string // unpacked release
	dbChange bool   // core: the release raises the database
	req      Requirements
	rep      report.UpgradeElement
}

// open reports whether the element still waits for its outcome.
func (it *item) open() bool { return it.rep.Outcome == "" }

type runner struct {
	opts  Options
	pw    *progress.Writer
	rep   *report.Upgrade
	items []*item
	cores map[string]CoreFacts // installed core per installation
}

// Run walks the four phases and returns the report. The error is set when
// the run itself failed; the report names it as well.
func Run(opts Options) (*report.Upgrade, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DBTimeout <= 0 {
		opts.DBTimeout = time.Hour
	}
	pw := opts.Progress
	if pw == nil {
		pw, _ = progress.New("", "upgrade")
	}
	r := &runner{opts: opts, pw: pw, rep: report.NewUpgrade(opts.WebRoot, opts.DryRun),
		cores: map[string]CoreFacts{}}
	r.rep.PHPVersion = opts.PHPVersion
	defer func() {
		r.collect()
		r.rep.FinishedAt = time.Now().UTC()
		r.rep.Log = r.pw.Entries()
	}()

	if opts.PHPVersion == "" {
		return r.fail(fmt.Errorf("die PHP-Version der Website ist unbekannt"))
	}

	r.pw.Phase(1, phaseTotal, "detect")
	r.detect()

	r.pw.Phase(2, phaseTotal, "fetch")
	if err := r.fetch(); err != nil {
		return r.fail(err)
	}

	r.pw.Phase(3, phaseTotal, "verify")
	if err := r.verify(); err != nil {
		return r.fail(err)
	}
	baselines := r.baselines()

	if opts.DryRun {
		r.pw.Log("info", "Probelauf - es wird nichts geändert")
		r.finishDryRun(baselines)
		return r.rep, nil
	}

	r.pw.Phase(4, phaseTotal, "upgrade")
	r.upgradeAll(baselines)
	return r.rep, nil
}

// detect reads what is installed and turns down what cannot go ahead, before
// anything is fetched.
func (r *runner) detect() {
	var steps []progress.Step
	for _, inst := range r.opts.Plan.Installs {
		facts, coreErr := ReadCore(inst.Path)
		r.cores[inst.Path] = facts
		extras := map[string]cms.Install{}
		for _, x := range cms.WordPressExtras(inst.Path) {
			extras[x.Kind+":"+x.Slug] = x
		}
		multisite := Multisite(inst.Path)
		busy := MaintenanceActive(inst.Path, r.opts.Now())

		for _, el := range inst.Elements {
			it := &item{index: len(r.items), install: inst, el: el, locale: facts.Locale}
			if el.Kind == "core" {
				it.path, it.from = inst.Path, facts.Version
			} else if x, ok := extras[el.Kind+":"+el.Slug]; ok {
				it.path, it.from = x.Path, x.Version
			}
			it.rep = report.UpgradeElement{
				Kind: el.Kind, Slug: el.Slug, Install: inst.Path, Path: it.path,
				From: it.from, To: el.Version,
			}

			switch {
			case coreErr != nil:
				r.refuse(it, coreErr.Error())
			case it.path == "":
				r.refuse(it, "ist in dieser Installation nicht vorhanden")
			case multisite:
				r.refuse(it, "WordPress-Multisite wird nicht aktualisiert")
			case busy:
				r.refuse(it, "WordPress aktualisiert diese Installation gerade selbst (.maintenance)")
			case cms.Compare(el.Version, it.from) <= 0:
				r.refuse(it, fmt.Sprintf("Zielversion %s ist nicht höher als die installierte %s", el.Version, it.from))
			}

			state := stateWaiting
			if !it.open() {
				state = stateRefused
			}
			steps = append(steps, progress.Step{
				Kind: el.Kind, Slug: el.Slug, Path: it.path, From: it.from, To: el.Version, State: state,
			})
			r.items = append(r.items, it)
		}
	}
	r.pw.SetSteps(steps)
	r.pw.Log("info", "%d Element(e) im Plan", len(r.items))
}

// fetch loads the release of every open element. A release wordpress.org does
// not publish turns its element down; any other failure ends the run while
// the site is still untouched.
func (r *runner) fetch() error {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		dest, err := os.MkdirTemp(r.opts.StagingDir, "up-")
		if err != nil {
			return err
		}
		switch it.el.Kind {
		case "core":
			it.staged, err = r.opts.Fetcher.Core(it.el.Version, it.locale, dest)
		case "plugin":
			it.staged, err = r.opts.Fetcher.Plugin(it.el.Slug, it.el.Version, dest)
		case "theme":
			it.staged, err = r.opts.Fetcher.Theme(it.el.Slug, it.el.Version, dest)
		}
		switch {
		case errors.Is(err, vendorfiles.ErrNotPublished):
			r.refuse(it, fmt.Sprintf("Version %s ist bei wordpress.org nicht veröffentlicht", it.el.Version))
		case err != nil:
			return fmt.Errorf("%s %s: %w", label(it.el), it.el.Version, err)
		default:
			r.pw.StepState(it.index, stateFetched)
		}
	}
	return nil
}

// verify holds every fetched release against its checksums and checks what it
// asks of the site. A checksum that does not match ends the run; a
// requirement the site does not meet turns the element down.
func (r *runner) verify() error {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		if info, err := os.Stat(it.staged); err != nil || !info.IsDir() {
			r.refuse(it, "das geladene Archiv enthält das erwartete Verzeichnis nicht")
			continue
		}
		unverified, err := verifyStaged(r.opts.Checksums, it.el, it.locale, it.staged)
		if err != nil {
			return fmt.Errorf("%s %s: %w", label(it.el), it.el.Version, err)
		}
		it.rep.Unverified = unverified
		if reason := r.requirements(it); reason != "" {
			r.refuse(it, reason)
			continue
		}
		r.pw.StepState(it.index, stateVerified)
	}
	return nil
}

// requirements reads what the release asks and returns why the site cannot
// take it, or "". A plugin or theme is checked against the core the
// installation will run: the target of a core update in the same plan that
// is still open, the installed core otherwise.
func (r *runner) requirements(it *item) string {
	php := r.opts.PHPVersion
	if it.el.Kind == "core" {
		facts, err := ReadCore(it.staged)
		if err != nil {
			return err.Error()
		}
		it.dbChange = facts.DBVersion != r.cores[it.install.Path].DBVersion
		if it.dbChange && !r.opts.HasWPCLI {
			return "das Kern-Update hebt die Datenbank an und braucht dafür WP-CLI"
		}
		return Requirements{PHP: facts.RequiredPHP}.Check("WordPress "+it.el.Version, "", php)
	}

	var req Requirements
	var err error
	if it.el.Kind == "theme" {
		req, err = ThemeRequirements(it.staged)
	} else {
		req, err = PluginRequirements(it.staged)
	}
	if err != nil {
		return err.Error()
	}
	it.req = req
	return req.Check(it.el.Version, r.plannedCore(it.install.Path), php)
}

// plannedCore is the core version an installation runs once the core element
// of the plan, while still open, is in.
func (r *runner) plannedCore(install string) string {
	for _, it := range r.items {
		if it.install.Path == install && it.el.Kind == "core" && it.open() {
			return it.el.Version
		}
	}
	return r.cores[install].Version
}

// baselines fetches both pages of every installation with an open element,
// before anything changes.
func (r *runner) baselines() map[string][]Probe {
	out := map[string][]Probe{}
	for _, it := range r.items {
		if _, seen := out[it.install.Path]; seen || !it.open() {
			continue
		}
		out[it.install.Path] = r.probe(it)
	}
	return out
}

// probe fetches both pages of the installation, or nothing without a prober.
func (r *runner) probe(it *item) []Probe {
	if r.opts.Prober == nil {
		return nil
	}
	return probeSite(r.opts.Prober, it.install.URL)
}

func (r *runner) finishDryRun(baselines map[string][]Probe) {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		it.rep.Outcome = report.UpgradeWould
		it.rep.Checks = checks(pageURLs(it.install.URL), baselines[it.install.Path], nil, nil)
		r.pw.StepState(it.index, stateWould)
	}
}

// upgradeAll exchanges the open elements one by one. The check after each
// element is the baseline of the next. A site that stays broken after a
// rollback stops the run.
func (r *runner) upgradeAll(baselines map[string][]Probe) {
	current := map[string]string{}
	for path, facts := range r.cores {
		current[path] = facts.Version
	}
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		if it.el.Kind != "core" {
			if reason := it.req.Check(it.el.Version, current[it.install.Path], r.opts.PHPVersion); reason != "" {
				r.refuse(it, reason)
				continue
			}
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		baselines[it.install.Path] = r.upgradeOne(it, baselines[it.install.Path])

		switch it.rep.Outcome {
		case report.UpgradeUpdated:
			if it.el.Kind == "core" {
				current[it.install.Path] = it.el.Version
			}
		case report.UpgradeRollbackFailed:
			r.skipOpen("nach einem gescheiterten Zurückholen nicht begonnen")
			return
		}
	}
}

// upgradeOne exchanges one element and checks the site. It returns what the
// pages answer now, the baseline of the next element.
func (r *runner) upgradeOne(it *item, before []Probe) []Probe {
	install := it.install.Path
	repl := repair.Replacement{
		Root: install, QuarantineDir: r.opts.QuarantineDir, Domain: r.opts.Domain,
		Origin: "upgrade", Reason: fmt.Sprintf("Vor dem Update auf %s abgelegt", it.el.Version),
	}

	// The database first, while nothing has changed yet.
	dump := ""
	if it.dbChange {
		path, id, err := r.exportDB(it)
		if err != nil {
			r.refuse(it, "Datenbank-Export gescheitert: "+err.Error())
			return before
		}
		dump, it.rep.DBExportID = path, id
		defer os.Remove(dump)
	}

	if err := EnterMaintenance(install, r.opts.Now()); err != nil {
		r.refuse(it, "Wartungsmodus nicht setzbar: "+err.Error())
		return before
	}
	defer func() { _ = LeaveMaintenance(install) }()

	var added []string
	var err error
	if it.el.Kind == "core" {
		added = absentIn(install, it.staged)
		it.rep.Files, it.rep.QuarantineIDs, err = repair.ReplaceCore(repl, it.staged)
	} else {
		var entry quarantine.Entry
		entry, it.rep.Files, err = repair.ReplaceDir(repl, it.path, it.staged)
		if entry.ID != "" {
			it.rep.QuarantineIDs = []string{entry.ID}
		}
	}
	if err != nil {
		return r.rollBack(it, before, nil, added, "", report.UpgradeFailed, "Tausch gescheitert: "+err.Error())
	}
	r.pw.StepState(it.index, stateSwapped)

	if it.dbChange {
		r.pw.StepState(it.index, stateDatabase)
		ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
		err := r.opts.WPCLI.UpdateDB(ctx, install)
		cancel()
		if err != nil {
			return r.rollBack(it, before, nil, added, dump, report.UpgradeFailed,
				"Datenbank-Anhebung gescheitert: "+err.Error())
		}
	}

	if err := LeaveMaintenance(install); err != nil {
		r.pw.Log("warn", "%s: %v", install, err)
	}
	after := r.probe(it)
	it.rep.Checks = checks(pageURLs(it.install.URL), before, after, nil)
	if reason := siteBroken(before, after); reason != "" {
		return r.rollBack(it, before, after, added, dump, report.UpgradeRolledBack, reason)
	}

	it.rep.Outcome = report.UpgradeUpdated
	if !anyJudgeable(before) {
		it.rep.Message = "Nachprüfung ohne Aussage: keine Seite antwortete vorher mit einem Status unter 500"
	}
	r.pw.StepState(it.index, stateUpdated)
	r.pw.Log("ok", "aktualisiert %s %s → %s", label(it.el), it.from, it.el.Version)
	return after
}

// rollBack brings the old state back after a failed exchange or a broken
// site: the quarantine entries in reverse order, what the release added, the
// database when a dump is given, then a check. outcome is the verdict when the
// site answers as before; otherwise the element is rollback_failed.
func (r *runner) rollBack(it *item, before, after []Probe, added []string, dump string,
	outcome report.UpgradeOutcome, reason string) []Probe {
	install := it.install.Path
	r.pw.Log("warn", "%s %s: %s - der alte Stand wird zurückgeholt", label(it.el), it.el.Version, reason)
	var problems []string

	for i := len(it.rep.QuarantineIDs) - 1; i >= 0; i-- {
		if err := quarantine.Restore(r.opts.QuarantineDir, it.rep.QuarantineIDs[i], true); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, name := range added {
		target := filepath.Join(install, name)
		if err := safepath.InsideRoot(install, target); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if dump != "" {
		f, err := os.Open(dump)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
			err = r.opts.WPCLI.ImportDB(ctx, install, f)
			cancel()
			f.Close()
		}
		if err != nil {
			problems = append(problems, "Datenbank: "+err.Error())
		}
	}
	if err := LeaveMaintenance(install); err != nil {
		problems = append(problems, err.Error())
	}

	again := r.probe(it)
	it.rep.Checks = checks(pageURLs(it.install.URL), before, after, again)
	broken := siteBroken(before, again)
	if len(problems) > 0 || broken != "" {
		detail := broken
		if len(problems) > 0 {
			detail = strings.Join(problems, "; ")
		}
		it.rep.Outcome = report.UpgradeRollbackFailed
		it.rep.Message = reason + "; nach dem Zurückholen: " + detail
		r.pw.StepState(it.index, stateRollbackFailed)
		r.pw.Log("error", "%s: die Website bleibt nach dem Zurückholen fehlerhaft (%s)", install, detail)
		return again
	}

	it.rep.Outcome, it.rep.Message = outcome, reason
	if outcome == report.UpgradeFailed {
		r.pw.StepState(it.index, stateFailed)
	} else {
		r.pw.StepState(it.index, stateRolledBack)
	}
	r.pw.Log("warn", "zurückgeholt %s %s", label(it.el), it.from)
	return again
}

// exportDB writes the database of the installation into the staging
// directory and files a copy into quarantine. It returns the staged file,
// which a rollback imports, and the id of the quarantine entry.
func (r *runner) exportDB(it *item) (string, string, error) {
	name := "datenbank-" + randomHex() + ".sql"
	path := filepath.Join(r.opts.StagingDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
	err = r.opts.WPCLI.ExportDB(ctx, it.install.Path, f)
	cancel()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", "", err
	}
	entry, err := quarantine.StoreCopy(r.opts.QuarantineDir, quarantine.Source{
		Root: r.opts.StagingDir, RelPath: name, Domain: r.opts.Domain, Origin: "upgrade",
		Reason: fmt.Sprintf("Datenbank vor dem Kern-Update auf %s; einspielen mit wp db import", it.el.Version),
	})
	if err != nil {
		os.Remove(path)
		return "", "", err
	}
	return path, entry.ID, nil
}

// absentIn lists what a staged core adds to the installation: a core
// directory or a loose root file the installation lacks. A rollback removes
// them again.
func absentIn(install, staged string) []string {
	entries, err := os.ReadDir(staged)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && name != "wp-admin" && name != "wp-includes" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(install, name)); os.IsNotExist(err) {
			out = append(out, name)
		}
	}
	return out
}

// checks lines up what the pages answered before, after the exchange and
// after a rollback.
func checks(urls []string, before, after, afterRollback []Probe) []report.PageCheck {
	out := make([]report.PageCheck, len(urls))
	for i, u := range urls {
		out[i].URL = u
		if i < len(before) {
			out[i].Before = before[i].Status
		}
		if i < len(after) {
			out[i].After = after[i].Status
		}
		if i < len(afterRollback) {
			out[i].AfterRollback = afterRollback[i].Status
		}
	}
	return out
}

func anyJudgeable(probes []Probe) bool {
	for _, p := range probes {
		if Judgeable(p) {
			return true
		}
	}
	return false
}

// refuse turns an element down with its reason; nothing of it changes.
func (r *runner) refuse(it *item, reason string) {
	it.rep.Outcome, it.rep.Message = report.UpgradeRefused, reason
	r.pw.StepState(it.index, stateRefused)
	r.pw.Log("warn", "%s %s: %s", label(it.el), it.el.Version, reason)
}

// skipOpen marks every element without an outcome as skipped.
func (r *runner) skipOpen(reason string) {
	for _, it := range r.items {
		if it.open() {
			it.rep.Outcome, it.rep.Message = report.UpgradeSkipped, reason
			r.pw.StepState(it.index, stateSkipped)
		}
	}
}

// fail records a run error. Every element without an outcome is skipped.
func (r *runner) fail(err error) (*report.Upgrade, error) {
	r.rep.Errors = append(r.rep.Errors, err.Error())
	r.pw.Log("error", "%s", err.Error())
	r.skipOpen("Lauf abgebrochen")
	return r.rep, err
}

// collect writes the elements into the report, in plan order.
func (r *runner) collect() {
	r.rep.Elements = make([]report.UpgradeElement, 0, len(r.items))
	for _, it := range r.items {
		r.rep.Elements = append(r.rep.Elements, it.rep)
	}
}

func randomHex() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
```

- [ ] **Step 4: Run the package tests, gofmt and vet**

Run: `go test ./internal/upgrade/ && gofmt -l internal/upgrade && go vet ./internal/upgrade/`
Expected: PASS, keine Ausgabe von gofmt und vet

- [ ] **Step 5: Commit**

```bash
git add internal/upgrade/upgrade.go internal/upgrade/upgrade_test.go
git commit -m "feat(upgrade): the run - fetch, verify, exchange, check, roll back"
```

---

### Task 11: Der Befehl `malwatch upgrade`

**Files:**
- Create: `cmd/malwatch/upgrade.go`
- Modify: `cmd/malwatch/main.go`, `cmd/malwatch/usage.go`
- Test: `cmd/malwatch/upgrade_test.go`

**Interfaces:**
- Consumes: `upgrade.LoadPlan`, `upgrade.ParseRunAs`, `upgrade.Run`, `upgrade.Options`, `upgrade.WPCLI`, `upgrade.SystemExecutor`, `upgrade.NewProber`; `phpinfo.Version`; `knownfiles.NewFetcher`; `vendorfiles.NewFetcher`; `vendorBaseURLs` (cmd/malwatch/repair.go); `report.NewUpgrade`
- Produces: `func cmdUpgrade(args []string) int`; Schalter `--path`, `--plan`, `--run-as`, `--php`, `--wp-cli`, `--connect`, `--quarantine-dir`, `--staging-dir`, `--domain`, `--progress`, `--dry-run`, `--json`, `--out`, `--vendor-base`. Scheitert eine Vorprüfung, schreibt der Befehl trotzdem einen Bericht mit `errors` nach `--out`, damit das Panel den Grund zeigen kann.

- [ ] **Step 1: Write the failing tests**

`cmd/malwatch/upgrade_test.go`:

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRefusesWithoutPathOrPlan(t *testing.T) {
	if code := cmdUpgrade([]string{}); code != 3 {
		t.Errorf("exit code %d without --path, want 3", code)
	}
	if code := cmdUpgrade([]string{"--path=" + t.TempDir()}); code != 3 {
		t.Errorf("exit code %d without --plan, want 3", code)
	}
}

func TestUpgradeRefusesRootAndSaysSoInTheReport(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.json")
	code := cmdUpgrade([]string{
		"--path=" + root, "--plan=" + filepath.Join(root, "plan.json"),
		"--php=/usr/bin/php", "--quarantine-dir=" + t.TempDir(),
		"--run-as=root", "--json", "--out=" + out,
	})
	if code != 3 {
		t.Fatalf("exit code %d for --run-as=root, want 3", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	var doc struct {
		Schema int      `json:"schema"`
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || len(doc.Errors) == 0 || !strings.Contains(doc.Errors[0], "root") {
		t.Errorf("report = %s", raw)
	}
}

func TestUpgradeReportsARefusedPlan(t *testing.T) {
	root := t.TempDir()
	plan := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(plan, []byte(`{"schema":1,"installs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	code := cmdUpgrade([]string{
		"--path=" + root, "--plan=" + plan, "--php=/usr/bin/php", "--dry-run", "--json", "--out=" + out,
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), "keine Installation") {
		t.Errorf("the report does not name the refusal: %s", raw)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/malwatch/ -run TestUpgrade -v`
Expected: FAIL, `undefined: cmdUpgrade`

- [ ] **Step 3: Write `cmd/malwatch/upgrade.go`**

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/phpinfo"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/upgrade"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

func cmdUpgrade(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	path := fs.String("path", "", "")
	planFile := fs.String("plan", "", "")
	runAs := fs.String("run-as", "", "")
	phpBinary := fs.String("php", "", "")
	wpCLI := fs.String("wp-cli", "/usr/local/bin/wp", "")
	connect := fs.String("connect", "127.0.0.1", "")
	quarantineDir := fs.String("quarantine-dir", "", "")
	stagingDir := fs.String("staging-dir", "", "")
	domain := fs.String("domain", "", "")
	progressFile := fs.String("progress", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")
	vendorBase := fs.String("vendor-base", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" || *planFile == "" {
		fmt.Fprintln(os.Stderr, "upgrade braucht --path und --plan. Beispiel: malwatch upgrade "+
			"--path=/var/www/clients/client3/web12/web --plan=job.plan.json --run-as=web12:client3 "+
			"--php=/usr/bin/php8.2 --quarantine-dir=/var/lib/malwatch/quarantine")
		return report.ExitError
	}

	// A check that fails before the run still leaves a report: the panel reads
	// the reason from there.
	early := report.NewUpgrade(*path, *dryRun)
	refuse := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, msg)
		early.Errors = append(early.Errors, msg)
		early.FinishedAt = time.Now().UTC()
		_ = writeUpgradeReport(early, *out, *asJSON)
		return report.ExitError
	}

	if *phpBinary == "" {
		return refuse("upgrade braucht --php, das PHP-Binary der Website.")
	}
	if *quarantineDir == "" && !*dryRun {
		return refuse("upgrade braucht --quarantine-dir, außer mit --dry-run.")
	}
	var userName, group string
	if !*dryRun || *runAs != "" {
		var err error
		if userName, group, err = upgrade.ParseRunAs(*runAs, user.Lookup); err != nil {
			return refuse("%v", err)
		}
	}
	plan, err := upgrade.LoadPlan(*planFile, *path)
	if err != nil {
		return refuse("%v", err)
	}
	phpVersion, err := phpinfo.Version(*phpBinary, 20*time.Second)
	if err != nil {
		return refuse("PHP-Version der Website nicht ermittelbar: %v", err)
	}

	base := *stagingDir
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return refuse("Bereitstellungsverzeichnis: %v", err)
	}
	staging, err := os.MkdirTemp(base, "malwatch-upgrade-")
	if err != nil {
		return refuse("Bereitstellungsverzeichnis: %v", err)
	}
	defer os.RemoveAll(staging)

	info, statErr := os.Stat(*wpCLI)
	hasWPCLI := statErr == nil && info.Mode().IsRegular()

	pw, err := progress.New(*progressFile, "upgrade")
	if err != nil {
		return refuse("Fortschrittsdatei: %v", err)
	}
	defer pw.Close()

	result, runErr := upgrade.Run(upgrade.Options{
		WebRoot:       *path,
		Plan:          plan,
		QuarantineDir: *quarantineDir,
		StagingDir:    staging,
		Domain:        *domain,
		DryRun:        *dryRun,
		PHPVersion:    phpVersion,
		WPCLI: upgrade.WPCLI{Exec: upgrade.SystemExecutor{}, User: userName, Group: group,
			PHP: *phpBinary, Binary: *wpCLI},
		HasWPCLI:  hasWPCLI,
		Fetcher:   vendorfiles.NewFetcher(vendorBaseURLs(*vendorBase), 5*time.Minute),
		Checksums: knownfiles.NewFetcher("", 30*time.Second),
		Prober:    upgrade.NewProber(*connect, 20*time.Second),
		Progress:  pw,
	})

	if err := writeUpgradeReport(result, *out, *asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "Bericht konnte nicht geschrieben werden: %v\n", err)
		return report.ExitError
	}
	if runErr != nil {
		return report.ExitError
	}
	return result.ExitCode()
}

// writeUpgradeReport writes the report readable by its owner only: it names
// paths of a customer.
func writeUpgradeReport(rep *report.Upgrade, out string, asJSON bool) error {
	var w io.Writer = os.Stdout
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if asJSON {
		return rep.WriteJSON(w)
	}
	return rep.WriteText(w)
}
```

- [ ] **Step 4: Dispatch and document the command**

In `cmd/malwatch/main.go` nach dem Fall `"repair"`:

```go
	case "upgrade":
		return cmdUpgrade(args[1:])
```

In `cmd/malwatch/usage.go` im Block „Aufruf:“ nach der Zeile mit `malwatch repair`:

```
  malwatch upgrade --path=/var/www/web12/web --plan=… --run-as=… --php=… [Optionen]
```

Vor „Quarantäne verwalten (quarantine):“ einfügen:

```
Aktualisieren (upgrade):
  --path=PFAD              Webstamm der Website; jede Installation im Plan
                           liegt darunter
  --plan=DATEI             JSON mit Installationen, Adressen und Zielversionen
  --run-as=BENUTZER:GRUPPE Benutzer der Website für WP-CLI; root wird
                           abgewiesen, bei --dry-run verzichtbar
  --php=BINARY             PHP der Website, für Anforderungen und WP-CLI
  --wp-cli=PFAD            WP-CLI (Vorgabe: /usr/local/bin/wp)
  --connect=ADRESSE        Ziel der Nachprüfung, host oder host:port
                           (Vorgabe: 127.0.0.1)
  --quarantine-dir=PFAD    wohin ersetzte Ordner und Datenbank-Exporte gehen
                           (entfällt nur bei --dry-run)
  --staging-dir=PFAD       wo die Archive vor dem Tausch liegen
  --domain=DOMAIN          Website, der die Installationen gehören
  --progress=DATEI         laufender Zustand als JSON, für die Oberfläche
  --dry-run                holen, prüfen, Seiten abrufen, vor dem Tausch anhalten
  --vendor-base=URL        andere Bezugsadresse, für Tests

```

Nach dem Block „Rückgabecodes von repair:“ einfügen:

```
Rückgabecodes von upgrade:
  0  jedes Element aktualisiert, beim Probelauf ohne Einwand
  2  mindestens ein Element abgelehnt, zurückgeholt oder gescheitert;
     dort steht der alte Stand
  3  der Lauf ist gescheitert, oder eine Website blieb nach dem
     Zurückholen fehlerhaft

```

- [ ] **Step 5: Run the command tests and the build**

Run: `go test ./cmd/malwatch/ -run 'TestUpgrade|TestRepair' && go build ./... && go vet ./cmd/malwatch/`
Expected: PASS, Build ohne Fehler

- [ ] **Step 6: Commit**

```bash
git add cmd/malwatch/upgrade.go cmd/malwatch/upgrade_test.go cmd/malwatch/main.go cmd/malwatch/usage.go
git commit -m "feat(cli): malwatch upgrade"
```

---

### Task 12: Angaben für die Zielversionen im Scan-Bericht

**Files:**
- Modify: `internal/cms/latest.go`
- Test: `internal/cms/latest_test.go` (neu)
- Modify: `internal/report/report.go`
- Test: `internal/report/software_upgrade_test.go` (neu)
- Modify: `internal/scanner/scanner.go`, `cmd/malwatch/scan.go`, `cmd/malwatch/usage.go`

**Interfaces:**
- Consumes: `phpinfo.Version` (Task 4)
- Produces:
  - `type cms.PluginInfo struct { Version, RequiresWP, RequiresPHP string }`
  - `func (l *Lookup) LatestPluginInfo(kind, slug string) PluginInfo`
  - `func (l *Lookup) WordPressBranchLatest(current string) string`
  - `func (l *Lookup) WordPressRequiresPHP() string`
  - `report.Software.LatestRequiresWP` (`latest_requires_wp`), `LatestRequiresPHP` (`latest_requires_php`), `LatestInBranch` (`latest_in_branch`); `report.Report.PHPVersion` (`php_version`)
  - `scanner.Options.PHPBinary`; Schalter `--php` für `malwatch scan`

- [ ] **Step 1: Write the failing tests**

`internal/cms/latest_test.go`:

```go
package cms

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeWordPressOrg answers the wordpress.org endpoints the lookup asks.
func fakeWordPressOrg(t *testing.T) *Lookup {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/plugins/info/1.2/"):
			if r.URL.Query().Get("request[slug]") == "bezahlt" {
				_, _ = w.Write([]byte(`{"error":"Plugin not found."}`))
				return
			}
			_, _ = w.Write([]byte(`{"version":"5.3.3","requires":"6.2","requires_php":"7.2"}`))
		case strings.HasPrefix(r.URL.Path, "/themes/info/1.2/"):
			_, _ = w.Write([]byte(`{"version":"1.2","requires":false,"requires_php":false}`))
		case r.URL.Path == "/core/stable-check/1.0/":
			_, _ = w.Write([]byte(`{"6.4.2":"insecure","6.4.4":"insecure","6.4.5":"outdated","6.5.3":"outdated","7.1":"latest"}`))
		case r.URL.Path == "/core/version-check/1.7/":
			_, _ = w.Write([]byte(`{"offers":[{"version":"7.1","current":"7.1","php_version":"7.4"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	l := NewLookup(NewCache("", time.Hour), 5*time.Second)
	l.wporg = srv.URL
	return l
}

func TestLatestPluginInfoCarriesTheRequirements(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got := l.LatestPluginInfo("plugin", "akismet"); got != (PluginInfo{Version: "5.3.3", RequiresWP: "6.2", RequiresPHP: "7.2"}) {
		t.Errorf("plugin = %+v", got)
	}
	if got := l.LatestPluginInfo("theme", "twentytwentyfour"); got != (PluginInfo{Version: "1.2"}) {
		t.Errorf("theme with false requirements = %+v", got)
	}
	if got := l.LatestPlugin("plugin", "bezahlt"); got != "" {
		t.Errorf("a plugin wordpress.org does not list = %q", got)
	}
	// The second call comes from the cache and says the same.
	if got := l.LatestPluginInfo("plugin", "akismet"); got.RequiresPHP != "7.2" {
		t.Errorf("cached plugin = %+v", got)
	}
}

func TestWordPressBranchLatestStaysOnTheBranch(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got := l.WordPressBranchLatest("6.4.2"); got != "6.4.5" {
		t.Errorf("newest on the branch of 6.4.2 = %q, want 6.4.5", got)
	}
	if got := l.WordPressBranchLatest("6.5.3"); got != "" {
		t.Errorf("the newest of its branch has nothing newer: %q", got)
	}
	if got := l.WordPressRequiresPHP(); got != "7.4" {
		t.Errorf("requires php = %q", got)
	}
}
```

`internal/report/software_upgrade_test.go`:

```go
package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTheScanReportCarriesWhatAnUpgradeNeeds(t *testing.T) {
	rep := New([]string{"/w"})
	rep.PHPVersion = "8.2.10"
	rep.Software = append(rep.Software, Software{
		Path: "/w", Product: "wordpress", Kind: "core", Version: "6.4.2",
		LatestInBranch: "6.4.5", LatestRequiresPHP: "7.4",
	}, Software{
		Path: "/w/wp-content/plugins/akismet", Product: "wordpress", Kind: "plugin", Slug: "akismet",
		Version: "5.3.0", LatestRequiresWP: "6.2", LatestRequiresPHP: "7.2",
	})
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		PHPVersion string `json:"php_version"`
		Software   []struct {
			LatestInBranch    string `json:"latest_in_branch"`
			LatestRequiresWP  string `json:"latest_requires_wp"`
			LatestRequiresPHP string `json:"latest_requires_php"`
		} `json:"software"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PHPVersion != "8.2.10" || doc.Software[0].LatestInBranch != "6.4.5" ||
		doc.Software[1].LatestRequiresWP != "6.2" || doc.Software[1].LatestRequiresPHP != "7.2" {
		t.Errorf("report = %s", buf.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cms/ ./internal/report/ -run 'LatestPluginInfo|BranchLatest|WhatAnUpgradeNeeds' -v`
Expected: FAIL, `l.wporg undefined`, `undefined: PluginInfo`, `unknown field LatestInBranch`

- [ ] **Step 3: Extend the lookup in `internal/cms/latest.go`**

In `type Lookup struct` ein Feld ergänzen:

```go
	// wporg is the address of api.wordpress.org; the tests point it elsewhere.
	wporg string
```

In `NewLookup` in das zurückgegebene Literal `wporg: "https://api.wordpress.org",` aufnehmen. In `wordpressCore` die Adresse durch `l.wporg+"/core/version-check/1.7/"` ersetzen.

`LatestPlugin` und `fetchWordPressExtra` ersetzen durch:

```go
// PluginInfo is what wordpress.org says about the newest release of a plugin
// or theme: its version and what it asks of a site.
type PluginInfo struct {
	Version     string
	RequiresWP  string
	RequiresPHP string
}

// LatestPluginInfo returns the newest release of a WordPress plugin or theme
// with its requirements. An empty Version means wordpress.org does not list
// it, which is the normal case for paid and custom plugins.
func (l *Lookup) LatestPluginInfo(kind, slug string) PluginInfo {
	key := kind + "-info:" + slug
	if v, ok := l.cache.Get(key); ok {
		var info PluginInfo
		if len(v) > 0 {
			info.Version = v[0]
		}
		if len(v) > 2 {
			info.RequiresWP, info.RequiresPHP = v[1], v[2]
		}
		return info
	}
	info, err := l.fetchWordPressExtra(kind, slug)
	if err != nil {
		l.cache.Set(key, nil)
		return PluginInfo{}
	}
	l.cache.Set(key, []string{info.Version, info.RequiresWP, info.RequiresPHP})
	return info
}

// LatestPlugin returns the newest version of a WordPress plugin or theme.
func (l *Lookup) LatestPlugin(kind, slug string) string {
	return l.LatestPluginInfo(kind, slug).Version
}

func (l *Lookup) fetchWordPressExtra(kind, slug string) (PluginInfo, error) {
	base := l.wporg + "/plugins/info/1.2/?action=plugin_information"
	if kind == "theme" {
		base = l.wporg + "/themes/info/1.2/?action=theme_information"
	}
	u := base + "&request[slug]=" + url.QueryEscape(slug) +
		"&request[fields][sections]=0&request[fields][description]=0&request[fields][versions]=0"

	var payload struct {
		Version     string          `json:"version"`
		Requires    looseString     `json:"requires"`
		RequiresPHP looseString     `json:"requires_php"`
		Error       json.RawMessage `json:"error"`
	}
	if err := l.getJSON(u, &payload); err != nil {
		return PluginInfo{}, err
	}
	if payload.Version == "" {
		return PluginInfo{}, fmt.Errorf("nicht im Verzeichnis")
	}
	return PluginInfo{
		Version:     payload.Version,
		RequiresWP:  string(payload.Requires),
		RequiresPHP: string(payload.RequiresPHP),
	}, nil
}

// looseString reads a field wordpress.org sends as a string, as a number, or
// as false when a release names nothing.
type looseString string

func (s *looseString) UnmarshalJSON(raw []byte) error {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		*s = looseString(strings.TrimSpace(text))
		return nil
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		*s = looseString(number.String())
		return nil
	}
	*s = ""
	return nil
}

// WordPressBranchLatest returns the newest WordPress release on the major and
// minor branch of current - what an update reaches without a new major
// version - or "" when the list could not be loaded or holds nothing newer.
func (l *Lookup) WordPressBranchLatest(current string) string {
	best := ""
	for _, v := range l.wordpressReleases() {
		if !SameBranch(v, current, 2) || Compare(v, current) <= 0 {
			continue
		}
		if best == "" || Compare(v, best) > 0 {
			best = v
		}
	}
	return best
}

// wordpressReleases lists every WordPress release wordpress.org knows.
func (l *Lookup) wordpressReleases() []string {
	const key = "wordpress-releases"
	if v, ok := l.cache.Get(key); ok {
		return v
	}
	var statuses map[string]string
	if err := l.getJSON(l.wporg+"/core/stable-check/1.0/", &statuses); err != nil {
		l.note("WordPress: Liste der Versionen nicht ladbar (%v)", err)
		return nil
	}
	out := make([]string, 0, len(statuses))
	for v := range statuses {
		out = append(out, v)
	}
	sort.Strings(out)
	l.cache.Set(key, out)
	return out
}

// WordPressRequiresPHP returns the PHP version the newest WordPress release
// asks for, or "" when unknown.
func (l *Lookup) WordPressRequiresPHP() string {
	const key = "wordpress-requires-php"
	if v, ok := l.cache.Get(key); ok {
		if len(v) > 0 {
			return v[0]
		}
		return ""
	}
	var payload struct {
		Offers []struct {
			PHPVersion string `json:"php_version"`
		} `json:"offers"`
	}
	if err := l.getJSON(l.wporg+"/core/version-check/1.7/", &payload); err != nil || len(payload.Offers) == 0 {
		return ""
	}
	php := payload.Offers[0].PHPVersion
	l.cache.Set(key, []string{php})
	return php
}
```

- [ ] **Step 4: Extend the report in `internal/report/report.go`**

In `type Software struct` nach `Latest`:

```go
	// LatestRequiresWP and LatestRequiresPHP are what the newest release asks
	// of a site, as wordpress.org lists them; empty when unknown. For the
	// WordPress core LatestRequiresPHP belongs to the newest release overall.
	LatestRequiresWP  string `json:"latest_requires_wp,omitempty"`
	LatestRequiresPHP string `json:"latest_requires_php,omitempty"`
	// LatestInBranch is, for the WordPress core, the newest release on the
	// installed major and minor branch.
	LatestInBranch string `json:"latest_in_branch,omitempty"`
```

In `type Report struct` nach `Host`:

```go
	// PHPVersion is the version of the PHP the website runs, when the caller
	// named its binary.
	PHPVersion string `json:"php_version,omitempty"`
```

- [ ] **Step 5: Fill the fields in `internal/scanner/scanner.go`**

Im Importblock `"github.com/brightcolor/malwatch/internal/phpinfo"` ergänzen. In `type Options struct` nach `WPScanTokenFile`:

```go
	// PHPBinary names the PHP of the website; the report then carries its
	// version, so the panel can tell which releases the site can take.
	PHPBinary string
```

In `Run` direkt nach `rep := report.New(opts.Paths)`:

```go
	if opts.PHPBinary != "" {
		if v, err := phpinfo.Version(opts.PHPBinary, 10*time.Second); err != nil {
			rep.Errors = append(rep.Errors, "PHP-Version nicht ermittelbar: "+err.Error())
		} else {
			rep.PHPVersion = v
		}
	}
```

In `collectSoftware` den Block `if lookup != nil {` bis zur Zuweisung `entry.Latest = latest` ersetzen durch:

```go
		if lookup != nil {
			var latest string
			if inst.Kind == "core" {
				latest = lookup.Latest(inst.Product, inst.Version)
				if inst.Product == "wordpress" {
					entry.LatestInBranch = lookup.WordPressBranchLatest(inst.Version)
					entry.LatestRequiresPHP = lookup.WordPressRequiresPHP()
				}
			} else {
				info := lookup.LatestPluginInfo(inst.Kind, inst.Slug)
				latest = info.Version
				entry.LatestRequiresWP, entry.LatestRequiresPHP = info.RequiresWP, info.RequiresPHP
			}
			entry.Latest = latest
```

- [ ] **Step 6: Add `--php` to `malwatch scan`**

In `cmd/malwatch/scan.go` nach `wpscanTokenFile := …`:

```go
	phpBinary := fs.String("php", "", "")
```

Im Literal `scanner.Options{…}` nach `WPScanTokenFile: *wpscanTokenFile,`:

```go
		PHPBinary:       *phpBinary,
```

In `cmd/malwatch/usage.go` im Block „Prüfstufen:“ nach `--no-vuln-scan`:

```
  --php=BINARY             PHP der Website; der Bericht nennt ihre Version
```

- [ ] **Step 7: Run tests, build and vet**

Run: `go test ./internal/cms/ ./internal/report/ ./internal/phpinfo/ ./cmd/malwatch/ && go build ./... && go vet ./...`
Expected: PASS

Die Tests von `internal/scanner` laufen als Linux-Testbinary auf dem Server (siehe Global Constraints):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o scanner.test ./internal/scanner
```

Expected nach dem Hochladen, `chmod +x` und Aufruf im Paketverzeichnis: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/cms/latest.go internal/cms/latest_test.go internal/report/report.go internal/report/software_upgrade_test.go internal/scanner/scanner.go cmd/malwatch/scan.go cmd/malwatch/usage.go
git commit -m "feat(scan): requirements of the newest release, the newest on its branch, and the PHP of the site"
```

---

### Task 13: Abnahmetest in CI

**Files:**
- Modify: `.github/workflows/ci.yml` (neuer Job `upgrade-roundtrip`)

**Interfaces:**
- Consumes: `malwatch upgrade` (Task 11) mit `--vendor-base`, `--connect`, `--run-as`, `--php`, `--wp-cli`

Belegt am 14.09.2026: `wordpress-6.5.3.zip` und `wordpress-6.5.5.zip` sind veröffentlicht, beide mit `$wp_db_version = 57155` (kein Datenbankschritt); `akismet.5.3.2.zip`, `akismet.5.3.3.zip` und die Prüfsummenliste von akismet 5.3.3 antworten mit 200; `plugin-checksums/malwatch-probe/2.0.0.json` antwortet mit 404.

- [ ] **Step 1: Add the job**

An `.github/workflows/ci.yml` anhängen:

```yaml
  upgrade-roundtrip:
    # The promise of malwatch upgrade, in both directions: a real update leaves
    # the new release of the vendor in place with the site answering, and an
    # update that breaks the site is taken back with the site answering again.
    runs-on: ubuntu-latest
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: wordpress
        ports:
          - 3306:3306
        options: >-
          --health-cmd="mysqladmin ping -h 127.0.0.1 -proot"
          --health-interval=5s --health-timeout=5s --health-retries=30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
          cache: true
      - uses: shivammathur/setup-php@v2
        with:
          php-version: "8.2"
          extensions: mysqli
          tools: wp-cli
      - name: Build
        run: go build -o malwatch ./cmd/malwatch
      - name: WordPress 6.5.3 with akismet 5.3.2
        run: |
          mkdir -p www/wp
          wp core download --version=6.5.3 --locale=en_US --path=www/wp
          wp config create --path=www/wp --dbname=wordpress --dbuser=root --dbpass=root --dbhost=127.0.0.1
          wp core install --path=www/wp --url=http://127.0.0.1:8080 --title=Probe \
            --admin_user=probe --admin_password=probe --admin_email=probe@beispiel.de --skip-email
          wp plugin install akismet --version=5.3.2 --activate --path=www/wp
      - name: Serve it
        run: |
          (cd www/wp && php -S 127.0.0.1:8080 > "$RUNNER_TEMP/php-server.log" 2>&1 &)
          for i in $(seq 1 30); do
            curl -fsS -o /dev/null http://127.0.0.1:8080/wp-login.php && break
            sleep 1
          done
          curl -fsS -o /dev/null http://127.0.0.1:8080/
      - name: Upgrade the core within its branch and the plugin
        run: |
          cat > plan.json <<EOF
          {"schema":1,"installs":[{"path":"$PWD/www/wp","url":"http://127.0.0.1:8080/","elements":[
            {"kind":"core","version":"6.5.5"},
            {"kind":"plugin","slug":"akismet","version":"5.3.3"}]}]}
          EOF
          set +e
          ./malwatch upgrade --path="$PWD/www" --plan=plan.json --run-as="$(id -un)" \
            --php="$(command -v php)" --wp-cli="$(command -v wp)" --connect=127.0.0.1:8080 \
            --quarantine-dir=quarantine --progress=progress.json --json --out=upgrade.json
          code=$?
          set -e
          jq -r '.elements[] | "\(.kind) \(.slug // "") \(.outcome) \(.message // "")"' upgrade.json
          [ "$code" = "0" ] || { echo "exit code $code, expected 0"; cat upgrade.json; exit 1; }
          jq -e '[.elements[].outcome] == ["updated","updated"]' upgrade.json
          jq -e '.kind == "upgrade" and (.steps | length) == 2' progress.json
      - name: The files are the new releases, and the site answers
        run: |
          wp core verify-checksums --path=www/wp
          wp plugin verify-checksums akismet --path=www/wp
          grep -q "6.5.5" www/wp/wp-includes/version.php
          curl -fsS -o /dev/null http://127.0.0.1:8080/
          curl -fsS -o /dev/null http://127.0.0.1:8080/wp-login.php
      - name: A plugin release that breaks the site
        run: |
          mkdir -p www/wp/wp-content/plugins/malwatch-probe vendor/plugin build/malwatch-probe
          printf '<?php\n/*\nPlugin Name: malwatch probe\nVersion: 1.0.0\n*/\n' \
            > www/wp/wp-content/plugins/malwatch-probe/malwatch-probe.php
          wp plugin activate malwatch-probe --path=www/wp
          printf '<?php\n/*\nPlugin Name: malwatch probe\nVersion: 2.0.0\n*/\nmalwatch_probe_undefined_function();\n' \
            > build/malwatch-probe/malwatch-probe.php
          (cd build && zip -qr ../vendor/plugin/malwatch-probe.2.0.0.zip malwatch-probe)
          (cd vendor && python3 -m http.server 8090 > "$RUNNER_TEMP/vendor.log" 2>&1 &)
          for i in $(seq 1 30); do
            curl -fsS -o /dev/null http://127.0.0.1:8090/plugin/malwatch-probe.2.0.0.zip && break
            sleep 1
          done
      - name: Upgrade it and expect the rollback
        run: |
          cat > broken.json <<EOF
          {"schema":1,"installs":[{"path":"$PWD/www/wp","url":"http://127.0.0.1:8080/","elements":[
            {"kind":"plugin","slug":"malwatch-probe","version":"2.0.0"}]}]}
          EOF
          set +e
          ./malwatch upgrade --path="$PWD/www" --plan=broken.json --run-as="$(id -un)" \
            --php="$(command -v php)" --wp-cli="$(command -v wp)" --connect=127.0.0.1:8080 \
            --quarantine-dir=quarantine --vendor-base=http://127.0.0.1:8090/ --json --out=broken-run.json
          code=$?
          set -e
          jq . broken-run.json
          [ "$code" = "2" ] || { echo "exit code $code, expected 2"; exit 1; }
          jq -e '.elements[0].outcome == "rolled_back"' broken-run.json
          grep -q "Version: 1.0.0" www/wp/wp-content/plugins/malwatch-probe/malwatch-probe.php
          curl -fsS -o /dev/null http://127.0.0.1:8080/
          curl -fsS -o /dev/null http://127.0.0.1:8080/wp-login.php
          [ ! -e www/wp/.maintenance ] || { echo ".maintenance left behind"; exit 1; }
```

- [ ] **Step 2: Check the file locally**

Run: `gh workflow view ci --yaml > /dev/null 2>&1; grep -c "upgrade-roundtrip" .github/workflows/ci.yml`
Expected: `1`. Der Job selbst läuft beim ersten Push, der CI auslöst (Pull Request oder `main`); sein Ergebnis gehört vor die Freigabe in Teil B, Task 10.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: upgrade a real WordPress and take a breaking plugin release back"
```

---

## Abschluss von Teil A

- [ ] `gofmt -l .` liefert nichts, `go vet ./...` ist sauber.
- [ ] `go test ./internal/upgrade/ ./internal/repair/ ./internal/progress/ ./internal/report/ ./internal/phpinfo/ ./internal/cms/ ./internal/knownfiles/ ./internal/vendorfiles/ ./cmd/malwatch/` besteht lokal.
- [ ] Alle Pakete bestehen als Linux-Testbinaries auf dem Server, `internal/scanner` eingeschlossen.
- [ ] `malwatch upgrade --help` zeigt den Abschnitt „Aktualisieren (upgrade)“.
- [ ] Teil B beginnt erst, wenn diese vier Punkte erfüllt sind: das Addon ruft den Befehl mit genau diesen Schaltern auf.
