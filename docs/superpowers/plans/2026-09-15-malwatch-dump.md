# Dump einer Website — Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eine Website lässt sich im Panel als tar.gz mit Webverzeichnis, ausgewählten Datenbanken und auf Wunsch Protokollen packen und herunterladen.

**Architecture:** Der Scanner bekommt den Befehl `malwatch dump`, der alles in einem Durchgang in einen tar.gz-Strom schreibt. Das Addon reiht den Lauf über die bestehende Warteschlange ein (`job_kind = 'dump'`), liest den Bericht ein und führt die Dumps in einer eigenen Seite mit Liste, Auswahl der Datenbanken und Download. Der stündliche Lauf sammelt die Angaben zu den Datenbanken und räumt abgelaufene Dumps weg.

**Tech Stack:** Go (tar, gzip, os/exec für mysqldump), PHP 7.0 im ISPConfig-Addon, MariaDB, vlibTemplate, jQuery/Bootstrap 3 im Panel.

**Spec:** `docs/superpowers/specs/2026-09-14-malwatch-dump-design.md`

## Global Constraints

- PHP im Addon bleibt auf PHP 7.0 lauffähig: keine typisierten Eigenschaften, kein `??`, keine Pfeilfunktionen.
- Keine echten Kundendaten in Tests, Changelog oder Kommentaren; Beispiele heißen `beispiel.de`, `web12`, `client3`.
- Keine Fremdproduktnamen aus der bereinigten Historie; vor jedem Commit `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` ohne Treffer.
- Texte ohne Negativabgrenzungen und ohne Zeitangaben, auch in Oberfläche, Changelog und Commits.
- WP-CLI läuft nie als root; `mysqldump` läuft als root über den Socket.
- Jede Datei unter `interface/` und `server/` steht in `install/file.list`; Seiten werden kopiert, Module und Plugins verlinkt.
- Jeder Text der Oberfläche steht in `de_*.lng` und `en_*.lng`.
- Commit-Trailer: `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- Deploy erst nach grüner CI, danach `cmp` jeder `c:`-Zeile aus `install/file.list` und `render_pages.php`.

## Dateien

**Neu (Go):**
- `internal/dump/dump.go` — packt Dateien und Datenbanken in einen tar.gz-Strom, schreibt den Bericht.
- `internal/dump/space.go` — Größe der Quellen, freier Platz, Schwelle.
- `internal/dump/dump_test.go`, `internal/dump/space_test.go`.
- `cmd/malwatch/dump.go` — Schalter, Aufruf, Rückgabecode.

**Neu (Addon):**
- `ispconfig/interface/malwatch_dump_list.php` + `templates/malwatch_dump_list.htm` + `lang/de_malwatch_dump.lng` + `lang/en_malwatch_dump.lng`.
- `ispconfig/interface/malwatch_dump_databases.php` — JSON-Zeilen der Datenbankauswahl.
- `ispconfig/interface/malwatch_dump_download.php` — Auslieferung des Archivs.
- `ispconfig/tests/dump_helpers_test.php`.

**Geändert:**
- `cmd/malwatch/main.go` (Befehlsauswahl), `cmd/malwatch/usage.go` (Hilfe, Rückgabecodes).
- `ispconfig/install/schema.sql` (zwei Tabellen, `job_kind`), `ispconfig/install/installer.php` (Verzeichnis `dumps`), `ispconfig/install/file.list`.
- `ispconfig/interface/module.conf.php` (Menüpunkt), `ispconfig/interface/lib/malwatch_lib.inc.php` (Helfer, Auftrag).
- `ispconfig/server/lib/classes/malwatch_runner.inc.php` (Zweig `dump`, `ensure_shared_dir`), `malwatch_ingest.inc.php` (`ingest_dump`), `cron.d/560-malwatch.inc.php` (Verteilung, `collect_databases`, `clean_dumps`).
- `ispconfig/tests/check_wiring.sh`, `ispconfig/tests/render_pages.php`.
- `CHANGELOG.md`, `ispconfig/README.md`, `internal/version/version.go`, `ispconfig/version`.

---

### Task 1: Schema, Ablage, Auftragsart

**Files:**
- Modify: `ispconfig/install/schema.sql`, `ispconfig/install/installer.php`, `ispconfig/server/lib/classes/malwatch_runner.inc.php`
- Test: `ispconfig/tests/check_wiring.sh`

**Interfaces:**
- Produces: Tabellen `malwatch_dump` und `malwatch_database`, `job_kind` mit `dump`, Verzeichnis `<state_dir>/dumps`.

- [ ] **Step 1: Prüfung zuerst** — in `check_wiring.sh` als Prüfung 48 anhängen:

```bash
# 48. Die Ablage und die Auftragsart des Dumps hängen zusammen: ohne die
#     Tabellen läuft der Auftrag ins Leere, ohne das Verzeichnis findet der
#     Lauf sein Ziel nicht.
grep -q "CREATE TABLE IF NOT EXISTS \`malwatch_dump\`" "$root/install/schema.sql" \
	|| fail "schema.sql kennt malwatch_dump nicht"
grep -q "CREATE TABLE IF NOT EXISTS \`malwatch_database\`" "$root/install/schema.sql" \
	|| fail "schema.sql kennt malwatch_database nicht"
grep -q "''dump''" "$root/install/schema.sql" \
	|| fail "job_kind kennt die Auftragsart dump nicht"
grep -q "'/dumps'" "$root/install/installer.php" \
	|| fail "der Installer legt <state_dir>/dumps nicht an"
grep -q "/dumps" "$root/server/lib/classes/malwatch_runner.inc.php" \
	|| fail "der Runner stellt <state_dir>/dumps nicht sicher"
```

- [ ] **Step 2: Rot laufen lassen** — `bash ispconfig/tests/check_wiring.sh`, erwartet fünf FAIL-Zeilen.
- [ ] **Step 3: Schema ergänzen** — `malwatch_dump` und `malwatch_database` nach dem Muster von `malwatch_upgrade` anlegen (Spalten wie in der Spezifikation, Abschnitt „Schema“), dazu der selbstprüfende Zusatz für `job_kind`:

```sql
SET @mw := (SELECT IF(COUNT(*) = 1,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'',''upgrade'',''dump'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE NOT LIKE '%dump%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

- [ ] **Step 4: Installer und Runner** — `prepare_state_dir()` legt `dumps` mit 02750 und der Panelgruppe an, `ensure_shared_dir()` stellt es zur Laufzeit sicher, beides neben `runs` und `spool`.
- [ ] **Step 5: Grün** — `bash ispconfig/tests/check_wiring.sh` und `php -l` der geänderten Dateien.
- [ ] **Step 6: Commit** — `feat(dump): tables, job kind and storage for website dumps`.

---

### Task 2: Go-Paket `internal/dump`

**Files:**
- Create: `internal/dump/dump.go`, `internal/dump/space.go`, `internal/dump/dump_test.go`, `internal/dump/space_test.go`

**Interfaces:**
- Produces:

```go
type Options struct {
    WebRoot   string        // Webverzeichnis, Pflicht
    LogRoot   string        // Protokollverzeichnis, leer heißt ohne
    Databases []string      // Namen, in dieser Reihenfolge gepackt
    Archive   string        // Zieldatei
    MinFree   int64         // zusätzlicher freier Platz, 0 heißt nur die Reserve
    Dumper    Dumper        // nil heißt mysqldump
    Progress  *progress.Writer
}

type Dumper interface {
    Dump(name string, out io.Writer) error
}

type DatabaseReport struct {
    Name  string `json:"name"`
    Bytes int64  `json:"bytes"`
}

type Report struct {
    Schema      int              `json:"schema"`
    Version     string           `json:"malwatch_version"`
    WebRoot     string           `json:"web_root"`
    LogRoot     string           `json:"log_root,omitempty"`
    Files       int              `json:"files"`
    Bytes       int64            `json:"bytes"`
    Databases   []DatabaseReport `json:"databases"`
    ArchiveBytes int64           `json:"archive_bytes"`
    SHA256      string           `json:"sha256"`
    StartedAt   time.Time        `json:"started_at"`
    FinishedAt  time.Time        `json:"finished_at"`
    Reason      string           `json:"reason,omitempty"` // space, database, files
    Message     string           `json:"message,omitempty"`
}

func Run(opts Options) (*Report, error)
func FreeSpace(path string) (int64, error)
func SourceSize(roots ...string) (int64, error)
```

- [ ] **Step 1: Tests zuerst** — `dump_test.go` mit vier Fällen:

```go
func TestRunPacksWebLogsAndDatabases(t *testing.T) // Namen web/…, protokolle/…, datenbanken/x.sql, dump.json vorhanden
func TestRunKeepsSymlinkAsSymlink(t *testing.T)    // tar-Header Typeflag Symlink, Ziel unverändert
func TestRunFailsWhenDatabaseFails(t *testing.T)   // Dumper gibt Fehler, Archiv existiert danach nicht, Reason "database"
func TestRunRefusesWithoutSpace(t *testing.T)      // MinFree über dem freien Platz, Reason "space", kein Archiv
```

Der Dumper im Test schreibt `-- dump of <name>` und braucht keine Datenbank.

- [ ] **Step 2: Rot** — `go test ./internal/dump/` schlägt fehl, weil das Paket fehlt.
- [ ] **Step 3: Umsetzen** — `Run` legt die Zieldatei mit `0640` an, schreibt gzip über tar, packt `WebRoot` unter `web/`, `LogRoot` unter `protokolle/` (beide über einen Walk wie `internal/quarantine/archive.go`: Namen relativ zur Wurzel, Symlinks als Links, `safepath`), danach je Datenbank einen Eintrag `datenbanken/<name>.sql` aus dem `Dumper`, zuletzt `dump.json`. Die Prüfsumme entsteht über einen `io.MultiWriter` auf `sha256`. Scheitert etwas, wird die Zieldatei entfernt.
- [ ] **Step 4: Grün** — `go test ./internal/dump/ -v`, `gofmt -l internal` ohne Ausgabe.
- [ ] **Step 5: Commit** — `feat(dump): pack web directory, logs and databases into one archive`.

---

### Task 3: Befehl `malwatch dump`

**Files:**
- Create: `cmd/malwatch/dump.go`
- Modify: `cmd/malwatch/main.go:19-43`, `cmd/malwatch/usage.go`
- Test: `cmd/malwatch/dump_test.go`

**Interfaces:**
- Consumes: `dump.Run`, `dump.Options`.
- Produces: `cmdDump(args []string) int`; Aufruf laut Spezifikation, Rückgabecode 0 fertig, 3 gescheitert.

- [ ] **Step 1: Test zuerst** — `TestCmdDumpNeedsPathAndArchive` erwartet Code 3 ohne `--path`; `TestCmdDumpWritesReport` packt ein Testverzeichnis und prüft, dass `--out` eine Datei mit `"sha256"` enthält.
- [ ] **Step 2: Rot** — `go test ./cmd/malwatch/ -run Dump`.
- [ ] **Step 3: Umsetzen** — Schalter `--path`, `--archive`, `--logs`, `--db` (mehrfach), `--db-defaults`, `--min-free`, `--progress`, `--expect`, `--json`, `--out`; `mysqldump`-Dumper mit `--single-transaction --quick --routines --events --triggers --default-character-set=utf8mb4` und `--defaults-file`, wenn gesetzt; `case "dump"` in `main.go`; Hilfe und Rückgabecodes in `usage.go`.
- [ ] **Step 4: Grün** — `go test ./cmd/... ./internal/...`, `go vet ./...`.
- [ ] **Step 5: Commit** — `feat(dump): the dump command with its switches and report`.

---

### Task 4: Helfer im Addon

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_lib.inc.php`
- Test: `ispconfig/tests/dump_helpers_test.php`

**Interfaces:**
- Produces:

```php
malwatch_dump_database_rows(array $databases, array $wb)  // Zeilen der Auswahl: name, size_label, tables_label, used_label, write_label, has_marks
malwatch_dump_known_names(array $databases)                // Liste der erlaubten Namen
malwatch_dump_filter_names(array $posted, array $known)    // nur bekannte Namen, Reihenfolge wie known
malwatch_dump_rows(array $dumps, array $wb)                // Zeilen der Liste: state_label, size_label, content_label, valid_label, can_download
```

- [ ] **Step 1: Test zuerst** — `dump_helpers_test.php` prüft: Größe „12,4 MB“ und „0 B“, „keine Tabellen“ bei `tables = 0`, Zuordnung „WordPress /shop“, „zuletzt geschrieben 14.09.2026“, unbekannte Angaben lassen die Marken leer; `malwatch_dump_filter_names` wirft einen nachgereichten Namen weg und behält die Reihenfolge; `malwatch_dump_rows` bildet die vier Zustände ab.
- [ ] **Step 2: Rot** — `php ispconfig/tests/dump_helpers_test.php`.
- [ ] **Step 3: Umsetzen** — die vier Funktionen, Texte über `$wb`, Zahlen über die vorhandene Größenformatierung der Quarantäne.
- [ ] **Step 4: Grün** — derselbe Aufruf, dazu `php -l`.
- [ ] **Step 5: Commit** — `feat(dump): panel helpers for the database picker and the dump list`.

---

### Task 5: Seite „Dumps“

**Files:**
- Create: `ispconfig/interface/malwatch_dump_list.php`, `ispconfig/interface/templates/malwatch_dump_list.htm`, `ispconfig/interface/lang/de_malwatch_dump.lng`, `ispconfig/interface/lang/en_malwatch_dump.lng`
- Modify: `ispconfig/interface/module.conf.php`, `ispconfig/install/file.list`, `ispconfig/interface/lib/malwatch_lib.inc.php` (Auftrag)

**Interfaces:**
- Consumes: Helfer aus Task 4.
- Produces: `malwatch_queue_dump($app, $domain_id, array $databases, $with_logs, array $wb)` legt Zeile und Auftrag an und gibt die `dump_id` zurück.

- [ ] **Step 1: Seite und Vorlage** — Administratorprüfung, CSRF, POST-Aktionen `dump_start` und `dump_delete`; Auswahlfeld der Websites (dieselbe Abfrage wie `status.php`), Datenbankliste mit `mw-pick`, Häkchen „Protokolle mitnehmen“, Knopf mit Rückfrage über `templates/malwatch_modal.htm`, Liste der Dumps mit Herunterladen und Löschen; `templates/malwatch_selection.htm` für Umschalter und Zähler.
- [ ] **Step 2: Sprachdateien** — jede Zeile in de und en, dazu `btn_cancel_txt`, `btn_close_txt`, `hint_select_txt` und der Fußtext, der sagt, was in einem Dump steckt: Kundendaten, in den Protokollen Adressen der Besucher, bei einer befallenen Website auch der Schadcode.
- [ ] **Step 3: file.list und Menü** — vier `c:`-Zeilen, Menüpunkt „Dumps“ hinter „Quarantäne“.
- [ ] **Step 4: Prüfen** — `bash ispconfig/tests/check_wiring.sh` (Prüfungen 6, 8, 9, 33, 36, 41, 42 greifen), `php -l`.
- [ ] **Step 5: Commit** — `feat(dump): the Dumps page with the database picker`.

---

### Task 6: JSON-Seite für die Datenbankzeilen

**Files:**
- Create: `ispconfig/interface/malwatch_dump_databases.php`
- Modify: `ispconfig/install/file.list`, `ispconfig/interface/templates/malwatch_dump_list.htm` (Nachladen beim Wechsel der Website)

- [ ] **Step 1: Seite** — `Content-Type: application/json`, Administratorprüfung, keine Vorlage; Antwort `{"databases":[{"name","size_label","tables_label","used_label","write_label"}],"hint":"…"}`.
- [ ] **Step 2: Skript der Seite** — Wechsel der Website holt die Zeilen über `$.ajax` und baut die Liste neu, wie „Weitere Versionen laden“ in `malwatch_upgrade_start.htm`.
- [ ] **Step 3: Prüfen** — `check_wiring.sh` Prüfung 43, dazu `php -l`.
- [ ] **Step 4: Commit** — `feat(dump): reload the database rows when the website changes`.

---

### Task 7: Herunterladen

**Files:**
- Create: `ispconfig/interface/malwatch_dump_download.php`
- Modify: `ispconfig/install/file.list`, `ispconfig/tests/check_wiring.sh`

- [ ] **Step 1: Prüfung 49** — der Verweis der Seite benutzt `token=`, und die Seite prüft `is_admin`, nach dem Muster von Prüfung 34.
- [ ] **Step 2: Rot** — `bash ispconfig/tests/check_wiring.sh`.
- [ ] **Step 3: Umsetzen** — Token prüfen (`^[A-Za-z0-9_-]+$`), Zeile mit `dump_state = 'done'` und `expires_at > NOW()`, `hash_equals`, Puffer leeren, `readfile()` mit `Content-Type: application/gzip`, `Content-Length`, `Cache-Control: no-store`, Dateiname `malwatch-dump-<domain>-<datum>.tar.gz`.
- [ ] **Step 4: Grün** — `check_wiring.sh`, `php -l`.
- [ ] **Step 5: Commit** — `feat(dump): download a finished dump while it lasts`.

---

### Task 8: Serverseite

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_runner.inc.php:115-208`, `malwatch_ingest.inc.php`, `cron.d/560-malwatch.inc.php:56-116` und `housekeeping`

**Interfaces:**
- Consumes: `options` mit `dump_id`, `token`, `databases`, `logs`.
- Produces: `malwatch_ingest::ingest_dump($job)`, `collect_databases($config)`, `clean_dumps($config)`.

- [ ] **Step 1: Runner** — Zweig `dump` in `build_arguments()`: `--path`, `--archive=<state_dir>/dumps/<token>.tar.gz`, `--out=<result_file>`, `--json`, `--progress`, `--expect`, je Datenbank `--db=`, mit Häkchen `--logs=<document_root>/log`, dazu die defaults-Datei im Staging mit 0600.
- [ ] **Step 2: Einlesen** — `ingest_dump()` setzt die Zeile auf `done` mit Bytes, Dateien, Datenbankzahl, `ready_at` und `expires_at = NOW() + INTERVAL 7 DAY`, sonst auf `error` mit `reason` und Meldung; Verteilung in `collect_finished()` ergänzen.
- [ ] **Step 3: Sammeln** — `collect_databases()` im stündlichen Teil: `information_schema` über den lokalen `mysql`-Client als root je Datenbank einer Website, `wp-config.php` der gemeldeten Installationen für `DB_NAME`, Ergebnis in `malwatch_database`.
- [ ] **Step 4: Aufräumen** — `clean_dumps()` löscht abgelaufene Dateien und Zeilen sowie Dateien ohne Zeile.
- [ ] **Step 5: Prüfen** — `php -l` aller drei Dateien, `check_wiring.sh` (Prüfung 37 verlangt jeden Schalter in `usage.go`).
- [ ] **Step 6: Commit** — `feat(dump): runner branch, ingest, collection and cleanup`.

---

### Task 9: Renderprüfung und Staging

**Files:**
- Modify: `ispconfig/tests/render_pages.php`

- [ ] **Step 1: Seiten aufnehmen** — `malwatch_dump_list.php`, `malwatch_dump_databases.php?id=…` (JSON-Zweig) in die Liste; für die Downloadseite ohne Token bleibt die Prüfung aus, weil sie eine Datei ausliefert.
- [ ] **Step 2: Staging** — Paket auf den Server, `MW_SECURITY_DIR`-Lauf, alle Seiten rendern.
- [ ] **Step 3: Probelauf** — Dump einer kleinen Website über den Scanner auf dem Server, Archiv entpacken, Dateizahl und Datenbank gegen das Original halten.
- [ ] **Step 3a: Große Website** — ein Lauf mit einer großen Website für Laufzeit, Last und Platz, dazu ein Blick auf die Auswahl der Website mit 95 Datenbanken, damit die Liste dort lesbar bleibt.
- [ ] **Step 4: Commit** — `test(dump): render the new pages and run one dump on the server`.

---

### Task 10: Auslieferung 0.17.0

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`, `CHANGELOG.md`, `ispconfig/README.md`

- [ ] **Step 1: Version** — beide Dateien auf `0.17.0`.
- [ ] **Step 2: Changelog und README** — Abschnitt „Dumps“ mit Inhalt, Auswahl, Aufbewahrung und Download.
- [ ] **Step 3: Prüfen** — `check_wiring.sh`, alle PHP-Tests, `go test ./...`, `go vet ./...`, `gofmt -l internal cmd`.
- [ ] **Step 4: Commit, Tag, CI** — `git add -A`, Commit, Push, `git tag v0.17.0 && git push --tags`, CI und Release abwarten.
- [ ] **Step 5: Deploy** — Paket einspielen, `cmp` jeder `c:`-Zeile, `render_pages.php` gegen die Installation, Menüpunkt im Panel prüfen.
- [ ] **Step 6: Abschluss** — Ledger und Erinnerungen nachziehen, dem Nutzer die Testschritte nennen.
