# Quarantäne und Reparatur — Umsetzungsplan (Stufe 2)

> **Für Agenten:** PFLICHT-SUBSKILL: superpowers:subagent-driven-development.

**Ziel:** Alles, was das Addon entfernt, landet in einem durchsuchbaren Quarantänespeicher,
aus dem es zurückgeholt, als verschlüsseltes ZIP heruntergeladen oder endgültig gelöscht
werden kann — und die Oberfläche macht die Reparatur zu einer Entscheidung statt zu zwei
Knöpfen.

**Architektur:** Ein Speicher auf der Platte (`<state_dir>/quarantine`, ein Verzeichnis je
Eintrag mit `meta.json` und `payload.tar.gz`), ein Index in der Datenbank, den der Server
nach jedem Auftrag aus der vollständigen Liste des Scanners abgleicht, und Aktionen, die
wie alles andere über die Auftragswarteschlange laufen.

**Technik:** Go 1.24 ohne Fremdpakete, PHP 7/8 im ISPConfig-Stil, MySQL.

**Spec:** `docs/superpowers/specs/2026-09-07-quarantaene-und-reparatur-design.md`

## Global Constraints

- **Nur Standardbibliothek.** `go.mod` bleibt ohne `require`-Block. Kein `golang.org/x/…`.
- **Deutsch nach außen, Englisch im Code.** Meldungen, Sprachdateien und Doku auf Deutsch;
  Bezeichner, Kommentare und Commit-Zeilen auf Englisch, wie im Bestand.
- **Keine echten Kundendaten** in Tests, Doku oder Changelog. Beispiele heißen
  `beispiel.de` oder `web1`.
- **Kommentare sagen warum, nicht was.** Der Bestand ist so geschrieben; ein Kommentar,
  der die nächste Zeile nacherzählt, ist ein Fehler.
- **Jede Zeichenkette der Oberfläche kommt aus einer Sprachdatei**, `de_` und `en_`
  gleichzeitig, gleiche Schlüssel.
- **Jede Farbe kommt aus einer Theme-Variablen** mit Rückfallwert: `var(--cic-…, #…)`.
  Radius 3px.
- **Aufzählungswerte werden gegen `ispconfig/install/schema.sql` geprüft**, nicht geraten.
  `malwatch_scan.scan_state` ist `('clean','findings','outdated','error')` — es gibt kein
  `done`.
- **Verweise benutzen den Parameternamen, den die Zielseite liest.**
  `malwatch_site_show.php` liest `$_REQUEST['id']`.
- Nach jeder Aufgabe: `go build ./... && go vet ./... && go test ./...`, und wenn PHP
  berührt wurde, `bash ispconfig/tests/check_wiring.sh` und
  `php -l` auf jede geänderte Datei.
- Commits klein und je Aufgabe, Zweig `quarantaene`.

---

### Task 1: Der Quarantänespeicher

**Files:**
- Create: `internal/quarantine/entry.go`, `internal/quarantine/store.go`,
  `internal/quarantine/archive.go`
- Test: `internal/quarantine/store_test.go`, `internal/quarantine/archive_test.go`

**Interfaces (Produces):**

```go
package quarantine

type Entry struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"`   // RFC3339, UTC
	Domain       string `json:"domain"`
	Root         string `json:"root"`
	RelPath      string `json:"rel_path"`     // slash-separated, relative to Root
	EntryKind    string `json:"entry_kind"`   // "file" | "dir"
	Origin       string `json:"origin"`       // "manual" | "auto" | "repair"
	Reason       string `json:"reason"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Files        int    `json:"files"`
	Bytes        int64  `json:"bytes"`
	ArchiveBytes int64  `json:"archive_bytes"`
}

// Source describes what is about to be taken out of a website.
type Source struct {
	Root     string // web root, absolute
	RelPath  string // relative to Root, slash-separated
	Domain   string
	Origin   string
	Reason   string
	RuleID   string
	Severity string
}

// StoreCopy archives the source without touching it. Store archives and then
// removes it. A repair in overlay mode needs the copy without the removal.
func StoreCopy(storeRoot string, src Source) (Entry, error)
func Store(storeRoot string, src Source) (Entry, error)
func List(storeRoot string) ([]Entry, error)          // newest first
func Get(storeRoot, id string) (Entry, error)
func Restore(storeRoot, id string, force bool) error
func Delete(storeRoot, id string) error
func TotalBytes(entries []Entry) int64
```

`archive.go` hält die beiden Hälften, die sonst niemand braucht:

```go
func writeArchive(dst string, root, rel string) (files int, bytes int64, err error)
func readArchive(src string, destRoot string) error
```

**Verhalten, das der Test festhalten muss:**

- `Store` legt `<storeRoot>/<id>/payload.tar.gz` an, liest das Tar-Verzeichnis danach
  einmal vollständig zurück (Prüfung), schreibt **zuletzt** `meta.json` und entfernt erst
  dann die Quelle. Schlägt irgendetwas davor fehl, steht die Quelle noch da.
- `id` ist `time.Now().UTC().Format("20060102T150405Z")` + `-` + 8 Hex aus `crypto/rand`.
- `List` überspringt jedes Verzeichnis ohne lesbare `meta.json` (halb geschriebener
  Eintrag) und sortiert absteigend nach `ID`.
- `Restore` legt den Inhalt nach `Root + RelPath` zurück, weigert sich bei vorhandenem
  Ziel ohne `force` mit einer Meldung, die den Pfad nennt, und ruft für den Zielpfad
  `repair.InsideRoot(Root, ziel)` auf.
- `Delete` entfernt das Eintragsverzeichnis; ein unbekanntes `id` ist ein Fehler, kein
  stiller Erfolg.
- Symlinks werden als Symlinks gepackt, nie verfolgt (wie `repair.Backup`).
- Das Tar trägt Rechte, Eigentümer und Zeitstempel; `readArchive` setzt sie zurück, soweit
  der Prozess darf (`os.Chtimes`, `os.Chmod`; `Chown` nur wenn es gelingt).

**Steps:**

- [ ] Test schreiben: Datei ablegen, `List` findet sie, Quelle ist weg, `Restore` bringt
      sie mit gleichem Inhalt und gleichem Modus zurück.
- [ ] Test schreiben: Verzeichnis mit Unterverzeichnis, Symlink und leerem Ordner ablegen
      und zurückholen; `Files` und `Bytes` stimmen.
- [ ] Test schreiben: `Restore` auf vorhandenes Ziel schlägt fehl, mit `force` nicht.
- [ ] Test schreiben: ein Verzeichnis ohne `meta.json` im Speicher wird von `List`
      übersprungen.
- [ ] Tests laufen lassen (rot), `entry.go`, `archive.go`, `store.go` schreiben, Tests
      laufen lassen (grün).
- [ ] Commit: `feat(quarantine): store entries as tar with metadata`

---

### Task 2: Verschlüsseltes ZIP

**Files:**
- Create: `internal/quarantine/zipcrypt.go`, `internal/quarantine/export.go`
- Test: `internal/quarantine/zipcrypt_test.go`, `internal/quarantine/export_test.go`

**Interfaces (Produces):**

```go
// DefaultPassword is the convention security people use when they send a
// sample: every unpacker understands it, and no scanner looks inside.
const DefaultPassword = "infected"

func Export(storeRoot, id, outFile, password string) (int64, error) // returns file size
```

**Wie das ZIP entsteht** (alles Standardbibliothek):

1. Der Eintrag wird aus `payload.tar.gz` gelesen, Eintrag für Eintrag.
2. Je gewöhnlicher Datei: Klartext puffern, `crc32.ChecksumIEEE`, mit `flate` auf
   Stufe `flate.BestSpeed` komprimieren.
3. ZipCrypto: drei 32-Bit-Schlüssel (`0x12345678`, `0x23456789`, `0x34567890`), über das
   Passwort aktualisiert; zwölf zufällige Kopfbytes, deren letztes das höchstwertige Byte
   der CRC ist; danach der komprimierte Strom durch dieselbe Stromchiffre.
4. `zip.Writer.CreateRaw` mit `FileHeader{Name, Method: zip.Deflate, Flags: 0x1,
   CRC32: crc, CompressedSize64: uint64(12+len(deflated)), UncompressedSize64:
   uint64(len(plain)), Modified: hdr.ModTime}`, dann `w.Write(verschlüsselt)`.
5. Verzeichnisse werden als Einträge mit Schrägstrich am Ende und ohne Inhalt geschrieben,
   unverschlüsselt (sie tragen keine Daten).

**Verhalten, das der Test festhalten muss:**

- Der Test schreibt **einen eigenen, unabhängigen Entschlüsseler** aus der Beschreibung
  des Schlüsselplans (drei Startwerte, `updateKeys` über CRC32, das zwölfte Kopfbyte als
  Prüfbyte) und entschlüsselt damit, was `zipcrypt.go` erzeugt hat. Zwei Umsetzungen
  derselben Vorschrift, die sich treffen müssen — ein vertippter Startwert fällt auf,
  ohne dass eine Zahl aus dem Nichts im Test steht.
- Ein Rundlauf über den ganzen Weg: packen, entschlüsseln, inflaten, Klartext gleich.
- Der geschriebene Container ist ein gültiges ZIP: `zip.OpenReader` liest das
  Zentralverzeichnis, die Namen stimmen, `f.Flags&0x1 != 0`.
- Ein leerer Eintrag erzeugt ein gültiges, leeres ZIP statt eines Fehlers.

**Steps:**

- [ ] Test für die Schlüsselinitialisierung und den Rundlauf schreiben, laufen lassen (rot).
- [ ] `zipcrypt.go` schreiben (Schlüsselzustand, `updateKeys`, `decryptByte`,
      `encryptByte`), Tests grün.
- [ ] Test für `Export` schreiben: Eintrag mit zwei Dateien und einem Unterverzeichnis,
      danach `zip.OpenReader`, Namen und Flag prüfen.
- [ ] `export.go` schreiben, Tests grün.
- [ ] Kommentar an den Kopf von `zipcrypt.go`: das ist Eindämmung, keine Vertraulichkeit.
- [ ] Commit: `feat(quarantine): export an entry as a password-protected zip`

---

### Task 3: Der Befehl `quarantine`

**Files:**
- Modify: `cmd/malwatch/quarantine.go` (vollständig neu), `cmd/malwatch/usage.go`
- Test: `cmd/malwatch/quarantine_test.go`

**Interfaces (Consumes):** `internal/quarantine` aus Task 1 und 2.

**Aufrufform:**

```
malwatch quarantine add     --path=… --quarantine-dir=… --file=… [--reason=…] [--origin=…] [--domain=…] [--rule=…] [--severity=…]
malwatch quarantine list    --quarantine-dir=… [--json] [--out=…]
malwatch quarantine restore --quarantine-dir=… --id=… [--force]
malwatch quarantine delete  --quarantine-dir=… --id=…
malwatch quarantine export  --quarantine-dir=… --id=… --zip=… [--password=infected]
```

**`--out` und `--zip` sind zwei verschiedene Dinge und müssen es bleiben:** `--out` nimmt
überall den JSON-Bericht auf, auch bei `export`; `--zip` nimmt die ZIP-Datei auf. Ein
`export` bekommt vom Server beides.

- Beginnt `args[0]` mit `-` oder fehlt es, ist die Aktion `add`. Der bisherige Aufruf
  `quarantine --path=… --backup-dir=… --file=…` muss unverändert funktionieren.
- `--backup-dir` ist Zweitname von `--quarantine-dir`; ist beides gesetzt, gewinnt
  `--quarantine-dir`.
- `--file` und `--id` sind wiederholbar (`stringList` aus dem Bestand).
- **Nach jeder Aktion** wird, wenn `--json` und `--out` gesetzt sind, die vollständige
  Liste als JSON in die Ausgabedatei geschrieben:
  `{"schema":1,"generated_at":"…","entries":[…]}`. Ohne `--out` geht sie nach stdout.
- Rückgabe: `report.ExitError` bei jedem Fehlschlag, sonst 0. `add` schlägt für eine Datei
  fehl, die nicht existiert oder außerhalb der Wurzel liegt, und macht mit den übrigen
  weiter — wie bisher.
- `add` bekommt einen Grund je Aufruf, nicht je Datei; der Aufrufer schickt eine Datei
  je Grund, wenn er es genauer braucht.

**Steps:**

- [ ] Test schreiben: alter Aufruf ohne Aktionswort legt die Datei ab.
- [ ] Test schreiben: `list --json --out=…` schreibt eine Datei, deren `entries` die
      abgelegte Datei enthält.
- [ ] Test schreiben: `restore --id=…` bringt sie zurück, `delete --id=…` entfernt den
      Eintrag, danach ist `entries` leer.
- [ ] `quarantine.go` neu schreiben, `usage.go` ergänzen, Tests grün.
- [ ] Commit: `feat(cli): quarantine gains list, restore, delete and export`

---

### Task 4: Reparaturmodi

**Files:**
- Modify: `internal/repair/repair.go`, `internal/repair/plan.go`,
  `cmd/malwatch/repair.go`, `internal/report/…` (das Struct der Reparaturmeldung)
- Create: `internal/repair/overlay.go`
- Test: `internal/repair/repair_test.go` (ergänzen), `internal/repair/overlay_test.go`

**Interfaces (Produces):**

```go
type Options struct {
	Root         string
	QuarantineDir string           // war BackupDir
	StagingDir   string
	DryRun       bool
	Mode         string            // "replace" | "overlay"
	Only         []string          // "core", "plugin:elementor"; leer = alles
	NoOriginal   string            // "keep" | "quarantine"
	Domain       string
	Fetcher      *vendorfiles.Fetcher
	Progress     *progress.Writer
}

// Overlay copies newDir over oldDir, adding and replacing, leaving everything
// else in place. Ownership and mode come from the tree being written into.
func Overlay(root, oldDir, newDir string) (int, error)
```

`report.RepairElement` bekommt `QuarantineID string \`json:"quarantine_id,omitempty"\``,
`report.Repair` bekommt `Mode string \`json:"mode"\``. Neue `Outcome`-Werte
`OutcomeOverlaid = "overlaid"` und `OutcomeKept = "kept"`.

**Verhalten:**

- `Only` filtert `plan.Elements` nach `kind` bzw. `kind:slug`; ein Eintrag, der auf nichts
  passt, ist ein Fehler mit Namen (ein Tippfehler soll nicht stillschweigend alles
  überspringen).
- **Beide Modi** legen den vorhandenen Baum über `quarantine.Store` ab, mit
  `Origin: "repair"` und `Reason: "Beim Ersetzen durch das Original abgelegt"` bzw.
  `"Vor dem Darüberschreiben abgelegt"`. Die zurückgegebene `Entry.ID` steht im Bericht.
  Anschließend im Modus `replace` wie bisher `Swap`/`SwapCore`; im Modus `overlay`
  `Overlay`.
  **Achtung:** `quarantine.Store` entfernt die Quelle. Für `overlay` darf sie nicht
  entfernt werden — `Store` bekommt dafür kein zweites Verhalten, sondern `overlay` ruft
  `StoreCopy` auf. Ergänze in Task 1 nicht vorhandenes:
  `func StoreCopy(storeRoot string, src Source) (Entry, error)` — identisch, nur ohne das
  Entfernen der Quelle; `Store` ruft `StoreCopy` und entfernt danach.
- `NoOriginal == "keep"`: Element bleibt unangetastet, `Outcome = OutcomeKept`,
  `Message = "kein Original verfügbar"`, `pw.Log("warn", …)`.
- `NoOriginal == "quarantine"`: `quarantine.Store`, `Outcome = OutcomeDeleted`,
  `QuarantineID` gesetzt. `os.RemoveAll` ohne vorherige Ablage gibt es nicht mehr —
  `removeInside` entfällt.
- `cmd/malwatch/repair.go`: neue Schalter `--quarantine-dir` (Zweitname `--backup-dir`),
  `--mode`, `--only` (wiederholbar), `--no-original`, `--domain`. Ein unbekannter Wert für
  `--mode` oder `--no-original` ist ein Fehler mit der Liste der erlaubten Werte.

**Steps:**

- [ ] Test schreiben: `--mode=overlay` lässt eine fremde Datei im Elementverzeichnis
      stehen, `--mode=replace` nicht, und beide legen einen Quarantäneeintrag an.
- [ ] Test schreiben: `Only: []string{"plugin:eins"}` fasst `plugin:zwei` nicht an.
- [ ] Test schreiben: `NoOriginal: "keep"` lässt das Element stehen und meldet `kept`.
- [ ] Tests rot, `StoreCopy`, `overlay.go`, `repair.go` und `cmd/malwatch/repair.go`
      schreiben, Tests grün.
- [ ] Commit: `feat(repair): replace and overlay both archive into quarantine`

---

### Task 5: Regelkatalog nach außen

**Files:**
- Modify: `internal/rules/rule.go` bzw. wo `Rule` definiert ist, `internal/rules/catalog.go`
- Create: `cmd/malwatch/rules.go`
- Modify: `cmd/malwatch/main.go`, `cmd/malwatch/usage.go`
- Test: `internal/rules/catalog_test.go` (ergänzen), `cmd/malwatch/rules_test.go`

**Was dazukommt:** ein Feld `AutoSafe bool` an der Regelstruktur und ein Befehl

```
malwatch rules --json [--out=…]
```

der `{"schema":1,"rules":[{"id":…,"title":…,"severity":…,"auto_safe":true}]}` schreibt.

**`AutoSafe` heißt:** ein Treffer allein rechtfertigt das Verschieben der Datei, weil sie
keinen legitimen Zweck haben kann — Webshells, Nachlader, Einbindung von außen,
verschleierte Funktionsnamen. **Nicht** `auto_safe` sind Regeln, die den Ort oder die
Verpackung bewerten (`php.in_uploads`, `php.disguised_as_image`, `htaccess.*`,
`web.iframe.hidden`) — dort kann eine legitime Datei anschlagen.

**Steps:**

- [ ] Test schreiben: keine Regel unterhalb von `high` ist `auto_safe`; jede Regel mit
      `auto_safe` hat eine nicht leere `Title`; die Zahl der `auto_safe`-Regeln ist > 0.
- [ ] `AutoSafe` an der Struktur ergänzen und im Katalog setzen, Test grün.
- [ ] Test für `rules --json` schreiben, `rules.go` schreiben, verdrahten, Test grün.
- [ ] Commit: `feat(rules): mark rules that justify an automatic move`

---

### Task 6: Schema, Installer, Dateiliste

**Files:**
- Modify: `ispconfig/install/schema.sql`, `ispconfig/install/uninstall-schema.sql`,
  `ispconfig/install/installer.php`, `ispconfig/install/file.list`

**Schema** — alles über den `information_schema`-Weg, den die Datei schon benutzt:

- Neue Tabellen `malwatch_quarantine`, `malwatch_rule`, `malwatch_auto_preset` nach der
  Spaltenliste in Abschnitt 4 der Spec.
- `malwatch_config`: `auto_action enum('none','safe','critical','preset') NOT NULL
  DEFAULT 'none'`, `auto_preset_id int(11) unsigned NOT NULL DEFAULT '0'`.
- `malwatch_site`: `auto_action enum('inherit','none','safe','critical','preset') NOT NULL
  DEFAULT 'inherit'`, `auto_preset_id int(11) unsigned NOT NULL DEFAULT '0'`.
- `malwatch_action_log.action_type`: Wert `quarantine` ergänzen (MODIFY COLUMN, ebenfalls
  selbstprüfend über `information_schema.COLUMNS.COLUMN_TYPE`).
- `uninstall-schema.sql`: die drei neuen Tabellen mit abräumen.

**Installer** — `prepare_state_dir()`:

```php
// quarantine bleibt root-only: dort liegt Schadcode.
// runs und spool bekommen die Gruppe der Oberflaeche und das Setgid-Bit, damit
// neue Dateien die Gruppe erben. Ohne das konnte das Panel die Fortschrittsdatei
// nicht lesen und der Balken zaehlte bei jedem Lauf bis null.
```

- `''`, `/signatures`, `/state`, `/quarantine` → `0750`, `root:root`.
- `/runs`, `/spool` → `02750`, `root:<gruppe>`, wobei `<gruppe>` die erste vorhandene aus
  `ispconfig`, `ispapps`, `www-data` ist. Findet sich keine, bleibt `root:root` und der
  Installer schreibt eine Zeile, dass der Fortschrittszähler leer bleibt.
- Vorhandene Dateien in `runs` bekommen die Gruppe nachträglich (`chgrp` je Datei), sonst
  bleibt der laufende Auftrag unlesbar.

**file.list** — neu:

```
c:interface/malwatch_quarantine_list.php:interface/web/security/malwatch_quarantine_list.php
c:interface/malwatch_quarantine_download.php:interface/web/security/malwatch_quarantine_download.php
c:interface/malwatch_repair_start.php:interface/web/security/malwatch_repair_start.php
c:interface/templates/malwatch_quarantine_list.htm:interface/web/security/templates/malwatch_quarantine_list.htm
c:interface/templates/malwatch_repair_start.htm:interface/web/security/templates/malwatch_repair_start.htm
c:interface/lang/de_malwatch_quarantine.lng:interface/web/security/lib/lang/de_malwatch_quarantine.lng
c:interface/lang/en_malwatch_quarantine.lng:interface/web/security/lib/lang/en_malwatch_quarantine.lng
c:interface/lang/de_malwatch_repair.lng:interface/web/security/lib/lang/de_malwatch_repair.lng
c:interface/lang/en_malwatch_repair.lng:interface/web/security/lib/lang/en_malwatch_repair.lng
```

**Steps:**

- [ ] `schema.sql` ergänzen. Gegenlesen: jede Änderung an einer **bestehenden** Tabelle
      steht im `SET @mw := (SELECT IF(COUNT(*) = 0, 'ALTER …', 'DO 0') FROM
      information_schema.COLUMNS WHERE …); PREPARE stmt FROM @mw; EXECUTE stmt;
      DEALLOCATE PREPARE stmt;`-Muster der Datei, neue Tabellen als
      `CREATE TABLE IF NOT EXISTS`. Ein `ALTER TABLE` ohne diese Hülle ist ein Fehler:
      es bricht jedes zweite Update ab.
- [ ] `uninstall-schema.sql` ergänzen.
- [ ] `prepare_state_dir()` umschreiben, `php -l` grün.
- [ ] `file.list` ergänzen.
- [ ] Commit: `feat(ispconfig): quarantine tables, rule catalogue, readable run dir`

---

### Task 7: Runner, Ingest, Cron

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_runner.inc.php`,
  `ispconfig/server/lib/classes/malwatch_ingest.inc.php`,
  `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php`

**Runner** — `build_arguments()`:

- `repair`: `--quarantine-dir=<state_dir>/quarantine`, `--domain=<domain>`,
  `--mode=<options['mode'] ?: 'replace'>`, `--no-original=<options['no_original'] ?: 'keep'>`,
  je Eintrag in `options['only']` ein `--only=…`. `--backup-dir` entfällt.
- `quarantine`: `options['action']` (`add`|`restore`|`delete`|`export`) als erstes Argument,
  `--quarantine-dir=<state_dir>/quarantine`, `--json`, `--out=<result_file>`.
  Bei `add` zusätzlich `--path`, `--domain`, `--origin`, `--reason` und je Datei `--file`.
  Bei `restore`/`delete`/`export` je Eintrag `--id`.
  Bei `export` zusätzlich `--out-zip=<state_dir>/spool/<token>.zip` — **Achtung:** der
  Scanner kennt nur `--out` für den JSON-Bericht; für die ZIP-Datei heißt der Schalter
  `--zip`. Lege ihn in Task 3 so an.
- Aufrufe ohne `--progress` bleiben ohne Fortschrittsdatei; `quarantine` braucht keine.

**Ingest** — neue Methode `sync_quarantine($server_id, $entries)`:

- Zeilen dieses Servers, deren `entry_id` nicht mehr in der Liste steht, werden gelöscht.
- Neue `entry_id` werden eingefügt, mit `parent_domain_id` aus `web_domain` über die
  Domain (0, wenn nichts passt).
- Vorhandene bleiben, damit `export_token` nicht verloren geht.
- Wird nach jedem `quarantine`-Auftrag aus der Ergebnisdatei aufgerufen.
- Nach einem `repair`-Auftrag: für jedes Element mit `quarantine_id` eine Zeile einfügen,
  falls sie fehlt.
- Nach einem `export`: `export_token`, `export_bytes`, `export_ready_at = NOW()` auf der
  Zeile setzen, deren `entry_id` im Auftrag stand.

**Cron** — im vorhandenen Lauf ergänzen:

- Dateien in `<state_dir>/spool` älter als 24 Stunden löschen und die zugehörigen
  `export_token`, `export_bytes`, `export_ready_at` leeren.
- Einmal täglich `malwatch rules --json --out=<state_dir>/state/rules.json` aufrufen und
  `malwatch_rule` daraus fortschreiben (`INSERT … ON DUPLICATE KEY UPDATE`, `last_seen`).

**Steps:**

- [ ] `build_arguments()` ergänzen, `php -l` grün.
- [ ] `sync_quarantine()` schreiben und an den Auftragsabschluss hängen.
- [ ] Cron ergänzen.
- [ ] `bash ispconfig/tests/check_wiring.sh` grün.
- [ ] Commit: `feat(ispconfig): jobs for restore, delete and export`

---

### Task 8: Automatische Maßnahme

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_actions.inc.php`,
  `ispconfig/server/conf/malwatch_notification_de.txt`,
  `ispconfig/server/conf/malwatch_notification_en.txt`

**Was passiert:** Nach den Benachrichtigungen, vor dem Abschalten der Website.

```
$mode = site.auto_action === 'inherit' ? config.auto_action : site.auto_action;
```

- `none` → nichts.
- `safe` → Funde, deren `rule_id` in `malwatch_rule` mit `auto_safe = 'y'` steht.
- `critical` → Funde mit `severity = 'critical'`.
- `preset` → Funde, deren `rule_id` in den `rule_ids` des gewählten Presets steht.

Die betroffenen Pfade werden zu einem `quarantine`-Auftrag mit
`options = {action:'add', origin:'auto', reason:'Automatische Maßnahme nach dem geplanten Lauf', files:[…]}`
zusammengefasst — höchstens einer je Website und Lauf. Läuft für die Website schon ein
Auftrag, wird nichts eingereiht und das im Protokoll vermerkt.

Ein Eintrag in `malwatch_action_log` mit `action_type = 'quarantine'`,
`trigger_findings = <Anzahl>` und `detail = <die Pfade, je Zeile einer, höchstens 50>`.

Die Benachrichtigungsvorlagen bekommen einen Abschnitt, der die verschobenen Dateien
auflistet und sagt, wo sie liegen und wie man sie zurückholt.

**Steps:**

- [ ] Die Auswahl als eigene Methode `auto_paths($scan, $site, $config)` schreiben, damit
      sie ohne Nebenwirkung prüfbar ist.
- [ ] Den Auftrag einreihen und protokollieren.
- [ ] Vorlagen ergänzen, beide Sprachen.
- [ ] `php -l` grün, `check_wiring.sh` grün.
- [ ] Commit: `feat(ispconfig): move findings automatically after a scheduled scan`

---

### Task 9: Die Quarantäneseite

**Files:**
- Create: `ispconfig/interface/malwatch_quarantine_list.php`,
  `ispconfig/interface/templates/malwatch_quarantine_list.htm`,
  `ispconfig/interface/lang/de_malwatch_quarantine.lng`,
  `ispconfig/interface/lang/en_malwatch_quarantine.lng`,
  `ispconfig/interface/malwatch_quarantine_download.php`
- Modify: `ispconfig/interface/module.conf.php`,
  `ispconfig/interface/lib/malwatch_lib.inc.php`

**Aufbau** wie im abgenommenen Entwurf, Abschnitt `#quarantaene`:

- Überschrift mit der Zahl der Einträge, darunter ein Satz, der sagt, was hier liegt.
- Aktionsleiste oben: „Ausgewählte zurückholen", „Ausgewählte herunterladen",
  „Ausgewählte endgültig löschen", rechts „N von M ausgewählt · X belegt".
- Tabelle: Auswahl, Was (Art als Kennzeichen, Pfad einzeilig in Schreibmaschinenschrift),
  Website, Warum, Verschoben (Zeit und Herkunft), Größe, drei Knöpfe je Zeile.
- Fußnote: das ZIP ist passwortgeschützt, Passwort `infected`, warum.
- Zweite Fußnote: wo der Speicher liegt und dass nur gelöscht wird, was jemand löscht.

**Verhalten:**

- POST mit `csrf_token_check`, wie im Bestand.
- „Herunterladen" reiht einen `export`-Auftrag ein; solange `export_token` leer ist und ein
  Auftrag läuft, zeigt die Zeile „wird vorbereitet". Liegt ein Token vor, steht dort ein
  Verweis auf `malwatch_quarantine_download.php?token=…` mit der Größe.
- `malwatch_quarantine_download.php`: `check_module_permissions('security')`, Admin-Prüfung,
  Token gegen `malwatch_quarantine` (nicht älter als 24 Stunden), Datei aus
  `<state_dir>/spool` streamen, danach `export_token` leeren. Kein Template, keine Ausgabe
  vor den Kopfzeilen.
- Neue Helfer in `malwatch_lib.inc.php`: `malwatch_queue_quarantine_action($app, $ids,
  $action)`, `malwatch_bytes($n)` (1,4 kB / 41,8 MB, deutsches Dezimalkomma),
  `malwatch_origin_label($wb, $origin)`.
- `module.conf.php`: Eintrag „Quarantäne" zwischen „Funde" und „Prüfläufe".

**Steps:**

- [ ] Sprachdateien anlegen, beide gleich beschlüsselt.
- [ ] Vorlage schreiben, Farben aus `--cic-*` mit Rückfall, Radius 3px.
- [ ] Seite schreiben, `php -l` grün.
- [ ] Download-Endpunkt schreiben.
- [ ] `module.conf.php` ergänzen.
- [ ] `check_wiring.sh` grün, `php ispconfig/tests/render_pages.php` rendert die Seite.
- [ ] Commit: `feat(ui): the quarantine, with restore, download and delete`

---

### Task 10: Reparaturseite, Einstellungen, Detailseite

**Files:**
- Create: `ispconfig/interface/malwatch_repair_start.php`,
  `ispconfig/interface/templates/malwatch_repair_start.htm`,
  `ispconfig/interface/lang/de_malwatch_repair.lng`,
  `ispconfig/interface/lang/en_malwatch_repair.lng`
- Modify: `ispconfig/interface/malwatch_site_show.php`,
  `ispconfig/interface/templates/malwatch_site_show.htm`,
  `ispconfig/interface/malwatch_config_edit.php`,
  `ispconfig/interface/templates/malwatch_config_edit.htm`,
  `ispconfig/interface/form/malwatch_config.tform.php`,
  `ispconfig/interface/lang/{de,en}_malwatch_config.lng`,
  `ispconfig/interface/lang/{de,en}_malwatch.lng`

**Reparaturseite** wie im Entwurf, Abschnitt `#reparieren`: Rücklink auf die Website, zwei
Auswahlblöcke (Modus, fehlende Originale), die Elementtabelle aus `malwatch_software` mit
Auswahlkästchen und der Spalte „Was geschieht", der Hinweis „Nichts wird gelöscht" mit
Verweis auf die Quarantäne, unten Probelauf und Start. Der Aufruf ist
`malwatch_repair_start.php?id=<domain_id>` — derselbe Parametername, den
`malwatch_site_show.php` liest.

**Einstellungen:** ein Block „Was soll bei den nächtlichen Prüfungen automatisch
passieren?" mit vier Möglichkeiten, jede mit einem Satz, der den Preis nennt, und der Zahl
der umfassten Prüfungen aus `malwatch_rule`. Bei „eigene Auswahl" die Regelliste mit
Auswahlkästchen und einem Namensfeld zum Speichern; gespeicherte Zusammenstellungen
erscheinen danach als eigene Möglichkeit.

**Detailseite:** „Entfernen" heißt „In Quarantäne verschieben"; die beiden Reparaturknöpfe
werden ein Knopf „Herstellerdateien wiederherstellen", der auf die neue Seite führt; ein
Hinweis nennt die Zahl der Quarantäneeinträge dieser Website und verweist dorthin.

**Steps:**

- [ ] Sprachdateien, beide Sprachen, gleiche Schlüssel.
- [ ] Reparaturseite und Vorlage.
- [ ] Einstellungsblock samt Speichern eines Presets.
- [ ] Detailseite anpassen.
- [ ] `check_wiring.sh` und `render_pages.php` grün.
- [ ] Commit: `feat(ui): repair as a decision, automatic measures in the settings`

---

### Task 11: Prüfungen, Doku, Version

**Files:**
- Modify: `ispconfig/tests/check_wiring.sh`, `ispconfig/tests/render_pages.php`,
  `README.md`, `CHANGELOG.md`, `internal/version/version.go`, `ispconfig/version`,
  `docs/` (soweit die Befehlsübersicht dort steht)

**Neue Verdrahtungsprüfungen:**

- Jede `.php` und `.htm` unter `ispconfig/interface` steht in `file.list`.
- Jeder in einer Vorlage benutzte Sprachschlüssel steht in beiden Sprachdateien.
- Jeder `enum`-Wert, den PHP schreibt, steht in `schema.sql` (die vorhandene Prüfung um
  die neuen Spalten erweitern).
- Jeder `?…=`-Parameter in einem Verweis heißt so, wie die Zielseite ihn liest (Prüfung 34
  um die beiden neuen Seiten erweitern).
- Der Scanner-Schalter, den der Runner baut, existiert in `usage.go`.

**Version:** `0.10.0` in `internal/version/version.go` und `ispconfig/version`.

**CHANGELOG:** ein Abschnitt `## [0.10.0] – 2026-09-07` mit den Überschriften
„Hinzugefügt", „Geändert", „Behoben" — die Fortschrittsdatei-Rechte gehören unter
„Behoben" und müssen erklären, warum der Zähler bisher leer blieb.

**README:** der Abschnitt zu den Befehlen um `quarantine list/restore/delete/export` und
`rules` ergänzen, der Abschnitt zum Addon um die Quarantäne.

**Steps:**

- [ ] Prüfungen ergänzen, `check_wiring.sh` grün (die Zahl der Prüfungen im Kopf mitziehen).
- [ ] Version bumpen.
- [ ] CHANGELOG und README schreiben.
- [ ] `go build ./... && go vet ./... && go test ./...` grün.
- [ ] Commit: `chore: v0.10.0`
