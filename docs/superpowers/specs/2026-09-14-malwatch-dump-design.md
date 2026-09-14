# malwatch — Dump einer Website

Stand 14.09.2026. Grundlage für den Umsetzungsplan.

## Zweck

Ein Dump packt das Webverzeichnis einer Website und ausgewählte Datenbanken in
ein Archiv und stellt es im Panel zum Herunterladen bereit. Er dient dem
Sichern vor einer Reparatur, dem Umzug auf einen anderen Server und der
Übergabe an Dritte, etwa wenn ein Kunde seine Daten möchte.

Der Dump ist eine Kopie zum Mitnehmen. Das Zurückspielen bleibt Handarbeit und
gehört nicht zu dieser Stufe.

## Entscheidungen

Vom Nutzer am 14.09.2026 entschieden:

1. Inhalt: das Webverzeichnis der Website und die Datenbanken, die er beim
   Anlegen anhakt. Das Protokollverzeichnis kommt auf Wunsch dazu, ebenfalls
   über ein Häkchen je Lauf.
2. Auslöser: eine eigene Seite „Dumps“ mit einer Liste aller Dumps.
3. Aufbewahrung: 7 Tage, danach räumt der stündliche Lauf auf.
4. Format: tar.gz.
5. Weg: der Scanner packt, über einen neuen Befehl `malwatch dump` und die
   bestehende Auftragswarteschlange.
6. Download: der Verweis gilt, solange der Dump liegt, und lässt sich mehrfach
   benutzen. Er setzt eine angemeldete Administratorsitzung voraus.
7. Die Auswahl der Datenbanken zeigt je Datenbank Größe und Tabellenzahl, die
   Zuordnung zu einer gefundenen WordPress-Installation und den letzten
   Schreibzugriff. Beim Öffnen der Seite ist jede Datenbank angehakt.

## Lage auf dem Server

Gemessen am 14.09.2026 auf dem Zielserver:

- Eine Website liegt unter `web_domain.document_root`, das Webverzeichnis
  darunter als `web`, die Protokolle als `log` (eigenes Verzeichnis,
  `root:<client-gruppe>`, 0750, je Tag eine gepackte Datei).
- `web_database` führt je Datenbank `parent_domain_id`, `database_name`,
  `type` und `active`. Die größte Website dort hat 95 Datenbanken, die meisten
  haben eine. Deshalb die Auswahl mit Markierungen: bei 95 Zeilen entscheidet
  sie darüber, ob der Dump brauchbar bleibt.
- `mysqldump` (MariaDB 10.11) ist vorhanden und arbeitet als root über den
  Socket.
- `/var/lib` und `/var/www` liegen auf demselben Dateisystem, dort sind 837 GB
  von 1,5 TB frei. Eine Beispiel-Website wiegt 481 MB im Web und 2,9 MB im
  Protokoll.

Daraus folgen zwei Anforderungen: der Lauf prüft den freien Platz, bevor er
packt, und die Liste der Datenbanken kommt aus ISPConfig, statt sie zu raten.

## Teil 1 — der Befehl

### Aufruf

```
malwatch dump --path=<webverzeichnis> --archive=<datei.tar.gz>
              [--logs=<protokollverzeichnis>]
              [--db=<name> ...] [--db-defaults=<datei>]
              [--json --out=<bericht.json>] [--progress=<datei>] [--expect=<zahl>]
              [--min-free=<bytes>]
```

`--archive` nennt das Ziel, `--out` den Bericht: dieselbe Trennung wie bei
`quarantine export`, wo `--zip` das Archiv trägt und `--out` den Bericht.

### Aufbau des Archivs

```
web/…                  das Webverzeichnis, Namen relativ zu --path
protokolle/…           nur mit --logs
datenbanken/<name>.sql eine Datei je angehakter Datenbank
dump.json              der Bericht, auch im Archiv
```

Die Dateien gehen durch dieselbe Technik wie `internal/quarantine/archive.go`:
gzip über tar, Namen relativ zur Wurzel, Symlinks als Links gespeichert und
niemals verfolgt, jeder Name über `safepath` geprüft. Ein neues Paket
`internal/dump` schreibt den Strom und nimmt die Datenbanken als weitere
Einträge auf, damit alles in einem Durchgang entsteht.

### Datenbanken

Je Datenbank läuft `mysqldump --single-transaction --quick --routines --events
--triggers --default-character-set=utf8mb4 <name>`; die Ausgabe geht als
Tar-Eintrag `datenbanken/<name>.sql` in den Strom, ohne Zwischendatei auf der
Platte. Die Zugangsdaten stehen in der Datei aus `--db-defaults`, die der
Runner mit 0600 im Staging-Verzeichnis anlegt und nach dem Lauf entfernt; ohne
diesen Schalter arbeitet mysqldump als root über den Socket.

Scheitert eine Datenbank, endet der Lauf, das halbe Archiv wird gelöscht, und
der Bericht nennt Namen und Meldung. Ein Dump, dem eine Datenbank fehlt, sieht
brauchbar aus und ist es nicht.

### Platz

Vor dem ersten Byte summiert der Lauf die Größe der Quellen und vergleicht sie
mit dem freien Platz des Zielverzeichnisses. Liegt der freie Platz unter der
Summe plus einem Zehntel Reserve, endet der Lauf, bevor er etwas anlegt, und
der Bericht nennt beide Zahlen. `--min-free` hebt die Schwelle für Fälle, in
denen auf der Platte noch anderes Platz braucht.

### Fortschritt

Wie bei Prüfung, Reparatur und Update schreibt der Lauf mit `--progress` eine
Fortschrittsdatei über `internal/progress`. Nenner ist `--expect`, den das
Addon aus der Dateizahl des letzten Prüflaufs dieser Website nimmt. Die
Datenbanken zählen als je ein Schritt am Ende.

### Bericht

`dump.json` und die Datei aus `--out` tragen denselben Inhalt: Schema-Version,
Website, gepackte Wurzeln, Zahl der Dateien und Bytes, je Datenbank Name und
Bytes, Größe des Archivs, SHA256 des Archivs, Beginn und Ende, und im
Fehlerfall `reason` mit einem der Werte `space`, `database`, `files` samt
Meldung. Der Rückgabecode folgt den Codes, die `usage.go` bereits führt; den
Grund liest das Addon aus dem Bericht.

### Grenzen dieser Stufe

Ein Lauf packt eine Website. Kein Zeitplan, kein Zurückspielen, keine
Verschlüsselung, kein Ablegen auf fremdem Speicher.

## Teil 2 — das Addon

### Seite „Dumps“

Ein eigener Menüpunkt unter Security, hinter „Quarantäne“.

Oben der Kasten zum Anlegen: ein Auswahlfeld mit denselben Websites, die die
Statusseite führt, und über dieselbe Abfrage geholt, darunter die Liste der
Datenbanken dieser Website, dazu das Häkchen „Protokolle mitnehmen“ und der
Knopf „Dump erstellen“. Der Knopf fragt über den Dialog nach und nennt dabei
Website, Größe des Webverzeichnisses und Zahl der angehakten Datenbanken.

Darunter die Liste der Dumps, der jüngste zuerst: Website, angelegt am,
Zustand, Größe, Inhalt (Dateien, Datenbanken, Protokolle), gültig bis, und die
Knöpfe „Herunterladen“ und „Löschen“. Ein laufender Dump zeigt den Fortschritt
wie ein laufender Prüflauf; ein gescheiterter zeigt seine Meldung in der Zeile.

### Auswahl der Datenbanken

Je Datenbank eine Zeile mit Häkchen, Name, Größe und Tabellenzahl, darunter
die Markierungen, sobald sie bekannt sind:

```
aps5e2f16775dd25   12,4 MB  38 Tabellen
    WordPress /shop   zuletzt geschrieben 14.09.2026
web104_alt          1,1 MB  12 Tabellen
    zuletzt geschrieben 02.03.2024
web104_test         0 B     keine Tabellen
```

Beim Öffnen ist jede Datenbank angehakt; abgewählt wird, was draußen bleiben
soll. Die Umschalter „Alle auswählen“ und „Auswahl umkehren“ und der Zähler
sind dieselben wie auf der Reparaturseite, also
`templates/malwatch_selection.htm`.

Ein Wechsel der Website holt die Zeilen neu, über denselben Weg wie „Weitere
Versionen laden“ auf der Seite „Updates“: `malwatch_dump_databases.php`
liefert sie als JSON, prüft die Administratorrechte und lädt keine Vorlage.

### Woher die Angaben kommen

Der stündliche Teil von `housekeeping` bekommt `collect_databases()`:

1. Für jede Website mit Datenbanken in ISPConfig liest er über den lokalen
   `mysql`-Client als root aus `information_schema.tables` je Datenbank die
   Zahl der Tabellen, die Summe aus `data_length` und `index_length` und den
   jüngsten `update_time`.
2. Für jede WordPress-Installation, die der letzte Prüflauf dieser Website
   gemeldet hat, liest er die `wp-config.php` und nimmt `DB_NAME` heraus.
3. Beides landet in `malwatch_database`, zusammen mit `checked_at`.

Die Seite zeigt, was dort steht. Vor dem ersten Lauf nach dem Einspielen steht
dort nichts; dann zeigt die Liste Namen und Häkchen, und ihr Kopf sagt, dass
Größe und Markierungen mit dem nächsten stündlichen Lauf dazukommen.

### Auftrag

Die Seite prüft die Administratorrechte, liest `document_root` und
`system_user` der Website aus ISPConfig und nimmt die angehakten Datenbanken
entgegen. Jeder Name geht gegen die Datenbanken dieser Website
(`web_database` mit `parent_domain_id`, `active = 'y'`, `type = 'mysql'`) —
dieselbe Prüfung gegen die eigene Liste wie auf der Reparaturseite, damit ein
nachgereichter Name ins Leere läuft. Dann legt sie eine Zeile in
`malwatch_dump` mit `dump_state = 'pending'` und einem Token aus
`random_bytes(20)` an und reiht über `datalogInsert` einen Job mit
`job_kind = 'dump'` ein. `options` trägt `dump_id`, `token`, `databases` mit
den geprüften Namen und `logs`.

### Runner

`build_arguments()` bekommt einen Zweig `dump`: er legt die defaults-Datei an,
setzt `--path` auf das Webverzeichnis, `--archive` auf
`<state_dir>/dumps/<token>.tar.gz`, `--out` auf den Bericht unter `runs/`,
dazu `--progress`, `--expect`, `--json`, je Datenbank ein `--db` und mit
Häkchen `--logs`. Gestartet wird wie jeder andere Auftrag: abgekoppelt, mit
`nice` und `ionice`.

### Einlesen

`malwatch_ingest` bekommt `ingest_dump()`: Bericht lesen, bei `exit_code = 0`
die Zeile auf `done` setzen mit Bytes, Dateizahl, Datenbankzahl,
`ready_at = NOW()` und `expires_at = NOW() + 7 Tage`; sonst auf `error` mit
der Meldung aus `reason`. Fehlt das Archiv, gilt der Lauf als gescheitert.

### Aufräumen

Der stündliche Teil von `housekeeping` bekommt `clean_dumps()`: Zeilen, deren
`expires_at` vorbei ist, verlieren ihre Datei und ihren Token und werden
gelöscht; Dateien in `dumps/` ohne Zeile ebenso. Ein Dump, den jemand in der
Liste löscht, geht denselben Weg sofort.

### Herunterladen

`malwatch_dump_download.php` prüft die Administratorsitzung, nimmt den Token
aus der Adresse (`^[A-Za-z0-9_-]+$`), sucht die Zeile mit
`dump_state = 'done'` und `expires_at > NOW()`, vergleicht den Token in PHP
mit `hash_equals` und schickt die Datei mit `Content-Type: application/gzip`,
`Content-Length`, `Cache-Control: no-store` und dem Namen
`malwatch-dump-<domain>-<datum>.tar.gz`. Alle Ausgabepuffer fallen vor
`readfile()`, wie beim Quarantäne-Download. Der Token bleibt gültig, bis der
Dump abläuft.

### Schema

Neue Tabelle `malwatch_dump`: `dump_id`, die sechs `sys_`-Spalten,
`server_id`, `parent_domain_id`, `domain`, `job_id`, `dump_state`
enum('pending','running','done','error'), `token` varchar(64), `archive_path`
varchar(255), `archive_bytes` bigint, `files` int, `databases` int,
`with_logs` enum('n','y'), `error_reason` varchar(32), `job_log` text,
`created_at`, `ready_at`, `expires_at`, Schlüssel auf `token` und auf
`(server_id, dump_state)`.

Neue Tabelle `malwatch_database`: `database_id`, die sechs `sys_`-Spalten,
`server_id`, `parent_domain_id`, `database_name` varchar(64), `tables` int,
`bytes` bigint, `last_write` datetime NULL, `used_kind` varchar(16) (leer oder
`wordpress`), `used_by` varchar(255) (Pfad der Installation), `checked_at`
datetime, eindeutiger Schlüssel auf `(server_id, database_name)`, Schlüssel
auf `parent_domain_id`.

`job_kind` wächst um `dump`, über denselben selbstprüfenden Zusatz in
`information_schema`, den `schema.sql` schon für `vulncheck` und `upgrade`
benutzt.

### Ablage und Rechte

`<state_dir>/dumps`, angelegt vom Installer und von `ensure_shared_dir()`:
Verzeichnis 02750 `root:<panelgruppe>`, Dateien 0640. Damit liest das Panel
die Datei zum Ausliefern, und sonst niemand auf dem Server.

### Was im Dump steckt

Ein Dump trägt Kundendaten, in den Protokollen auch Adressen der Besucher, und
bei einer befallenen Website den Schadcode mit. Deshalb: Ablage nur für root
und das Panel, Download nur für angemeldete Administratoren, Aufbewahrung 7
Tage. Der Fußtext der Seite sagt das in einem Satz, damit beim Weitergeben
klar ist, was man weitergibt.

## Was diese Stufe ausklammert

- Zurückspielen eines Dumps.
- Zeitplan und wiederkehrende Dumps.
- Zugriff für Kunden.
- Verschlüsselung und Passwortschutz des Archivs.
- Dumps über mehrere Websites in einem Archiv.
- Ablage auf externem Speicher.
- Datenbanken, die ISPConfig der Website nicht zuordnet; die Auswahl zeigt,
  was in `web_database` steht.

## Prüfung

1. Go: Tests für `internal/dump` — Aufbau des Archivs (Namen relativ zur
   Wurzel, `web/`, `protokolle/`, `datenbanken/`), Symlink bleibt Symlink,
   Name außerhalb der Wurzel wird abgelehnt, Platzprüfung schlägt an, Bericht
   trägt Prüfsumme und Zahlen. Die Datenbank kommt über einen eingesetzten
   Befehl, damit der Test ohne Datenbank läuft.
2. PHP: Tests in `ispconfig/tests/` für die Zeilen der Datenbankauswahl
   (Größe, „keine Tabellen“, „zuletzt geschrieben“, Zuordnung) und für die
   Prüfung der angehakten Namen gegen die Liste der Website.
3. `check_wiring`: die neue Auftragsart steht in `usage.go`, jede Datei der
   neuen Seiten steht in `file.list`, der Menüpunkt zeigt auf eine vorhandene
   Seite, der Download-Verweis benutzt `token=`, die JSON-Seite lädt keine
   Vorlage und prüft die Administratorrechte, die Seite bindet Dialog und
   Auswahl ein.
4. `render_pages`: die neue Seite, die JSON-Seite und die Downloadseite
   rendern gegen die Installation.
5. Staging auf dem Server, danach ein Probelauf mit einer kleinen Website:
   Archiv entpacken, Dateizahl und Datenbank gegen das Original halten.
6. Zum Schluss ein Lauf mit einer großen Website, um Laufzeit, Last und Platz
   zu sehen, und ein Blick auf die Website mit 95 Datenbanken, damit die
   Auswahl dort lesbar bleibt.

## Auslieferung

Version 0.17.0. CHANGELOG, `ispconfig/README.md` um den Abschnitt „Dumps“,
`install/file.list` um Seite, Vorlage, Sprachdateien, JSON-Seite und
Downloadseite, `module.conf.php` um den Menüpunkt, Schema um beide Tabellen
und die Auftragsart. Deploy wie bisher: Paket, `manual_install.php`, `cmp`
jeder kopierten Datei, `render_pages` gegen die Installation.
