# Quarantäne und Reparatur — Entwurf (Stufe 2)

**Stand:** 2026-09-07
**Vorlage:** der abgenommene Entwurf https://claude.ai/code/artifact/48b9f42c-4de1-4ebc-9cb5-429244691f94
**Baut auf:** `2026-09-07-security-bereich-design.md` (Stufe 1: eigenes Modul, Statusseite, Fortschritt)

## Warum

Nach Stufe 1 kann der Bediener sehen, was los ist. Handeln kann er kaum: „Entfernen"
kopiert die Datei in ein Verzeichnis, das niemand ansieht, und löscht sie. Was dort
liegt, ist unauffindbar, nicht zurückholbar und nicht herunterladbar. Eine Reparatur
packt den alten Baum in ein `.tar.gz` unter `backups/` — 1,1 GB auf dem Livesystem,
die kein Mensch je wieder anfasst.

Stufe 2 macht aus dem Sicherungsverzeichnis einen **Quarantänespeicher**: eine Liste
mit Namen, Datum, Größe und Grund, aus der jeder Eintrag zurückgeholt, heruntergeladen
oder endgültig gelöscht werden kann. Alles, was das Addon entfernt — einzelne Funde,
ganze ersetzte Verzeichnisse, automatisch verschobene Dateien —, landet dort und
nirgendwo sonst.

## Was dabei aufgefallen ist

Die Oberfläche kann die Fortschrittsdatei nicht lesen. `/var/lib/malwatch` ist
`0750 root:root`, die Panel-Prozesse laufen als Benutzer `ispconfig`:

```
$ sudo -u ispconfig cat /var/lib/malwatch/runs/job-100.progress
cat: … Permission denied
```

Damit kam von der ganzen Zählerarbeit aus Stufe 1 (`--expect`, Nenner, Prozentzahl)
nichts im Browser an; der Balken zeigte nur die Phasen, die die Vorlage selbst setzt.
Der Installer richtet das mit ein (Abschnitt „Verzeichnisse und Rechte").

---

## 1. Der Speicher

Wurzel: `<state_dir>/quarantine`, `0750 root:root`, außerhalb jedes Webverzeichnisses.

Ein Eintrag ist ein Verzeichnis `<store>/<id>/` mit genau zwei Dateien:

| Datei | Inhalt |
|---|---|
| `meta.json` | die Beschreibung des Eintrags |
| `payload.tar.gz` | der Inhalt, immer als gepacktes Tar |

`id` = `<UTC-Zeitstempel>-<8 Hex>`, etwa `20260907T221034Z-a3f19b2c`. Der Zeitstempel
macht die Liste im Dateisystem von selbst chronologisch, die Zufallshälfte verhindert
Kollisionen innerhalb einer Sekunde.

**Warum immer ein Tar, auch für eine einzelne Datei.** Drei Gründe, jeder für sich
ausreichend: im Tar bleiben Rechte, Eigentümer und Zeitstempel erhalten, ohne sie
neben die Nutzlast schreiben zu müssen; nichts im Speicher trägt ein x-Bit, also kann
nichts versehentlich laufen; und Datei und Verzeichnis brauchen nur einen Codepfad
statt zweier.

`meta.json`:

```json
{
  "schema": 1,
  "id": "20260907T221034Z-a3f19b2c",
  "created_at": "2026-09-07T22:10:34Z",
  "domain": "torrios.de",
  "root": "/var/www/torrios.de/web",
  "rel_path": "wp-content/plugins/elementor",
  "entry_kind": "dir",
  "origin": "repair",
  "reason": "Beim Ersetzen durch das Original abgelegt",
  "rule_id": "",
  "severity": "",
  "files": 1043,
  "bytes": 43855872,
  "archive_bytes": 9912310
}
```

`origin` ist `manual` (jemand hat geklickt), `auto` (automatische Maßnahme nach einem
geplanten Lauf) oder `repair` (eine Reparatur hat es abgelegt).

### Operationen

Paket `internal/quarantine`:

```go
type Entry struct { … die Felder aus meta.json … }

func Store(storeRoot string, src Source) (Entry, error)    // packt und entfernt die Quelle
func List(storeRoot string) ([]Entry, error)               // liest jede meta.json
func Restore(storeRoot, id string, force bool) error       // packt zurück an rel_path
func Delete(storeRoot, id string) error                    // löscht den Eintrag
func Export(storeRoot, id, outFile, password string) error // verschlüsseltes ZIP
```

`Store` schreibt erst die Nutzlast vollständig, prüft sie durch erneutes Lesen des
Tar-Verzeichnisses und entfernt die Quelle erst danach. Bricht der Vorgang vorher ab,
steht die Website unverändert da und im Speicher liegt ein unvollständiger Eintrag,
den `List` an der fehlenden `meta.json` erkennt und überspringt — `meta.json` wird
zuletzt geschrieben.

`Restore` weigert sich, ein vorhandenes Ziel zu überschreiben, außer mit `force`, und
prüft den Zielpfad wie jede andere Schreiboperation über `repair.InsideRoot`.

### Das ZIP

`Export` schreibt ein ZIP mit klassischer PKWARE-Verschlüsselung (ZipCrypto), Passwort
standardmäßig `infected`. Das ist die Übereinkunft, mit der Sicherheitsleute Proben
verschicken: jeder Entpacker versteht sie, und jeder Virenscanner lässt die Datei in
Ruhe, weil er nicht hineinsieht.

**Das ist keine Vertraulichkeit.** ZipCrypto ist gebrochen; wer den Inhalt haben will,
bekommt ihn. Der Zweck ist Eindämmung: die Probe soll den Weg zum Arbeitsplatz
überleben und dort nicht von allein laufen. So steht es auch in der Oberfläche.

Umsetzung mit der Standardbibliothek: `compress/flate` erzeugt den Datenstrom,
`hash/crc32` die Prüfsumme, der Stromchiffre-Teil sind drei 32-Bit-Schlüssel und zwölf
Kopfbytes, und `archive/zip` nimmt das Ergebnis über `Writer.CreateRaw` unverändert
entgegen. Kein Fremdpaket.

---

## 2. Die Kommandozeile

```
malwatch quarantine add     --path=… --quarantine-dir=… --file=… [--reason=…] [--origin=…] [--domain=…]
malwatch quarantine list    --quarantine-dir=… [--json] [--out=…]
malwatch quarantine restore --quarantine-dir=… --id=… [--force]
malwatch quarantine delete  --quarantine-dir=… --id=…
malwatch quarantine export  --quarantine-dir=… --id=… --out=… [--password=infected]
```

`--file` und `--id` sind wiederholbar. Fehlt das Aktionswort — beginnt das erste
Argument mit `-` —, ist die Aktion `add`; damit funktioniert der bisherige Aufruf
unverändert weiter. `--backup-dir` bleibt als Zweitname von `--quarantine-dir`
bestehen, aus demselben Grund.

Jede Aktion mit `--json --out=…` schreibt anschließend die **vollständige Liste** des
Speichers in die Ausgabedatei. Das ist die Schnittstelle, aus der das Panel seinen
Index aufbaut: eine Aktion und ihr Ergebnis in einer Datei, und weil es die ganze
Liste ist, heilt sich der Index bei jedem Auftrag selbst.

---

## 3. Reparatur

Neue Schalter für `malwatch repair`:

| Schalter | Werte | Vorgabe | Bedeutung |
|---|---|---|---|
| `--quarantine-dir` | Pfad | — | Wohin der alte Inhalt geht (Zweitname `--backup-dir`) |
| `--mode` | `replace`, `overlay` | `replace` | Wie ersetzt wird |
| `--only` | `kind[:slug]`, wiederholbar | alles | Welche Elemente angefasst werden |
| `--no-original` | `keep`, `quarantine` | `keep` | Was mit Elementen ohne Herstellerdatei geschieht |

**`replace`** — „Vollständig ersetzen". Der vorhandene Baum wandert als Eintrag in die
Quarantäne, dann kommt das Original an seine Stelle. Untergeschobene Dateien sind
damit aus dem Webverzeichnis heraus, auch die, die keine Prüfung gefunden hat.

**`overlay`** — „Darüberschreiben, nichts verschieben". Der vorhandene Baum wandert
**ebenfalls** als Eintrag in die Quarantäne — er wird nur nicht gelöscht, sondern
bleibt liegen, und die Herstellerdateien werden darübergelegt. Angepasste Vorlagen und
eigene Ergänzungen bleiben in Betrieb; eine untergeschobene Datei auch.

Dass beide Modi sichern, ist Absicht: „Nichts geht verloren" ist ein Satz, den die
Oberfläche sagt, und er muss ohne Fußnote stimmen. Der Unterschied zwischen den Modi
liegt allein darin, was danach im Webverzeichnis steht.

**`--no-original=keep`** ist die neue Vorgabe. Bisher löschte die Reparatur ein
Element, dessen Version der Hersteller nicht veröffentlicht — bezahlte Plugins, selbst
gebaute Themes. Das ist die falsche Vorgabe: die Website verliert eine Funktion, weil
eine Datei nicht öffentlich ist. Mit `quarantine` wandert das Element in die Quarantäne
statt gelöscht zu werden; `os.RemoveAll` ohne Kopie gibt es nicht mehr.

Der JSON-Bericht bekommt je Element das Feld `quarantine_id` und der Bericht ein Feld
`mode`. `outcome` kennt zusätzlich `overlaid` und `kept`.

---

## 4. Datenbank

Neue Tabelle `malwatch_quarantine` — der Index, den die Oberfläche liest:

```
quarantine_id, sys_*, server_id, parent_domain_id, domain,
entry_id      varchar(64)   -- die Kennung im Speicher
entry_kind    enum('file','dir')
rel_path      varchar(1024)
origin        enum('manual','auto','repair')
reason        varchar(255)
rule_id       varchar(128)
severity      varchar(10)
files         int unsigned
bytes         bigint unsigned
created_at    datetime
export_token  varchar(64)     -- gesetzt, sobald ein ZIP bereitliegt
export_bytes  bigint unsigned
export_ready_at datetime
UNIQUE KEY (server_id, entry_id)
```

Neue Tabelle `malwatch_rule` — der Regelkatalog des Scanners, damit die Oberfläche
Regeln beim Namen nennen kann:

```
rule_id varchar(128) PRIMARY KEY, title varchar(255), severity varchar(10),
auto_safe enum('n','y'), last_seen datetime
```

Neue Tabelle `malwatch_auto_preset` — eigene Zusammenstellungen:

```
preset_id, sys_*, preset_name varchar(64), rule_ids mediumtext, created_at
```

Neue Spalten in `malwatch_config`:

```
auto_action enum('none','safe','critical','preset') NOT NULL DEFAULT 'none'
auto_preset_id int unsigned NOT NULL DEFAULT 0
```

In `malwatch_site` dieselben Spalten, `auto_action` jedoch als
`enum('inherit','none','safe','critical','preset') DEFAULT 'inherit'`, damit eine
einzelne Website von der globalen Vorgabe abweichen kann.

`malwatch_action_log.action_type` bekommt den Wert `quarantine`.

Alle Änderungen an bestehenden Tabellen laufen über den `information_schema`-Weg, den
`schema.sql` schon benutzt: selbstprüfend, bei jeder Installation und jedem Update.

---

## 5. Serverseite

**Runner.** Der Auftrag `quarantine` liest `options['action']` (`add`, `restore`,
`delete`, `export`) und baut den passenden Aufruf. Der Auftrag `repair` reicht
`--mode`, `--only`, `--no-original` und `--quarantine-dir` durch. Beide bekommen
`--json --out=<result_file>`.

**Ingest.** Nach einem `quarantine`-Auftrag ist die Ergebnisdatei die vollständige
Liste: die Zeilen dieses Servers werden dagegen abgeglichen — was fehlt, fliegt raus,
was neu ist, kommt hinein. Nach einem `repair`-Auftrag werden die im Bericht genannten
`quarantine_id` eingefügt. Nach einem `export` werden zusätzlich `export_token`,
`export_bytes` und `export_ready_at` gesetzt.

**Automatische Maßnahme.** `malwatch_actions` bekommt einen Schritt nach den
Benachrichtigungen: steht für die Website `auto_action` auf etwas anderes als `none`,
werden die Funde des Laufs gegen die erlaubten Regeln gefiltert und als
`quarantine`-Auftrag mit `origin=auto` eingereiht. Die Liste steht in der Mail und im
Aktionsprotokoll. `safe` heißt: nur Regeln mit `auto_safe = 'y'`. `critical`: jeder
Fund der Stufe `critical`. `preset`: die Regeln der gewählten Zusammenstellung.

**Regelkatalog.** Neuer Befehl `malwatch rules --json`. Der Cron ruft ihn einmal
täglich auf und schreibt `malwatch_rule` fort. Das Feld `auto_safe` ist ein neues Feld
im Katalog des Scanners (`internal/rules`) und bedeutet: ein Treffer allein
rechtfertigt das Verschieben, weil die Datei keinen legitimen Zweck haben kann. Ein
Test hält fest, dass keine Regel unterhalb von `high` als `auto_safe` markiert ist.

---

## 6. Verzeichnisse und Rechte

`prepare_state_dir()` im Installer legt an und richtet ein:

| Verzeichnis | Rechte | Eigentümer | Warum |
|---|---|---|---|
| `<state_dir>` | `0750` | `root:root` | wie bisher |
| `signatures`, `state` | `0750` | `root:root` | wie bisher |
| `quarantine` | `0750` | `root:root` | Schadcode, nur root |
| `runs` | `2750` | `root:ispconfig` | **damit das Panel den Fortschritt lesen kann** |
| `spool` | `2750` | `root:ispconfig` | damit das Panel das ZIP ausliefern kann |

Das Setgid-Bit sorgt dafür, dass neu angelegte Dateien die Gruppe des Verzeichnisses
erben; der Scanner schreibt sie mit `0640`, also liest sie die Gruppe `ispconfig` und
sonst niemand. Gibt es die Gruppe nicht, bleibt es bei `root:root` und der Installer
sagt es — dann fehlt der Zähler, aber nichts ist kaputt.

Im Spool liegt nur, was jemand ausdrücklich angefordert hat, und der Cron räumt dort
nach 24 Stunden auf und löscht das zugehörige `export_token`.

---

## 7. Oberfläche

### Quarantäne (neu)

`malwatch_quarantine_list.php`. Die Liste aller Einträge, neueste zuerst, mit
Auswahlkästchen, Sammelaktionen oben (zurückholen, herunterladen, endgültig löschen)
und denselben drei Aktionen je Zeile. Spalten: Was (Art und Pfad), Website, Warum,
Verschoben (Zeitpunkt und Herkunft), Größe. Im Kopf steht, wie viel Platz der Speicher
belegt.

Herunterladen ist zweistufig, weil das ZIP auf dem Server entsteht: der Knopf reiht den
Auftrag ein, die Zeile zeigt „wird vorbereitet", und sobald das ZIP bereitliegt, steht
dort ein Verweis mit der Größe. Die Seite fragt den Fortschritt genauso ab wie die
Statusseite.

`malwatch_quarantine_download.php?token=…` liefert die Datei aus: Modulrecht und
Administratorprüfung wie überall, Abgleich des Tokens gegen die Tabelle,
`Content-Disposition: attachment`, danach ist das Token verbraucht.

### Reparieren (neu)

`malwatch_repair_start.php`. Was bisher zwei Knöpfe auf der Detailseite waren, wird eine
Seite mit einer Entscheidung: der Modus, der Umgang mit fehlenden Originalen, die Liste
der Elemente mit Auswahlkästchen und der Angabe, was mit jedem geschieht. Unten der
Probelauf und der Start.

Die Elementliste kommt aus `malwatch_software` des letzten Laufs. Ein Element ohne
Herstellerversion wird als solches gekennzeichnet und ist nicht vorausgewählt.

### Detailseite

Die Entfernen-Knöpfe heißen „In Quarantäne verschieben". Die Reparaturknöpfe führen auf
die neue Seite. Ein Hinweis nennt die Zahl der Einträge, die diese Website in der
Quarantäne hat, und verweist dorthin.

### Einstellungen

Ein neuer Block „Was soll bei den nächtlichen Prüfungen automatisch passieren?" mit den
vier Möglichkeiten aus dem Entwurf: nichts anfassen, eindeutige Schädlinge entfernen,
alles Kritische entfernen, eigene Auswahl. Bei „eigene Auswahl" eine Liste der Regeln
mit Auswahlkästchen, die sich unter einem Namen speichern lässt; gespeicherte
Zusammenstellungen erscheinen danach in der Auswahl.

Neben jeder Möglichkeit steht, wie viele der Prüfungen sie umfasst — gezählt aus
`malwatch_rule`, nicht fest im Text.

### Seitenleiste

Ein Eintrag „Quarantäne" mit der Zahl der gehaltenen Einträge, zwischen „Funde" und
„Prüfläufe".

---

## 8. Was diese Stufe nicht macht

- Mehrserverbetrieb: Der Download setzt voraus, dass Panel und Speicher auf demselben
  Rechner liegen. Auf einem anderen Server zeigt die Zeile den Servernamen statt des
  Verweises. Alles andere (Liste, Zurückholen, Löschen) geht über die
  Auftragswarteschlange und funktioniert verteilt.
- Kein automatisches Aufräumen nach Ablauf: Der Bericht erinnert nach 90 Tagen, gelöscht
  wird nur auf Klick.
- Die Quarantäne ersetzt `backups/` nicht rückwirkend. Was dort schon liegt, bleibt
  liegen; der Installer fasst es nicht an.

## 9. Prüfungen

- Go: Einheitstests für Packen/Entpacken, Rundlauf des verschlüsselten ZIP gegen einen
  festen Vektor, Ablehnung eines Ziels außerhalb der Wurzel, `Store` lässt bei einem
  Fehler die Quelle stehen, `--only` und `--mode` in `internal/repair`.
- `ispconfig/tests/check_wiring.sh`: jede neue Seite in `file.list`, jeder neue
  Sprachschlüssel in beiden Sprachdateien, jeder Verweis mit dem Parameternamen, den die
  Zielseite liest, jeder Aufzählungswert gegen `schema.sql`.
- `ispconfig/tests/render_pages.php` rendert die beiden neuen Seiten.
