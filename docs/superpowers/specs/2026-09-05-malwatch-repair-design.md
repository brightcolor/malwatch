# malwatch — Wiederherstellung von Herstellerdateien

Stand: 05.09.2026

## Zweck

Eine befallene WordPress-Installation so weit auf den Auslieferungszustand
zurücksetzen, dass übrig bleibt, was fremd ist. Kern, sämtliche Plugins und
sämtliche Themes werden versionsgenau durch die Originale ersetzt — der alte
Ordner vorher vollständig entfernt, damit nichts dazwischen überlebt. Ein Lauf
des Scanners unmittelbar danach zeigt, was kein Hersteller je ausgeliefert hat.

Der Gedanke dahinter: Regeln und Signaturen finden, was sie kennen. Ein
vollständiger Austausch braucht nichts zu kennen — was danach noch dasteht, ist
per Definition nicht Teil der Software.

Damit schreibt der Scanner erstmals. Die Grenze dieser Erlaubnis ist der
wichtigste Teil dieses Entwurfs.

## Teil 1 — der Befehl

```
malwatch repair --path=/var/www/clients/client9/web130/web \
                --backup-dir=/var/lib/malwatch/backups/gameday-film.de \
                --progress=/var/lib/malwatch/runs/job-8.progress \
                --json --out=/var/lib/malwatch/runs/job-8.json
```

Weitere Schalter: `--dry-run` spielt den Lauf bis vor den ersten
Schreibvorgang durch und erzeugt den Bericht, den es würde. `--threads` wie
beim Scan. `--cache` und `--sig-dir` unverändert.

### Die sechs Phasen

| | Phase | Was passiert | Website berührt |
|---|---|---|---|
| 1 | Erkennen | `cms.Detect` liefert Kern, Plugins und Themes mit Version und Sprache | nein |
| 2 | Holen | Archive in ein Bereitstellungsverzeichnis | nein |
| 3 | Prüfen | Entpacken und gegen die Prüfsummenlisten halten | nein |
| 4 | Sichern | Jeder betroffene Ordner als `tar.gz` in die Sicherung | nein |
| 5 | Tauschen | Je Element: alter Ordner weg, geprüfter Baum an seinen Platz | **ja** |
| 6 | Nachprüfen | Das Addon hängt einen normalen Scan an | nein |

Die Phasen 1 bis 5 gehören dem Binary, Phase 6 ist ein eigener Scanauftrag mit
eigener Fortschrittsdatei. Der Fortschritt einer Wiederherstellung zählt
deshalb bis fünf, nicht bis sechs.

Der Schnitt liegt zwischen 4 und 5. Bis dorthin ist keine Datei der Website
angefasst: reißt das Netz ab oder stimmt eine Prüfsumme nicht, bricht der Lauf
ab und die Website steht unverändert da. Der Preis ist kurzzeitig doppelter
Platzbedarf für eine Installation ohne `uploads`.

**Ein Fehlschlag und ein fehlendes Original sind nicht dasselbe.** Antwortet
die Quelle mit 404, ist die Version schlicht nicht veröffentlicht — das ist eine
Tatsache über das Element, kein Fehler, und es wird nach den Regeln weiter unten
behandelt. Ein abgebrochener Download, ein Zeitüberlauf, ein Serverfehler oder
eine Prüfsumme, die nicht stimmt, sind Fehler und beenden den Lauf, bevor
irgendetwas getauscht wurde. Der Unterschied entscheidet zwischen „die Website
verliert ein Plugin" und „die Website bleibt, wie sie war".

`--dry-run` lädt und prüft vollständig — nur so weiß der Bericht, was sich
beschaffen ließe. Er hält vor Phase 5 an.

### Herkunft der Archive

| Element | Quelle |
|---|---|
| Kern, international | `wordpress.org/wordpress-<version>.zip` |
| Kern, lokalisiert | `<sprache>.wordpress.org/wordpress-<version>-<locale>.zip` |
| Plugin | `downloads.wordpress.org/plugin/<slug>.<version>.zip` |
| Theme | `downloads.wordpress.org/theme/<slug>.<version>.zip` |

Verifiziert wird gegen dieselben Listen, die der Scanner ohnehin lädt:
`api.wordpress.org/core/checksums/1.0/` für den Kern,
`downloads.wordpress.org/plugin-checksums/<slug>/<version>.json` für Plugins.

**Themes haben keine Prüfsummen-Schnittstelle.** Ein Theme lässt sich nur so
weit verifizieren, dass das Archiv vollständig geladen und entpackbar ist. Der
Bericht sagt das, statt eine Sicherheit vorzutäuschen, die es nicht gibt.

### Die Grenze

Der Scanner schreibt ausschließlich unterhalb von `--path` und `--backup-dir`.
Ein Pfad, der nach Auflösung aller Symlinks außerhalb liegt, führt zum
**Abbruch**, nicht zum Überspringen — ein Überspringen würde eine
Manipulation still hinnehmen. Diese Regel ist als Test festgenagelt.

### Was nie angefasst wird

| | Warum |
|---|---|
| `wp-config.php` | Zugangsdaten und Schlüssel, kein Original vorhanden |
| `wp-content/uploads` | Kundendaten ohne Herstellerfassung |
| `wp-content`, soweit nicht Plugin- oder Theme-Ordner | `languages`, `cache`, `upgrade`, eigene Verzeichnisse |
| Fremde Dateien im Webstamm | `.htaccess`, `robots.txt`, alles, was die Prüfsummenliste nicht nennt |

Der letzte Punkt ist Absicht: **genau diese Reste soll der anschließende Lauf
zeigen.** Räumte die Wiederherstellung sie mit ab, verlöre das Verfahren seine
Aussage.

Vom Kern werden `wp-admin/` und `wp-includes/` vollständig entfernt und neu
aufgebaut, die Dateien im Stammverzeichnis einzeln nach Namen aus der
Prüfsummenliste ersetzt.

`wp-content/mu-plugins` wird nicht gelöscht — dort liegt auch legitimer Code von
Hostern —, aber im Bericht an erster Stelle ausgewiesen. Es ist eine klassische
Stelle für Hintertüren und hat nie ein Original.

### Elemente ohne Original

Ein gekauftes Plugin, ein eigenes Theme, eine Version, die wordpress.org nicht
mehr ausliefert: der Ordner wird **trotzdem entfernt**. Die Entscheidung ist
bewusst und hat einen Preis — die Website ist danach unvollständig.

Damit sie nicht verloren ist, greift die Sicherung: vor jedem Eingriff wandert
der betroffene Ordner als Archiv in ein Verzeichnis, das das Binary unter
`--backup-dir` je Lauf mit dem Zeitstempel anlegt — das Addon übergibt
`/var/lib/malwatch/backups/<domain>`, daraus wird
`/var/lib/malwatch/backups/<domain>/2026-09-05T004102Z/`. Gesichert wird alles,
was angefasst wird, nicht nur das Unersetzliche: eine falsch erkannte Version
ist damit ebenso zurückholbar wie ein gekauftes Plugin.

Jedes solche Element steht mit **Name und Version** im Protokoll, wird im
Bericht eigens gezählt und trägt den Hinweis, dass die Website Ersatz braucht.

### Eigentümer und Rechte

Eigentümer, Gruppe und Modus werden vom ersetzten Verzeichnis abgelesen und auf
den neuen Baum übertragen. Ein Baum, der root gehört, lässt die Website auf 500
laufen oder gibt ihr falsche Schreibrechte; ein fester Standardwert würde eine
gehärtete Installation aufweichen. ACLs und SELinux liegen außerhalb dieser
Version, der Bericht sagt das.

### Wenn etwas schiefgeht

| Wann | Was passiert |
|---|---|
| Phase 1–4 | Abbruch, keine Datei berührt, Website zurückgeschaltet, Grund im Bericht |
| Kein Original | Element gelöscht, Name und Version im Protokoll, eigener Zähler, Hinweis auf die Sicherung |
| Fehler beim Tauschen | Lauf hält an. Die Sicherung liegt bereits; der Bericht nennt Archiv und Befehl zum Zurückspielen, und **die Website bleibt abgeschaltet.** Eine halb getauschte Installation darf nicht zurück ans Netz |
| Absturz des Binaries | Das Zurückschalten macht das Addon, nie der Scanner. Der bestehende Aufräumer für hängende Aufträge nach sechs Stunden greift |

## Teil 2 — der Fortschritt

Das Binary schreibt die Datei aus `--progress` alle 500 ms und bei jedem
Zustandswechsel. **Schreiben, dann umbenennen** — ein Leser sieht nie ein halbes
Dokument. Das ist die einzige Eigenschaft, auf die sich das Panel verlässt.

```json
{ "schema": 1, "kind": "repair",
  "started_at": "2026-09-05T00:41:02Z",
  "phase": "swap", "phase_index": 5, "phase_total": 5,
  "elements_done": 8, "elements_total": 14,
  "element": { "kind": "plugin", "slug": "contact-form-7", "version": "5.9.8" },
  "files_done": 412, "files_total": 1284,
  "file": "wp-content/plugins/contact-form-7/includes/mail.php",
  "log": [ { "t": "2026-09-05T00:41:22Z", "level": "ok",
             "text": "ersetzt akismet 5.3.3" } ] }
```

Alle 500 ms statt je Datei: bei 1.284 Dateien eine Handvoll Schreibvorgänge
statt tausend.

Das Feld `log` ist dasselbe, das im Bericht landet. Die laufende Anzeige und das
dauerhafte Protokoll teilen sich damit einen Mechanismus.

**Der Scan bekommt dieselbe Datei** mit `kind: "scan"` und den Dateizählern.
Heute meldet eine Prüfung „eingeplant" und dann minuten- bis stundenlang nichts.

### Anzeige im Panel

`sites/malwatch_progress.php?job_id=N` liest die Datei und gibt sie als JSON
zurück: Administratorprüfung wie überall, aber ohne Vorlagenmaschinerie, sonst
käme HTML mit. Die Website-Seite fragt alle zwei Sekunden, solange ein Auftrag
`pending` oder `running` ist, und hört bei `done` auf; kein Zeitgeber überlebt
den Seitenwechsel.

Dargestellt wird:

- eine schmale Kopfzeile mit den fünf Phasen des Binaries und, als sechster
  Schritt, dem angehängten Scan — den kennt das Addon aus seiner eigenen
  Warteschlange, nicht aus der Fortschrittsdatei,
- darunter eine Zeile je Element — Kern, Plugin, Theme — mit Version und
  Zustand: wartet, holt, geprüft, gesichert, ersetzt, gelöscht ohne Original,
  fehlgeschlagen,
- nach dem Lauf das Protokoll am Bericht, mit Zeitstempel je Zeile.

Bei einer Installation mit dreißig Plugins ist „welches gerade" die nützlichere
Auskunft als ein Prozentwert, und ein Fehlschlag steht sofort da statt erst im
Bericht.

## Teil 3 — das Addon

### Ablauf

1. Knopf **Wiederherstellen** auf der Website-Seite, mit einer Rückfrage, die
   benennt, was geschieht: welche Elemente, dass gelöscht wird, dass gesichert
   wird, dass die Website währenddessen abgeschaltet ist.
2. Website über `datalogUpdate` auf `active = 'n'`, wie es der Kern bei der
   Traffic-Sperre tut.
3. Auftrag `malwatch_job` mit `job_kind = 'repair'`.
4. Server-Plugin startet das Binary abgekoppelt, wie beim Scan.
5. Cron-Klasse liest das Ergebnis ein, schreibt `malwatch_repair` und
   `malwatch_repair_element`.
6. Bei Erfolg: Scanauftrag anhängen, danach Website in den vorherigen Zustand
   zurück. Bei Fehler beim Tauschen: abgeschaltet lassen.

Abgeschaltet wird nur für die Dauer des Laufs, und nur, weil die Installation
währenddessen unvollständig ist und eine noch erreichbare Hintertür sonst
mitschreiben könnte.

### Tabellen

- `malwatch_repair` — ein Lauf: Zeiten, Zahl der Elemente je Ausgang,
  Rückgabecode, Pfad zur Sicherung, Rohbericht als JSON.
- `malwatch_repair_element` — je Element: Art, Slug, Version, Sprache, Ausgang,
  Zahl der Dateien, Meldung.

Beide mit den ISPConfig-Spalten `sys_userid`, `sys_groupid`, `sys_perm_*` und
`server_id`, wie die übrigen.

`malwatch_job` bekommt `job_kind enum('scan','repair')`.

### Schema-Änderungen

`schema.sql` besteht aus `CREATE TABLE IF NOT EXISTS` und ändert an einer
bestehenden Tabelle nichts. Eine neue Spalte in `malwatch_job` erreicht damit
keine vorhandene Installation.

Deshalb bekommt `schema.sql` einen zweiten Teil: Änderungen, die sich selbst
prüfen, bevor sie zuschlagen — je Spalte ein Blick in `information_schema`, und
nur bei Fehlen ein `ALTER TABLE`. Das bleibt idempotent, läuft bei jeder
Installation und jedem Update mit und braucht keine Versionszählung.

## Was nicht in diese Version kommt

Andere CMS als WordPress — für Joomla, TYPO3 und die übrigen gibt es keine
verlässliche Quelle für versionsgenaue Archive. Das Säubern von
`wp-content/uploads`. Das Löschen von `mu-plugins`. Eine Wiederherstellung ohne
Betreiber, also als selbsttätige Aktion auf einen Fund hin. Mehrere Server.
Zurückspielen einer Sicherung über die Oberfläche — der Bericht nennt Archiv und
Befehl, das Zurückspielen bleibt Handarbeit.

## Prüfung

| | Was geprüft wird |
|---|---|
| 1 | Ein Symlink nach `/etc` im Baum und ein Pfad mit `..` führen zum Abbruch, nicht zum Überspringen |
| 2 | Ein vorgetäuschter Herstellerserver lässt den dritten Download scheitern — der Baum ist danach byteweise unverändert |
| 3 | Das Sicherungsarchiv existiert und enthält die alten Dateien, bevor das Verzeichnis verschwindet |
| 4 | Fehlt das Original, wird gelöscht, mit Slug und Version im Protokoll und eigenem Zähler im Bericht |
| 5 | Der ersetzte Baum trägt Eigentümer, Gruppe und Modus des alten (übersprungen, wo nicht als root gelaufen) |
| 6 | Eine Leseschleife parallel zum Lauf sieht nie ungültiges JSON |
| 7 | Die Fortschrittsdatei eines Scans trägt dieselbe Form wie die einer Wiederherstellung |

Dazu der Abnahmetest in CI, der das Verfahren als Ganzes nachrechnet. Er hat
zwei Hälften, und die erste Fassung dieses Abschnitts hatte sie verwechselt:

> WordPress 6.6.2 frisch herunterladen und vier Webshells ablegen — zwei
> **innerhalb** von Herstellerverzeichnissen (`wp-includes`, ein Plugin), zwei
> **außerhalb** (Webstamm, `uploads`). Dann `repair`, dann `scan`.
>
> Erwartung: Die beiden innerhalb sind **weg**, denn ihr Verzeichnis wurde
> vollständig ersetzt. Die beiden außerhalb sind **da** und genau das, was der
> Scan meldet — sonst nichts.

Die erste Hälfte ist der Zweck der Funktion: eine abgelegte Datei verschwindet
nur mit dem Verzeichnis, in dem sie sitzt. Die zweite ist ihre Grenze: was
außerhalb liegt, gehört dem Kunden und bleibt liegen, damit der Scan es zeigen
kann. Wer die erste falsch baut, lässt Schadcode stehen; wer die zweite falsch
baut, löscht Kundendaten.

Der CI-Lauf lädt für die Fehlalarmprüfung ohnehin schon echtes WordPress; die
Maschinerie steht.

## Auslieferung

Wie gehabt: ein Tag `vX.Y.Z` baut Binaries, CMS-Hashliste, Addon-Paket und
`SHA256SUMS`. Danach Installation auf dem Host und ein erster Lauf mit
`--dry-run` gegen eine Website, bevor zum ersten Mal wirklich getauscht wird.
