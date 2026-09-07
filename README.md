# malwatch

Scanner für Schadcode und veraltete Web-Software auf Webservern, der eine
befallene WordPress-Installation auch wieder auf den Auslieferungszustand
zurücksetzen kann, dazu ein Addon für ISPConfig 3.3, das ihn über die
Oberfläche bedienbar macht.

Zwei Teile in einem Repository:

| Teil | Was |
|---|---|
| `cmd/malwatch`, `internal/` | ein statisch gelinktes Go-Binary, allein lauffähig |
| `ispconfig/` | Addon nach der Extension-Struktur von ISPConfig 3.3 |

Der Scanner kennt ISPConfig nicht und läuft überall. Das Addon startet ihn,
liest seinen Bericht und zeigt die Ergebnisse an.

## Was der Scanner prüft

**Schadcode** in drei Stufen. Signaturen aus der frei verfügbaren Sammlung von
Linux Malware Detect, Hashes und Bytemuster. Eine Heuristik mit Regeln für PHP,
JavaScript, HTML und `.htaccess`: Verschleierung, Ausführung von Anfragedaten,
Webshell-Merkmale, eingeschleuste Rahmen und Weiterleitungen, PHP an Orten, wo
nur Uploads liegen dürfen. ClamAV zusätzlich, wenn es installiert ist.

**Veränderte Herstellerdateien.** Für WordPress werden Kern und Plugins gegen
die offiziellen Prüfsummen verglichen. Eine unveränderte Originaldatei erzeugt
keinen Fehlalarm, eine veränderte einen eigenen Befund. Verglichen wird, was
die Herstellerliste tragfähig abdeckt: `wp-admin`, `wp-includes` und die
Dateien in der Wurzel. Ausgenommen bleiben die mitgelieferten Themes unter
`wp-content`, die eigenen Aktualisierungen folgen, und `wp-config-sample.php`,
für die wordpress.org in jeder Sprache nur die englische Prüfsumme
veröffentlicht. Beide Ausnahmen gelten nur für diesen Vergleich; Signaturen
und Heuristik lesen die Dateien weiter.

**Veraltete Installationen** von WordPress samt Plugins und Themes, Joomla,
Drupal, TYPO3, Contao, Nextcloud, phpMyAdmin, Matomo, MediaWiki, Shopware und
Magento, abgeglichen mit den Herstellerquellen.

## Installieren

```bash
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh
malwatch update
```

Das Installationsskript lädt das Binary für die passende Architektur, prüft die
Prüfsumme und legt es unter `/usr/local/bin` ab. `malwatch update` holt die
Signaturen; ohne diesen Schritt läuft nur die Heuristik.

## Benutzen

```bash
malwatch scan --path=/var/www
```

Ein Lauf ohne Netzzugriff, nur Dateien:

```bash
malwatch scan --path=/var/www --offline --no-version-scan
```

Ein täglicher Lauf, der nur die letzten zwei Tage ansieht und den Bericht
verschickt:

```bash
malwatch scan --path=/var/www --max-age=2 --cache=/var/lib/malwatch/clean.json \
  --email=admin@example.com --min-severity=high
```

Alle Schalter zeigt `malwatch --help`.

### Rückgabecodes

| Code | Bedeutung |
|---|---|
| 0 | nichts gefunden |
| 1 | Funde ab der eingestellten Stufe |
| 2 | nur veraltete Software gefunden |
| 3 | der Lauf selbst ist gescheitert |

### Fehlalarme freigeben

```bash
malwatch whitelist --file=/var/www/web1/tool.php
```

Die Datei wird über ihre Prüfsumme freigegeben, nicht über ihren Pfad. Wird sie
verändert, meldet der Scanner sie wieder.

Eine ganze Regel abschalten geht auch, ist aber selten richtig:

```bash
malwatch scan --path=/var/www --ignore=php.eval.variable
```

## Wiederherstellen

Regeln und Signaturen finden, was sie kennen. Ein vollständiger Austausch
braucht nichts zu kennen:

```bash
malwatch repair --path=/var/www/web1/web --quarantine-dir=/var/lib/malwatch/quarantine/web1
```

(`--backup-dir` ist der alte Name desselben Schalters und funktioniert
unverändert weiter.)

Kern, sämtliche Plugins und sämtliche Themes werden versionsgenau durch die
Originale von wordpress.org ersetzt — der alte Ordner vorher vollständig
entfernt, denn eine abgelegte Datei überlebt nur, solange ihr Verzeichnis
überlebt. Ein Lauf danach zeigt, was übrig ist, und das ist per Definition
nicht Teil der Software.

Erst wird alles geholt und geprüft, dann gesichert, dann getauscht. Bis zum
Tauschen ist keine Datei der Website angefasst: reißt das Netz ab, kostet das
einen Lauf und keine Website. Was angefasst wird, landet vorher in derselben
Quarantäne, die auch `malwatch quarantine` verwaltet (siehe unten) — als
`tar.gz` unter `--quarantine-dir`, mit `restore` von dort auch von Hand
zurückholbar.

Zwei Schalter steuern den Tausch selbst. `--mode=overlay` kopiert die
Herstellerdateien nur darüber, statt den alten Ordner vorher zu leeren —
nützlich, wenn eigene Anpassungen im selben Verzeichnis liegen und erhalten
bleiben sollen, auf Kosten der Gewissheit, die ein vollständiger Austausch
gibt. `--only=core` bzw. `--only=plugin:elementor` beschränkt den Lauf auf
einzelne Elemente und ist mehrfach angebbar.

Unangetastet bleiben:

| | Warum |
|---|---|
| `wp-config.php` | Zugangsdaten, kein Original vorhanden |
| `wp-content/uploads` | Kundendaten ohne Herstellerfassung |
| `wp-content`, soweit nicht Plugin oder Theme | `languages`, `cache`, eigene Verzeichnisse |
| fremde Dateien im Webstamm | genau die soll der Lauf danach zeigen |

`wp-content/mu-plugins` wird im Bericht ausgewiesen, nicht gelöscht: dort liegt
ebenso oft legitimer Code von Hostern wie eine Hintertür.

Findet sich für ein Element kein Original — ein gekauftes Plugin, ein
zurückgezogenes Release —, bleibt der Ordner in Ruhe (`--no-original=keep`,
die Vorgabe): ein Löschen kostete sonst eine bezahlte Erweiterung, nur weil
der Hersteller sie nicht öffentlich anbietet. Mit `--no-original=quarantine`
wandert er stattdessen in dieselbe Quarantäne wie ein ersetztes Element, mit
Name und Version im Protokoll. Der Kern selbst bleibt davon immer unberührt,
ganz gleich was `--no-original` sagt — für ihn gibt es keinen sinnvollen Weg,
"das Verzeichnis" als ein Stück wegzulegen, ohne `wp-content` und
`wp-config.php` gleich mitzunehmen.

Vorher ansehen, ohne etwas zu ändern:

```bash
malwatch repair --path=/var/www/web1/web --dry-run
```

Nur WordPress. Für Joomla, TYPO3 und die übrigen gibt es keine verlässliche
Quelle für versionsgenaue Archive; sie werden im Bericht benannt und in Ruhe
gelassen.

### Rückgabecodes von repair

| Code | Bedeutung |
|---|---|
| 0 | alles durch die Originale ersetzt |
| 2 | fertig, aber Elemente ohne Original wurden gelöscht oder blieben mangels Herstellerversion unverändert stehen |
| 3 | gescheitert; kam der Abbruch vor dem Tauschen, ist die Website unverändert |

### Fortschritt mitlesen

```bash
malwatch repair --path=… --quarantine-dir=… --progress=/var/lib/malwatch/runs/job-8.progress
```

Die Datei enthält Phase, Element, Datei, Zähler und ein mitlaufendes Protokoll
als JSON. Sie wird geschrieben und dann umbenannt, sodass ein mitlesendes
Programm nie ein halbes Dokument sieht. `malwatch scan` kennt denselben
Schalter.

## Quarantäne verwalten

Was `repair` beim Tauschen ersetzt und was von Hand aus einem Fund entfernt
wird, landet nicht im Papierkorb, sondern in einer eigenen Ablage: jeder
Eintrag als `meta.json` mit den Eckdaten und `payload.tar.gz` mit dem Inhalt,
unter einer Kennung aus Zeitstempel und Zufallswert.

```bash
malwatch quarantine list --quarantine-dir=/var/lib/malwatch/quarantine/web1
```

Fehlt das Aktionswort, oder beginnt das erste Argument mit `-`, gilt `add` —
der Aufruf, den es schon vor dieser Erweiterung gab:

```bash
malwatch quarantine add --path=/var/www/web1/web \
  --quarantine-dir=/var/lib/malwatch/quarantine/web1 \
  --file=wp-content/uploads/shell.php
```

| Aktion | Was passiert |
|---|---|
| `add` | legt eine oder mehrere Dateien ab, relativ zum Webstamm |
| `list` | zeigt den Bestand, als Text oder mit `--json` |
| `restore` | legt einen Eintrag an seinen ursprünglichen Platz zurück (`--force` überschreibt ein inzwischen neu entstandenes Ziel) |
| `delete` | entfernt einen Eintrag endgültig |
| `export` | packt einen oder mehrere Einträge in ein gemeinsames ZIP |

`restore`, `delete` und `export` nehmen eine oder mehrere `--id=`, nie einen
Pfad — die Kennung, die `add` vergeben hat und `list` anzeigt.

```bash
malwatch quarantine export --quarantine-dir=… --id=20260907T101500Z-ab12cd34 --zip=probe.zip
```

Das ZIP aus `export` trägt ein Passwort, `infected` in der Vorgabe
(`--password` setzt ein anderes). Das ist die Übereinkunft, mit der
Sicherheitsleute Schadcode-Proben verschicken: jedes Packprogramm kennt sie,
kein Virenscanner nimmt die Datei deshalb unterwegs weg, und der eigene
Rechner sammelt sie beim Entpacken nicht sofort wieder ein.

## Regelkatalog ausgeben

```bash
malwatch rules --json
```

Gibt jede bekannte Regel mit Kennung, Titel und Schwere aus, dazu ob ein
Treffer allein genügt, um eine Datei automatisch in Quarantäne zu geben
(`auto_safe`) — Kandidaten dafür sind Regeln, bei denen eine Datei keinen
legitimen Zweck haben kann. Das ISPConfig-Addon liest diese Liste einmal
täglich per Cron, um Regeltitel neben ihrer Kennung anzuzeigen und eigene
Auswahlen für die automatische Maßnahme zusammenzustellen.

## Das ISPConfig-Addon

Für ISPConfig 3.3. Es bringt einen eigenen Bereich **Security** in die obere
Leiste, in dem sich Websites einzeln oder gesammelt prüfen lassen, Funde
nachlesbar sind und je Website ein Zeitplan mit Aktionen hinterlegt werden
kann: Benachrichtigung an den Betreiber, Benachrichtigung an den Kunden,
Abschalten der Website, dazu wahlweise eine automatische Maßnahme, die
verdächtige Dateien nach einem geplanten Lauf gleich in Quarantäne legt.

### Quarantäne

Was `repair` beim Tauschen ersetzt, was die automatische Maßnahme nach einem
geplanten Lauf einreiht, und was von Hand aus einem Fund entfernt wird, landet
serverweit an einer Stelle unter **Security > Quarantäne** — über alle
Websites dieses Servers hinweg, nicht nur der einen, von der ein Eintrag
stammt.

- **Zurückholen** legt einen Eintrag an seinen ursprünglichen Platz zurück.
- **Herunterladen** baut ein ZIP im Hintergrund; sobald es bereitsteht,
  erscheint ein Verweis, der 24 Stunden gilt und beim ersten Klick verbraucht
  ist. Das ZIP trägt das Passwort `infected` — die Übereinkunft, mit der
  Sicherheitsleute Schadcode-Proben verschicken. Sie hält jeden Virenscanner
  unterwegs davon ab, die Datei einfach wegzunehmen, und verhindert, dass der
  eigene Rechner sie beim Entpacken genauso einsammelt wie dieser Server sie
  gefunden hat.
- **Endgültig löschen** entfernt einen Eintrag von der Platte.

Nichts räumt von selbst auf: ein Eintrag bleibt liegen, bis jemand ihn löscht
oder zurückholt. Dieselbe Ablage steht auch von der Kommandozeile aus über
`malwatch quarantine` offen (siehe oben) — das Addon bedient sie nur, es hält
keine eigene Kopie.

Installation und Bedienung stehen in [ispconfig/README.md](ispconfig/README.md).

## Selbst bauen

```bash
make build
make test
```

Gebraucht wird Go 1.24 oder neuer. Weitere Abhängigkeiten hat das Programm
nicht.

## Herkunft der Signaturen

Die Bytemuster und Hashes stammen von Linux Malware Detect
(`cdn.rfxn.com`) und werden von `malwatch update` geladen. malwatch liefert
keine eigenen Signaturen mit. Die Prüfsummen der Herstellerdateien kommen von
`api.wordpress.org` und `downloads.wordpress.org`.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
