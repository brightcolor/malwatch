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
malwatch repair --path=/var/www/web1/web --backup-dir=/var/lib/malwatch/backups/web1
```

Kern, sämtliche Plugins und sämtliche Themes werden versionsgenau durch die
Originale von wordpress.org ersetzt — der alte Ordner vorher vollständig
entfernt, denn eine abgelegte Datei überlebt nur, solange ihr Verzeichnis
überlebt. Ein Lauf danach zeigt, was übrig ist, und das ist per Definition
nicht Teil der Software.

Erst wird alles geholt und geprüft, dann gesichert, dann getauscht. Bis zum
Tauschen ist keine Datei der Website angefasst: reißt das Netz ab, kostet das
einen Lauf und keine Website. Was angefasst wird, liegt vorher als `tar.gz`
unter `--backup-dir`.

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
zurückgezogenes Release —, wird der Ordner **trotzdem** entfernt, mit Name und
Version im Protokoll und mit Sicherung. Die Website braucht danach Ersatz.

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
| 2 | fertig, aber Elemente ohne Original wurden gelöscht |
| 3 | gescheitert; kam der Abbruch vor dem Tauschen, ist die Website unverändert |

### Fortschritt mitlesen

```bash
malwatch repair --path=… --backup-dir=… --progress=/var/lib/malwatch/runs/job-8.progress
```

Die Datei enthält Phase, Element, Datei, Zähler und ein mitlaufendes Protokoll
als JSON. Sie wird geschrieben und dann umbenannt, sodass ein mitlesendes
Programm nie ein halbes Dokument sieht. `malwatch scan` kennt denselben
Schalter.

## Das ISPConfig-Addon

Für ISPConfig 3.3. Es fügt dem Modul **Websites** einen Bereich hinzu, in dem
sich Websites einzeln oder gesammelt prüfen lassen, Funde nachlesbar sind und
je Website ein Zeitplan mit Aktionen hinterlegt werden kann: Benachrichtigung
an den Betreiber, Benachrichtigung an den Kunden, Abschalten der Website.

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
