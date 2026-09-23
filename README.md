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

Geprüft wird jede Datei, und was eine Datei ist, entscheiden ihre ersten Bytes,
nicht ihre Endung. So findet der Scanner PHP, das als `.css`, `.txt` oder
`.orig` abgelegt und von anderer Stelle eingebunden wird, und Code hinter einem
Bildkopf, auch wenn die Datei keine Bildendung trägt. Die Endung entscheidet
weiter dort, wo es auf sie ankommt: ob der Webserver eine Datei ausführt, hängt
am Namen, deshalb bleibt „PHP im Upload-Verzeichnis" eine Frage der Endung.

**Veränderte Herstellerdateien.** Für WordPress werden Kern und Plugins gegen
die offiziellen Prüfsummen verglichen. Eine unveränderte Originaldatei erzeugt
keinen Fehlalarm, eine veränderte einen eigenen Befund. Verglichen wird, was
die Herstellerliste tragfähig abdeckt: `wp-admin`, `wp-includes` und die
Dateien in der Wurzel. Ausgenommen bleiben die mitgelieferten Themes unter
`wp-content`, die eigenen Aktualisierungen folgen, und `wp-config-sample.php`,
für die wordpress.org in jeder Sprache nur die englische Prüfsumme
veröffentlicht. Beide Ausnahmen gelten nur für diesen Vergleich; Signaturen
und Heuristik lesen die Dateien weiter.

`wp-admin` und `wp-includes` liefert WordPress als Ganzes aus: Was dort steht
und nicht zur Auslieferung gehört, ist auf einem anderen Weg hineingekommen.
Eine ausführbare Datei in diesen beiden Ordnern, die die Herstellerliste nicht
kennt, wird deshalb als fremd gemeldet — der Weg, auf dem etwa eine
untergeschobene `wp-admin/wp-admin.php` auffällt. Die Wurzel bleibt teilweise
bekannt: dort liegen die Konfiguration und `wp-content`, die der Website
gehören.

**Veraltete Installationen** von WordPress samt Plugins und Themes, Joomla,
Drupal, TYPO3, Contao, Nextcloud, phpMyAdmin, Matomo, MediaWiki, Shopware und
Magento, abgeglichen mit den Herstellerquellen.

**Bekannte Schwachstellen** genau der installierten Version, jede mit
CVE-Nummer, Einstufung und der Version, die sie behebt:

| Software | Quelle |
|---|---|
| WordPress, Plugins, Themes | WPVulnerability und wordpress.org, mit API-Schlüssel zusätzlich WPScan |
| Joomla | Joomla Security Centre |
| Drupal, TYPO3, phpMyAdmin, Contao, Shopware, MediaWiki, Magento 2 | OSV, Datenbank der Composer-Pakete |

Für Nextcloud, Matomo und Magento 1 gibt es keine tragfähige Quelle; ihre
Installationen tragen den Hinweis „Lücken nicht geprüft“.

Beschreiben mehrere Quellen dieselbe Lücke, erscheint sie einmal. Die
OSV-Datenbank wird als Ganzes geladen und auf dem Server durchsucht; an
WPVulnerability und WPScan gehen Name und Version der jeweiligen Komponente.
Jede Antwort bleibt einen Tag gespeichert, eine von WPScan eine Woche, weil
der kostenlose Tarif 25 Abfragen am Tag erlaubt.

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

Nur die Software abgleichen, Versionen und bekannte Lücken, mit WPScan als
zusätzlicher Quelle:

```bash
malwatch scan --path=/var/www --no-malware-scan --wpscan-token-file=/etc/malwatch/wpscan.token
```

Der Schlüssel steht in einer Datei oder in `MALWATCH_WPSCAN_TOKEN`. Als
Schalter auf der Kommandozeile wäre er für jeden Benutzer der Maschine in
`/proc` lesbar.

Alle Schalter zeigt `malwatch --help`.

### Rückgabecodes

| Code | Bedeutung |
|---|---|
| 0 | nichts gefunden |
| 1 | Funde ab der eingestellten Stufe |
| 2 | nur veraltete Software oder Software mit bekannten Lücken gefunden |
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
einzelne Elemente und ist mehrfach angebbar. Mit `@` und einem Ordner unter
`--path` gilt ein Wert allein für die Installation dort:
`--only=plugin:elementor@blog`, `--only=core@.` für die Installation in
`--path` selbst.

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

## Aktualisieren

`upgrade` bringt WordPress-Kern, Plugins und Themes auf eine Zielversion von
wordpress.org. Welche Elemente auf welche Version gehen, steht in einer
Plandatei:

```json
{"schema":1,"installs":[{"path":"/var/www/web1/web","url":"https://beispiel.de/",
  "elements":[{"kind":"core","version":"6.4.5"},{"kind":"plugin","slug":"akismet","version":"5.3.3"}]}]}
```

```
malwatch upgrade --path=/var/www/web1/web --plan=plan.json --run-as=web1:client1 \
                 --php=/usr/bin/php8.2 --quarantine-dir=/var/lib/malwatch/quarantine
```

Je Element:

1. Archiv laden, Prüfsummen und Anforderungen prüfen
2. die Datenbank exportieren, wenn ein Kern-Update sie anhebt
3. den alten Ordner in die Quarantäne legen, den neuen einsetzen, die Datenbank anheben
4. Startseite und Anmeldeseite abrufen und bei einem Fehler den alten Stand zurückholen

WP-CLI läuft als `--run-as`; root wird abgewiesen. `--dry-run` hält vor dem
Tausch an. Die Rückgabecodes stehen in `malwatch --help`.

Nach dem Tausch und nach einem Zurückholen wartet `upgrade` die Zeit aus
`--settle` (Vorgabe `3s`), bevor es die Seiten abruft: So lange führt PHP mit
OPcache die übersetzten alten Dateien weiter aus. Passend ist
`opcache.revalidate_freq` plus eine Sekunde.

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
serverweit an einer Stelle unter **Security > Scanner > Quarantäne** — über alle
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

Eine Übersicht über der Liste zählt die Einträge je Website mit ihrer Größe auf
der Platte; ein Klick auf eine Website zeigt nur deren Einträge.

Nichts räumt von selbst auf: ein Eintrag bleibt liegen, bis jemand ihn löscht
oder zurückholt. Dieselbe Ablage steht auch von der Kommandozeile aus über
`malwatch quarantine` offen (siehe oben) — das Addon bedient sie nur, es hält
keine eigene Kopie.

### Abwehr

**Security > Abwehr > Übersicht** schaltet die Web Application Firewall (ModSecurity mit dem
OWASP-Regelwerk) je Website zwischen „aus“, „mitschreiben“ und „scharf“ und wertet
ihr Audit-Log aus: Treffer je Website und Tag, Regeln mit Erklärung, Auslöser,
Einordnung und den Adressen ihrer Treffer samt Land, Provider und den Merkmalen
Tor, VPN und Rechenzentrum, einzelne Anfragen und die Vorschau, was
„scharf“ abgewiesen hätte. Ausnahmen entstehen per Knopf aus
einem Treffer. Auf dem Webserver richtet `waf/install.sh` die WAF ein, siehe
[waf/README.md](waf/README.md).

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
