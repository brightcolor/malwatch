# malwatch

Scanner für Schadcode und veraltete Web-Software auf Webservern, dazu ein
Addon für ISPConfig 3.3, das ihn über die Oberfläche bedienbar macht.

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
keinen Fehlalarm, eine veränderte einen eigenen Befund.

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
