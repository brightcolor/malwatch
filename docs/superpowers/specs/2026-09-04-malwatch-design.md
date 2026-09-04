# malwatch — Entwurf

Stand: 04.09.2026

## Zweck

Ein offen lesbarer Ersatz für ISPProtect: ein Scanner, der Webspace auf
Schadcode und veraltete Web-Software prüft, und ein ISPConfig-Addon, das ihn
über die Oberfläche bedienbar macht.

Zwei Teile in einem Repository:

| Teil | Was |
|---|---|
| `cmd/malwatch` + `internal/` | Go-Binary, allein lauffähig, ohne ISPConfig |
| `ispconfig/` | ISPConfig-Addon, Paket nach der Extension-Struktur von 3.3 |

Der Scanner kennt ISPConfig nicht. Das Addon startet ihn, liest sein JSON und
zeigt die Ergebnisse an.

## Teil 1 — der Scanner

### Befehle

```
malwatch scan --path=/var/www [Optionen]
malwatch update
malwatch version
```

Schalter englisch, Ausgabe deutsch.

Wichtige Optionen: `--path` (mehrfach), `--exclude`, `--exclude-from`,
`--max-age`, `--min-severity`, `--json`, `--out`, `--email`, `--email-from`,
`--smtp`, `--threads`, `--no-version-scan`, `--no-malware-scan`,
`--no-clamav`, `--ignore`, `--whitelist`, `--whitelist-path`, `--cache`,
`--sig-dir`, `--quiet`.

### Dateilauf

Nebenläufig über `--threads` Arbeiter, Vorgabe: Anzahl Kerne. Symlinks werden
nicht verfolgt, Gerätegrenzen nicht überschritten. Ein Cache unter
`--cache` merkt sich Pfad, Größe, Änderungszeit und Inode zu jeder als sauber
bewerteten Datei; unverändert bleibt sie beim nächsten Lauf außen vor. Größere
Dateien als 32 MB werden nur in den ersten und letzten 512 KB geprüft.

### Stufe 1 — Signaturen

Zwei Quellen, beide frei:

- Die Hash-Liste und die Hex-Muster aus Linux Malware Detect
  (`rfxn.hdb`, `rfxn.ndb`). `malwatch update` lädt sie und legt sie unter
  `/var/lib/malwatch/signatures` ab. Hashes werden als MD5 über die ganze
  Datei geprüft, Hex-Muster über eine Aho-Corasick-Suche in einem Durchgang.
- ClamAV, falls vorhanden, als zusätzliche Stufe über `clamdscan` beziehungsweise
  `clamscan`. Fehlt ClamAV, läuft der Scan trotzdem und sagt das im Bericht.

### Stufe 2 — Heuristik

Ein Regelkatalog in `internal/rules`, je Regel eine Kennung, eine Schwere und
ein Muster. Geprüft werden PHP, JS, HTML, `.htaccess` und Dateien ohne
Endung mit PHP-Kopf.

Regelgruppen:

- Verschleierung: lange base64-Blöcke mit anschließender Ausführung, `eval`
  über `gzinflate`, `str_rot13`, `hex2bin`, `chr`-Ketten; Variablenfunktionen
  auf Anfragedaten; `preg_replace` mit `/e`; `create_function`.
- Ausführung: `system`, `exec`, `passthru`, `popen`, `proc_open`,
  Backticks mit Anteilen aus `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`.
- Webshell-Merkmale: Datei-Explorer-Formulare, Kennwortabfrage plus `eval`,
  bekannte Shell-Kopfzeilen, `assert` auf Anfragedaten.
- Einschleusung: `<iframe>` mit Nullgröße, `document.write` aus
  entschlüsselten Zeichenketten, Weiterleitungen auf fremde Hosts in
  Kopfzeilen, Miner-Skripte.
- Ort statt Inhalt: PHP in Upload-Verzeichnissen, PHP in Dateien mit
  Bildendung, `AddType`- und `php_value`-Zeilen in `.htaccess` unterhalb des
  Webroots, `auto_prepend_file` auf eine Datei im Kundenverzeichnis.

Jede Regel liefert Datei, Zeile, Regelkennung und einen kurzen Ausschnitt.
Schweren: `critical`, `high`, `medium`, `low`.

### Positivliste gegen Fehlalarme

- WordPress-Kern und Plugins werden gegen die offiziellen Prüfsummen von
  wordpress.org verglichen. Eine unveränderte Originaldatei erzeugt keinen
  Treffer. Eine veränderte Originaldatei erzeugt einen eigenen Befund
  `core.modified` mit Schwere `high`.
- Für Joomla, Drupal, TYPO3, Contao, Nextcloud, phpMyAdmin, Matomo,
  MediaWiki, Shopware und Magento baut ein wöchentlicher CI-Lauf aus den
  Release-Archiven eine SHA-256-Liste, die als Release-Anhang veröffentlicht
  und von `malwatch update` geladen wird.
- Eine örtliche Freigabeliste über `--whitelist` nimmt einzelne Dateien per
  SHA-256 dauerhaft heraus.

### Stufe 3 — Versionen

Erkennung anhand von Merkmaldateien, Version aus der jeweiligen Quelldatei.
Vergleich gegen diese Herstellerquellen, alle geprüft:

| Software | Quelle |
|---|---|
| WordPress | `api.wordpress.org/core/version-check/1.7/` |
| WordPress-Plugins und -Themes | `api.wordpress.org/plugins/info/1.2/`, `themes/info/1.2/` |
| Joomla | `update.joomla.org/core/list.xml` |
| Drupal | `updates.drupal.org/release-history/drupal/current` |
| TYPO3 | `get.typo3.org/api/v1/major/` |
| Contao, Shopware | `repo.packagist.org/p2/<paket>.json` |
| phpMyAdmin | `phpmyadmin.net/home_page/version.json` |
| Matomo | `api.matomo.org/1.0/getLatestVersion/` |
| Nextcloud, Magento | GitHub-Releases |
| MediaWiki | `releases.wikimedia.org/mediawiki/` |

Die Abfrage läuft einmal je Lauf, das Ergebnis wird 24 Stunden
zwischengespeichert. Ohne Netz meldet der Bericht die gefundenen Versionen
ohne Bewertung, statt still nichts zu sagen.

Schwachstellen zu WordPress-Plugins nur, wenn ein Wordfence-Zugangsschlüssel
gesetzt ist; die frei zugängliche Schnittstelle verlangt seit der Ablösung von
Version 2 einen Schlüssel.

### Ausgabe

Text für den Menschen, JSON für Maschinen. Das JSON hat eine
Schemaversion und diese Form:

```json
{
  "schema": 1,
  "malwatch_version": "0.1.0",
  "started_at": "...", "finished_at": "...",
  "paths": ["/var/www/clients/client4/web12/web"],
  "stats": {"files_scanned": 0, "files_skipped": 0, "bytes": 0},
  "engines": {"clamav": "1.0.7", "signatures": "2026052490478"},
  "findings": [
    {"path": "...", "line": 12, "rule": "php.eval.base64",
     "severity": "critical", "engine": "heuristic",
     "sha256": "...", "excerpt": "...", "size": 1234, "mtime": "..."}
  ],
  "software": [
    {"path": "...", "product": "wordpress", "version": "5.9",
     "latest": "6.6.2", "outdated": true, "kind": "core"}
  ],
  "errors": ["..."]
}
```

Rückgabecodes: 0 kein Fund, 1 Funde ab der eingestellten Mindestschwere,
2 nur veraltete Software, 3 Laufzeitfehler.

E-Mail-Bericht über `sendmail` oder SMTP, deutsch, mit Kopfzeile je Fundart.

## Teil 2 — das ISPConfig-Addon

### Einbindung

Paket nach der Extension-Struktur von ISPConfig 3.3: ein Verzeichnis
`/usr/local/ispconfig/extensions/malwatch` mit `version`, `install/file.list`,
`install/installer.php` und `install/schema.sql`. Der Kern übernimmt
Installieren, Aktualisieren, Ein- und Ausschalten und Entfernen über
`extension_plugin` und `extension_installer`; die Klasse
`malwatch_installer extends extension_installer_base` liefert die Haken dazu.

Nachtrag vom 05.09.2026: Das Schema heißt `schema.sql` und nicht `install.sql`.
Den Namen `install.sql` greift der Kern selbst auf und lädt die Datei über
`load_install_sql()` ein zweites Mal — mit Zugangsdaten aus `$conf['mysql']`,
die es nur während der ISPConfig-Einrichtung gibt. Auf einem laufenden System
läuft der Aufruf ohne Passwort, `mysql` fragt danach, liest die Antwort aus der
umgeleiteten SQL-Datei und scheitert am Rest. `manual_install.php` lädt das
Schema selbst, mit dem Verwaltungskonto.

Kein Eingriff in Kerndateien. Die Oberfläche hängt sich über
`interface/web/sites/lib/menu.d/malwatch.menu.php` in das vorhandene Modul
**Websites**. Das ist der Weg, den der neue Mechanismus vorsieht, und er
erspart einen eigenen Modulnamen in der Benutzertabelle. Seiten, Listen,
Formulare, Vorlagen und Sprachdateien werden als Dateien in das
`sites`-Modul kopiert, alle mit dem Namensteil `malwatch_`.

Interface-Dateien werden **kopiert** (`c:`), nicht verlinkt: relative
Einbindungen wie `require_once '../../lib/config.inc.php'` lösen hinter einem
Symlink ins Leere. Server-Modul und -Plugin werden verlinkt (`s:`),
Dienstklassen kopiert, weil `app::uses()` auf einem Produktivsystem
Symlinks stillschweigend überspringt.

Installation ohne das offizielle Repository: `install.sh` lädt das
`.pkg` aus dem GitHub-Release, entpackt es nach `extensions/malwatch` und
ruft `install/manual_install.php` auf, das die Tabellen mit den
Administrationsrechten aus `mysql_clientdb.conf` anlegt und danach
`install_extension()` aufruft. Liegt das Verzeichnis schon da, überspringt
der Kern den Download und führt nur den Installer aus.

### Tabellen

- `malwatch_config` — globale Einstellungen: Pfad zum Binary, Vorgabe für
  Zeitplan und Aktionen, Absender, Empfänger für Admin-Post, Höchstzahl
  gleichzeitiger Läufe, Aufbewahrung alter Läufe.
- `malwatch_site` — je Website: Zeitplan, Mindestschwere je Aktion, Schalter
  für Benachrichtigung an Admin und Kunde, Schalter für Deaktivieren,
  eigene Ausschlussmuster, letzter Lauf, letzter Zustand.
- `malwatch_job` — Warteschlange: `server_id`, `parent_domain_id`,
  `job_type` (`scan`, `scan_all`), `job_status`
  (`pending`, `running`, `done`, `error`), Startzeit, Ergebnisdatei, Protokoll.
- `malwatch_scan` — ein Lauf: Zeiten, geprüfte Dateien, Zahl der Funde je
  Schwere, Rückgabecode, Rohbericht als JSON.
- `malwatch_finding` — ein Fund: Pfad, Zeile, Regel, Schwere, Ausschnitt,
  SHA-256, Zustand (`open`, `ignored`, `fixed`), erstmals und zuletzt gesehen.
- `malwatch_software` — erkannte Installation je Lauf mit Version und Stand.
- `malwatch_ignore` — dauerhafte Freigaben je SHA-256 oder Pfadmuster.
- `malwatch_action_log` — was das Addon getan hat: Mail an wen, Website
  deaktiviert, mit Zeitpunkt und auslösendem Fund.

Alle Tabellen tragen die ISPConfig-Spalten `sys_userid`, `sys_groupid`,
`sys_perm_*` und `server_id`.

### Ablauf

1. Die Oberfläche legt über `datalogInsert` einen Eintrag in `malwatch_job` an.
2. Das Server-Modul meldet die Tabellenänderung, das Server-Plugin nimmt den
   Auftrag an. Es beansprucht ihn erst per bedingtem Update, damit ein zweiter
   Durchlauf des Datalogs ihn nicht ein zweites Mal startet.
3. Das Plugin startet das Binary **abgekoppelt** mit `setsid`, `nohup`, `nice`
   und `ionice`, Ausgabe in eine Ergebnisdatei unter `/var/lib/malwatch/runs`.
   `server.php` läuft sofort weiter; ein Scan über Stunden blockiert die
   Warteschlange nicht.
4. Eine Cron-Klasse `560-malwatch` läuft jede Minute und tut vier Dinge:
   fällige Zeitpläne in Aufträge übersetzen, fertige Ergebnisdateien einlesen,
   Aktionen ausführen, hängengebliebene Aufträge nach sechs Stunden abräumen.
5. Beim Einlesen werden Funde mit dem Vorlauf abgeglichen: was schon offen war,
   bleibt offen; was verschwunden ist, wird `fixed`; freigegebene Fundstellen
   bleiben `ignored`.

### Aktionen

Je Website einzeln schaltbar, jede mit eigener Mindestschwere:

- **Admin benachrichtigen** — Mail an die Adresse aus den globalen
  Einstellungen.
- **Kunde benachrichtigen** — Mail an `client.email` der Website.
- **Website deaktivieren** — `datalogUpdate` auf `web_domain` mit
  `active = 'n'`, wie es der Kern bei der Traffic-Sperre tut. Damit ist die
  Sperre im Panel sichtbar und dort auch wieder aufhebbar.

Grenzen, absichtlich eng:

- Deaktiviert wird **nur wegen neuer Funde** ab der eingestellten Schwere,
  nie wegen veralteter Software.
- Ein Lauf ohne Funde hebt eine Sperre **nicht** von selbst auf. Das
  Zurückschalten ist eine Entscheidung des Betreibers, nicht des Scanners.
- Jede Aktion steht in `malwatch_action_log`, mit dem Fund, der sie ausgelöst
  hat.
- Mailvorlagen liegen unter `server/conf/malwatch_notification_{de,en}.txt`
  und lassen sich wie beim Kern unter `conf-custom` überschreiben.

### Seiten

Alle nur für Administratoren, deutsch und englisch:

- **Übersicht** — alle Websites mit letztem Lauf, Zustand, offenen Funden,
  Zeitplan. Knopf „Jetzt prüfen" je Zeile und „Alle prüfen".
- **Website** — Funde mit Pfad, Zeile, Regel, Ausschnitt; Freigeben je Fund;
  erkannte Software mit Versionsstand; Verlauf der Läufe.
- **Funde** — über alle Websites, filterbar nach Schwere, Zustand, Regel.
- **Läufe** — Verlauf mit Dauer, Dateizahl und Ergebnis.
- **Einstellungen je Website** — Zeitplan, Aktionen, Schwellen, Ausschlüsse.
- **Globale Einstellungen** — Binary-Pfad, Vorgaben, Empfänger, Grenzen.

## Was nicht in die erste Version kommt

Quarantäne, Datenbank-Scan, Blacklist-Abfragen, Zugriff für Kunden auf die
Oberfläche, ISPConfig 3.2, mehrere Server.

## Prüfung

- Regeltests gegen selbst erzeugte Proben, je Regel ein Treffer- und ein
  Fehlalarmfall.
- Ein CI-Lauf lädt WordPress und Joomla frisch herunter und verlangt null
  Funde ab `high`. Das ist die Gegenprobe gegen den eigenen Regelkatalog.
- Ein Test verändert eine Kerndatei und verlangt genau einen
  `core.modified`-Befund.
- Versionserkennung gegen abgelegte Beispieldateien, ohne Netz.
- PHP-Syntaxprüfung über alle Addon-Dateien.

## Auslieferung

Ein Tag `vX.Y.Z` baut über GitHub Actions Binaries für linux/amd64 und
linux/arm64, die CMS-Hashliste, das Addon-Paket `malwatch.pkg` und
`SHA256SUMS`, und veröffentlicht sie als Release. Danach Installation auf dem
ISPConfig-Host und ein erster Lauf gegen eine Website.
