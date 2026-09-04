# malwatch für ISPConfig

Addon nach der Extension-Struktur von ISPConfig 3.3. Es fügt dem Modul
**Websites** einen Bereich hinzu, in dem Websites geprüft, Funde nachgelesen
und Zeitpläne mit Aktionen hinterlegt werden.

## Voraussetzungen

- ISPConfig 3.3 auf dem Master und auf jedem Webserver
- der Scanner `malwatch` auf jedem Webserver, üblicherweise unter
  `/usr/local/bin/malwatch`
- optional ClamAV mit `clamdscan`

## Installieren

```bash
mkdir -p /usr/local/ispconfig/extensions
cd /usr/local/ispconfig/extensions
curl -fsSLO https://github.com/brightcolor/malwatch/releases/latest/download/malwatch.pkg
mkdir -p malwatch && cd malwatch && unzip -o ../malwatch.pkg && rm -f ../malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php
```

Das Skript legt die Tabellen an, verlinkt beziehungsweise kopiert die Dateien
nach `/usr/local/ispconfig` und lädt Scanner und Signaturen nach. Danach einmal
ab- und wieder anmelden, dann steht **Websites > malwatch** im Menü.

Auf einem Server ohne Netzzugang scheitert nur der Download des Scanners; die
Erweiterung ist trotzdem installiert. Den Scanner dann von Hand ablegen und den
Pfad unter **Einstellungen** prüfen.

## Was wo passiert

| Ort | Aufgabe |
|---|---|
| Oberfläche | legt Aufträge in `malwatch_job` an |
| Server-Plugin | startet den Scanner abgekoppelt, wartet nicht auf ihn |
| Cron-Klasse `560-malwatch` | plant Zeitpläne ein, liest Berichte ein, führt Aktionen aus, räumt auf |

Die Cron-Klasse läuft jede Minute. Eine von Hand angestoßene Prüfung startet
also innerhalb einer Minute, das Ergebnis erscheint, sobald der Lauf fertig ist.

## Aktionen

Je Website einzeln schaltbar, jede mit eigener Mindeststufe:

- **Betreiber benachrichtigen** an die Adresse aus den Einstellungen
- **Kunde benachrichtigen** an die Adresse des Kunden
- **Website abschalten** über denselben Weg, den ISPConfig bei einer
  Traffic-Sperre nimmt

Drei Grenzen sind fest eingebaut:

1. Nur Funde, die seit dem letzten Lauf neu sind, lösen eine Aktion aus.
2. Veraltete Software schaltet nie eine Website ab.
3. Ein sauberer Lauf schaltet eine gesperrte Website nicht von selbst wieder
   ein. Das bleibt eine Entscheidung des Betreibers.

Jede ausgeführte Aktion steht mit ihrem Auslöser im Protokoll auf der Seite der
Website.

## Mailvorlagen anpassen

Die Vorlagen liegen unter `/usr/local/ispconfig/server/conf/`:

```
malwatch_notification_de.txt          an den Betreiber
malwatch_client_notification_de.txt   an den Kunden
```

Eine Kopie unter `/usr/local/ispconfig/server/conf-custom/mail/` wird
bevorzugt und übersteht ein Update. Verfügbare Platzhalter: `{domain}`,
`{hostname}`, `{scan_time}`, `{scan_path}`, `{count}`, `{worst}`,
`{files_scanned}`, `{outdated}`, `{findings}`.

## Entfernen

Im Panel unter **System > Extensions** deinstallieren, oder von Hand:

```bash
php -r '
  require "/usr/local/ispconfig/server/lib/config.inc.php";
  define("SCRIPT_PATH", "/usr/local/ispconfig/server");
  require SCRIPT_PATH."/lib/app.inc.php";
  $app->uses("extension_installer");
  $app->load("extension_installer_base");
  $app->extension_installer->uninstall_extension("malwatch");
'
```

Das Arbeitsverzeichnis `/var/lib/malwatch` bleibt stehen. Es enthält die
Signaturen und die Berichte vergangener Läufe; wer die nicht mehr braucht,
löscht es von Hand.

## Aufbau

```
install/          file.list, installer.php, Schema, manual_install.php
interface/        Seiten, Listen, Formulare, Vorlagen, Sprachdateien
server/           Modul, Plugin, Dienstklassen, Cron-Klasse, Mailvorlagen
```

Die Oberfläche hängt sich über `interface/web/sites/lib/menu.d/` in das
vorhandene Modul **Websites**. Ein eigener Modulname müsste in
`sys_user.modules` eingetragen werden, also in Kerndaten; der Weg über
`menu.d` kommt ohne diesen Eingriff aus.

Interface-Dateien werden kopiert, nicht verlinkt: die Seiten binden über
relative Pfade ein, und hinter einem Symlink zeigen die ins Leere.
Dienstklassen werden ebenfalls kopiert, weil `app::uses()` auf einem
Produktivsystem Symlinks stillschweigend überspringt.
