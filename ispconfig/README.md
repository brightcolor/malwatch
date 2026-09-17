# malwatch für ISPConfig

Addon nach der Extension-Struktur von ISPConfig 3.3. Es bringt einen
**eigenen Bereich „Security"** in der oberen Leiste, in dem Websites geprüft,
Funde nachgelesen und Zeitpläne mit Aktionen hinterlegt werden.

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
ab- und wieder anmelden, dann steht **Security** in der oberen Leiste.

Auf einem Server ohne Netzzugang scheitert nur der Download des Scanners; die
Erweiterung ist trotzdem installiert. Den Scanner dann von Hand ablegen und den
Pfad unter **Security > Scanner > Einstellungen** prüfen.

## Was wo passiert

| Ort | Aufgabe |
|---|---|
| Oberfläche | legt Aufträge in `malwatch_job` an |
| Server-Plugin | startet den Scanner abgekoppelt, wartet nicht auf ihn |
| Cron-Klasse `560-malwatch` | plant Zeitpläne ein, liest Berichte ein, führt Aktionen aus, räumt auf |
| Klasse `malwatch_waf` | liest aus der Cron-Klasse das Audit-Log der WAF ein, führt WAF-Aufträge aus, räumt auf |

Die Cron-Klasse läuft jede Minute. Eine von Hand angestoßene Prüfung startet
also innerhalb einer Minute, das Ergebnis erscheint, sobald der Lauf fertig ist.

## Schwachstellen

**Security > Scanner > Schwachstellen** gliedert nach Websites: je Website ihre
Installationen mit bekannten Lücken, die schwerste Einstufung zuerst. In der
Zeile jeder Website führen Knöpfe zu ihren Updates, zu ihren Lücken und, bei
offenen Funden, zu den Malware-Funden auf ihrer Seite. Die Seite
der Website listet die Lücken einzeln, jede mit CVE-Nummer, der Version, die
sie behebt, und einem Verweis auf ihren Eintrag.

Gefüllt wird die Liste auf zwei Wegen:

1. Jede reguläre Prüfung einer Website gleicht ihre Software ab.
2. Ein eigener Abgleich läuft einmal am Tag ab 4 Uhr für jede aktive Website.
   Er führt allein die Softwarestufe des Scanners aus: erkennen und
   nachschlagen. Bis zu drei Abgleiche laufen gleichzeitig, zusätzlich zu den
   eingestellten gleichzeitigen Prüfungen. Der Knopf **Alle Websites jetzt
   abgleichen** stößt die Runde sofort an.

Unter **Security > Scanner > Einstellungen** lässt sich der Abgleich abschalten und ein
WPScan-API-Schlüssel eintragen. Der Runner legt den Schlüssel als
`state/wpscan.token` mit Rechten 0600 ab und übergibt dem Scanner nur den
Dateinamen. Laut WPScan braucht einen Enterprise-Tarif, wer die Daten in einen
Dienst für Kunden einbindet.

## Updates

Die Seite **Updates** einer Website gliedert nach WordPress-Installation und
listet je Ordner Kern, Plugins und Themes mit neuerer Version bei wordpress.org.
Jede Zeile bietet jede veröffentlichte Version über der installierten an:
vorgewählt ist die neueste passende, markiert die kleinste, die alle bekannten
Lücken schließt. Die Liste der Versionen liefert der tägliche Abgleich. Das
Feld zeigt zuerst eine kurze Auswahl, dazu die neueste Version jeder der fünf
neuesten Hauptversionen; „Weitere Versionen laden …“ holt die übrigen.
Die Seite startet ohne Auswahl; der Verweis „Aktualisieren“ einer Softwarezeile
hakt dieses Element an. Jeder Ordner hat Probelauf und Start für seine
angehakten Elemente, die Knöpfe unter der Liste gelten für alle Ordner. Die
Reparaturseite ist genauso nach Ordnern gegliedert.
Der Runner schreibt eine Plandatei und startet `malwatch upgrade` als Benutzer
der Website mit ihrer PHP-Version; die Nachprüfung verbindet sich mit der IP des
Vhosts. Vor der Nachprüfung wartet malwatch `opcache.revalidate_freq` des
PHP-FPM-Pools plus eine Sekunde; den Wert liest der Runner aus php.ini, conf.d
und der Pool-Datei der Website. Prüft OPcache dort keine Zeitstempel, lehnt der
Runner das Update ab.

Scheitert die Nachprüfung, holt malwatch den alten Stand zurück und meldet es
dem Betreiber, bei eingeschaltetem „Kunde benachrichtigen“ auch dem Kunden. Den
Pfad zu WP-CLI trägt **Security > Scanner > Einstellungen**.

## Dumps

**Security > Scanner > Dumps** packt eine Website in ein `tar.gz`: das Webverzeichnis,
die angehakten Datenbanken und auf Wunsch das Protokollverzeichnis.

Die Auswahl zeigt je Datenbank ihre Größe, die Zahl der Tabellen, die
WordPress-Installation, zu der sie gehört, und den letzten Schreibzugriff.
Diese Angaben sammelt der stündliche Lauf; nach dem Einspielen stehen sie ab
seinem ersten Durchgang bereit.

Im Archiv liegen `web/`, mit Häkchen `protokolle/`, je Datenbank
`datenbanken/<name>.sql` und der Bericht `dump.json` mit Zahlen und Prüfsumme.

Ein Dump liegt sieben Tage unter `/var/lib/malwatch/dumps`, lesbar für root und
das Panel. Der Verweis zum Herunterladen gilt so lange und lässt sich mehrfach
benutzen; danach räumt der stündliche Lauf Archiv und Zeile weg. „Löschen“ in
der Liste nimmt die Zeile sofort heraus, das Archiv holt derselbe Lauf.

Vor dem Packen vergleicht der Lauf die geschätzte Größe mit dem freien Platz
und hält an, wenn es eng wird. Ein Dump trägt Kundendaten, in den Protokollen
die Adressen der Besucher und bei einer befallenen Website den Schadcode.

### Öffentlich freigeben

„Öffentlich freigeben“ in der Zeile eines fertigen Dumps legt einen zweiten
Verweis mit 40 Zeichen Zufall an, der ohne Anmeldung funktioniert — gedacht für
die Übergabe an den Kunden. Dabei wählst du, wie lange er gilt: solange der
Dump liegt, 24 Stunden oder ein einziger Abruf. Ein Passwort ist möglich; das
Panel schlägt eines vor, gespeichert wird nur sein Hash.

Jeder Abruf steht mit Zeit und Adresse in der Zeile. „Freigabe aufheben“ macht
den Verweis sofort ungültig und lässt Dump und Panel-Download unberührt.

## Abwehr

**Security > Abwehr > Übersicht** zeigt die WAF aller Websites dieses Servers. Die Seite füllt
sich, sobald `waf/install.sh` ModSecurity im nginx eingerichtet hat
([waf/README.md](../waf/README.md)).

| Zustand | Wirkung |
|---|---|
| aus | die Website läuft ohne WAF |
| mitschreiben | Treffer landen im Audit-Log, die Anfragen gehen durch |
| scharf | Anfragen über der Punktgrenze bekommen 403 |

- **Übersicht:** alle aktiven Websites mit Zustand, Treffern, „wäre abgewiesen“ und
  häufigster Regel; Mehrfachauswahl für den Zustand, dazu „Notaus“ und der Knopf für
  die Seitenantwort.
- **Website:** Schalter mit Vorschau für „scharf“, Verlauf, Regeln mit Erklärung,
  Auslösern, Einordnung und Adressen, Pfade, einzelne Anfragen (ein Klick auf eine
  Adresse filtert sie), ihre Ausnahmen und das Formular „Ausnahme anlegen“.
- **Ausnahmen:** alle Ausnahmen mit Zustand und Fehlergrund, gefiltert nach Zustand
  und Website.
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zahl der Einzeltreffer für die Regel-Karten, Herkunft der Adressen, Zeilen je
  Durchgang, Frist für den vhost.

Jeder Knopf legt einen Auftrag in `malwatch_job` mit `job_kind = 'waf'` an. Die
Cron-Klasse ruft jede Minute `malwatch_waf` auf: Sie liest höchstens so viele Zeilen
des Audit-Logs wie eingestellt (Lesestand je Server in
`/var/lib/malwatch/waf/reader.json`) und führt einen Auftrag nach dem anderen aus.
Ein Zustandswechsel läuft über das Feld „nginx-Direktiven“: Der Auftrag schreibt es,
wartet auf den vhost von ISPConfig, prüft `nginx -t` und bestätigt den Zustand. Nach
der Frist nimmt er seine Änderung zurück, sofern niemand das Feld inzwischen geändert
hat.

Dateien unter `/etc/nginx/waf` ändern sich nur über eine Kopie,
`modsec-rules-check`, `nginx -t` und einen Reload; der letzte geprüfte Stand liegt
unter `/var/lib/malwatch/waf/last-good/`. Der stündliche Wächter `waf-guard` legt ihn
zurück, wenn `nginx -t` eine Datei der WAF nennt, und schaltet auf den harten Notaus,
wenn das Modul fehlt.

Einzelne Anfragen enthalten Besucheradressen, Kopfzeilen und Anfrageinhalte und
bleiben so lange wie eingestellt; Werte von `Cookie` und `Authorization` werden vor
dem Speichern entfernt. Die Tageszahlen enthalten keine Adressen. Seitenantworten
liegen gepackt unter `/var/lib/malwatch/waf/responses/`, lesbar für root und das
Panel, und öffnen im Panel ausschließlich als Text.

Die Erklärungen der Regeln stehen in `interface/lang/de_malwatch_waf_rules.lng` und
`en_malwatch_waf_rules.lng`, im Format der Sprachdateien von ISPConfig: je Regel
`rule_<id>_title`, `rule_<id>_what` und `rule_<id>_class`, bei Bedarf
`rule_<id>_note` und `rule_<id>_trigger`, je Gruppe `group_<nnn>_what` und
`group_<nnn>_class`. `tests/waf_rules_catalog_test.php` prüft den Katalog gegen die
Regelliste `tests/fixtures/crs-3.3.5-pl1-rule-ids.txt`; ein neuer Regelsatz braucht
eine neue Liste und die passenden Einträge.

Die Herkunft einer Adresse kommt aus Listen, die der Server selbst lädt: DB-IP Lite
oder MaxMind GeoLite2 (Land und Provider), die Liste des Tor-Projekts und die
X4BNet-Listen (VPN und Rechenzentren). Jede Quelle steht einzeln in den
Einstellungen und beginnt auf „aus“. Der Auftrag `origin_update` baut jede Liste in
eine Bereichsdatei unter `/var/lib/malwatch/waf/origin/` um und tauscht sie erst
nach der Plausibilitätsprüfung; `malwatch_waf_origin_source` hält den Stand je
Quelle. Beim Einlesen schlägt der Cron jede neue Adresse in den Bereichsdateien
nach und legt das Ergebnis in `malwatch_waf_ip` ab. Die Zeile verschwindet mit dem
letzten Treffer der Adresse. Ein Lizenzschlüssel steht nie in einem Auftrag,
Protokoll oder Fehlertext.

## Aktionen

Je Website einzeln schaltbar, jede mit eigener Mindeststufe:

- **Betreiber benachrichtigen** an die Adresse aus den Einstellungen
- **Kunde benachrichtigen** an die Adresse des Kunden
- **Website abschalten** über denselben Weg, den ISPConfig bei einer
  Traffic-Sperre nimmt

Drei Grenzen sind fest eingebaut:

1. Nur Funde, die seit dem letzten Lauf neu sind, lösen eine Aktion aus.
2. Veraltete Software und bekannte Lücken schalten nie eine Website ab und
   verschieben keine Datei in die Quarantäne.
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

Der Weg über die Kommandozeile muss **als root** laufen: die Erweiterung
löscht ihre zwanzig Tabellen selbst, und das Verwaltungskonto dafür steht in
`mysql_clientdb.conf`, die nur root lesen darf. Über **System > Extensions**
im Panel bleiben die Tabellen deshalb stehen; die Erweiterung druckt in dem
Fall die nötigen `DROP`-Anweisungen aus.

Das Arbeitsverzeichnis `/var/lib/malwatch` bleibt stehen. Es enthält die
Signaturen und die Berichte vergangener Läufe; wer die nicht mehr braucht,
löscht es von Hand.

## Aufbau

```
install/          file.list, installer.php, Schema, manual_install.php
interface/        Seiten, Listen, Formulare, Vorlagen, Sprachdateien
server/           Modul, Plugin, Dienstklassen, Cron-Klasse, Mailvorlagen
```

Die Oberfläche läuft in einem eigenen Modul namens **security** unter
`interface/web/security/`. Der Modulname ist in `sys_user.modules`
eingetragen und in `interface/module.conf.php` konfiguriert, so dass der Punkt
in der oberen Leiste erscheint. (Früher hing die Oberfläche als
Navigationsgruppe in der Seitenleiste eines fremden Moduls, eingetragen über
eine Menüdatei; beides entfällt.)

Interface-Dateien werden kopiert, nicht verlinkt: die Seiten binden über
relative Pfade ein, und hinter einem Symlink zeigen die ins Leere.
Dienstklassen werden ebenfalls kopiert, weil `app::uses()` auf einem
Produktivsystem Symlinks stillschweigend überspringt.
