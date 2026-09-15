# WAF für web.herkules — Design

Stand: 16.09.2026. Abgestimmt mit Mathias in vier Abschnitten.

## 1. Ziel und Rahmen

web.herkules bekommt eine Web Application Firewall im nginx: ModSecurity als Modul,
dazu das Regelwerk OWASP CRS. Die WAF ist je Website schaltbar. In diesem Auftrag
laufen alle 33 WordPress-Websites im Mitschreib-Modus, damit die Fehlalarme sichtbar
werden. Blockiert wird in diesem Auftrag nirgends.

Umgebung: Ubuntu 24.04, nginx 1.24.0 mit `--with-compat`, ISPConfig 3.3.1p1,
55 aktive Websites, 8 CPUs, 15 GB Arbeitsspeicher. Die Liste der WordPress-Websites
steht im Serverprotokoll `web.herkules.bright-color.de.md`.

## 2. Harte Vorgabe: Verfügbarkeit

Vorgabe von Mathias: **Der Webserver darf niemals ausfallen.** Diese Vorgabe steht
über allen anderen Zielen dieses Designs. Daraus folgt:

1. Änderungen an der Konfiguration werden erst nach `nginx -t` übernommen, und nginx
   wird ausschließlich neu geladen (`reload`), niemals neu gestartet.
2. Die Konfiguration bleibt zu jedem Zeitpunkt gültig, damit auch ein Neustart durch
   Reboot oder Paketaktualisierung sicher bleibt.
3. Die Direktive `modsecurity` steht nur in vhosts, solange das Modul installiert ist.
   Beide Pakete werden mit `apt-mark hold` gegen automatisches Entfernen gesichert.
4. Ein Wächter prüft stündlich `nginx -t`. Schlägt der Test wegen der WAF fehl,
   schaltet er die WAF global aus und lädt nginx neu.
5. Jede Stufe der Einführung hat Abbruchgrenzen (Abschnitt 9). Beim Überschreiten
   wird zurückgeschaltet, bevor weitergemacht wird.

## 3. Entscheidungen

| Frage | Entscheidung |
|---|---|
| Umfang | Installation, Grundkonfiguration, Schalter je Website, Messung, alle 33 WordPress-Websites im Mitschreib-Modus |
| Grundlage | Pakete aus dem Ubuntu-Archiv: Modul 1.0.3, Engine 3.0.12, CRS 3.3.5. Ein späterer Umstieg auf eigene Pakete mit Engine 3.0.16 und CRS 4.25 LTS bleibt offen |
| Schalter | markierter Block im Feld „nginx-Direktiven" je Website, gesetzt über das Datalog von ISPConfig |
| Audit-Log | mit Anfrageinhalt, 7 Tage aufbewahrt |
| Weg | ModSecurity im nginx. aaWAF von aaPanel bleibt eine Option für eine spätere zentrale WAF auf eigener VM |
| Verfügbarkeit | Der Webserver darf niemals ausfallen |

Hintergrund zur Grundlage: CRS 3.3 läuft in Q3 2026 aus, und die Engine 3.0.12 aus
Ubuntu trägt die offene Umgehung CVE-2026-52747. Die gepflegten CRS-Versionen
verlangen Engine 3.0.16, die Ubuntu weder in 24.04 noch in 26.04 liefert. Mathias hat
sich bewusst für den einfachen Weg über die Ubuntu-Pakete entschieden.

## 4. Architektur

```
OPNsense (Proxy, Firewall)
    │  X-Forwarded-For
    ▼
nginx 1.24  ──  ngx_http_modsecurity_module  ──  libmodsecurity 3.0.12
    │                    │
    │                    └── Regeln einmal global geladen (/etc/nginx/waf/main.conf)
    │                         Zustand je Website über „modsecurity on;" im vhost
    ▼
PHP-FPM je Website
```

- Die Regeln werden einmal im `http`-Block geladen. Die Websites schalten sich nur
  ein, sie laden keine eigenen Regelsätze.
- Die echte Besucher-IP liegt bereits vor: `set_real_ip_from 10.50.0.1`,
  `real_ip_header X-Forwarded-For`, `real_ip_recursive on`.
- Antworten werden nicht geprüft (`SecResponseBodyAccess Off`).

## 5. Dateien

### Pakete

`libnginx-mod-http-modsecurity` (1.0.3) und `modsecurity-crs` (3.3.5). Mit ihnen
kommen `libmodsecurity3t64`, `libnginx-mod-http-ndk`, `libmodsecurity-dev`,
`libfuzzy2`, `liblua5.3-0` und `libyajl2`. Das Modulpaket legt
`/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf` an und löst den Trigger
`nginx-reload` aus.

### Eigene Dateien

| Datei | Inhalt |
|---|---|
| `/etc/nginx/conf.d/waf.conf` | `modsecurity_rules_file /etc/nginx/waf/main.conf;` |
| `/etc/nginx/waf/main.conf` | Reihenfolge der Includes (unten) |
| `/etc/nginx/waf/einstellungen.conf` | Engine, Grenzen, Audit-Log |
| `/etc/nginx/waf/crs-zusatz.conf` | WordPress-Ausnahmen des Regelwerks einschalten |
| `/etc/nginx/waf/ausnahmen-vorher.conf` | Selbstaufrufe, Datenschutzregeln |
| `/etc/nginx/waf/ausnahmen-nachher.conf` | Ausnahmen je Website aus der Auswertung |
| `/etc/nginx/waf/zustand.conf` | Notaus-Schalter, im Normalfall leer |
| `/var/cache/waf` | Arbeitsverzeichnis der Engine (`SecTmpDir`, `SecDataDir`), gehört `www-data`, Rechte 0750 |
| `/var/log/waf` | Audit-Log und Protokoll des Wächters, gehört `www-data`, Rechte 0750 |
| `/etc/logrotate.d/waf` | Rotation des Audit-Logs: täglich, 7 Stände, gepackt, `copytruncate` |

Reihenfolge in `main.conf`:

```
Include /etc/nginx/modsecurity.conf
Include /etc/nginx/waf/einstellungen.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/nginx/waf/crs-zusatz.conf
Include /etc/nginx/waf/ausnahmen-vorher.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/nginx/waf/ausnahmen-nachher.conf
Include /etc/nginx/waf/zustand.conf
```

**Vor dem ersten Laden zu prüfen:** `/etc/nginx/modsecurity.conf` und
`/etc/nginx/modsecurity_includes.conf` aus dem Paket lesen. Lädt eine dieser Dateien
das Regelwerk bereits, wird dieser Include hier weggelassen, damit keine Regel-ID
doppelt vorkommt.

### Einstellungen (`einstellungen.conf`)

```
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^$"
SecAuditLogParts ABCFHZ
SecAuditLogType Serial
SecAuditLog /var/log/waf/audit.log
SecAuditLogFormat JSON
SecAuditLogFileMode 0600
SecAuditLogDirMode 0750
SecTmpDir /var/cache/waf
SecDataDir /var/cache/waf
SecDebugLogLevel 0
SecStatusEngine Off
```

Die Teile I und K des Audit-Logs sind in Engine 3 nicht umgesetzt. Für den
Anfrageinhalt bleibt Teil C, der bei Uploads den ganzen Inhalt enthält. Deshalb
schalten zwei Regeln Teil C gezielt ab (unten).

`SecStatusEngine Off` hält die Engine davon ab, Versionsdaten nach außen zu melden.

### Eigene Regeln (`ausnahmen-vorher.conf`)

IDs aus dem freien Bereich 10000 bis 99999.

```
# Selbstaufrufe des Servers, vor allem wp-cron über die OPNsense
SecRule REMOTE_ADDR "@ipMatch 10.50.0.11" \
    "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"

# Anmeldewege: Anfrageinhalt nicht ins Audit-Log
SecRule REQUEST_FILENAME "@rx (?i)(wp-login\.php|xmlrpc\.php|/wp-json/[^?]*(users|application-passwords))" \
    "id:10010,phase:1,pass,nolog,ctl:auditLogParts=-C"

# Uploads: Anfrageinhalt nicht ins Audit-Log
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \
    "id:10011,phase:1,pass,nolog,ctl:auditLogParts=-C"
```

### Regelwerk (`crs-zusatz.conf`)

```
SecAction "id:10100,phase:1,pass,nolog,setvar:tx.crs_exclusions_wordpress=1"
```

Paranoia-Stufe 1 und die Schwellen des Regelwerks bleiben auf den Voreinstellungen.
Beim Einrichten wird geprüft, ob `crs-setup.conf` aus dem Paket die Regel 900130
bereits aktiv enthält; dann entfällt diese Zeile.

## 6. Schalter je Website

### Zustände

| Zustand | Block im Feld „nginx-Direktiven" |
|---|---|
| aus | kein Block |
| mitschreiben | `modsecurity on;` |
| scharf | `modsecurity on;` und `modsecurity_rules 'SecRuleEngine On';` |

Der Block steht zwischen zwei Markierungen:

```
# WAF-Anfang (mitschreiben) – verwaltet von waf-schalter
modsecurity on;
# WAF-Ende
```

### Skript `/usr/local/sbin/waf-schalter`

PHP-Skript, bindet `/usr/local/ispconfig/server/lib/config.inc.php` und
`app.inc.php` ein und schreibt über `$app->dbmaster->datalogUpdate('web_domain', …)`.
Denselben Weg nutzt malwatch bereits. Der Quelltext aller drei Werkzeuge dieses
Designs liegt im malwatch-Repo unter `waf/`: `waf-schalter`, der Wächter `waf-wache`
und die Auswertung `waf-bericht`. Eingespielt werden sie nach `/usr/local/sbin/`.

Aufrufe:

| Aufruf | Wirkung |
|---|---|
| `waf-schalter status` | Tabelle: Website, Zustand laut Datenbank, Zustand laut vhost-Datei |
| `waf-schalter setze <aus\|mitschreiben\|scharf> <domain…>` | Zustand setzen, `--wordpress` wählt die 33 WordPress-Websites |
| `waf-schalter probe …` | zeigt die Änderung, schreibt nichts |
| `waf-schalter notaus` | `SecRuleEngine Off` in `zustand.conf`, Reload; Websites im Zustand „scharf" fallen auf „mitschreiben" zurück |
| `waf-schalter zurueck <sicherung>` | stellt gesicherte Feldinhalte wieder her |

Ablauf beim Setzen, je Website:

1. Feld `nginx_directives` lesen und nach
   `/var/backups/waf-schalter/<Zeitstempel>/<domain>.txt` sichern.
2. Vorhandenen Block zwischen den Markierungen entfernen, neuen Block anhängen.
   Alles außerhalb der Markierungen bleibt Zeichen für Zeichen gleich.
3. `datalogUpdate` schreiben.
4. Warten, bis der Server-Cron (jede Minute) den vhost neu gebaut hat, erkennbar an
   der Markierung in `/etc/nginx/sites-available/<domain>.vhost`.
5. `nginx -t` prüfen. Schlägt der Test fehl oder liegt eine `.err`-Datei vor, schreibt
   das Skript den gesicherten Feldinhalt zurück und meldet den Fehler.

Sicherheitsnetz von ISPConfig: Startet nginx nach einer Änderung nicht, stellt das
nginx-Plugin den alten vhost wieder her und legt die fehlerhafte Fassung als `.err`
ab (`nginx_plugin.inc.php`, Zeilen 2049–2062).

### Wächter

`/usr/local/sbin/waf-wache`, stündlich per Cron:

1. `nginx -t` ausführen.
2. Bei Fehler mit Bezug auf `modsecurity`: `waf-schalter notaus`, anschließend
   `systemctl reload nginx` und Meldung an healthchecks.
3. Ergebnis in `/var/log/waf/wache.log` festhalten.

## 7. Logs und Datenschutz

- Audit-Log: `/var/log/waf/audit.log`, JSON, ein Eintrag je Anfrage mit Regeltreffer.
- Verzeichnis `/var/log/waf` gehört `www-data`, Rechte 0750, Datei 0600.
- Rotation: täglich, 7 Stände, gepackt, `copytruncate`, eigene logrotate-Datei
  `/etc/logrotate.d/waf`.
- Regeln 10010 und 10011 halten Passwörter und hochgeladene Dateien aus dem Log.
- Im Mitschreib-Modus bleibt die `error.log` der Websites frei von WAF-Meldungen: Der
  Connector meldet Treffer mit `NGX_LOG_INFO`, ISPConfig schreibt `error.log` ab Stufe
  `error`. Blockaden im Zustand „scharf" erscheinen dort und folgen der Aufbewahrung
  der jeweiligen Website (10, 30 oder 60 Tage).
- Das Audit-Log enthält IP-Adressen und Formularinhalte. Zweck ist die
  Angriffserkennung, die Aufbewahrung beträgt 7 Tage, Zugriff hat root. Der Eintrag
  gehört in das Verzeichnis der Verarbeitungstätigkeiten.

### Auswertung

`/usr/local/sbin/waf-bericht` liest das Audit-Log und fasst zusammen:

- Treffer je Website, Regel-ID, Pfad und Anomalie-Punktzahl
- eine Beispielanfrage je Regel-ID
- Ausgabe als Tabelle und als Markdown-Abschnitt für das Serverprotokoll

## 8. Einführung in Stufen

| Stufe | Inhalt |
|---|---|
| 0 | Pakete einspielen, eigene Dateien anlegen, `nginx -t`, Reload. Keine Website eingeschaltet |
| 1 | bright-color.de auf „mitschreiben", Tests, Messung |
| 2 | zehn weitere WordPress-Websites dazu, Messung. Ausgewählt werden die zehn mit den wenigsten Anfragen des Vortags laut `access.log` |
| 3 | die übrigen WordPress-Websites, aufsteigend nach Anfragen des Vortags, die lastreichste Website zuletzt, Messung |
| 4 | Auswertung mit `waf-bericht`, Ausnahmen je Website eintragen, erneut messen |

Vor Stufe 0 wird `nginx -t` gegen den aktuellen Stand geprüft, damit der Trigger des
Pakets auf eine gültige Konfiguration trifft.

Jede Stufe bekommt einen Eintrag im Serverprotokoll `web.herkules.bright-color.de.md`:
Datum und Uhrzeit vom Server, was getan wurde, warum, die Befehle, die Messwerte, die
Prüfung und der Rückweg. Der Eintrag entsteht während der Arbeit und wird mit dem
Ergebnis abgeschlossen.

## 9. Messwerte und Abbruchgrenzen

| Messwert | Ausgangswert | Abbruch |
|---|---|---|
| nginx gesamt (RSS) | 175 MB | freier Arbeitsspeicher unter 2 GB |
| freier Arbeitsspeicher | 6,3 GB | unter 2 GB |
| Swap belegt | 1,7 GB | Anstieg um mehr als 1 GB |
| Load (5 Minuten) | 1,19 bei 8 CPUs | dauerhaft über 6 |
| Antwortzeit dreier Seiten | wird in Stufe 0 gemessen | Verdopplung |
| 5xx-Anteil | wird in Stufe 0 gemessen | Anstieg |
| Abgestürzte Worker | 0 | jeder Eintrag „exited on signal" |
| Audit-Log | 0 | Wachstum über 1 GB je Tag |

Beim Überschreiten: `waf-schalter notaus`, Messwerte festhalten, Ursache klären.

## 10. Tests

1. `nginx -t` fehlerfrei; `modsec-rules-check` über die Regelkette.
2. Erkennung: Abruf mit einem Angriffsmuster auf eine eingeschaltete Website.
   Erwartung: Eintrag im Audit-Log, Antwort weiterhin 200.
3. Gegenprobe: dieselbe Anfrage auf eine Website im Zustand „aus". Erwartung: kein
   Eintrag.
4. Datenschutz: POST auf `wp-login.php` mit erfundenem Kennwort und ein kleiner
   Test-Upload, beides auf bright-color.de. Erwartung: Einträge ohne Teil C.
5. Selbstaufrufe: wp-cron-Aufrufe erzeugen keine Einträge.
6. Verfügbarkeit: nach jeder Stufe fünf Websites über HTTP prüfen, Erwartung 200,
   dazu `systemctl is-active nginx` und ein Blick in `/var/log/nginx/error.log`.
7. Schalter: `waf-schalter probe` zeigt die Änderung; `status` stimmt mit den
   vhost-Dateien überein; `notaus` wirkt mit einem Reload.

## 11. Rückweg

1. Sofort: `waf-schalter notaus`.
2. Je Website: `waf-schalter setze aus <domain…>`.
3. Vollständig: alle Websites auf „aus", Kontrolle mit `status`, dann
   `apt purge libnginx-mod-http-modsecurity modsecurity-crs`, danach
   `/etc/nginx/conf.d/waf.conf` und `/etc/nginx/waf` entfernen, `nginx -t`, Reload.
   Die Reihenfolge ist zwingend, damit nginx keine unbekannte Direktive vorfindet.
4. Sicherungen der Feldinhalte liegen unter `/var/backups/waf-schalter/`.

## 12. Risiken und offene Punkte

1. **Speicher beim Zusammenführen der Regeln:** Der Connector führt den Regelsatz je
   `server`- und `location`-Block zusammen. Bei 55 vhosts mit vielen `location`-Blöcken
   ist der Bedarf zu messen. Stufe 0 misst vor dem Einschalten.
2. **Engine 3.0.12:** Die Umgehung CVE-2026-52747 im Multipart-Parser bleibt offen.
   Der Absturzfehler CVE-2026-30923 betrifft nur Regeln mit `t:hexDecode`, die CRS
   nicht verwendet.
3. **CRS 3.3.5:** läuft aus. Der Umstieg auf CRS 4.25 LTS braucht Engine 3.0.16 und
   damit eigene Pakete.
4. **Ubuntu 26.04:** Vor dem Upgrade werden WAF abgeschaltet und die Pakete entfernt,
   danach die Pakete von 26.04 eingespielt. Das gehört in den Upgrade-Plan.
5. **Fehlalarme:** Die Auswertung entscheidet, welche Ausnahmen nötig sind. Der
   Zustand „scharf" kommt erst danach zur Sprache.

## 13. Nicht im Umfang

- Blockieren („scharf") auf Kundenseiten
- Seite „Abwehr" in malwatch
- Eigene Pakete mit Engine 3.0.16 und CRS 4.25 LTS
- aaWAF als zentrale WAF auf eigener VM
- Ratenlimits in nginx
