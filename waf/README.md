# WAF für web.herkules

ModSecurity als nginx-Modul mit dem OWASP-Regelwerk CRS, je Website schaltbar. Bedient
wird sie im Panel unter **Security > Abwehr** (malwatch ab 0.19.0) oder mit
`waf-switch`. Entwürfe: `docs/superpowers/specs/2026-09-16-waf-web-herkules-design.md` und
`docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md`.

**Der Webserver darf niemals ausfallen.** Dateien der WAF ändern sich nur über eine
geprüfte Kopie, `nginx -t` und einen Reload; scheitert ein Schritt, bleibt der vorherige
Stand, und nginx wird nicht neu geladen.

## Inhalt

| Pfad | Zweck |
|---|---|
| `waf-switch` | Zustand je Website, Notaus, Seitenantwort, Aufträge, Einlesen, Wächter |
| `waf-guard` | stündlicher Wächter über `nginx -t`, ruft `waf-switch guard` |
| `waf-report` | Treffer je Website und Regel aus dem Audit-Log |
| `conf/` | Dateien ohne Orte für das Regelverzeichnis: CRS-Zusatz, Ausnahmen, Seitenantwort, Notaus-Schalter |
| `install.sh` | spielt alles ein, legt neue Orte an und stellt von den ersten Namen um |

Die Funktionen liegen in malwatch (`ispconfig/interface/lib/malwatch_waf_lib.inc.php`,
`ispconfig/server/lib/classes/malwatch_waf.inc.php`) und werden dort getestet.
`main.conf`, `settings.conf`, die beiden Einbindungen, die logrotate-Datei und die
Cron-Datei schreibt `install.sh` aus den Einstellungen (`waf-switch paths render`);
`ispconfig/tests/fixtures/waf/` hält sie so, wie sie mit den Vorgaben entstehen, und
`ispconfig/tests/waf_install_probe.sh` spielt den Installer gegen einen Wegwerf-Baum durch.

## Einspielen

Voraussetzung: die Pakete `libnginx-mod-http-modsecurity` und `modsecurity-crs`, dazu
malwatch ab 0.35.0.

```bash
scp -r waf ispconfig:/root/waf-einspielen
ssh ispconfig 'bash /root/waf-einspielen/install.sh'
```

`install.sh --check` zeigt vorher die Orte und was sich ändert, und ändert dabei nichts.

`install.sh` darf mehrfach laufen. Ein Server mit den ersten Namen (`waf-schalter`,
`waf-wache`, `waf-bericht`, `einstellungen.conf`, `crs-zusatz.conf`,
`ausnahmen-vorher.conf`, `ausnahmen-nachher.conf`, `zustand.conf`, `antwortrumpf.conf`)
wird dabei umgestellt: neue Dateien neben die alten, neue `main.conf` nach Regelprüfung
und `nginx -t`, erst danach verschwinden die alten Namen. Die Cron-Zeile wechselt auf
`waf-guard`, und `waf-switch migrate` schreibt die alten Markierungen im Feld
„nginx-Direktiven" um. Seit 0.35.0 läuft die Wache aus der Cron-Datei der Abwehr;
ihre Zeile in der crontab von root nimmt `install.sh` heraus.

## Orte

Jeder Ort und Name der Abwehr auf dem Server ist eine Einstellung; Vorgabe ist der Wert
bis 0.34.0. `waf-switch paths` listet sie, `waf-switch paths get <name>` gibt einen für
Skripte aus, das Panel zeigt sie unter Abwehr > Einstellungen > Stand auf dem Server.
Geändert wird ein Ort über den Installer: die Variable mit dem neuen Wert vor den Aufruf.

```bash
MALWATCH_WAF_CONF_DIR=/etc/nginx/waf2 bash /root/waf-einspielen/install.sh --check
MALWATCH_WAF_CONF_DIR=/etc/nginx/waf2 bash /root/waf-einspielen/install.sh
```

| Variable | Vorgabe | Ort |
|---|---|---|
| `MALWATCH_WAF_CONF_DIR` | `/etc/nginx/waf` | Regelverzeichnis |
| `MALWATCH_WAF_RULES_INCLUDE` | `/etc/nginx/conf.d/waf.conf` | Einbindung der Regeln |
| `MALWATCH_WAF_BLOCKED_INCLUDE` | `/etc/nginx/conf.d/waf-blocked.conf` | Einbindung der Sperrliste |
| `MALWATCH_WAF_NGINX_SERVICE` | `nginx` | Dienst von nginx für systemctl |
| `MALWATCH_WAF_MODSEC_BASE` | `/etc/nginx/modsecurity.conf` | Grundkonfiguration von ModSecurity |
| `MALWATCH_WAF_CRS_SETUP` | `/etc/modsecurity/crs/crs-setup.conf` | Einstellungen der CRS |
| `MALWATCH_WAF_CRS_RULES` | `/usr/share/modsecurity-crs/rules/*.conf` | Regeln der CRS |
| `MALWATCH_WAF_RULES_CHECK` | `/usr/lib/*/libexec/modsec-rules-check` | Regelprüfung |
| `MALWATCH_WAF_CACHE_DIR` | `/var/cache/waf` | Zwischenspeicher von ModSecurity |
| `MALWATCH_WAF_AUDIT_LOG` | `/var/log/waf/audit.log` | Audit-Log |
| `MALWATCH_WAF_BLOCKED_LOG` | `/var/log/waf/blocked.log` | Sperrprotokoll |
| `MALWATCH_WAF_GUARD_LOG` | `/var/log/waf/guard.log` | Protokoll der Wache |
| `MALWATCH_WAF_BACKUP_DIR` | `/var/backups/waf-switch` | Sicherungen |
| `MALWATCH_WAF_LOGROTATE_FILE` | `/etc/logrotate.d/waf` | logrotate-Datei |
| `MALWATCH_WAF_TOOLS_DIR` | `/usr/local/sbin` | Werkzeuge |
| `MALWATCH_WAF_CRON_FILE` | `/etc/cron.d/malwatch-waf` | Cron-Datei |
| `MALWATCH_WAF_HC_RUN` | `/usr/local/sbin/hc-run` | hc-run; leer: die Läufe starten direkt |
| `MALWATCH_WAF_HC_TICK_NAME` | `waf-tick` | Check des Minutentakts in healthchecks |
| `MALWATCH_WAF_HC_GUARD_NAME` | `waf-guard` | Check der Wache in healthchecks |
| `MALWATCH_WAF_BIN_DIRS` | `/usr/local/sbin,/usr/local/bin,/usr/sbin,/usr/bin,/sbin,/bin` | Programmverzeichnisse |

Der Installer legt den neuen Ort an, prüft mit der Regelprüfung, `nginx -t` und `nginx -T`
(lädt nginx beide Einbindungen?) und speichert die Orte erst danach. Scheitert ein
Schritt, legt er jede Datei zurück, und die Einstellungen behalten ihren Wert. Ein
neues Regelverzeichnis beginnt mit allem aus dem alten, auch der Sperrliste und den
Ausnahmen des Panels; die Einbindungen, die Cron- und die logrotate-Datei eines alten
Ortes nimmt er weg. Protokolle, Sicherungen und ein altes Regelverzeichnis bleiben
liegen, die Ausgabe nennt sie. Vor einem neuen Sperrprotokoll fragt er nach: Dann
schreibt `waf-switch migrate` jede Website mit Abwehr neu, über ISPConfig wie beim
Umschalten; ohne Terminal bestätigt `--yes`. Das alte Audit-Log liest die Abwehr vor
dem Umzug zu Ende. Eine Variable, die keinen Ort nennt, ein relativer Pfad oder zwei
Orte in einer Datei halten den Installer an, bevor er etwas ändert, mit Ursache und
Abhilfe.

Die Minuten von Wache und Stundenlauf und die Grenzen von ModSecurity für den
Anfragekörper stehen im Panel unter Abwehr > Einstellungen; der Auftrag nach dem
Speichern schreibt die Cron-Datei und `settings.conf` neu, `settings.conf` über
Regelprüfung, `nginx -t` und Reload.

## Zustände je Website

| Zustand | Oberfläche | Wirkung |
|---|---|---|
| `off` | aus | kein Block im Feld „nginx-Direktiven" |
| `detect` | mitschreiben | `modsecurity on;`, Treffer gehen ins Audit-Log |
| `enforce` | scharf | zusätzlich `SecRuleEngine On`, Anfragen werden abgewiesen |

```bash
waf-switch status
waf-switch probe detect beispiel.de
waf-switch set detect beispiel.de --wait
waf-switch set detect --wordpress
waf-switch jobs
waf-switch restore /var/backups/waf-switch/<zeitstempel>-job<nummer>
```

`set` legt einen Auftrag an. Der Cron schreibt das Feld, wartet auf den vhost von
ISPConfig, prüft `nginx -t` und bestätigt den Zustand; nach der Frist aus den
Einstellungen nimmt er seine Änderung zurück, sofern niemand das Feld inzwischen geändert
hat. „scharf" setzt voraus, dass die Website lange genug mitschreibt.

## Notaus

```bash
waf-switch emergency on
waf-switch emergency off
waf-switch emergency on --hard
```

`on` schreibt `SecRuleEngine Off` in `state.conf` im Regelverzeichnis, lädt nginx neu und
setzt scharfe Websites auf „mitschreiben". `--hard` ist für ein nginx ohne Modul: die
Einbindung der Regeln bekommt die Endung `.off`, die vhosts verlieren ihre
`modsecurity`-Zeilen, die Felder ihren Block. Wieder eingeschaltet wird dann mit
`install.sh`.

## Minutentakt

`waf-switch tick` führt jede Minute den Lauf der Abwehr aus: Audit-Log einlesen,
Herkunft nachschlagen, Sperren erkennen, beenden und in die Datei für nginx schreiben,
Aufträge abarbeiten, fail2ban lesen; zur „Minute des Stundenlaufs“ (Vorgabe 7) folgt der
Stundenteil. Gestartet wird er aus der Cron-Datei der Abwehr (Vorgabe
`/etc/cron.d/malwatch-waf`) über `hc-run waf-tick`, unabhängig vom Cron von ISPConfig. Der führt alle seine Jobs nacheinander unter einer Sperre aus; ein langer
Lauf dort, nachts AWStats, hielt die Abwehr sonst eine halbe Stunde an.

Solange der Takt läuft, überlässt der Cron-Job von malwatch in ISPConfig ihm den Lauf.
Bleibt der Takt drei Minuten aus, übernimmt der Cron-Job wieder. Den Takt überwacht
healthchecks, sobald `/etc/hc-run.d/waf-tick.url` die Ping-Adresse enthält. Fällt der Takt
aus, startet der Cron-Job den Stundenteil zur selben Minute.

Hält gerade ein anderer Teil der Abwehr die Sperre, etwa `waf-guard` zur „Minute der
Wache“ (Vorgabe 5),
wartet der Takt darauf, höchstens so viele Sekunden, wie „Wartezeit des Minutentakts“
unter Abwehr > Einstellungen sagt (Vorgabe 30). Ist die Abwehr danach noch belegt,
fällt der Lauf dieser Minute aus. Der Cron-Job von ISPConfig wartet nie, weil er
sonst alle Jobs von ISPConfig aufhält. Das Warten braucht `waf-switch` ab malwatch
0.28.1: Nach einem Update von malwatch `waf-switch` aus diesem Ordner in den Ordner der
Werkzeuge kopieren (Vorgabe `/usr/local/sbin`); `install.sh` spielt dagegen alles ein,
auch die Dateien für nginx.

## Wächter

`waf-guard` läuft stündlich zur „Minute der Wache“ aus der Cron-Datei der Abwehr, über
`hc-run waf-guard`; healthchecks meldet ihn, sobald `/etc/hc-run.d/waf-guard.url` die
Ping-Adresse enthält. Besteht `nginx -t`, arbeitet er
hängende Aufträge ab. Fehlt das Modul, folgt der harte Notaus; nennt der Fehler eine
Datei der WAF, legt er den letzten geprüften Stand zurück. Protokoll: das Protokoll der
Wache (Vorgabe `/var/log/waf/guard.log`); `waf-guard` findet `waf-switch` neben sich.

## Logs

Audit-Log (Vorgabe `/var/log/waf/audit.log`): JSON, ein Eintrag je Anfrage mit Treffer, täglich
rotiert; die Zahl der Stände steht in den Einstellungen der Seite Abwehr. Passwörter der
Anmeldewege und hochgeladene Dateien bleiben durch die Regeln 10010 und 10011 draußen.
`waf-report` fasst das Log zusammen; ohne Angabe liest es das Audit-Log der Einstellungen.
