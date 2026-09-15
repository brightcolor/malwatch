# WAF für web.herkules

ModSecurity als nginx-Modul mit dem OWASP-Regelwerk CRS, je Website schaltbar.
Entwurf und Ablauf stehen in `docs/superpowers/specs/2026-09-16-waf-web-herkules-design.md`
und `docs/superpowers/plans/2026-09-16-waf-web-herkules.md`.

**Der Webserver darf niemals ausfallen.** Änderungen greifen erst nach `nginx -t`,
nginx wird ausschließlich neu geladen, die Konfiguration bleibt jederzeit gültig.

## Inhalt

| Pfad | Zweck |
|---|---|
| `lib/waf_block.inc.php` | reine Funktionen für den markierten Block im Feld „nginx-Direktiven" |
| `lib/waf_audit.inc.php` | reine Funktionen zum Auswerten des Audit-Logs |
| `waf-schalter` | Zustand je Website setzen, lesen, zurücknehmen, Notaus |
| `waf-wache` | stündlicher Wächter über `nginx -t` |
| `waf-bericht` | Auswertung des Audit-Logs |
| `conf/` | Dateien für `/etc/nginx/waf/`, die Einbindung und logrotate |
| `install.sh` | spielt Dateien und Werkzeuge auf dem Server ein |
| `tests/` | Tests der reinen Funktionen, mit erfundenen Beispieldaten |

## Tests

```bash
php waf/tests/waf_block_test.php
php waf/tests/waf_audit_test.php
```

## Einspielen

Die Pakete `libnginx-mod-http-modsecurity` und `modsecurity-crs` müssen liegen, sonst
bricht das Skript ab.

```bash
scp -r waf ispconfig:/root/waf-einspielen
ssh ispconfig 'cd /root/waf-einspielen && bash install.sh'
```

Danach ist das Modul geladen und keine Website eingeschaltet.

## Zustände je Website

| Zustand | Wirkung |
|---|---|
| aus | kein Block im Feld „nginx-Direktiven" |
| mitschreiben | `modsecurity on;`, Treffer gehen ins Audit-Log |
| scharf | zusätzlich `SecRuleEngine On`, Anfragen werden abgewiesen |

```bash
waf-schalter status
waf-schalter probe mitschreiben beispiel.de
waf-schalter setze mitschreiben beispiel.de
waf-schalter setze mitschreiben --wordpress
waf-schalter notaus
waf-schalter zurueck /var/backups/waf-schalter/<zeitstempel>
```

`notaus` schreibt `SecRuleEngine Off` in `/etc/nginx/waf/zustand.conf`, setzt scharfe
Websites auf „mitschreiben" zurück und lädt nginx neu. Mit `--hart` nimmt es zusätzlich
den Block aus allen Websites, etwa wenn das Modul fehlt.

## Logs

Audit-Log: `/var/log/waf/audit.log`, JSON, ein Eintrag je Anfrage mit Treffer, täglich
rotiert und 7 Tage aufbewahrt. Passwörter der Anmeldewege und hochgeladene Dateien
bleiben durch die Regeln 10010 und 10011 draußen.
