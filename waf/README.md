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
| `conf/` | Dateien für `/etc/nginx/waf/`, die Einbindung und logrotate |
| `install.sh` | spielt alles ein und stellt von den ersten Namen um |

Die Funktionen liegen in malwatch (`ispconfig/interface/lib/malwatch_waf_lib.inc.php`,
`ispconfig/server/lib/classes/malwatch_waf.inc.php`) und werden dort getestet.

## Einspielen

Voraussetzung: die Pakete `libnginx-mod-http-modsecurity` und `modsecurity-crs`, dazu
malwatch ab 0.19.0.

```bash
scp -r waf ispconfig:/root/waf-einspielen
ssh ispconfig 'bash /root/waf-einspielen/install.sh'
```

`install.sh` darf mehrfach laufen. Ein Server mit den ersten Namen (`waf-schalter`,
`waf-wache`, `waf-bericht`, `einstellungen.conf`, `crs-zusatz.conf`,
`ausnahmen-vorher.conf`, `ausnahmen-nachher.conf`, `zustand.conf`, `antwortrumpf.conf`)
wird dabei umgestellt: neue Dateien neben die alten, neue `main.conf` nach Regelprüfung
und `nginx -t`, erst danach verschwinden die alten Namen. Die Cron-Zeile wechselt auf
`waf-guard`, und `waf-switch migrate` schreibt die alten Markierungen im Feld
„nginx-Direktiven" um.

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

`on` schreibt `SecRuleEngine Off` in `/etc/nginx/waf/state.conf`, lädt nginx neu und setzt
scharfe Websites auf „mitschreiben". `--hard` ist für ein nginx ohne Modul: die Einbindung
wandert nach `waf.conf.off`, die vhosts verlieren ihre `modsecurity`-Zeilen, die Felder
ihren Block. Wieder eingeschaltet wird dann mit `install.sh`.

## Wächter

`waf-guard` läuft stündlich über `hc-run waf-guard`. Besteht `nginx -t`, arbeitet er
hängende Aufträge ab. Fehlt das Modul, folgt der harte Notaus; nennt der Fehler eine
Datei der WAF, legt er den letzten geprüften Stand zurück. Protokoll:
`/var/log/waf/guard.log`.

## Logs

Audit-Log: `/var/log/waf/audit.log`, JSON, ein Eintrag je Anfrage mit Treffer, täglich
rotiert; die Zahl der Stände steht in den Einstellungen der Seite Abwehr. Passwörter der
Anmeldewege und hochgeladene Dateien bleiben durch die Regeln 10010 und 10011 draußen.
`waf-report` fasst das Log zusammen.
