# Sperren, Stufe 2: fail2ban im Panel und „überall sperren"

> **Für Agenten:** REQUIRED SUB-SKILL: superpowers:executing-plans. Die Schritte
> tragen Kästchen (`- [ ]`).

**Ziel:** Die Sperren von fail2ban stehen auf der Seite „Sperren" mit Grund, Beginn
und Ende; jede lässt sich freigeben, und jede Adresse lässt sich „überall sperren".
Was „überall" bedeutet, ist global einstellbar, je fail2ban-Jail für den Knopf und
je Abwehr-Regel für die Automatik.

**Architektur:** Der Cron liest jede Minute alle Jails mit `fail2ban-client` und
spiegelt die Sperren in die eigene Tabelle `malwatch_f2b_ban`. Das Panel liest nur
diese Tabelle; jeder Knopf wird ein Auftrag, den der Cron als root ausführt. Die
reinen Teile (Ausgabe lesen, Grund, Modus auflösen) liegen in einer eigenen
Bibliothek `malwatch_waf_f2b.inc.php`.

**Technik:** PHP ab 7.0, ISPConfig-Interface, Serverklasse `malwatch_waf`,
fail2ban 1.0 (`get <jail> banip --with-time`), Tests in `ispconfig/tests`.

**Spec:** `docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md`, Abschnitt 12,
erweitert um „überall sperren" (Entscheidungen von Mathias am 22.09.2026: einstellbar,
global, pro Jail und pro Abwehr-Regel).

## Globale Vorgaben

- Bezeichner, Dateinamen und Code-Kommentare englisch; Texte für Menschen deutsch mit
  echten Umlauten; jede Meldung nennt Ursache und nächsten Schritt.
- Zeiträume und Schwellen sind Einstellungen.
- Der Webserver darf nicht ausfallen: Nichts in dieser Stufe fasst nginx an, außer
  über das bestehende `ban_apply()`.
- **Nie sperren, auch nicht in fail2ban:** eigene Netze (`waf_ban_fixed_allow()`), die
  Adressen des Servers und „Nie sperren". fail2ban hat auf web.herkules keine
  `ignoreip`; eine Sperre auf allen Ports für 10.50.0.1 schaltete jede Website ab.
- Befehle nur über die Liste in `run_command()`, jedes Argument durch
  `escapeshellarg()`; Jail-Namen nur in der Form `^[A-Za-z0-9_.-]{1,64}$`.
- Zeilenumbrüche in PHP-Zeichenketten als Escape-Folge; Dateien mit dem
  Write-Werkzeug schreiben, nicht über ein Python-Skript.
- Release erst nach grünem CI (`&&`), dann Einspielen, Probe am lebenden Server,
  Protokolleintrag.

## Abweichung von der Spec

Abschnitt 12 wollte die Sperren von fail2ban in `malwatch_waf_ban` mit
`source = 'fail2ban'` halten. Diese Tabelle hat einen eindeutigen Schlüssel je
Adresse; eine Adresse, die malwatch und fail2ban zugleich sperren, hätte darin nur
eine Zeile. Deshalb eine eigene Tabelle `malwatch_f2b_ban` mit Schlüssel
(Server, Jail, Adresse).

## Die Modi von „überall sperren"

| Modus | Web (malwatch) | fail2ban |
|---|---|---|
| `web_jail` (Vorgabe) | Sperre mit der Staffel 1 Std., 24 Std., 7 Tage | Sperre im Jail `waf_everywhere_jail` (Vorgabe `recidive`) |
| `web_forever_jail` | Sperre ohne Ende | wie oben |
| `jail_only` | — | wie oben |

Auflösung für den Knopf an einer Zeile von fail2ban: Modus des Jails, sonst global.
Für das Eingabefeld: global. Für die Automatik: Modus der Regel, die die Sperre
auslöste (`''` = nur Web wie bisher; `jail_only` gibt es dort nicht, die Automatik
sperrt immer im Web).

---

### Aufgabe G1: Bibliothek `malwatch_waf_f2b.inc.php`

**Dateien:**
- Neu: `ispconfig/interface/lib/malwatch_waf_f2b.inc.php`
- Neu: `ispconfig/tests/waf_f2b_test.php`
- Ändern: `ispconfig/install/file.list`, `.github/workflows/ci.yml`

**Schnittstellen (liefert):**
- `waf_f2b_jail_ok($jail)`: bool
- `waf_f2b_jails($status_output)`: array von Jail-Namen
- `waf_f2b_bans($output)`: array von `array('ip' => string, 'banned_at' => 'Y-m-d H:i:s', 'until' => 'Y-m-d H:i:s')`
- `waf_f2b_reason($jail)`: deutscher Grund
- `waf_f2b_modes()`: `array('web_jail', 'web_forever_jail', 'jail_only')`
- `waf_f2b_rule_modes()`: `array('', 'web_jail', 'web_forever_jail')`
- `waf_f2b_mode($jail, $jail_modes, $settings)`: Modus für den Knopf
- `waf_f2b_plan($mode)`: `array('web' => bool, 'forever' => bool, 'jail' => bool)`

- [ ] **Schritt 1: Prüfungen** mit den echten Ausgaben vom 22.09.2026:
  - `fail2ban-client status` → `"Status\n|- Number of jail:\t5\n`- Jail list:\tdovecot, postfix-sasl, pure-ftpd, recidive, sshd\n"` ergibt fünf Namen.
  - `get recidive banip --with-time` → `"91.92.243.20 \t2026-09-15 21:20:27 + 686484 = 2026-09-23 20:01:51\n"` ergibt Adresse, Beginn, Ende.
  - leerer Jail `"\n"` → leere Liste; Zeilen mit kaputter Adresse oder Zeit fallen weg.
  - Grund: `sshd` → „SSH: zu viele fehlgeschlagene Anmeldungen (sshd)", `dovecot` →
    „Mail-Abruf: …", `postfix-sasl` → „Mailversand: …", `pure-ftpd` → „FTP: …",
    `recidive` → „Wiederholungstäter, alle Dienste gesperrt (recidive)", unbekannt →
    „fail2ban-Jail <name>".
  - Modus: Jail-Modus vor global; unbekannter Modus fällt auf global; kaputter globaler
    Modus auf `web_jail`.
  - Plan: `web_jail` → web, jail; `web_forever_jail` → web, forever, jail; `jail_only` → jail.
- [ ] **Schritt 2:** laufen lassen, erwartet: Fehler, Funktionen fehlen.
- [ ] **Schritt 3:** Bibliothek schreiben (reine Funktionen, keine Datenbank).
- [ ] **Schritt 4:** laufen lassen, erwartet: bestanden; Eintrag in `file.list`
  (`c:interface/lib/malwatch_waf_f2b.inc.php:interface/web/security/lib/malwatch_waf_f2b.inc.php`)
  und in `ci.yml`.

### Aufgabe G2: Schema und Einstellungen

**Dateien:** `ispconfig/install/schema.sql`, `ispconfig/interface/lib/malwatch_waf_lib.inc.php`,
`ispconfig/interface/form/malwatch_waf_config.tform.php`,
`ispconfig/interface/templates/malwatch_waf_config_edit.htm`, beide `*_malwatch_waf_config.lng`

- [ ] **Schritt 1:** Tabellen
  - `malwatch_f2b_ban` (`server_id`, `jail` varchar(64), `ip` varchar(45), `banned_at`, `until`, `seen_at`; Schlüssel `server_id, jail, ip`; Index `ip`)
  - `malwatch_f2b_state` (`server_id` Schlüssel, `state` varchar(16), `error` varchar(255), `read_at`)
  - `malwatch_f2b_jail` (`server_id`, `jail`, `everywhere_mode` varchar(20); Schlüssel `server_id, jail`)
  - `malwatch_waf_ban_rule` (`rule_id` varchar(16) Schlüssel, `everywhere_mode` varchar(20), `changed_at`, `changed_by`)
- [ ] **Schritt 2:** Spalten in `malwatch_config`: `waf_f2b` enum('off','on') Vorgabe 'on',
  `waf_everywhere_mode` varchar(20) Vorgabe 'web_jail', `waf_everywhere_jail` varchar(64)
  Vorgabe 'recidive'. `waf_settings()` prüft Modus und Jail und fällt auf die Vorgabe zurück.
- [ ] **Schritt 3:** Formularfelder (zwei SELECT, ein TEXT mit REGEX-Prüfung), Wörter, Vorlage.
- [ ] **Schritt 4:** `waf_lib_test.php`, `waf_panel_test.php` laufen lassen.

### Aufgabe G3: Serverklasse — lesen

**Dateien:** `ispconfig/server/lib/classes/malwatch_waf.inc.php`, `ispconfig/tests/waf_class_probe.php`

- [ ] **Schritt 1:** `run_command()` kennt `f2b_status`, `f2b_banned` (Argument: Jail),
  `f2b_unban` und `f2b_ban` (Argument: `array(jail, ip)`), jedes Argument durch
  `escapeshellarg()`. Fehlt `fail2ban-client`, antwortet der Befehl mit 127 und einer Meldung.
- [ ] **Schritt 2:** `f2b_read()` im Minutenlauf nach `ban_apply()`: aus → Zustand `off`, Zeilen
  des Servers weg; sonst Jails lesen, je Jail die Sperren, Tabelle abgleichen (neue Zeilen
  anlegen, fortgefallene löschen), Zustand `ok` oder `error` mit Meldung.
- [ ] **Schritt 3:** Klassenprobe mit `$answers` für die vier Befehle: Abgleich legt an, hält
  und löscht; ein Fehler von fail2ban lässt die Tabelle stehen und schreibt den Zustand.

### Aufgabe G4: Serverklasse — Aufträge und Automatik

- [ ] **Schritt 1:** Der Web-Teil von `ban_add` wird eine eigene Methode `ban_web_by_hand($ip,
  $permanent, $user, $now, $settings)`, die `ban_add` und `ban_everywhere` teilen.
- [ ] **Schritt 2:** Aufträge
  - `f2b_unban` (`jail`, `ip`): Form prüfen, `fail2ban-client set <jail> unbanip <ip>`,
    Meldung „freigegeben" oder „war dort nicht mehr gesperrt", danach `f2b_read()`.
  - `ban_everywhere` (`ip`, optional `jail`): Form prüfen, „Nie sperren", eigene Netze und
    Serveradressen abweisen, Modus auflösen, Web- und fail2ban-Teil nach Plan, eine Meldung
    für beides, danach `ban_apply()` und `f2b_read()`.
  - `f2b_jail_modes` (`modes`: Jail → Modus): je Jail speichern, `''` löscht.
  - `ban_rule_mode` (`rule`, `mode`): Regel `^[0-9]{3,9}$`, Modus aus `waf_f2b_rule_modes()`.
- [ ] **Schritt 3:** Automatik: Wird in `ban_scan()` eine Sperre aktiv und ist ihre häufigste
  Regel markiert, folgt der Plan des Regel-Modus (ohne Ende bei `web_forever_jail`,
  fail2ban-Sperre im Jail). Scheitert fail2ban, bleibt die Web-Sperre und das Protokoll
  sagt es.
- [ ] **Schritt 4:** Klassenprobe: jeder Auftrag, jeder Modus, die Abweisung von 10.50.0.1,
  die Automatik mit markierter Regel.

### Aufgabe G5: Panel

**Dateien:** `malwatch_waf_ban_list.php`, `templates/malwatch_waf_ban_list.htm`,
`malwatch_waf_show.php`, `templates/malwatch_waf_show.htm`, `lib/malwatch_waf_panel.inc.php`,
beide `*_malwatch_waf.lng`

- [ ] **Schritt 1:** Seite „Sperren", Abschnitt „fail2ban" nach den Vorschlägen: Zustand
  (gelesen um …, aus, Fehler), Tabelle (Adresse, Grund, seit, bis), Knöpfe „freigeben" und
  „überall sperren", Eingabefeld „Adresse überall sperren" mit dem geltenden Modus, Tabelle
  der Jails mit Modus-Auswahl und einem Speicherknopf. Neue versteckte Felder `mw-waf-jail`.
- [ ] **Schritt 2:** Website-Seite: je Regel-Karte eine Auswahl „Sperren wegen dieser Regel"
  (nur Web, Web + fail2ban, Web dauerhaft + fail2ban) mit Knopf; versteckte Felder `mw-waf-rule`.
- [ ] **Schritt 3:** Handler in `waf_panel_handle_post()` für die vier Aufträge; reine
  Hilfsfunktion `waf_panel_f2b_rows()` für die Tabelle.
- [ ] **Schritt 4:** `waf_panel_test.php`, `waf_panel_post_test.php`, `check_wiring.sh`
  (Prüfung 84 verlangt die neuen Felder).

### Aufgabe G6: waf-switch

- [ ] `waf-switch ban everywhere <ip>` (Auftrag `ban_everywhere`), `waf-switch ban f2b`
  (Liste aus `malwatch_f2b_ban`). Hilfetexte.

### Aufgabe G7: Verdrahtung, Nachbau

- [ ] Prüfungen in `check_wiring.sh`: Befehle nur mit `escapeshellarg`, `ban_everywhere`
  fragt `waf_ban_allowed()`, Bibliothek in `file.list`, Wörter in beiden Sprachen.
- [ ] Nachbau: `fake_db.php` kennt die neuen Tabellen; Seite rendert; Klickprobe der Knöpfe.

### Aufgabe G8: Veröffentlichen, einspielen, prüfen

- [ ] Version 0.26.0, Changelog, alle Prüfungen, Klassenprobe am Server.
- [ ] Commit, `main`, CI grün, erst dann Marke und Release.
- [ ] Einspielen; Probe mit 192.0.2.62: „überall sperren" → Web-Sperre und `recidive`,
  „freigeben" → aus `recidive`; die echten Sperren von fail2ban erscheinen.
- [ ] Protokolleintrag, Memory, Spec Abschnitt 12 nachziehen.
