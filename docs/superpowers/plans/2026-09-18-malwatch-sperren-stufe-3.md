# Sperren, Stufe 3: URL-Liste für die OPNsense

> **Für Agenten:** REQUIRED SUB-SKILL: superpowers:executing-plans. Die Schritte
> tragen Kästchen (`- [ ]`).

**Ziel:** Die aktiven Sperren stehen unter einer Adresse mit Schlüssel als reine
Adressliste bereit, damit die OPNsense sie als „URL Table (IPs)"-Alias holen und
an der Kante sperren kann.

**Architektur:** Der Cron schreibt bei jeder Änderung der Sperrdatei zusätzlich
`<state_dir>/waf/blocked.txt` — eine Adresse je Zeile, sonst nichts. Eine eigene
Stelle im Panel-vhost liefert diese Datei aus, wenn der Schlüssel aus der
Konfiguration stimmt; ohne oder mit falschem Schlüssel antwortet sie mit 404.
Fehlt die Datei, liest die Stelle die aktiven Sperren aus der Datenbank, damit
die OPNsense nie versehentlich eine leere Liste bekommt.

**Technik:** PHP ab 7.0, ISPConfig-Interface, Serverklasse `malwatch_waf`,
`waf-switch`, Tests in `ispconfig/tests`.

**Spec:** `docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md`,
Abschnitt 13.

## Globale Vorgaben

- Bezeichner, Dateinamen und Code-Kommentare englisch; alle Texte für Menschen
  deutsch mit echten Umlauten.
- Jede Meldung nennt Ursache und nächsten Schritt.
- Schwellen und Zeiträume sind einstellbar, nie fest im Code.
- Der Webserver darf nicht ausfallen: Diese Stufe fasst weder nginx noch die
  vhosts an. Es wird nichts neu geladen.
- Der Schlüssel steht nie in einem Protokoll, weder im Auftragsprotokoll noch im
  Audit-Log. Auf der Seite „Sperren" steht die vollständige Adresse, weil Mathias
  sie in die OPNsense eintragen muss.
- Release, Einspielen und Prüfen auf web.herkules; Protokolleintrag danach.

---

### Aufgabe E1: Schlüssel und Listentext

**Dateien:**
- Ändern: `ispconfig/interface/lib/malwatch_waf_ban.inc.php`
- Test: `ispconfig/tests/waf_ban_test.php`

**Schnittstellen:**
- Liefert: `waf_ban_token_new()`, `waf_ban_token_ok($token)`,
  `waf_ban_list_text($ips)`, `waf_ban_list_url($host, $token)`

- [ ] **Schritt 1: Prüfungen schreiben** — Schlüssel hat 32 Zeichen aus
  `[a-f0-9]`, zwei Aufrufe liefern verschiedene Schlüssel; die Formprüfung weist
  leere, zu kurze, zu lange und großgeschriebene Werte ab; der Listentext nimmt
  nur gültige Adressen, wirft Doppelte weg, sortiert und endet mit einem
  Zeilenumbruch; eine leere Liste ergibt einen leeren Text; die Adresse entsteht
  aus Rechnername und Schlüssel.
- [ ] **Schritt 2: Prüfungen laufen lassen** — erwartet: Fehler, Funktionen fehlen.
- [ ] **Schritt 3: Funktionen schreiben.**
- [ ] **Schritt 4: Prüfungen laufen lassen** — erwartet: bestanden.

### Aufgabe E2: Spalte für den Schlüssel

**Dateien:**
- Ändern: `ispconfig/install/schema.sql`, `ispconfig/interface/lib/malwatch_waf_lib.inc.php`

- [ ] **Schritt 1:** `ALTER TABLE malwatch_config ADD COLUMN waf_ban_token varchar(64) NOT NULL DEFAULT ''`
  nach dem Muster der übrigen Spalten.
- [ ] **Schritt 2:** `waf_settings_defaults()` bekommt `'waf_ban_token' => ''`.
  Keine Grenze, kein Feld im Formular: Der Schlüssel entsteht von selbst.
- [ ] **Schritt 3:** `php ispconfig/tests/waf_lib_test.php`.

### Aufgabe E3: Die Datei und der Schlüssel in der Serverklasse

**Dateien:**
- Ändern: `ispconfig/server/lib/classes/malwatch_waf.inc.php`
- Test: `ispconfig/tests/waf_class_probe.php`

- [ ] **Schritt 1:** `ban_apply()` schreibt nach dem erfolgreichen Reload auch
  `<state_dir>/waf/blocked.txt` mit `waf_ban_list_text()`, Rechte 0644, damit das
  Panel sie lesen kann. Schlägt das Schreiben fehl, bleibt die Sperre trotzdem
  stehen; die Meldung nennt die Datei und den nächsten Schritt.
- [ ] **Schritt 2:** `ban_token()` liefert den Schlüssel und erzeugt ihn, wenn er
  fehlt. Der Fall `ban_mode` ruft ihn auf, sobald die Automatik auf `propose`
  oder `block` geht.
- [ ] **Schritt 3:** Neuer Auftragsfall `ban_token_new`: erzeugt einen neuen
  Schlüssel und meldet „Neuer Schlüssel erzeugt. Die alte Adresse antwortet nicht
  mehr; bitte den Alias in der OPNsense auf die neue Adresse umstellen." Der
  Schlüssel selbst steht nicht im Auftragsprotokoll.
- [ ] **Schritt 4:** Klassenprobe ergänzen: Datei entsteht mit den aktiven
  Adressen, Schlüssel entsteht beim Einschalten, ein neuer Schlüssel ist anders,
  das Auftragsprotokoll nennt ihn nicht.
- [ ] **Schritt 5:** Probe laufen lassen.

### Aufgabe E4: Die Stelle, die die Liste ausliefert

**Dateien:**
- Neu: `ispconfig/interface/malwatch_waf_ban_url.php`
- Ändern: `ispconfig/install/file.list`

- [ ] **Schritt 1:** Seite nach dem Muster der öffentlichen Tür von
  `malwatch_dump_download.php`: kein Modul, keine Anmeldung, Parameter `list`.
  Form prüfen, dann `hash_equals` gegen den Schlüssel aus der Konfiguration.
  Stimmt er nicht, `404` mit einer kurzen Zeile. Stimmt er, `Content-Type:
  text/plain; charset=us-ascii`, `Cache-Control: no-store` und die Liste.
- [ ] **Schritt 2:** Fehlt die Datei, kommt die Liste aus der Datenbank.
- [ ] **Schritt 3:** Eintrag in `install/file.list`.
- [ ] **Schritt 4:** `php -l` und `sh ispconfig/tests/check_wiring.sh`.

### Aufgabe E5: Die Adresse auf der Seite „Sperren"

**Dateien:**
- Ändern: `ispconfig/interface/malwatch_waf_ban_list.php`,
  `ispconfig/interface/templates/malwatch_waf_ban_list.htm`,
  `ispconfig/interface/lib/malwatch_waf_panel.inc.php`,
  `ispconfig/interface/lib/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng`

- [ ] **Schritt 1:** `waf_panel_ban_url()` liefert Adresse, Zahl der Adressen und
  den Hinweis; ohne Schlüssel den Satz „Die Liste entsteht, sobald die Automatik
  läuft."
- [ ] **Schritt 2:** Abschnitt in der Vorlage mit der Adresse zum Kopieren, der
  Zahl der Adressen und dem Knopf „Neuen Schlüssel erzeugen" mit Rückfrage.
- [ ] **Schritt 3:** Wörter in beiden Sprachen.
- [ ] **Schritt 4:** `php ispconfig/tests/waf_panel_test.php`,
  `waf_panel_post_test.php`, `check_wiring.sh`.

### Aufgabe E6: waf-switch

**Dateien:**
- Ändern: `waf/waf-switch`

- [ ] **Schritt 1:** `waf-switch ban url` zeigt die Adresse und die Zahl der
  Adressen, `waf-switch ban url new` erzeugt einen neuen Schlüssel.
- [ ] **Schritt 2:** Hilfetext ergänzen, `php -l`.

### Aufgabe E7: Verdrahtung prüfen

**Dateien:**
- Ändern: `ispconfig/tests/check_wiring.sh`

- [ ] **Schritt 1:** Neue Prüfungen: Die Stelle prüft den Schlüssel mit
  `hash_equals`; sie verlangt keine Modulrechte; die Serverklasse schreibt
  `blocked.txt`; der Schlüssel steht in keinem Auftragsprotokoll.
- [ ] **Schritt 2:** `sh ispconfig/tests/check_wiring.sh`.

### Aufgabe E8: Veröffentlichen, einspielen, prüfen

- [ ] **Schritt 1:** Version auf 0.24.0, Changelog, alle Prüfungen, Harness.
- [ ] **Schritt 2:** Commit mit Anhang, nach `main`, Marke `v0.24.0`, Release.
- [ ] **Schritt 3:** Einspielen auf web.herkules, `Kopien geprüft` ohne Abweichung.
- [ ] **Schritt 4:** Live prüfen: Adresse ohne Schlüssel gibt 404, mit Schlüssel
  die Liste; die Liste stimmt mit `/etc/nginx/waf/blocked.conf` überein.
- [ ] **Schritt 5:** Protokolleintrag mit der Adresse **ohne** Schlüssel und der
  Anleitung für die OPNsense.
