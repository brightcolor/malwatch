# malwatch Abwehr, Teil A: Unterbau — Umsetzungsplan

> **Für ausführende Helfer:** Dieser Plan wird Aufgabe für Aufgabe abgearbeitet, über
> `superpowers:executing-plans`. Agenten werden dafür nur nach ausdrücklicher Freigabe
> von Mathias gestartet, siehe globale Vorgaben. Die Schritte tragen Kästchen (`- [ ]`)
> zum Abhaken.

**Ziel:** Der Server liest das Audit-Log der WAF in die Datenbank, räumt es auf und führt
WAF-Aufträge aus (Zustand je Website, Ausnahmen, Notaus, Seitenantwort, Einstellungen).
Die Werkzeuge auf web.herkules tragen danach englische Namen und nutzen denselben Code.

**Aufbau:** Eine Datei mit reinen Funktionen (`malwatch_waf_lib.inc.php`) trägt alle
Entscheidungen und wird am Rechner getestet. Die Serverklasse `malwatch_waf` ist die
dünne Schicht darüber: Datenbank, Dateien, Befehle. Der malwatch-Cron ruft sie jede
Minute auf; `waf-switch`, `waf-guard` und `waf-report` rufen dieselbe Klasse und
dieselben Funktionen auf. Dateien der WAF ändern sich nur über `waf_apply_files()`:
Kopie prüfen, tauschen, `nginx -t`, Reload, bei Fehler zurück ohne Reload.

**Technik:** PHP (Addon: lauffähig ab PHP 7.0, am Rechner PHP 8.4, am Server PHP 8.3 und
`php7.0` zur Syntaxprüfung), MySQL/MariaDB über die Datenbankklasse von ISPConfig 3.3.1p1,
nginx 1.24 mit ModSecurity 3.0.12 und CRS 3.3.5, Bash für Einspielen und Wächter.

**Spec:** `docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md`
Grundlage: `docs/superpowers/specs/2026-09-16-waf-web-herkules-design.md`

Teil B (`docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md`) baut die Seiten im
Panel, veröffentlicht 0.19.0 und spielt alles auf web.herkules ein. Teil A verändert am
Server nichts; seine letzte Aufgabe prüft den Stand dort rein lesend.

## Globale Vorgaben

- **Der Webserver darf niemals ausfallen.** nginx wird nur neu geladen
  (`systemctl reload nginx`), nie neu gestartet, und nur nach bestandenem `nginx -t`. Die
  Konfiguration auf der Platte bleibt jederzeit gültig.
- Jeder Schritt am Server wird vorher von Mathias freigegeben und danach im
  Serverprotokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
  festgehalten: Datum und Uhrzeit vom Server, was, warum, wie, Prüfung, Rückweg. Einträge
  kommen als gezielte Einfügung in die frisch gelesene Datei, neueste zuerst. Keine
  Zugangsdaten im Protokoll.
- Agenten (Subagenten, Hintergrundagenten, Workflows) nur nach ausdrücklicher Freigabe von
  Mathias.
- Namen: Variablen, Funktionen, Dateien, Tabellen, Spalten, Schlüssel, Befehle und
  Code-Kommentare englisch. Oberfläche, Meldungen in `job_log`, Specs und Pläne deutsch.
- Zeiträume und Schwellen sind Einstellungen mit Vorgabe (`waf_settings_defaults()`),
  nie feste Zahlen im Code.
- PHP 7.0: kein `??`, keine Typangaben an Eigenschaften, keine Pfeilfunktionen, keine
  nullbaren Typen. Prüfung: `php7.0 -l` am Server (Aufgabe A9).
- Zeit: PHP läuft in den Serverskripten von ISPConfig in UTC (`$conf['timezone']`),
  MySQL in CEST. Zeitrechnung deshalb in SQL (`NOW()`, `CURDATE()`,
  `UNIX_TIMESTAMP()`); reine Funktionen bekommen Zeitpunkte als `Y-m-d H:i:s` übergeben.
- Keine echten Kundendaten im Repo. Beispiele: `beispiel.test`, `zweite.test`, Adressen
  aus `198.51.100.0/24` und `203.0.113.0/24`.
- Keine Anmeldung im ISPConfig-Panel. WP-CLI nie als root. `/root/mw-db` bleibt unberührt.
- Commits enden mit `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Vor jedem
  Commit läuft `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` und muss leer
  bleiben.
- Gearbeitet wird auf dem Zweig `waf-herkules`. Geschoben wird nur auf Ansage.

## Entscheidungen beim Planen

Diese Punkte präzisieren die Spec; Aufgabe B8 trägt sie dort nach.

1. **Lesestand je Server** in `<state_dir>/waf/reader.json` statt in `malwatch_config`.
   `malwatch_config` ist eine Zeile für alle Server; der Cron hat das schon beim
   Schwachstellenabgleich so gelöst (`queue_due_vulnchecks`).
2. **Notaus hart** schreibt die vhost-Dateien direkt um. Fehlt das Modul, verwirft der
   nginx-Test von ISPConfig jede neu geschriebene vhost-Datei, solange irgendeine andere
   noch `modsecurity` nennt; über das Datalog allein käme der Server nie heraus. Das Feld
   in der Datenbank wird danach trotzdem angepasst, damit ISPConfig denselben Stand
   erzeugt.
3. **Ausnahmen** nehmen keine eigenen Regeln (10000–10999, darunter 10010 gegen
   Passwörter im Log) und keine Wertungsregeln (949xxx, 959xxx, 980xxx) an.
4. **Tageszahlen:** `malwatch_waf_site_day.would_block_logged_in` für die Vorschau vor
   „scharf", `malwatch_waf_day.rule_msg` für „Woran erkannt?".
5. **Eine Prüfung je Durchgang:** Bestätigt ein Durchgang mehrere Websites, läuft
   `nginx -t` einmal für alle.
6. **Eine Ausnahme je Auftrag:** Die Regeldateien entstehen aus den aktiven Ausnahmen und
   der des Auftrags. Unveränderte Dateien lösen keinen Reload aus.
7. **Abgleich:** `migrate_markers` nimmt jede Website mit Block (alte oder neue Markierung)
   und gleicht dabei auch `malwatch_site.waf_state` ab.
8. **Befehle mit festem Pfad** (`/usr/sbin/nginx`, `/usr/bin/systemctl`,
   `/usr/sbin/logrotate`), weil der Cron keinen verlässlichen `PATH` mitbringt.

## Dateien

| Pfad | Aufgabe | Zweck |
|---|---|---|
| `ispconfig/interface/lib/malwatch_waf_lib.inc.php` | A1–A4 | reine Funktionen, installiert unter `interface/web/security/lib/` |
| `ispconfig/tests/waf_lib_test.php` | A1–A4 | Tests der reinen Funktionen |
| `ispconfig/tests/waf_audit_sample.log` | A2 | erfundene Audit-Zeilen im Aufbau von ModSecurity 3.0.12 |
| `ispconfig/install/schema.sql` | A5 | vier Tabellen, neue Spalten, `waf` in zwei Aufzählungen |
| `ispconfig/install/uninstall-schema.sql` | A5 | entfernt die vier Tabellen (und die zwei vergessenen des Dumps) |
| `ispconfig/install/installer.php` | A5 | legt `<state_dir>/waf` mit Unterordnern an |
| `ispconfig/install/file.list` | A5, A6 | neue Dateien |
| `ispconfig/server/lib/classes/malwatch_waf.inc.php` | A6, A7 | Einlesen, Aufräumen, Aufträge, Wächter |
| `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php` | A7 | ruft die Klasse auf, hält `waf` vom Runner fern |
| `ispconfig/server/lib/classes/malwatch_helper.inc.php` | A7 | zählt `waf` nicht als Prüfung |
| `ispconfig/server/plugins/malwatch_plugin.inc.php` | A7 | startet keinen `waf`-Auftrag |
| `ispconfig/tests/check_wiring.sh` | A5, A7, A8 | Prüfungen 51 bis 54 |
| `ispconfig/tests/waf_class_probe.php` | A6, A7 | Test der Serverklasse in einer Wegwerf-Datenbank am Server |
| `ispconfig/tests/waf_ingest_dryrun.php` | A8 | Probelauf des Einlesens gegen den echten Server, schreibt nichts |
| `ispconfig/tests/waf_rules_probe.php` | A9 | prüft die Regeldateien mit `modsec-rules-check` neben `/etc/nginx` |
| `.github/workflows/ci.yml` | A1, A8 | neuer Test, Syntax der Werkzeuge |
| `waf/waf-switch`, `waf/waf-guard`, `waf/waf-report` | A8 | Werkzeuge unter neuen Namen |
| `waf/conf/*.conf`, `waf/conf/logrotate-waf` | A8 | Dateien unter neuen Namen, zwei neue für das Panel |
| `waf/install.sh` | A8 | Umstellung von den alten Namen, mehrfach lauffähig |
| `waf/README.md` | A8 | neue Namen |
| entfällt: `waf/lib/`, `waf/tests/`, `waf/waf-schalter`, `waf/waf-wache`, `waf/waf-bericht`, `waf/conf/{einstellungen,crs-zusatz,ausnahmen-vorher,ausnahmen-nachher,zustand,antwortrumpf}.conf` | A8 | |

## Schnittstellen im Überblick

Reine Funktionen (`malwatch_waf_lib.inc.php`), in der Reihenfolge der Aufgaben:

- A1: `waf_states()`, `waf_state_valid($s)`, `waf_state_normalize($s)`, `waf_block_text($s)`,
  `waf_block_remove($text)`, `waf_block_set($text, $s)`, `waf_block_state($text)`,
  `waf_block_is_old($text)`, `waf_vhost_state($vhost)`, `waf_vhost_strip($vhost)`,
  `waf_response_body_valid($m)`, `waf_response_body_text($m)`,
  `waf_response_body_mode($text)`, `waf_state_file_text($emergency)`,
  `waf_state_file_is_emergency($text)`, `waf_cut($text, $bytes)`, `waf_json($value)`
- A2: `waf_utf8_clean($text)`, `waf_audit_time($stamp)`, `waf_audit_header($headers, $name)`,
  `waf_host_normalize($host)`, `waf_cookie_names($header)`, `waf_headers_sanitize($headers)`,
  `waf_is_scoring_rule($id)`, `waf_audit_param($data)`, `waf_audit_parse_line($line)`,
  `waf_audit_summarize($lines)`, `waf_reader_start($inode, $offset, $new_inode, $size)`,
  `waf_read_lines($file, $offset, $max)`
- A3: `waf_host_map($rows)`, `waf_host_lookup($map, $host)`, `waf_hosts_of($map, $site)`,
  `waf_host_pattern($hosts)`, `waf_exception_scopes()`, `waf_exception_check($row)`,
  `waf_exception_rule_id($id)`, `waf_exception_rules($rows, $hosts)`,
  `waf_exception_preview($items, $exception)`
- A4: `waf_settings_defaults()`, `waf_settings_limits()`, `waf_settings($row)`,
  `waf_enforce_free_from($since, $days)`, `waf_enforce_block_reason(...)`,
  `waf_periods($stats_days)`, `waf_period($requested, $stats_days)`,
  `waf_logrotate_text($days, $log)`, `waf_site_plan(...)`, `waf_site_progress(...)`,
  `waf_rollback_allowed($text, $hash)`, `waf_conf_files($dir)`, `waf_write_atomic($file, $text)`,
  `waf_remove_dir($dir)`, `waf_snapshot($dir, $target)`, `waf_restore_snapshot($snap, $dir)`,
  `waf_apply_files($paths, $changes, $run)`

Serverklasse `malwatch_waf` (A6, A7), öffentlich: `ready()`, `settings()`, `cron_minute()`,
`cron_hourly()`, `ingest($opts)`, `ingest_locked()`, `cleanup()`, `run_jobs()`, `pass()`,
`queue($action, $fields, $user)`, `execute_now($action, $fields, $user)`, `job($id)`,
`vhost_state($domain)`, `guard()`, `snapshot()`, `run_command($name, $argument)`.

Auftrag (`malwatch_job`): `job_kind = 'waf'`, `parent_domain_id = 0`, `options` als JSON mit
`action` und `user`, dazu je Aktion:

| `action` | Felder | Zusatz während des Laufs |
|---|---|---|
| `set_state` | `domain_ids`, `state` | `progress` (Liste je Website), `backup_dir` |
| `migrate_markers` | — | wie `set_state` |
| `exception_add`, `exception_remove` | `exception_id` | — |
| `emergency` | `on`, `hard` | — |
| `response_body` | `mode` | — |
| `apply_settings` | — | — |

Ein Eintrag in `progress`: `domain_id`, `domain`, `target`, `status`
(`waiting`, `confirmed`, `skipped`, `failed`), `reason`, `backup`, `written_hash`,
`rollback`, `detail`.

---

### Aufgabe A1: Zustände, Block, vhost, Seitenantwort, Notausdatei

Die bisherigen Funktionen aus `waf/lib/waf_block.inc.php` ziehen mit englischen Namen in
die gemeinsame Datei. Die alte Markierung bleibt lesbar.

**Dateien:**
- Neu: `ispconfig/interface/lib/malwatch_waf_lib.inc.php`
- Neu: `ispconfig/tests/waf_lib_test.php`
- Ändern: `ispconfig/install/file.list` (eine Zeile am Ende)
- Ändern: `.github/workflows/ci.yml` (ein Testschritt)

**Schnittstellen:**
- Nutzt: nichts
- Liefert: Konstanten `WAF_MARK_BEGIN`, `WAF_MARK_END`, `WAF_MARK_BEGIN_OLD`,
  `WAF_MARK_END_OLD`, `WAF_REMOVED` (`'[entfernt]'`), `WAF_RULE_LEAN` (10199),
  `WAF_RULE_EXCEPTION_BASE` (10200) und die Funktionen der Zeile A1 im Überblick.
  Zustände sind immer `'off'`, `'detect'`, `'enforce'`; Modi der Seitenantwort `'full'`,
  `'lean'`.

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_lib_test.php`:

```php
<?php
/**
 * Checks the pure functions of the WAF part ("Abwehr").
 *
 *   php ispconfig/tests/waf_lib_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_lib.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

// --- A1: states, block, vhost, response body, state file ---------------------

$block_detect = "# WAF-BEGIN (detect) - managed by waf-switch\nmodsecurity on;\n# WAF-END\n";
$block_enforce = "# WAF-BEGIN (enforce) - managed by waf-switch\nmodsecurity on;\nmodsecurity_rules 'SecRuleEngine On';\n# WAF-END\n";
$block_old = "# WAF-Anfang (mitschreiben) \xE2\x80\x93 verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n";

expect_same('states', waf_states(), array('off', 'detect', 'enforce'));
expect_same('valid detect', waf_state_valid('detect'), true);
expect_same('invalid old name', waf_state_valid('scharf'), false);
expect_same('normalize old', waf_state_normalize('mitschreiben'), 'detect');
expect_same('normalize scharf', waf_state_normalize('scharf'), 'enforce');
expect_same('normalize aus', waf_state_normalize('aus'), 'off');
expect_same('normalize new', waf_state_normalize('enforce'), 'enforce');
expect_same('normalize junk', waf_state_normalize('an'), '');

expect_same('empty field, detect', waf_block_set('', 'detect'), $block_detect);
expect_same('empty field, enforce', waf_block_set('', 'enforce'), $block_enforce);
expect_same('empty field, off', waf_block_set('', 'off'), '');
expect_same('unknown state writes nothing', waf_block_set('', 'an'), '');
expect_same('null field', waf_block_set(null, 'detect'), $block_detect);

$own = "location = /xmlrpc.php {\n    deny all;\n}\n";
$set = waf_block_set($own, 'detect');
expect_same('own directives stay', substr($set, 0, strlen($own)), $own);
expect_same('block at the end', substr($set, -strlen($block_detect)), $block_detect);
expect_same('round trip', waf_block_set($set, 'off'), $own);
$enforced = waf_block_set($set, 'enforce');
expect_same('one begin', substr_count($enforced, '# WAF-BEGIN'), 1);
expect_same('one end', substr_count($enforced, '# WAF-END'), 1);
expect_same('round trip after change', waf_block_set($enforced, 'off'), $own);

$crlf = "location / {\r\n    try_files \$uri =404;\r\n}\r\n";
expect_same('CRLF stays', waf_block_set(waf_block_set($crlf, 'detect'), 'off'), $crlf);
expect_same('line break added', waf_block_set('client_max_body_size 64M;', 'detect'), "client_max_body_size 64M;\n" . $block_detect);

// The block of the first tool is replaced, not doubled.
$old_field = $own . $block_old;
expect_same('old marker is old', waf_block_is_old($old_field), true);
expect_same('new marker is not old', waf_block_is_old($set), false);
expect_same('old state read', waf_block_state($old_field), 'detect');
expect_same('old block replaced', waf_block_set($old_field, 'detect'), $set);
expect_same('old block removed', waf_block_remove($old_field), $own);
expect_same('state detect', waf_block_state($set), 'detect');
expect_same('state enforce', waf_block_state($enforced), 'enforce');
expect_same('state without block', waf_block_state($own), 'off');
expect_same('state with odd marker', waf_block_state("# WAF-BEGIN (maybe)\nmodsecurity on;\n# WAF-END\n"), 'off');

// ISPConfig drops comment lines when it writes the vhost; only directives count.
expect_same('vhost off', waf_vhost_state("server {\n    listen 80;\n}\n"), 'off');
expect_same('vhost detect', waf_vhost_state("server {\n    modsecurity on;\n}\n"), 'detect');
expect_same('vhost enforce', waf_vhost_state("server {\n    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n}\n"), 'enforce');
expect_same('vhost commented', waf_vhost_state("server {\n    # modsecurity on;\n}\n"), 'off');
expect_same('vhost switched off', waf_vhost_state("server {\n    modsecurity off;\n}\n"), 'off');
expect_same('vhost empty', waf_vhost_state(''), 'off');

$vhost = "server {\n    listen 80;\n    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n    root /var/www;\n}\n";
$stripped = waf_vhost_strip($vhost);
expect_same('strip removes both lines', $stripped, array("server {\n    listen 80;\n    root /var/www;\n}\n", 2));
expect_same('strip leaves a clean file', waf_vhost_strip("server {\n}\n"), array("server {\n}\n", 0));
expect_same('stripped vhost is off', waf_vhost_state($stripped[0]), 'off');

$full = waf_response_body_text('full');
$lean = waf_response_body_text('lean');
expect_same('full without rule', strpos($full, 'ctl:auditLogParts=-E'), false);
expect_same('lean rule', strpos($lean, 'SecAction "id:10199,phase:5,pass,nolog,ctl:auditLogParts=-E"') !== false, true);
expect_same('mode full', waf_response_body_mode($full), 'full');
expect_same('mode lean', waf_response_body_mode($lean), 'lean');
expect_same('mode of empty file', waf_response_body_mode(''), 'full');
expect_same('mode ignores comments', waf_response_body_mode("# ctl:auditLogParts=-E\n"), 'full');
expect_same('valid lean', waf_response_body_valid('lean'), true);
expect_same('invalid old name', waf_response_body_valid('schlank'), false);
expect_same('unknown mode writes full', waf_response_body_text('schlank'), $full);

expect_same('state file normal', waf_state_file_is_emergency(waf_state_file_text(false)), false);
expect_same('state file emergency', waf_state_file_is_emergency(waf_state_file_text(true)), true);
expect_same('state file emergency line', substr(waf_state_file_text(true), -18), "SecRuleEngine Off\n");
expect_same('old state file', waf_state_file_is_emergency("# Notaus-Schalter\nSecRuleEngine Off\n"), true);

expect_same('cut keeps short text', waf_cut('abc', 5), 'abc');
expect_same('cut on a character boundary', waf_cut("a\xC3\xA4b", 2), 'a');
expect_same('json of a list', waf_json(array('a' => '/x', 'b' => "\xC3\xA4")), "{\"a\":\"/x\",\"b\":\"\xC3\xA4\"}");
expect_same('json of broken text', waf_json(array("\xFF")), '[]');

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_lib: alle Prüfungen bestanden\n";
```

Spätere Aufgaben fügen ihre Abschnitte unmittelbar vor der Zeile
`// --- summary ---` ein.

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: Abbruch mit „Failed opening required … malwatch_waf_lib.inc.php"

- [ ] **Schritt 3: Funktionen schreiben**

`ispconfig/interface/lib/malwatch_waf_lib.inc.php`:

```php
<?php

/**
 * Pure functions for the WAF part of malwatch ("Abwehr" in the panel).
 *
 * Shared by the panel pages, the server class malwatch_waf, the tools under
 * waf/ and the tests. Text and arrays in, text and arrays out. The only file
 * access sits in waf_read_lines() and the file helpers at the end, which take
 * their paths and commands from the caller.
 *
 * Runs on PHP 7.0: no ??, no typed properties, no arrow functions.
 */

if (!defined('WAF_MARK_BEGIN')) {
	define('WAF_MARK_BEGIN', '# WAF-BEGIN');
	define('WAF_MARK_END', '# WAF-END');
	// Written by the first tool (waf-schalter) and still recognised.
	define('WAF_MARK_BEGIN_OLD', '# WAF-Anfang');
	define('WAF_MARK_END_OLD', '# WAF-Ende');
	// Shown in the panel in place of a removed header value.
	define('WAF_REMOVED', '[entfernt]');
	define('WAF_RULE_LEAN', 10199);
	define('WAF_RULE_EXCEPTION_BASE', 10200);
}

function waf_states()
{
	return array('off', 'detect', 'enforce');
}

function waf_state_valid($state)
{
	return in_array($state, waf_states(), true);
}

/** Maps the names of the first tool onto the current ones; '' for anything else. */
function waf_state_normalize($state)
{
	$old = array('aus' => 'off', 'mitschreiben' => 'detect', 'scharf' => 'enforce');
	$state = (string) $state;
	if (isset($old[$state])) {
		return $old[$state];
	}
	return waf_state_valid($state) ? $state : '';
}

/** The managed block for the field "nginx directives"; '' for off. */
function waf_block_text($state)
{
	if ($state === 'off' || !waf_state_valid($state)) {
		return '';
	}
	$lines = array(WAF_MARK_BEGIN . ' (' . $state . ') - managed by waf-switch', 'modsecurity on;');
	if ($state === 'enforce') {
		$lines[] = "modsecurity_rules 'SecRuleEngine On';";
	}
	$lines[] = WAF_MARK_END;
	return implode("\n", $lines) . "\n";
}

/**
 * Removes the managed block, new or old marker, with its own line break.
 * Everything around it stays byte for byte, the break of the line before
 * included.
 */
function waf_block_remove($text)
{
	$pattern = '/(?:' . preg_quote(WAF_MARK_BEGIN, '/') . '.*?' . preg_quote(WAF_MARK_END, '/')
		. '|' . preg_quote(WAF_MARK_BEGIN_OLD, '/') . '.*?' . preg_quote(WAF_MARK_END_OLD, '/')
		. ')[^\r\n]*(?:\R)?/s';
	return preg_replace($pattern, '', (string) $text);
}

function waf_block_set($text, $state)
{
	$rest = waf_block_remove($text);
	$block = waf_block_text($state);
	if ($block === '') {
		return $rest;
	}
	if (trim($rest) === '') {
		return $block;
	}
	// A text without a closing line break gets one; anything else stays as it is.
	if (!preg_match('/\R$/', $rest)) {
		$rest .= "\n";
	}
	return $rest . $block;
}

/** The state the managed block names; 'off' without a block or with an unknown name. */
function waf_block_state($text)
{
	$text = (string) $text;
	foreach (array(WAF_MARK_BEGIN, WAF_MARK_BEGIN_OLD) as $mark) {
		if (preg_match('/' . preg_quote($mark, '/') . '\s*\(([a-z]+)\)/', $text, $m)) {
			$state = waf_state_normalize($m[1]);
			return $state === '' ? 'off' : $state;
		}
	}
	return 'off';
}

function waf_block_is_old($text)
{
	return strpos((string) $text, WAF_MARK_BEGIN_OLD) !== false;
}

/**
 * The state a generated vhost file shows. ISPConfig drops comment lines when
 * it copies the directives into the vhost, so only the directives count.
 */
function waf_vhost_state($vhost)
{
	$on = false;
	$enforce = false;
	foreach (preg_split('/\R/', (string) $vhost) as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if (preg_match('/^modsecurity\s+on\s*;/i', $line)) {
			$on = true;
		}
		if (preg_match('/^modsecurity_rules\s+.*SecRuleEngine\s+On/i', $line)) {
			$enforce = true;
		}
	}
	if ($on && $enforce) {
		return 'enforce';
	}
	return $on ? 'detect' : 'off';
}

/**
 * The vhost text without any modsecurity directive, for the hard emergency
 * stop: with the module gone, nginx rejects every file that still names one.
 * Returns array(text, number of removed lines).
 */
function waf_vhost_strip($vhost)
{
	$kept = array();
	$removed = 0;
	foreach (preg_split('/(?<=\n)/', (string) $vhost, -1, PREG_SPLIT_NO_EMPTY) as $line) {
		if (preg_match('/^\s*modsecurity(?:_[a-z_]+)?\s/i', $line)) {
			$removed++;
			continue;
		}
		$kept[] = $line;
	}
	return array(implode('', $kept), $removed);
}

function waf_response_body_valid($mode)
{
	return in_array($mode, array('full', 'lean'), true);
}

/**
 * Content of response-body.conf. 110 CRS rules set ctl:auditLogParts=+E and so
 * write the whole response into the entry; "lean" takes it back out in phase 5,
 * after every CRS rule ran. Anything but 'lean' writes 'full'.
 */
function waf_response_body_text($mode)
{
	$lean = $mode === 'lean';
	$lines = array(
		'# Response body in the audit log: ' . ($lean ? 'lean' : 'full'),
		'# Managed by malwatch (page Abwehr, waf-switch response-body). Do not edit.',
		'#',
		'# full: CRS rules may write the whole response into the entry. 110 rules set',
		'#       ctl:auditLogParts=+E; a hit then weighs about 125 KB instead of about 4 KB.',
		'# lean: a phase 5 rule takes the response back out after every CRS rule ran.',
		'#       Matches, headers and the request body stay complete.',
	);
	if ($lean) {
		$lines[] = 'SecAction "id:' . WAF_RULE_LEAN . ',phase:5,pass,nolog,ctl:auditLogParts=-E"';
	}
	return implode("\n", $lines) . "\n";
}

/** The mode a response-body.conf (or the old antwortrumpf.conf) carries. Comments do not count. */
function waf_response_body_mode($text)
{
	foreach (preg_split('/\R/', (string) $text) as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if (strpos($line, 'ctl:auditLogParts=-E') !== false) {
			return 'lean';
		}
	}
	return 'full';
}

/** Content of state.conf, the emergency switch; included after every other file. */
function waf_state_file_text($emergency)
{
	$text = "# Emergency switch. Empty in normal operation; the emergency stop writes\n"
		. "# SecRuleEngine Off below. Managed by malwatch, do not edit.\n";
	return $emergency ? $text . "SecRuleEngine Off\n" : $text;
}

function waf_state_file_is_emergency($text)
{
	foreach (preg_split('/\R/', (string) $text) as $line) {
		if (preg_match('/^\s*SecRuleEngine\s+Off\b/i', $line)) {
			return true;
		}
	}
	return false;
}

/** At most $bytes bytes of $text, cut on a UTF-8 character boundary. */
function waf_cut($text, $bytes)
{
	$text = (string) $text;
	if (strlen($text) <= $bytes) {
		return $text;
	}
	if (function_exists('mb_strcut')) {
		return mb_strcut($text, 0, $bytes, 'UTF-8');
	}
	return preg_replace('/[\x80-\xFF]+$/', '', substr($text, 0, $bytes));
}

/** JSON for the database; '[]' when the value cannot be encoded. */
function waf_json($value)
{
	$json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	return $json === false ? '[]' : $json;
}
```

- [ ] **Schritt 4: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [ ] **Schritt 5: Datei eintragen und in die CI aufnehmen**

In `ispconfig/install/file.list` unter der letzten Zeile
(`c:interface/lib/malwatch_lib.inc.php:interface/web/security/lib/malwatch_lib.inc.php`):

```text
# Pure functions of the WAF part; the server class and the tools under waf/
# include them from this installed path.
c:interface/lib/malwatch_waf_lib.inc.php:interface/web/security/lib/malwatch_waf_lib.inc.php
```

In `.github/workflows/ci.yml` im Job `php-syntax` nach dem Schritt „Panel helpers":

```yaml
      - name: WAF functions
        run: php ispconfig/tests/waf_lib_test.php
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Schritt 6: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/tests/waf_lib_test.php ispconfig/install/file.list .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): shared WAF functions for block, vhost and response body" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Die grep-Zeile muss ohne Ausgabe bleiben.

### Aufgabe A2: Audit-Zeilen lesen

Eine Zeile des JSON-Audit-Logs wird zu einem Treffer: Zeit, Host, Pfad, Regeln, Punktzahl,
„angemeldet", bereinigte Kopfzeilen, Anfrageinhalt und Seitenantwort. Dazu das Lesen in
Stücken mit Lesestand und die Zusammenfassung für `waf-report`.

Der Aufbau der Beispielzeilen folgt einer echten Zeile von web.herkules (ModSecurity
3.0.12, rein lesend am 16.09.2026 angesehen, Werte ersetzt): `time_stamp` im Format von
`ctime` in Ortszeit, `unique_id` mit 19 Zeichen, Regel 949110 mit „Total Score: 5",
Kopfzeilen mit großen Anfangsbuchstaben, `request.body` als Text, `response.body` nur bei
Regeln mit `+E`.

**Dateien:**
- Neu: `ispconfig/tests/waf_audit_sample.log`
- Ändern: `ispconfig/tests/waf_lib_test.php` (Abschnitt A2)
- Ändern: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (Funktionen anhängen)

**Schnittstellen:**
- Nutzt: `waf_cut()`, `WAF_REMOVED` aus A1
- Liefert: `waf_audit_parse_line($line)` gibt `null` oder dieses Feld zurück:
  `unique_id` (string ≤ 64, ersatzweise `'sha1-' . sha1(Zeile)`), `seen_at` (`Y-m-d H:i:s`),
  `client_ip` (gültige IP oder `''`), `host` (normalisiert oder `''`), `method`, `uri`
  (≤ 2048 Bytes), `path` (ohne Query, ≤ 1024 Bytes), `status` (int), `rules` (Liste aus
  `id`, `msg`, `data`, `param`, je Regel einmal, höchstens 50), `anomaly_score` (int),
  `would_block` (bool), `logged_in` (bool), `headers` (bereinigt), `body` (string oder
  `null`), `response_body` (string oder `null`).
  `waf_read_lines()` gibt `array('lines' => …, 'offset' => int, 'more' => bool)` oder
  `null` zurück. `waf_audit_summarize()` liefert Zeilen mit `host`, `rule_id`, `message`,
  `hits`, `example`.

- [ ] **Schritt 1: Beispieldaten anlegen**

`ispconfig/tests/waf_audit_sample.log`:

```text
{"transaction":{"client_ip":"198.51.100.7","time_stamp":"Wed Sep 16 21:09:19 2026","server_id":"0f3d6a2b9c8e7d6f5a4b3c2d1e0f9a8b7c6d5e4f","client_port":0,"host_ip":"10.50.0.11","host_port":80,"unique_id":"1758049759112233445","request":{"method":"POST","http_version":1.1,"uri":"/wp-json/batch/v1","body":"{\"requests\":[{\"path\":\"/wp/v2/posts?filter=exec master..xp_cmdshell\"}]}","headers":{"Content-Length":"73","X-Forwarded-Host":"beispiel.test","Content-Type":"application/json","X-Forwarded-For":"198.51.100.7","Cookie":"wordpress_logged_in_0a1b2c=geheim%7C123; wp-settings-1=libraryContent%3Dbrowse","Authorization":"Basic Z2VoZWltOmdlaGVpbQ==","Host":"beispiel.test"}},"response":{"http_code":207,"headers":{"Content-Type":"application/json; charset=UTF-8"}},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"DetectionOnly","components":["OWASP_CRS/3.3.5\""]},"messages":[{"message":"Detects MSSQL code execution and information gathering attempts","details":{"match":"Matched \"Operator `Rx' with parameter `(?i:(?:[\\s(]+(?:exec' against variable `ARGS:json.requests.0.path'","reference":"o36,10v42,73","ruleId":"942190","file":"/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"165","data":"Matched Data: exec master..xp_cmdshell found within ARGS:json.requests.0.path: /wp/v2/posts?filter=exec master..xp_cmdshell","severity":"2","ver":"OWASP_CRS/3.3.5","rev":"","tags":["application-multi","language-multi","platform-multi","attack-sqli"],"maturity":"0","accuracy":"0"}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"match":"Matched \"Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )","reference":"","ruleId":"949110","file":"/usr/share/modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf","lineNumber":"81","data":"","severity":"2","ver":"OWASP_CRS/3.3.5","rev":"","tags":["application-multi","language-multi","platform-multi","attack-generic"],"maturity":"0","accuracy":"0"}}]}}
{"transaction":{"client_ip":"203.0.113.9","time_stamp":"Sun Sep  6 09:05:00 2026","server_id":"0f3d6a2b9c8e7d6f5a4b3c2d1e0f9a8b7c6d5e4f","client_port":0,"host_ip":"10.50.0.11","host_port":80,"unique_id":"1757142300998877665","request":{"method":"GET","http_version":1.1,"uri":"/suche?q=1%27+OR+%271%27%3D%271","headers":{"Host":"WWW.Beispiel.TEST:8080","User-Agent":"Mozilla/5.0"}},"response":{"body":"<html><body>Treffer</body></html>","http_code":200,"headers":{"Content-Type":"text/html; charset=UTF-8"}},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"DetectionOnly","components":["OWASP_CRS/3.3.5\""]},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","reference":"v8,26","ruleId":"942100","file":"/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"46","data":"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1","severity":"2","ver":"OWASP_CRS/3.3.5","rev":"","tags":["attack-sqli"],"maturity":"0","accuracy":"0"}}]}}
{"transaction":{"client_ip":"198.51.100.9","time_stamp":"Wed Sep 16 09:05:00 2026","client_port":0,"host_ip":"10.50.0.11","host_port":80,"request":{"method":"GET","http_version":1.1,"uri":"/seite?x=%3Cscript%3E","headers":{"host":"zweite.test"}},"response":{"http_code":404,"headers":{}},"messages":[{"message":"XSS Attack Detected via libinjection","details":{"ruleId":"941100","data":"Matched Data: XSS data found within ARGS:x: <script>","severity":"2"}},{"message":"XSS Attack Detected via libinjection","details":{"ruleId":"941100","data":"Matched Data: XSS data found within ARGS_NAMES:x: x","severity":"2"}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 10)","details":{"ruleId":"949110","data":""}},{"message":"Inbound Anomaly Score Exceeded (Total Inbound Score: 10 - SQLI=0,XSS=10,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 10, 0, 0, 0","details":{"ruleId":"980130","data":""}}]}}
kaputte zeile ohne json
{"transaction":{"client_ip":"198.51.100.1","time_stamp":"Wed Sep 16 10:00:00 2026","request":{"method":"GET","uri":"/","headers":{"Host":"beispiel.test"}},"response":{"http_code":200},"messages":[]}}
{"transaction":{"client_ip":"198.51.100.2","time_stamp":"Wed Sep 16 11:00:00 2026","unique_id":"1758013200000000001","request":{"method":"GET","uri":"/.env","headers":{"Host":"fremd.test"}},"response":{"http_code":404},"messages":[{"message":"Restricted File Access Attempt","details":{"ruleId":"930130","data":"Matched Data: /.env found within REQUEST_FILENAME: /.env"}}]}}
{"transaction":{"time_stamp":"gestern","request":{"uri":"/","headers":{"Host":"beispiel.test"}},"messages":[{"message":"x","details":{"ruleId":"941100"}}]}}
{"transaction":{"client_ip":"198.51.100.9","time_stamp":"Wed Sep 16 09:06:00 2026","unique_id":"1757999160000000002","request":{"method":"GET","uri":"/seite?x=%3Csvg%3E","headers":{"Host":"zweite.test"}},"response":{"http_code":404},"messages":[{"message":"XSS Attack Detected via libinjection","details":{"ruleId":"941100","data":"Matched Data: XSS data found within ARGS:x: <svg>"}}]}}
```

Die Datei endet mit einem Zeilenumbruch. Adressen und Namen sind erfunden.

- [ ] **Schritt 2: Test schreiben**

In `ispconfig/tests/waf_lib_test.php` vor der Zeile `// --- summary ---` einfügen:

`ispconfig/tests/waf_lib_test.php` (Abschnitt vor summary):

```php
// --- A2: audit lines ---------------------------------------------------------

$sample = file(__DIR__ . '/waf_audit_sample.log', FILE_IGNORE_NEW_LINES);
expect_same('sample has eight lines', count($sample), 8);

$hit = waf_audit_parse_line($sample[0]);
expect_same('1 unique id', $hit['unique_id'], '1758049759112233445');
expect_same('1 time', $hit['seen_at'], '2026-09-16 21:09:19');
expect_same('1 client', $hit['client_ip'], '198.51.100.7');
expect_same('1 host', $hit['host'], 'beispiel.test');
expect_same('1 method', $hit['method'], 'POST');
expect_same('1 uri', $hit['uri'], '/wp-json/batch/v1');
expect_same('1 path', $hit['path'], '/wp-json/batch/v1');
expect_same('1 status', $hit['status'], 207);
expect_same('1 rule ids', array($hit['rules'][0]['id'], $hit['rules'][1]['id']), array('942190', '949110'));
expect_same('1 rule message', $hit['rules'][0]['msg'], 'Detects MSSQL code execution and information gathering attempts');
expect_same('1 parameter', $hit['rules'][0]['param'], 'json.requests.0.path');
expect_same('1 no parameter on the score', $hit['rules'][1]['param'], '');
expect_same('1 score', $hit['anomaly_score'], 5);
expect_same('1 would block', $hit['would_block'], true);
expect_same('1 logged in', $hit['logged_in'], true);
expect_same('1 cookie values removed', $hit['headers']['Cookie'], 'wordpress_logged_in_0a1b2c=[entfernt]; wp-settings-1=[entfernt]');
expect_same('1 authorization removed', $hit['headers']['Authorization'], '[entfernt]');
expect_same('1 other headers stay', $hit['headers']['Content-Type'], 'application/json');
expect_same('1 body', $hit['body'], '{"requests":[{"path":"/wp/v2/posts?filter=exec master..xp_cmdshell"}]}');
expect_same('1 no response body', $hit['response_body'], null);
expect_same('1 no secret left', strpos(waf_json($hit), 'geheim'), false);

$hit = waf_audit_parse_line($sample[1]);
expect_same('2 padded day', $hit['seen_at'], '2026-09-06 09:05:00');
expect_same('2 host with port and capitals', $hit['host'], 'www.beispiel.test');
expect_same('2 path without query', $hit['path'], '/suche');
expect_same('2 uri with query', $hit['uri'], '/suche?q=1%27+OR+%271%27%3D%271');
expect_same('2 parameter q', $hit['rules'][0]['param'], 'q');
expect_same('2 would not block', $hit['would_block'], false);
expect_same('2 score zero', $hit['anomaly_score'], 0);
expect_same('2 not logged in', $hit['logged_in'], false);
expect_same('2 no body', $hit['body'], null);
expect_same('2 response body', $hit['response_body'], '<html><body>Treffer</body></html>');

$hit = waf_audit_parse_line($sample[2]);
expect_same('3 id from the line', substr($hit['unique_id'], 0, 5) . strlen($hit['unique_id']), 'sha1-45');
expect_same('3 same id twice', waf_audit_parse_line($sample[2])['unique_id'], $hit['unique_id']);
expect_same('3 lower-case host header', $hit['host'], 'zweite.test');
expect_same('3 each rule once', count($hit['rules']), 3);
expect_same('3 first match names the parameter', $hit['rules'][0]['param'], 'x');
expect_same('3 score', $hit['anomaly_score'], 10);
expect_same('3 status', $hit['status'], 404);

expect_same('4 broken line', waf_audit_parse_line($sample[3]), null);
expect_same('5 no messages', waf_audit_parse_line($sample[4]), null);
expect_same('7 no time', waf_audit_parse_line($sample[6]), null);
expect_same('empty line', waf_audit_parse_line(''), null);

$bad = str_replace('/seite?x=%3Csvg%3E', "/seite\xFF?x=1", $sample[7]);
$hit = waf_audit_parse_line($bad);
expect_same('invalid UTF-8 still read', is_array($hit), true);
expect_same('invalid UTF-8 replaced in the path', $hit['path'], "/seite\xEF\xBF\xBD");
expect_same('invalid UTF-8 keeps the query apart', $hit['uri'], "/seite\xEF\xBF\xBD?x=1");
expect_same('invalid UTF-8 encodes', waf_json($hit) !== '[]', true);

expect_same('utf8 clean keeps valid', waf_utf8_clean("gr\xC3\xBC\xC3\x9F"), "gr\xC3\xBC\xC3\x9F");
expect_same('utf8 clean replaces', waf_utf8_clean("a\xFFb"), "a\xEF\xBF\xBDb");

expect_same('time', waf_audit_time('Wed Sep 16 21:09:19 2026'), '2026-09-16 21:09:19');
expect_same('time impossible date', waf_audit_time('Mon Feb 30 10:00:00 2026'), '');
expect_same('time words', waf_audit_time('gestern'), '');

expect_same('header lookup', waf_audit_header(array('host' => 'a.test'), 'Host'), 'a.test');
expect_same('header missing', waf_audit_header(array(), 'Host'), '');

expect_same('host dot', waf_host_normalize('beispiel.test.'), 'beispiel.test');
expect_same('host ipv6', waf_host_normalize('[::1]:80'), '');
expect_same('host space', waf_host_normalize('bad host'), '');
expect_same('host underscore', waf_host_normalize('a_b.test'), '');
expect_same('host empty', waf_host_normalize(''), '');

expect_same('cookie names', waf_cookie_names('a=1; b=2;c'), array('a', 'b', 'c'));
expect_same('no cookies', waf_cookie_names(''), array());

expect_same('score 949', waf_is_scoring_rule('949110'), true);
expect_same('score 959', waf_is_scoring_rule('959100'), true);
expect_same('score 980', waf_is_scoring_rule('980130'), true);
expect_same('detection rule', waf_is_scoring_rule('942100'), false);
expect_same('own rule', waf_is_scoring_rule('10001'), false);

expect_same('param of ARGS', waf_audit_param('Matched Data: x found within ARGS:q: y'), 'q');
expect_same('param of ARGS_NAMES', waf_audit_param('found within ARGS_NAMES:x: x'), '');
expect_same('param of a file name', waf_audit_param('found within REQUEST_FILENAME: /.env'), '');

$report = waf_audit_summarize($sample);
expect_same('report groups', count($report), 4);
expect_same('report first', array($report[0]['host'], $report[0]['rule_id'], $report[0]['hits']), array('zweite.test', '941100', 2));
expect_same('report example', $report[0]['example'], '/seite');
expect_same('report second by name', array($report[1]['host'], $report[1]['rule_id']), array('beispiel.test', '942190'));
expect_same('report leaves the score out', in_array('949110', array_column($report, 'rule_id'), true), false);

expect_same('reader new inode', waf_reader_start(0, 0, 5, 100), 0);
expect_same('reader goes on', waf_reader_start(5, 50, 5, 100), 50);
expect_same('reader after copytruncate', waf_reader_start(5, 50, 5, 40), 0);
expect_same('reader after rotation', waf_reader_start(5, 50, 6, 100), 0);

$log = tempnam(sys_get_temp_dir(), 'waf');
file_put_contents($log, "a\nb\nc");
expect_same('read complete lines', waf_read_lines($log, 0, 10), array('lines' => array('a', 'b'), 'offset' => 4, 'more' => false));
expect_same('read one line', waf_read_lines($log, 0, 1), array('lines' => array('a'), 'offset' => 2, 'more' => true));
file_put_contents($log, "\n", FILE_APPEND);
expect_same('read the finished line', waf_read_lines($log, 4, 10), array('lines' => array('c'), 'offset' => 6, 'more' => false));
expect_same('read past the end', waf_read_lines($log, 6, 10), array('lines' => array(), 'offset' => 6, 'more' => false));
unlink($log);
expect_same('read a missing file', waf_read_lines($log, 0, 10), null);
```

- [ ] **Schritt 3: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: Abbruch mit „Call to undefined function waf_audit_parse_line()"

- [ ] **Schritt 4: Funktionen anhängen**

Am Ende von `ispconfig/interface/lib/malwatch_waf_lib.inc.php`:

`ispconfig/interface/lib/malwatch_waf_lib.inc.php` (anhängen):

```php
// --- Audit log ---------------------------------------------------------------

/**
 * Replaces bytes that are no valid UTF-8 with U+FFFD, so json_decode and
 * MySQL accept the text. A question mark would read as the start of a query.
 */
function waf_utf8_clean($text)
{
	$text = (string) $text;
	if (preg_match('//u', $text) === 1) {
		return $text;
	}
	if (function_exists('mb_convert_encoding')) {
		$previous = mb_substitute_character();
		mb_substitute_character(0xFFFD);
		$text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
		mb_substitute_character($previous);
		return $text;
	}
	return preg_replace('/[\x80-\xFF]/', "\xEF\xBF\xBD", $text);
}

/** 'Wed Sep 16 21:09:19 2026' (ctime, local time of the web server) as 'Y-m-d H:i:s'; '' otherwise. */
function waf_audit_time($stamp)
{
	$months = array('Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4, 'May' => 5, 'Jun' => 6,
		'Jul' => 7, 'Aug' => 8, 'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12);
	if (!preg_match('/^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/', trim((string) $stamp), $m)) {
		return '';
	}
	if (!isset($months[$m[1]]) || !checkdate($months[$m[1]], (int) $m[2], (int) $m[6])
		|| (int) $m[3] > 23 || (int) $m[4] > 59 || (int) $m[5] > 60) {
		return '';
	}
	return sprintf('%04d-%02d-%02d %02d:%02d:%02d', (int) $m[6], $months[$m[1]], (int) $m[2],
		(int) $m[3], (int) $m[4], min(59, (int) $m[5]));
}

/** A request header by name, whatever its case; '' when missing. */
function waf_audit_header($headers, $name)
{
	if (!is_array($headers)) {
		return '';
	}
	foreach ($headers as $key => $value) {
		if (strcasecmp((string) $key, $name) === 0) {
			return is_array($value) ? implode(', ', $value) : (string) $value;
		}
	}
	return '';
}

/** A host name the way the host map knows it: lower case, no port, no closing dot; '' if unusable. */
function waf_host_normalize($host)
{
	$host = strtolower(trim((string) $host));
	$host = rtrim(preg_replace('/:\d+$/', '', $host), '.');
	if ($host === '' || strlen($host) > 253
		|| !preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/', $host)) {
		return '';
	}
	return $host;
}

/** The cookie names of a Cookie header, in order, without their values. */
function waf_cookie_names($header)
{
	$names = array();
	foreach (explode(';', (string) $header) as $pair) {
		$pos = strpos($pair, '=');
		$name = trim($pos === false ? $pair : substr($pair, 0, $pos));
		if ($name !== '') {
			$names[] = $name;
		}
	}
	return $names;
}

/**
 * The request headers as they are stored: the values of Cookie,
 * Authorization and Proxy-Authorization are replaced, the cookie names stay.
 * Names are cut at 128 bytes, values at 1000.
 */
function waf_headers_sanitize($headers)
{
	$clean = array();
	if (!is_array($headers)) {
		return $clean;
	}
	foreach ($headers as $name => $value) {
		$name = waf_cut((string) $name, 128);
		$value = is_array($value) ? implode(', ', $value) : (string) $value;
		$lower = strtolower($name);
		if ($lower === 'cookie') {
			$parts = array();
			foreach (waf_cookie_names($value) as $cookie) {
				$parts[] = $cookie . '=' . WAF_REMOVED;
			}
			$value = implode('; ', $parts);
		} elseif ($lower === 'authorization' || $lower === 'proxy-authorization') {
			$value = WAF_REMOVED;
		}
		$clean[$name] = waf_cut($value, 1000);
	}
	return $clean;
}

/** CRS rules that only add up and report: 949 and 959 act on the score, 980 correlates. */
function waf_is_scoring_rule($rule_id)
{
	return preg_match('/^(?:949|959|980)\d{3}$/', (string) $rule_id) === 1;
}

/** The ARGS name a CRS match names ("... found within ARGS:filter: ..."); '' otherwise. */
function waf_audit_param($data)
{
	if (preg_match('/found within ARGS:([A-Za-z0-9_.\[\]-]{1,128})(?::|\s|$)/', (string) $data, $m)) {
		return $m[1];
	}
	return '';
}

/**
 * One line of the JSON audit log as a hit, or null for a line that is no
 * usable entry. tests/waf_audit_sample.log shows the shape ModSecurity 3.0.12
 * writes.
 */
function waf_audit_parse_line($line)
{
	$line = trim((string) $line);
	if ($line === '' || $line[0] !== '{') {
		return null;
	}
	$doc = json_decode(waf_utf8_clean($line), true);
	if (!is_array($doc) || !isset($doc['transaction']) || !is_array($doc['transaction'])) {
		return null;
	}
	$t = $doc['transaction'];
	$seen_at = waf_audit_time(isset($t['time_stamp']) ? $t['time_stamp'] : '');
	$messages = isset($t['messages']) && is_array($t['messages']) ? $t['messages'] : array();
	if ($seen_at === '' || count($messages) === 0) {
		return null;
	}

	$rules = array();
	$seen = array();
	$score = 0;
	$would_block = false;
	foreach ($messages as $message) {
		$details = is_array($message) && isset($message['details']) && is_array($message['details'])
			? $message['details'] : array();
		$rule_id = isset($details['ruleId']) ? (string) $details['ruleId'] : '';
		if (!preg_match('/^[0-9]{1,9}$/', $rule_id)) {
			continue;
		}
		$text = isset($message['message']) ? (string) $message['message'] : '';
		if ($rule_id === '949110') {
			$would_block = true;
			if (preg_match('/Total Score:\s*(\d+)/', $text, $m)) {
				$score = max($score, (int) $m[1]);
			}
		}
		if (isset($seen[$rule_id]) || count($rules) >= 50) {
			continue;
		}
		$seen[$rule_id] = true;
		$data = isset($details['data']) ? (string) $details['data'] : '';
		$rules[] = array(
			'id' => $rule_id,
			'msg' => waf_cut($text, 255),
			'data' => waf_cut($data, 300),
			'param' => waf_audit_param($data),
		);
	}
	if (count($rules) === 0) {
		return null;
	}

	$request = isset($t['request']) && is_array($t['request']) ? $t['request'] : array();
	$response = isset($t['response']) && is_array($t['response']) ? $t['response'] : array();
	$headers = isset($request['headers']) && is_array($request['headers']) ? $request['headers'] : array();
	$uri = isset($request['uri']) ? (string) $request['uri'] : '';
	$query = strpos($uri, '?');
	$path = $query === false ? $uri : substr($uri, 0, $query);

	$logged_in = false;
	foreach (waf_cookie_names(waf_audit_header($headers, 'Cookie')) as $name) {
		if (strpos($name, 'wordpress_logged_in_') === 0) {
			$logged_in = true;
		}
	}
	$client_ip = isset($t['client_ip']) ? (string) $t['client_ip'] : '';
	$unique_id = isset($t['unique_id']) ? (string) $t['unique_id'] : '';
	if (!preg_match('/^[A-Za-z0-9.@_-]{1,64}$/', $unique_id)) {
		// Without an id of its own the line names itself, so a second read of
		// the same line still finds its row.
		$unique_id = 'sha1-' . sha1($line);
	}
	$method = isset($request['method']) ? strtoupper((string) $request['method']) : '';

	return array(
		'unique_id' => $unique_id,
		'seen_at' => $seen_at,
		'client_ip' => filter_var($client_ip, FILTER_VALIDATE_IP) !== false ? $client_ip : '',
		'host' => waf_host_normalize(waf_audit_header($headers, 'Host')),
		'method' => substr(preg_replace('/[^A-Z]/', '', $method), 0, 10),
		'uri' => waf_cut(waf_utf8_clean($uri), 2048),
		'path' => waf_cut(waf_utf8_clean($path), 1024),
		'status' => isset($response['http_code']) ? (int) $response['http_code'] : 0,
		'rules' => $rules,
		'anomaly_score' => $score,
		'would_block' => $would_block,
		'logged_in' => $logged_in,
		'headers' => waf_headers_sanitize($headers),
		'body' => isset($request['body']) ? waf_cut((string) $request['body'], 1048576) : null,
		'response_body' => isset($response['body']) ? (string) $response['body'] : null,
	);
}

/** Hits per host and rule for waf-report, the most first. Scoring rules are left out. */
function waf_audit_summarize($lines)
{
	$groups = array();
	foreach ($lines as $line) {
		$hit = waf_audit_parse_line($line);
		if ($hit === null) {
			continue;
		}
		foreach ($hit['rules'] as $rule) {
			if (waf_is_scoring_rule($rule['id'])) {
				continue;
			}
			$key = $hit['host'] . '|' . $rule['id'];
			if (!isset($groups[$key])) {
				$groups[$key] = array('host' => $hit['host'], 'rule_id' => $rule['id'],
					'message' => $rule['msg'], 'hits' => 0, 'example' => $hit['path']);
			}
			$groups[$key]['hits']++;
		}
	}
	$report = array_values($groups);
	usort($report, function ($a, $b) {
		if ($a['hits'] === $b['hits']) {
			return strcmp($a['host'] . '|' . $a['rule_id'], $b['host'] . '|' . $b['rule_id']);
		}
		return $b['hits'] - $a['hits'];
	});
	return $report;
}

/** Where reading starts: 0 for another file (inode) or one that shrank (copytruncate). */
function waf_reader_start($stored_inode, $stored_offset, $inode, $size)
{
	$stored_offset = max(0, (int) $stored_offset);
	if ((int) $stored_inode !== (int) $inode || (int) $size < $stored_offset) {
		return 0;
	}
	return $stored_offset;
}

/**
 * Up to $max_lines complete lines from $offset on. A last line without its
 * line break stays for the next run. Returns array('lines', 'offset', 'more')
 * or null when the file cannot be opened.
 */
function waf_read_lines($file, $offset, $max_lines)
{
	$handle = @fopen($file, 'rb');
	if ($handle === false) {
		return null;
	}
	$offset = (int) $offset;
	$lines = array();
	$more = false;
	if (fseek($handle, $offset) === 0) {
		while (true) {
			$line = fgets($handle);
			if ($line === false || substr($line, -1) !== "\n") {
				break;
			}
			if (count($lines) >= $max_lines) {
				$more = true;
				break;
			}
			$offset += strlen($line);
			$lines[] = rtrim($line, "\r\n");
		}
	}
	fclose($handle);
	return array('lines' => $lines, 'offset' => $offset, 'more' => $more);
}
```

- [ ] **Schritt 5: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [ ] **Schritt 6: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/tests/waf_lib_test.php ispconfig/tests/waf_audit_sample.log
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): read audit log lines into hits" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A3: Hosts zuordnen, Ausnahmen prüfen und in Regeln fassen

Ein Host aus dem Audit-Log findet seine Website über `web_domain`: der vhost selbst,
immer auch mit `www.`, Aliase und Subdomains über ihr `parent_domain_id`, Platzhalter
(`subdomain = '*'`) für jede Tiefe. Dieselbe Zuordnung liefert die Hostmuster der
Ausnahmeregeln. Regeldateien entstehen nur aus geprüften Feldern.

**Dateien:**
- Ändern: `ispconfig/tests/waf_lib_test.php` (Abschnitt A3)
- Ändern: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (Funktionen anhängen)

**Schnittstellen:**
- Nutzt: `waf_host_normalize()`, `waf_is_scoring_rule()` aus A2,
  `WAF_RULE_EXCEPTION_BASE` aus A1
- Liefert:
  - `waf_host_map($rows)`: `$rows` sind Zeilen aus `web_domain` mit `domain_id`,
    `parent_domain_id`, `type`, `domain`, `subdomain`, `active`; Ergebnis
    `array('exact' => array(host => site_id), 'wildcard' => array(domain => site_id))`
  - `waf_host_lookup($map, $host)` → `int` (0 ohne Treffer)
  - `waf_hosts_of($map, $site_id)` → `array('exact' => sortierte Liste, 'wildcard' => sortierte Liste)`
  - `waf_host_pattern($hosts)` → regulärer Ausdruck für `REQUEST_HEADERS:Host` oder `''`
  - `waf_exception_check($row)` → `''` oder `'scope'`, `'site'`, `'rule_id'`, `'path'`, `'param'`
  - `waf_exception_rules($rows, $hosts)` → `array('before' => Text, 'after' => Text,
    'skipped' => array(exception_id => Grund))`; `$hosts` ist `site_id => waf_hosts_of()`
  - `waf_exception_preview($items, $exception)` → `array('covered' => int, 'total' => int)`;
    `$items` tragen `parent_domain_id`, `rule_id`, `path`, `hits` und wahlweise `params`

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_lib_test.php` (Abschnitt vor summary):

```php
// --- A3: host map and exceptions ---------------------------------------------

$rows = array(
	array('domain_id' => 11, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'beispiel.test', 'subdomain' => 'www', 'active' => 'y'),
	array('domain_id' => 12, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'zweite.test', 'subdomain' => '*', 'active' => 'y'),
	array('domain_id' => 13, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'aus.test', 'subdomain' => 'none', 'active' => 'n'),
	array('domain_id' => 21, 'parent_domain_id' => 11, 'type' => 'alias', 'domain' => 'Alias-Beispiel.test', 'subdomain' => 'www', 'active' => 'y'),
	array('domain_id' => 22, 'parent_domain_id' => 11, 'type' => 'vhostsubdomain', 'domain' => 'shop.beispiel.test', 'subdomain' => 'none', 'active' => 'y'),
	// An alias that claims the name of another website does not win.
	array('domain_id' => 23, 'parent_domain_id' => 11, 'type' => 'alias', 'domain' => 'zweite.test', 'subdomain' => 'none', 'active' => 'y'),
	array('domain_id' => 24, 'parent_domain_id' => 0, 'type' => 'alias', 'domain' => 'waise.test', 'subdomain' => 'none', 'active' => 'y'),
);
$map = waf_host_map($rows);
expect_same('lookup vhost', waf_host_lookup($map, 'beispiel.test'), 11);
expect_same('lookup www', waf_host_lookup($map, 'WWW.beispiel.test:443'), 11);
expect_same('lookup alias', waf_host_lookup($map, 'alias-beispiel.test'), 11);
expect_same('lookup alias www', waf_host_lookup($map, 'www.alias-beispiel.test'), 11);
expect_same('lookup subdomain website', waf_host_lookup($map, 'shop.beispiel.test'), 11);
expect_same('vhost wins over alias', waf_host_lookup($map, 'zweite.test'), 12);
expect_same('wildcard', waf_host_lookup($map, 'a.b.zweite.test'), 12);
expect_same('inactive website', waf_host_lookup($map, 'aus.test'), 0);
expect_same('alias without parent', waf_host_lookup($map, 'waise.test'), 0);
expect_same('unknown host', waf_host_lookup($map, 'fremd.test'), 0);
expect_same('no wildcard for a plain vhost', waf_host_lookup($map, 'x.beispiel.test'), 0);
expect_same('empty host', waf_host_lookup($map, ''), 0);

$hosts11 = waf_hosts_of($map, 11);
expect_same('hosts of a website', $hosts11, array(
	'exact' => array('alias-beispiel.test', 'beispiel.test', 'shop.beispiel.test', 'www.alias-beispiel.test', 'www.beispiel.test'),
	'wildcard' => array(),
));
$hosts12 = waf_hosts_of($map, 12);
expect_same('hosts with wildcard', $hosts12, array('exact' => array('www.zweite.test', 'zweite.test'), 'wildcard' => array('zweite.test')));
$pattern12 = '^(?:www\.zweite\.test|zweite\.test|(?:[a-z0-9-]+\.)+zweite\.test)(?::\d+)?$';
expect_same('pattern', waf_host_pattern($hosts12), $pattern12);
expect_same('pattern without names', waf_host_pattern(array('exact' => array(), 'wildcard' => array())), '');
expect_same('pattern skips odd names', waf_host_pattern(array('exact' => array('a"b.test'), 'wildcard' => array())), '');
expect_same('pattern matches', preg_match('/' . $pattern12 . '/', 'shop.zweite.test:8080'), 1);
expect_same('pattern rejects', preg_match('/' . $pattern12 . '/', 'zweite.test.fremd.test'), 0);

$ok = array('scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '');
$site_row = array('scope' => 'site', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => '');
$param_row = array('scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => 'filter');
expect_same('valid site_path', waf_exception_check($ok), '');
expect_same('valid site', waf_exception_check($site_row), '');
expect_same('valid site_param', waf_exception_check($param_row), '');
expect_same('valid all', waf_exception_check(array('scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '')), '');
expect_same('unknown scope', waf_exception_check(array_merge($ok, array('scope' => 'server'))), 'scope');
expect_same('site scope without website', waf_exception_check(array_merge($ok, array('parent_domain_id' => 0))), 'site');
expect_same('all scope with website', waf_exception_check(array('scope' => 'all_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/x', 'param' => '')), 'site');
expect_same('rule id with quote', waf_exception_check(array_merge($ok, array('rule_id' => '942100"'))), 'rule_id');
expect_same('rule id too short', waf_exception_check(array_merge($ok, array('rule_id' => '12'))), 'rule_id');
expect_same('own rule', waf_exception_check(array_merge($ok, array('rule_id' => '10010'))), 'rule_id');
expect_same('scoring rule', waf_exception_check(array_merge($ok, array('rule_id' => '949110'))), 'rule_id');
expect_same('path with quote', waf_exception_check(array_merge($ok, array('path' => '/a"b'))), 'path');
expect_same('path with line break', waf_exception_check(array_merge($ok, array('path' => "/a\nSecRuleEngine Off"))), 'path');
expect_same('path with space', waf_exception_check(array_merge($ok, array('path' => '/a b'))), 'path');
expect_same('path without slash', waf_exception_check(array_merge($ok, array('path' => 'wp-admin'))), 'path');
expect_same('path missing', waf_exception_check(array_merge($ok, array('path' => ''))), 'path');
expect_same('path not allowed for site', waf_exception_check(array_merge($site_row, array('path' => '/x'))), 'path');
expect_same('param missing', waf_exception_check(array_merge($param_row, array('param' => ''))), 'param');
expect_same('param with control character', waf_exception_check(array_merge($param_row, array('param' => "a\x00b"))), 'param');
expect_same('param with comma', waf_exception_check(array_merge($param_row, array('param' => 'a,ctl:ruleEngine=Off'))), 'param');
expect_same('param not allowed', waf_exception_check(array_merge($ok, array('param' => 'x'))), 'param');
expect_same('rule id of an exception', waf_exception_rule_id(3), 10203);

$exceptions = array(
	array('exception_id' => 4, 'scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '/xmlrpc.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 1, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 2, 'scope' => 'site_path', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'exception_state' => 'pending'),
	array('exception_id' => 3, 'scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => 'filter', 'exception_state' => 'active'),
	array('exception_id' => 5, 'scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 6, 'scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q', 'exception_state' => 'active'),
	array('exception_id' => 7, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'removing'),
	array('exception_id' => 8, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '10010', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 9, 'scope' => 'site', 'parent_domain_id' => 99, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
);
$rules = waf_exception_rules($exceptions, array(12 => $hosts12));
$host_rule = 'SecRule REQUEST_HEADERS:Host "@rx ' . $pattern12 . '" ';
$expected_before = "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n"
	. "# Included before the CRS rules: runtime exclusions (ctl).\n"
	. "\n# exception 1 (site)\n"
	. $host_rule . "\"id:10201,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveById=942100\"\n"
	. "\n# exception 2 (site_path)\n"
	. $host_rule . "\"id:10202,phase:1,pass,nolog,t:none,t:lowercase,chain\"\n"
	. "    SecRule REQUEST_FILENAME \"@beginsWith /wp-admin/admin-ajax.php\" \"t:none,ctl:ruleRemoveById=942100\"\n"
	. "\n# exception 3 (site_param)\n"
	. $host_rule . "\"id:10203,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveTargetById=942100;ARGS:filter\"\n"
	. "\n# exception 4 (all_path)\n"
	. "SecRule REQUEST_FILENAME \"@beginsWith /xmlrpc.php\" \"id:10204,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=941100\"\n"
	. "\n# exception 6 (site_param)\n"
	. $host_rule . "\"id:10206,phase:1,pass,nolog,t:none,t:lowercase,chain\"\n"
	. "    SecRule REQUEST_FILENAME \"@beginsWith /suche\" \"t:none,ctl:ruleRemoveTargetById=942100;ARGS:q\"\n";
expect_same('rules before', $rules['before'], $expected_before);
expect_same('rules after', $rules['after'], "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n"
	. "# Included after the CRS rules: exclusions for every website.\n"
	. "\n# exception 5 (all)\nSecRuleRemoveById 941160\n");
expect_same('rules skipped', $rules['skipped'], array(8 => 'rule_id', 9 => 'site'));
expect_same('rules are stable', waf_exception_rules(array_reverse($exceptions), array(12 => $hosts12)), $rules);
$empty = waf_exception_rules(array(), array());
expect_same('empty files keep their header', array(substr_count($empty['before'], "\n"), substr_count($empty['after'], "\n"), $empty['skipped']), array(2, 2, array()));
$bad_id = waf_exception_rules(array(array_merge($exceptions[1], array('exception_id' => 0))), array(12 => $hosts12));
expect_same('bad exception id', $bad_id['skipped'], array(0 => 'exception_id'));

$items = array(
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 18),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/kontakt', 'hits' => 3),
	array('parent_domain_id' => 12, 'rule_id' => '941100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 5),
	array('parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 7),
);
expect_same('preview site_path', waf_exception_preview($items, array('scope' => 'site_path', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/', 'param' => '')), array('covered' => 18, 'total' => 21));
expect_same('preview site', waf_exception_preview($items, array('scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '')), array('covered' => 21, 'total' => 21));
expect_same('preview all_path', waf_exception_preview($items, array('scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '')), array('covered' => 25, 'total' => 28));
expect_same('preview all', waf_exception_preview($items, array('scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '', 'param' => '')), array('covered' => 5, 'total' => 5));
$hit_items = array(
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'hits' => 1, 'params' => array('q')),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'hits' => 1, 'params' => array('s')),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/liste', 'hits' => 1, 'params' => array('q')),
);
expect_same('preview site_param', waf_exception_preview($hit_items, array('scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => 'q')), array('covered' => 2, 'total' => 3));
expect_same('preview site_param with path', waf_exception_preview($hit_items, array('scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q')), array('covered' => 1, 'total' => 3));
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: Abbruch mit „Call to undefined function waf_host_map()"

- [ ] **Schritt 3: Funktionen anhängen**

`ispconfig/interface/lib/malwatch_waf_lib.inc.php` (anhängen):

```php
// --- Websites and their names ------------------------------------------------

/**
 * Which website a host name belongs to. A vhost always answers to www. as
 * well; alias and subdomain rows belong to their parent; subdomain '*' makes
 * a wildcard. Websites come first, so an alias never takes another website's
 * name. Inactive rows are left out.
 */
function waf_host_map($rows)
{
	$map = array('exact' => array(), 'wildcard' => array());
	$groups = array(0 => array(), 1 => array());
	foreach ($rows as $row) {
		if ((string) $row['active'] === 'y') {
			$groups[(string) $row['type'] === 'vhost' ? 0 : 1][] = $row;
		}
	}
	$children = array('alias', 'subdomain', 'vhostalias', 'vhostsubdomain');
	foreach ($groups as $group) {
		foreach ($group as $row) {
			$type = (string) $row['type'];
			if ($type === 'vhost') {
				$site = (int) $row['domain_id'];
			} elseif (in_array($type, $children, true)) {
				$site = (int) $row['parent_domain_id'];
			} else {
				continue;
			}
			$domain = waf_host_normalize($row['domain']);
			if ($site < 1 || $domain === '') {
				continue;
			}
			$sub = isset($row['subdomain']) ? (string) $row['subdomain'] : 'none';
			$names = array($domain);
			if ($type === 'vhost' || $sub === 'www') {
				$names[] = 'www.' . $domain;
			}
			foreach ($names as $name) {
				if (!isset($map['exact'][$name])) {
					$map['exact'][$name] = $site;
				}
			}
			if ($sub === '*' && !isset($map['wildcard'][$domain])) {
				$map['wildcard'][$domain] = $site;
			}
		}
	}
	return $map;
}

/** The website of a host, 0 when none: the exact name first, then the closest wildcard. */
function waf_host_lookup($map, $host)
{
	$host = waf_host_normalize($host);
	if ($host === '') {
		return 0;
	}
	if (isset($map['exact'][$host])) {
		return (int) $map['exact'][$host];
	}
	$labels = explode('.', $host);
	for ($i = 1; $i < count($labels) - 1; $i++) {
		$parent = implode('.', array_slice($labels, $i));
		if (isset($map['wildcard'][$parent])) {
			return (int) $map['wildcard'][$parent];
		}
	}
	return 0;
}

/** The names of one website, sorted. */
function waf_hosts_of($map, $site_id)
{
	$exact = array_keys($map['exact'], (int) $site_id, true);
	$wildcard = array_keys($map['wildcard'], (int) $site_id, true);
	sort($exact);
	sort($wildcard);
	return array('exact' => $exact, 'wildcard' => $wildcard);
}

/**
 * The pattern for REQUEST_HEADERS:Host in a rule file; the rule lowercases
 * the header first. Only names that pass waf_host_normalize() get in, so the
 * dot is the one character to escape. '' when no name is left.
 */
function waf_host_pattern($hosts)
{
	$parts = array();
	foreach ($hosts['exact'] as $host) {
		if (waf_host_normalize($host) === $host) {
			$parts[] = str_replace('.', '\.', $host);
		}
	}
	foreach ($hosts['wildcard'] as $domain) {
		if (waf_host_normalize($domain) === $domain) {
			$parts[] = '(?:[a-z0-9-]+\.)+' . str_replace('.', '\.', $domain);
		}
	}
	if (count($parts) === 0) {
		return '';
	}
	return '^(?:' . implode('|', $parts) . ')(?::\d+)?$';
}

// --- Exceptions --------------------------------------------------------------

function waf_exception_scopes()
{
	return array('site', 'site_path', 'site_param', 'all', 'all_path');
}

/**
 * Checks one exception before the panel stores it and again before a job
 * turns it into a rule. Returns '' or the field that is wrong.
 */
function waf_exception_check($row)
{
	$scope = isset($row['scope']) ? (string) $row['scope'] : '';
	$site = isset($row['parent_domain_id']) ? (int) $row['parent_domain_id'] : 0;
	$rule = isset($row['rule_id']) ? (string) $row['rule_id'] : '';
	$path = isset($row['path']) ? (string) $row['path'] : '';
	$param = isset($row['param']) ? (string) $row['param'] : '';

	if (!in_array($scope, waf_exception_scopes(), true)) {
		return 'scope';
	}
	if ((strpos($scope, 'site') === 0) !== ($site > 0)) {
		return 'site';
	}
	// The own rules (10000-10999) keep passwords out of the log and the
	// server's own requests out of the check; the scoring rules only add up.
	if (!preg_match('/^[0-9]{3,7}$/', $rule) || waf_is_scoring_rule($rule)
		|| ((int) $rule >= 10000 && (int) $rule <= 10999)) {
		return 'rule_id';
	}
	$path_needed = $scope === 'site_path' || $scope === 'all_path';
	if ($path === '' ? $path_needed : (!($path_needed || $scope === 'site_param')
		|| !preg_match('#^/[A-Za-z0-9._~/%+-]{0,1023}$#', $path))) {
		return 'path';
	}
	if (($scope === 'site_param') !== ($param !== '')
		|| ($param !== '' && !preg_match('/^[A-Za-z0-9_.\[\]-]{1,128}$/', $param))) {
		return 'param';
	}
	return '';
}

function waf_exception_rule_id($exception_id)
{
	return WAF_RULE_EXCEPTION_BASE + (int) $exception_id;
}

/**
 * The two rule files the panel owns: exclusions-panel-before.conf (included
 * before the CRS rules, runtime ctl actions) and exclusions-panel-after.conf
 * (after them, SecRuleRemoveById for every website). Only pending and active
 * rows count, in the order of their ids. A row that fails the check, or whose
 * website has no name in $hosts, stays out and is listed in 'skipped'. The
 * note of an exception never reaches a file.
 */
function waf_exception_rules($rows, $hosts)
{
	$header = "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n";
	$before = $header . "# Included before the CRS rules: runtime exclusions (ctl).\n";
	$after = $header . "# Included after the CRS rules: exclusions for every website.\n";
	$skipped = array();

	usort($rows, function ($a, $b) {
		return (int) $a['exception_id'] - (int) $b['exception_id'];
	});
	foreach ($rows as $row) {
		$state = isset($row['exception_state']) ? (string) $row['exception_state'] : '';
		if ($state !== 'pending' && $state !== 'active') {
			continue;
		}
		$id = (int) $row['exception_id'];
		// CRS owns the ids from 900000 on.
		$reason = ($id < 1 || waf_exception_rule_id($id) >= 900000) ? 'exception_id' : waf_exception_check($row);
		if ($reason !== '') {
			$skipped[$id] = $reason;
			continue;
		}
		$scope = (string) $row['scope'];
		$rule = (string) $row['rule_id'];
		$path = (string) $row['path'];
		$rid = waf_exception_rule_id($id);
		$title = "\n# exception " . $id . ' (' . $scope . ")\n";

		if ($scope === 'all') {
			$after .= $title . 'SecRuleRemoveById ' . $rule . "\n";
			continue;
		}
		if ($scope === 'all_path') {
			$before .= $title . 'SecRule REQUEST_FILENAME "@beginsWith ' . $path . '" "id:' . $rid
				. ',phase:1,pass,nolog,t:none,ctl:ruleRemoveById=' . $rule . "\"\n";
			continue;
		}

		$site = (int) $row['parent_domain_id'];
		$pattern = isset($hosts[$site]) ? waf_host_pattern($hosts[$site]) : '';
		if ($pattern === '') {
			$skipped[$id] = 'site';
			continue;
		}
		$ctl = $scope === 'site_param'
			? 'ctl:ruleRemoveTargetById=' . $rule . ';ARGS:' . (string) $row['param']
			: 'ctl:ruleRemoveById=' . $rule;
		$host_rule = 'SecRule REQUEST_HEADERS:Host "@rx ' . $pattern . '" "id:' . $rid
			. ',phase:1,pass,nolog,t:none,t:lowercase,';
		if ($path === '') {
			$before .= $title . $host_rule . $ctl . "\"\n";
		} else {
			$before .= $title . $host_rule . "chain\"\n"
				. '    SecRule REQUEST_FILENAME "@beginsWith ' . $path . '" "t:none,' . $ctl . "\"\n";
		}
	}
	return array('before' => $before, 'after' => $after, 'skipped' => $skipped);
}

/**
 * How many hits an exception would have prevented. total counts the hits of
 * the rule on the exception's websites (all websites for all and all_path);
 * covered the part the exception matches. Rows of the day table carry no
 * params, so site_param needs rows built from single hits.
 */
function waf_exception_preview($items, $exception)
{
	$scope = (string) $exception['scope'];
	$site = (int) $exception['parent_domain_id'];
	$rule = (string) $exception['rule_id'];
	$path = isset($exception['path']) ? (string) $exception['path'] : '';
	$param = isset($exception['param']) ? (string) $exception['param'] : '';
	$per_site = strpos($scope, 'site') === 0;
	$covered = 0;
	$total = 0;
	foreach ($items as $item) {
		if ((string) $item['rule_id'] !== $rule || ($per_site && (int) $item['parent_domain_id'] !== $site)) {
			continue;
		}
		$hits = (int) $item['hits'];
		$total += $hits;
		if ($path !== '' && strpos((string) $item['path'], $path) !== 0) {
			continue;
		}
		if ($scope === 'site_param') {
			$params = isset($item['params']) && is_array($item['params']) ? $item['params'] : array();
			if (!in_array($param, $params, true)) {
				continue;
			}
		}
		$covered += $hits;
	}
	return array('covered' => $covered, 'total' => $total);
}
```

- [ ] **Schritt 4: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [ ] **Schritt 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/tests/waf_lib_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): map hosts to websites and build exception rules" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A4: Einstellungen, Entscheidungen, sicherer Dateitausch

Die letzten reinen Bausteine: Einstellungen mit Vorgaben und Grenzen, die Freigabe für
„scharf", Zeiträume, der Text für logrotate, die Entscheidungen eines Zustandswechsels je
Website und der Tausch der WAF-Dateien. `waf_apply_files()` bekommt die Befehle als
Funktion übergeben; der Test ersetzt sie durch eine Attrappe und prüft die Reihenfolge.

**Dateien:**
- Ändern: `ispconfig/tests/waf_lib_test.php` (Abschnitt A4)
- Ändern: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (Funktionen anhängen)

**Schnittstellen:**
- Nutzt: A1 bis A3
- Liefert:
  - `waf_settings($row)` mit den Schlüsseln aus `waf_settings_defaults()`: Zahlen als
    `int` innerhalb von `waf_settings_limits()`, Pfade ohne abschließenden Schrägstrich,
    `waf_emergency` als `'y'`/`'n'`, `waf_emergency_since` als Text oder `null`
  - `waf_enforce_free_from($since, $days)` → `Y-m-d H:i:s` oder `''`
  - `waf_enforce_block_reason($state, $since, $now, $min_days, $emergency)` → `''`,
    `'emergency'`, `'not_detect'` oder `'too_early'`
  - `waf_periods($stats_days)` → Liste aus 1, 7, 30, 90; `waf_period($requested, $stats_days)` → int
  - `waf_logrotate_text($keep_days, $audit_log)` → Text für `/etc/logrotate.d/waf`
  - `waf_site_plan($web, $site, $target, $mode, $server_id, $vhost_state, $now, $settings)` →
    `array('action' => 'skip'|'confirm'|'wait'|'write', 'reason', 'text', 'target')`;
    `$mode` ist `'set'` oder `'keep'`
  - `waf_site_progress($entry, $vhost_state, $rejected, $overdue)` → `'confirmed'`,
    `'waiting'`, `'failed:rejected'` oder `'failed:deadline'`
  - `waf_rollback_allowed($current_text, $written_hash)` → bool
  - `waf_apply_files($paths, $changes, $run)` → `array('ok' => bool, 'reason', 'detail')`;
    `$paths` mit `conf_dir`, `staging`, `last_good`; `$run($name, $argument)` gibt
    `array(exit_code, output)` zurück für `rules_check`, `nginx_test`, `nginx_reload`,
    `nginx_active`, `nginx_start`. Gründe: `''`, `'unchanged'`, `'bad_name'`,
    `'missing_file'`, `'staging'`, `'rules_check'`, `'nginx_test'`, `'nginx_reload'`,
    `'nginx_inactive'`
  - `waf_conf_files($dir)`, `waf_write_atomic($file, $text)`, `waf_remove_dir($dir)`,
    `waf_snapshot($dir, $target)`, `waf_restore_snapshot($snapshot, $dir)` → Liste der
    zurückgelegten Dateinamen

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_lib_test.php` (Abschnitt vor summary):

```php
// --- A4: settings, decisions, files ------------------------------------------

$defaults = waf_settings(null);
expect_same('default detail days', $defaults['waf_detail_days'], 7);
expect_same('default stats days', $defaults['waf_stats_days'], 90);
expect_same('default response body', $defaults['waf_response_body'], 'full');
expect_same('default conf dir', $defaults['waf_conf_dir'], '/etc/nginx/waf');
expect_same('default emergency', array($defaults['waf_emergency'], $defaults['waf_emergency_since']), array('n', null));
expect_same('keys', array_keys($defaults), array_keys(waf_settings_defaults()));
$custom = waf_settings(array('waf_detail_days' => '30', 'waf_stats_days' => '0', 'waf_ingest_max_lines' => '999999',
	'waf_response_body' => 'lean', 'waf_emergency' => 'y', 'waf_emergency_since' => '2026-09-16 21:00:00',
	'waf_conf_dir' => '/etc/nginx/waf/', 'waf_audit_log' => '/var/log/../etc/passwd', 'waf_job_deadline_minutes' => ''));
expect_same('custom days', $custom['waf_detail_days'], 30);
expect_same('days held to the minimum', $custom['waf_stats_days'], 1);
expect_same('lines held to the maximum', $custom['waf_ingest_max_lines'], 100000);
expect_same('empty value takes the default', $custom['waf_job_deadline_minutes'], 5);
expect_same('lean kept', $custom['waf_response_body'], 'lean');
expect_same('emergency kept', array($custom['waf_emergency'], $custom['waf_emergency_since']), array('y', '2026-09-16 21:00:00'));
expect_same('closing slash dropped', $custom['waf_conf_dir'], '/etc/nginx/waf');
expect_same('path with dots refused', $custom['waf_audit_log'], '/var/log/waf/audit.log');
$odd = waf_settings(array('waf_response_body' => 'schlank', 'waf_conf_dir' => '//'));
expect_same('odd mode refused', $odd['waf_response_body'], 'full');
expect_same('root dir refused', $odd['waf_conf_dir'], '/etc/nginx/waf');

expect_same('free from', waf_enforce_free_from('2026-09-16 13:20:15', 7), '2026-09-23 13:20:15');
expect_same('free from over the clock change', waf_enforce_free_from('2026-10-20 12:00:00', 7), '2026-10-27 12:00:00');
expect_same('free from without date', waf_enforce_free_from(null, 7), '');
expect_same('free from zero date', waf_enforce_free_from('0000-00-00 00:00:00', 7), '');
expect_same('enforce allowed', waf_enforce_block_reason('detect', '2026-09-16 13:20:15', '2026-09-23 13:20:15', 7, 'n'), '');
expect_same('enforce too early', waf_enforce_block_reason('detect', '2026-09-16 13:20:15', '2026-09-23 13:20:14', 7, 'n'), 'too_early');
expect_same('enforce from off', waf_enforce_block_reason('off', '', '2026-09-23 13:20:15', 7, 'n'), 'not_detect');
expect_same('enforce during emergency', waf_enforce_block_reason('detect', '2026-09-01 00:00:00', '2026-09-23 13:20:15', 7, 'y'), 'emergency');
expect_same('enforce again', waf_enforce_block_reason('enforce', '2026-09-01 00:00:00', '2026-09-23 13:20:15', 7, 'n'), '');
expect_same('enforce without waiting time', waf_enforce_block_reason('detect', '2026-09-23 13:20:15', '2026-09-23 13:20:15', 0, 'n'), '');
expect_same('detect without date', waf_enforce_block_reason('detect', null, '2026-09-23 13:20:15', 7, 'n'), 'too_early');

expect_same('periods', waf_periods(90), array(1, 7, 30, 90));
expect_same('periods of a short keep', waf_periods(10), array(1, 7));
expect_same('periods of one day', waf_periods(1), array(1));
expect_same('period chosen', waf_period('30', 90), 30);
expect_same('period unknown', waf_period('14', 90), 7);
expect_same('period beyond the keep', waf_period(90, 10), 7);
expect_same('period of one day', waf_period(7, 1), 1);

$rotate = waf_logrotate_text(14, '/var/log/waf/audit.log');
expect_same('logrotate path', strpos($rotate, "\n/var/log/waf/audit.log {\n") !== false, true);
expect_same('logrotate keep', strpos($rotate, "\trotate 14\n") !== false, true);
expect_same('logrotate copytruncate', strpos($rotate, "\tcopytruncate\n") !== false, true);
expect_same('logrotate minimum', strpos(waf_logrotate_text(0, '/x'), "\trotate 1\n") !== false, true);

$web = array('domain_id' => 11, 'domain' => 'beispiel.test', 'type' => 'vhost', 'server_id' => 1, 'nginx_directives' => $own);
$web_detect = array_merge($web, array('nginx_directives' => $set));
$site_detect = array('waf_state' => 'detect', 'waf_state_since' => '2026-09-01 10:00:00');
$now = '2026-09-16 12:00:00';
$plan = waf_site_plan($web, null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan writes', array($plan['action'], $plan['text'], $plan['target']), array('write', $set, 'detect'));
$plan = waf_site_plan(null, null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan missing website', array($plan['action'], $plan['reason']), array('skip', 'not_found'));
$plan = waf_site_plan(array_merge($web, array('type' => 'alias')), null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan alias', $plan['reason'], 'not_found');
$plan = waf_site_plan($web, null, 'detect', 'set', 2, 'off', $now, $defaults);
expect_same('plan other server', $plan['reason'], 'other_server');
$plan = waf_site_plan($web, null, 'an', 'set', 1, 'off', $now, $defaults);
expect_same('plan unknown state', $plan['reason'], 'state');
$plan = waf_site_plan($web, null, 'enforce', 'set', 1, 'off', $now, $defaults);
expect_same('plan enforce from off', $plan['reason'], 'not_detect');
$plan = waf_site_plan($web_detect, $site_detect, 'enforce', 'set', 1, 'detect', $now, $defaults);
expect_same('plan enforce after waiting', array($plan['action'], $plan['text']), array('write', $enforced));
$plan = waf_site_plan($web_detect, $site_detect, 'enforce', 'set', 1, 'detect', $now, $custom);
expect_same('plan enforce during emergency', $plan['reason'], 'emergency');
$plan = waf_site_plan($web_detect, $site_detect, 'detect', 'set', 1, 'detect', $now, $defaults);
expect_same('plan confirms a match', $plan['action'], 'confirm');
$plan = waf_site_plan($web_detect, $site_detect, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan waits for ISPConfig', $plan['action'], 'wait');
$plan = waf_site_plan(array_merge($web, array('nginx_directives' => $old_field)), null, '', 'keep', 1, 'detect', $now, $defaults);
expect_same('plan rewrites the old marker', array($plan['action'], $plan['target'], $plan['text']), array('write', 'detect', $set));
$plan = waf_site_plan($web_detect, null, '', 'keep', 1, 'detect', $now, $defaults);
expect_same('plan keeps a new marker', array($plan['action'], $plan['target']), array('confirm', 'detect'));
$plan = waf_site_plan($web, null, '', 'keep', 1, 'off', $now, $defaults);
expect_same('plan keep without block', array($plan['action'], $plan['target']), array('confirm', 'off'));
$plan = waf_site_plan(array_merge($web, array('nginx_directives' => $enforced)), null, '', 'keep', 1, 'enforce', $now, $custom);
expect_same('plan keep does not ask for enforce', $plan['action'], 'confirm');

$entry = array('target' => 'detect');
expect_same('progress confirmed', waf_site_progress($entry, 'detect', false, false), 'confirmed');
expect_same('progress waiting', waf_site_progress($entry, 'off', false, false), 'waiting');
expect_same('progress overdue', waf_site_progress($entry, 'off', false, true), 'failed:deadline');
expect_same('progress rejected', waf_site_progress($entry, 'detect', true, false), 'failed:rejected');
expect_same('rollback allowed', waf_rollback_allowed($set, sha1($set)), true);
expect_same('rollback refused', waf_rollback_allowed($set . "# edited\n", sha1($set)), false);
expect_same('rollback without hash', waf_rollback_allowed('', ''), false);

$tmp = sys_get_temp_dir() . '/waf_test_' . getmypid();
waf_remove_dir($tmp);
mkdir($tmp . '/conf', 0777, true);
file_put_contents($tmp . '/conf/main.conf', 'Include ' . $tmp . "/conf/state.conf\nInclude " . $tmp . "/conf/response-body.conf\n");
file_put_contents($tmp . '/conf/state.conf', waf_state_file_text(false));
file_put_contents($tmp . '/conf/response-body.conf', waf_response_body_text('full'));
file_put_contents($tmp . '/conf/notes.txt', 'no rule file');
expect_same('conf files', array_map('basename', waf_conf_files($tmp . '/conf')), array('main.conf', 'response-body.conf', 'state.conf'));
$paths = array('conf_dir' => $tmp . '/conf', 'staging' => $tmp . '/staging/7', 'last_good' => $tmp . '/last-good');

// Stands in for the real commands and records every call.
$calls = array();
$answers = array();
$run = function ($name, $argument) use (&$calls, &$answers) {
	$calls[] = $name;
	if ($name === 'rules_check') {
		// The check must read the staged copy, never the live file.
		$calls[] = strpos((string) file_get_contents($argument), '/staging/7/state.conf') !== false ? 'staged' : 'live';
	}
	return isset($answers[$name]) ? $answers[$name] : array(0, '');
};

$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(true)), $run);
expect_same('apply ok', $result, array('ok' => true, 'reason' => '', 'detail' => ''));
expect_same('apply order', $calls, array('rules_check', 'staged', 'nginx_test', 'nginx_reload', 'nginx_active'));
expect_same('apply wrote', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('apply snapshot', file_get_contents($tmp . '/last-good/state.conf'), waf_state_file_text(true));
expect_same('apply cleaned up', is_dir($tmp . '/staging/7'), false);

$calls = array();
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(true)), $run);
expect_same('apply without change', array($result['ok'], $result['reason'], $calls), array(true, 'unchanged', array()));

$calls = array();
$answers = array('rules_check' => array(1, 'Rules error. File: state.conf. Line: 3.'));
$result = waf_apply_files($paths, array('state.conf' => "SecRuleEngine Broken\n"), $run);
expect_same('rules check refuses', $result, array('ok' => false, 'reason' => 'rules_check', 'detail' => 'Rules error. File: state.conf. Line: 3.'));
expect_same('nothing touched after the check', $calls, array('rules_check', 'staged'));
expect_same('live file unchanged', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);

$calls = array();
$answers = array('nginx_test' => array(1, 'nginx: [emerg] test failed'));
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(false)), $run);
expect_same('nginx -t refuses', $result['reason'], 'nginx_test');
expect_same('no reload after a failed test', in_array('nginx_reload', $calls, true), false);
expect_same('old file back', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('snapshot unchanged', waf_state_file_is_emergency(file_get_contents($tmp . '/last-good/state.conf')), true);

$calls = array();
$answers = array('nginx_active' => array(3, 'inactive'));
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(false)), $run);
expect_same('inactive after reload', array($result['reason'], $calls), array('nginx_inactive',
	array('rules_check', 'staged', 'nginx_test', 'nginx_reload', 'nginx_active', 'nginx_start')));
expect_same('old file back after inactive', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);

$answers = array();
$result = waf_apply_files($paths, array('exclusions-panel-before.conf' => "# x\n"), $run);
expect_same('missing file refused', $result['reason'], 'missing_file');
$result = waf_apply_files($paths, array('main.conf' => "# x\n"), $run);
expect_same('main.conf refused', $result['reason'], 'bad_name');
$result = waf_apply_files($paths, array('../main.conf' => "# x\n"), $run);
expect_same('path in the name refused', $result['reason'], 'bad_name');

file_put_contents($tmp . '/conf/state.conf', "broken\n");
expect_same('restore snapshot', waf_restore_snapshot($tmp . '/last-good', $tmp . '/conf'), array('state.conf'));
expect_same('restored content', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('restore twice changes nothing', waf_restore_snapshot($tmp . '/last-good', $tmp . '/conf'), array());
expect_same('restore from nothing', waf_restore_snapshot($tmp . '/missing', $tmp . '/conf'), array());

waf_write_atomic($tmp . '/conf/new.conf', "x\n");
expect_same('atomic write', array(file_get_contents($tmp . '/conf/new.conf'), is_file($tmp . '/conf/new.conf.new')), array("x\n", false));
waf_remove_dir($tmp);
expect_same('tree removed', is_dir($tmp), false);
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: Abbruch mit „Call to undefined function waf_settings()"

- [ ] **Schritt 3: Funktionen anhängen**

`ispconfig/interface/lib/malwatch_waf_lib.inc.php` (anhängen):

```php
// --- Settings ----------------------------------------------------------------

/** The WAF settings in malwatch_config with their defaults. */
function waf_settings_defaults()
{
	return array(
		'waf_detail_days' => 7,
		'waf_stats_days' => 90,
		'waf_log_keep_days' => 7,
		'waf_preview_days' => 7,
		'waf_min_detect_days' => 7,
		'waf_response_body' => 'full',
		'waf_ingest_max_lines' => 5000,
		'waf_job_deadline_minutes' => 5,
		'waf_audit_log' => '/var/log/waf/audit.log',
		'waf_conf_dir' => '/etc/nginx/waf',
		'waf_emergency' => 'n',
		'waf_emergency_since' => null,
	);
}

/** The range each number is held to: array(min, max). */
function waf_settings_limits()
{
	return array(
		'waf_detail_days' => array(1, 3650),
		'waf_stats_days' => array(1, 3650),
		'waf_log_keep_days' => array(1, 365),
		'waf_preview_days' => array(1, 365),
		'waf_min_detect_days' => array(0, 365),
		'waf_ingest_max_lines' => array(100, 100000),
		'waf_job_deadline_minutes' => array(2, 120),
	);
}

/**
 * The WAF settings from a malwatch_config row. A column an older schema lacks,
 * or an empty value, takes its default; numbers stay within their limits;
 * the two paths must be plain absolute paths.
 */
function waf_settings($row)
{
	$row = is_array($row) ? $row : array();
	$defaults = waf_settings_defaults();
	$settings = array();
	foreach ($defaults as $key => $default) {
		$value = isset($row[$key]) ? $row[$key] : null;
		$settings[$key] = ($value === null || $value === '') ? $default : $value;
	}
	foreach (waf_settings_limits() as $key => $limit) {
		$settings[$key] = max($limit[0], min($limit[1], (int) $settings[$key]));
	}
	if (!waf_response_body_valid($settings['waf_response_body'])) {
		$settings['waf_response_body'] = $defaults['waf_response_body'];
	}
	$settings['waf_emergency'] = $settings['waf_emergency'] === 'y' ? 'y' : 'n';
	foreach (array('waf_audit_log', 'waf_conf_dir') as $key) {
		$path = rtrim((string) $settings[$key], '/');
		if ($path === '' || !preg_match('#^/[A-Za-z0-9._/-]+$#', $path) || preg_match('#(?:^|/)\.\.?(?:/|$)#', $path)) {
			$path = $defaults[$key];
		}
		$settings[$key] = $path;
	}
	return $settings;
}

// --- Decisions ---------------------------------------------------------------

/**
 * When a website that detects since $since may enforce. Both are wall-clock
 * times from the database; the arithmetic runs in UTC so a clock change never
 * moves the result. '' without a date.
 */
function waf_enforce_free_from($since, $min_days)
{
	$since = (string) $since;
	if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $since) || $since === '0000-00-00 00:00:00') {
		return '';
	}
	$date = DateTime::createFromFormat('Y-m-d H:i:s', $since, new DateTimeZone('UTC'));
	if ($date === false) {
		return '';
	}
	$date->modify('+' . max(0, (int) $min_days) . ' days');
	return $date->format('Y-m-d H:i:s');
}

/** Why a website may not be switched to enforce now; '' when it may. */
function waf_enforce_block_reason($state, $since, $now, $min_days, $emergency)
{
	if ($emergency === 'y') {
		return 'emergency';
	}
	if ($state === 'enforce') {
		return '';
	}
	if ($state !== 'detect') {
		return 'not_detect';
	}
	$free = waf_enforce_free_from($since, $min_days);
	if ($free === '' || strcmp((string) $now, $free) < 0) {
		return 'too_early';
	}
	return '';
}

/** The periods the overview offers, in days, within the time day figures are kept. */
function waf_periods($stats_days)
{
	$periods = array();
	foreach (array(1, 7, 30, 90) as $days) {
		if ($days <= max(1, (int) $stats_days)) {
			$periods[] = $days;
		}
	}
	return $periods;
}

function waf_period($requested, $stats_days)
{
	$periods = waf_periods($stats_days);
	if (in_array((int) $requested, $periods, true)) {
		return (int) $requested;
	}
	return in_array(7, $periods, true) ? 7 : $periods[count($periods) - 1];
}

/** Content of /etc/logrotate.d/waf. copytruncate keeps the file ModSecurity holds open. */
function waf_logrotate_text($keep_days, $audit_log)
{
	return "# Managed by malwatch (Abwehr > Einstellungen). Every change here is overwritten.\n"
		. $audit_log . " {\n"
		. "\tdaily\n"
		. "\trotate " . max(1, (int) $keep_days) . "\n"
		. "\tcompress\n"
		. "\tdelaycompress\n"
		. "\tmissingok\n"
		. "\tnotifempty\n"
		. "\tcopytruncate\n"
		. "}\n";
}

/**
 * What a job does with one website when it starts. $web is the web_domain
 * row (domain_id, domain, type, server_id, nginx_directives) or null, $site
 * the malwatch_site row or null, $vhost_state what the vhost file shows now.
 * $mode 'keep' rewrites the marker and keeps the state the field names.
 * action: skip (reason says why), confirm (field and vhost already match),
 * wait (field matches, vhost not yet), write (store text in the field).
 */
function waf_site_plan($web, $site, $target, $mode, $server_id, $vhost_state, $now, $settings)
{
	$result = array('action' => 'skip', 'reason' => '', 'text' => '', 'target' => (string) $target);
	if (!is_array($web) || (string) $web['type'] !== 'vhost') {
		$result['reason'] = 'not_found';
		return $result;
	}
	if ((int) $web['server_id'] !== (int) $server_id) {
		$result['reason'] = 'other_server';
		return $result;
	}
	$old = (string) $web['nginx_directives'];
	if ($mode === 'keep') {
		$result['target'] = waf_block_state($old);
	}
	if (!waf_state_valid($result['target'])) {
		$result['reason'] = 'state';
		return $result;
	}
	if ($mode !== 'keep' && $result['target'] === 'enforce') {
		$state = is_array($site) ? (string) $site['waf_state'] : 'off';
		$since = is_array($site) ? $site['waf_state_since'] : null;
		$reason = waf_enforce_block_reason($state, $since, $now, $settings['waf_min_detect_days'], $settings['waf_emergency']);
		if ($reason !== '') {
			$result['reason'] = $reason;
			return $result;
		}
	}
	$new = waf_block_set($old, $result['target']);
	if ($new !== $old) {
		$result['action'] = 'write';
		$result['text'] = $new;
		return $result;
	}
	$result['action'] = $vhost_state === $result['target'] ? 'confirm' : 'wait';
	$result['text'] = $old;
	return $result;
}

/**
 * Where a waiting website stands in a later pass. $rejected: ISPConfig left
 * a fresh .err next to the vhost; $overdue: the job ran past its deadline.
 */
function waf_site_progress($entry, $vhost_state, $rejected, $overdue)
{
	if ($rejected) {
		return 'failed:rejected';
	}
	if ($vhost_state === $entry['target']) {
		return 'confirmed';
	}
	return $overdue ? 'failed:deadline' : 'waiting';
}

/** A failed website gets its old field back only while the field still holds what the job wrote. */
function waf_rollback_allowed($current_text, $written_hash)
{
	return hash_equals((string) $written_hash, sha1((string) $current_text));
}

// --- Files -------------------------------------------------------------------

/** The .conf files of a directory, sorted; an empty list when there is none. */
function waf_conf_files($dir)
{
	$files = glob(rtrim($dir, '/') . '/*.conf');
	if (!is_array($files)) {
		return array();
	}
	sort($files);
	return $files;
}

/** Writes through a temporary file and rename, mode 0644. */
function waf_write_atomic($file, $text)
{
	$tmp = $file . '.new';
	if (@file_put_contents($tmp, $text) === false) {
		return false;
	}
	@chmod($tmp, 0644);
	if (!@rename($tmp, $file)) {
		@unlink($tmp);
		return false;
	}
	return true;
}

/** Removes a directory tree. Links are removed, never followed. */
function waf_remove_dir($dir)
{
	if (is_link($dir)) {
		@unlink($dir);
		return;
	}
	if (!is_dir($dir)) {
		return;
	}
	$items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::CHILD_FIRST);
	foreach ($items as $item) {
		if ($item->isLink() || !$item->isDir()) {
			@unlink($item->getPathname());
		} else {
			@rmdir($item->getPathname());
		}
	}
	@rmdir($dir);
}

/** Copies every .conf of $dir into $target, which is emptied first. */
function waf_snapshot($dir, $target)
{
	waf_remove_dir($target);
	@mkdir($target, 0700, true);
	foreach (waf_conf_files($dir) as $file) {
		copy($file, rtrim($target, '/') . '/' . basename($file));
	}
}

/** Puts back every file of the snapshot that differs; returns their names. */
function waf_restore_snapshot($snapshot, $dir)
{
	$restored = array();
	foreach (waf_conf_files($snapshot) as $file) {
		$name = basename($file);
		$target = rtrim($dir, '/') . '/' . $name;
		$text = (string) file_get_contents($file);
		if (!is_file($target) || (string) file_get_contents($target) !== $text) {
			waf_write_atomic($target, $text);
			$restored[] = $name;
		}
	}
	return $restored;
}

function waf_apply_result($ok, $reason, $detail)
{
	return array('ok' => $ok, 'reason' => $reason, 'detail' => waf_cut(trim((string) $detail), 2000));
}

function waf_restore_previous($dir, $staging, $names)
{
	foreach ($names as $name) {
		$saved = $staging . '/previous/' . $name;
		if (is_file($saved)) {
			waf_write_atomic($dir . '/' . $name, (string) file_get_contents($saved));
		}
	}
}

/**
 * Replaces managed files in the WAF directory so that nginx never loads a
 * broken set: copy the directory to staging, write the changes there, check a
 * main.conf that includes the copy, swap the files by rename, nginx -t,
 * reload, is-active. A failed check changes nothing; a failed test or reload
 * puts the previous files back and never reloads. After success the directory
 * is copied to last_good. Only files that exist are replaced (waf/install.sh
 * creates all of them), main.conf never. On failure the staging directory
 * stays for inspection; the hourly cleanup removes it.
 */
function waf_apply_files($paths, $changes, $run)
{
	$dir = rtrim($paths['conf_dir'], '/');
	$staging = rtrim($paths['staging'], '/');
	foreach ($changes as $name => $text) {
		if ($name === 'main.conf' || !preg_match('/^[a-z0-9][a-z0-9.-]*\.conf$/', (string) $name)) {
			return waf_apply_result(false, 'bad_name', $name);
		}
		if (!is_file($dir . '/' . $name)) {
			return waf_apply_result(false, 'missing_file', $dir . '/' . $name);
		}
	}
	if (!is_file($dir . '/main.conf')) {
		return waf_apply_result(false, 'missing_file', $dir . '/main.conf');
	}
	foreach ($changes as $name => $text) {
		if ((string) file_get_contents($dir . '/' . $name) === (string) $text) {
			unset($changes[$name]);
		}
	}
	if (count($changes) === 0) {
		return waf_apply_result(true, 'unchanged', '');
	}

	waf_remove_dir($staging);
	if (!@mkdir($staging . '/previous', 0700, true)) {
		return waf_apply_result(false, 'staging', $staging);
	}
	foreach (waf_conf_files($dir) as $file) {
		copy($file, $staging . '/' . basename($file));
	}
	foreach ($changes as $name => $text) {
		file_put_contents($staging . '/' . $name, $text);
	}
	$main = str_replace('Include ' . $dir . '/', 'Include ' . $staging . '/', (string) file_get_contents($dir . '/main.conf'));
	file_put_contents($staging . '/main.check.conf', $main);

	$check = call_user_func($run, 'rules_check', $staging . '/main.check.conf');
	if ($check[0] !== 0) {
		return waf_apply_result(false, 'rules_check', $check[1]);
	}

	$names = array_keys($changes);
	foreach ($names as $name) {
		copy($dir . '/' . $name, $staging . '/previous/' . $name);
	}
	foreach ($changes as $name => $text) {
		waf_write_atomic($dir . '/' . $name, $text);
	}

	$test = call_user_func($run, 'nginx_test', '');
	if ($test[0] !== 0) {
		waf_restore_previous($dir, $staging, $names);
		return waf_apply_result(false, 'nginx_test', $test[1]);
	}
	$reload = call_user_func($run, 'nginx_reload', '');
	if ($reload[0] !== 0) {
		waf_restore_previous($dir, $staging, $names);
		return waf_apply_result(false, 'nginx_reload', $reload[1]);
	}
	$active = call_user_func($run, 'nginx_active', '');
	if ($active[0] !== 0) {
		// nginx went away after a reload that passed its test. The previous
		// files go back and nginx gets one start; waf-guard reports the rest.
		waf_restore_previous($dir, $staging, $names);
		call_user_func($run, 'nginx_start', '');
		return waf_apply_result(false, 'nginx_inactive', $active[1]);
	}

	waf_snapshot($dir, $paths['last_good']);
	waf_remove_dir($staging);
	return waf_apply_result(true, '', '');
}
```

- [ ] **Schritt 4: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [ ] **Schritt 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/tests/waf_lib_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): settings, switch decisions and the safe file exchange" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A5: Tabellen, Spalten, Verzeichnisse

Vier neue Tabellen, die Spalten für Zustand und Einstellungen, `waf` in `job_kind` und
`action_type`, die Verzeichnisse unter `<state_dir>/waf`. Alles über die
selbstprüfenden Zusätze, damit `schema.sql` bei jeder Installation und jedem Update
gefahrlos erneut läuft. Die Tabellen landen auf MariaDB 10.11 (web.herkules).

**Dateien:**
- Ändern: `ispconfig/tests/check_wiring.sh` (Prüfungen 51 und 52 vor dem Schlussblock)
- Ändern: `ispconfig/install/schema.sql` (am Ende anhängen)
- Ändern: `ispconfig/install/uninstall-schema.sql`
- Ändern: `ispconfig/install/installer.php` (`prepare_state_dir()`)

**Schnittstellen:**
- Nutzt: nichts
- Liefert: Tabellen `malwatch_waf_hit`, `malwatch_waf_site_day`, `malwatch_waf_day`,
  `malwatch_waf_exception` mit den Spalten unten; `malwatch_site.waf_state`,
  `waf_state_since`, `waf_job_id`, `waf_pending_state`; die zwölf Spalten aus
  `waf_settings_defaults()` in `malwatch_config`; Verzeichnisse `<state_dir>/waf`
  (02750 root:Panelgruppe), `waf/responses` (02750 root:Panelgruppe), `waf/staging` und
  `waf/last-good` (0750 root:root).

- [ ] **Schritt 1: Prüfungen schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 51. Die Abwehr braucht ihre vier Tabellen, die Zustandsspalte je Website, die
#     Einstellungen und den Wert waf in job_kind und action_type. Das
#     Entfernen des Addons nimmt die Tabellen wieder mit.
for table in malwatch_waf_hit malwatch_waf_site_day malwatch_waf_day malwatch_waf_exception; do
	grep -q "CREATE TABLE IF NOT EXISTS \`$table\`" "$root/install/schema.sql" \
		|| fail "schema.sql kennt die Tabelle $table nicht"
	grep -q "DROP TABLE IF EXISTS \`$table\`" "$root/install/uninstall-schema.sql" \
		|| fail "uninstall-schema.sql entfernt die Tabelle $table nicht"
done
for table in malwatch_dump malwatch_database; do
	grep -q "DROP TABLE IF EXISTS \`$table\`" "$root/install/uninstall-schema.sql" \
		|| fail "uninstall-schema.sql entfernt die Tabelle $table nicht"
done
grep -q "MODIFY COLUMN \`job_kind\` enum(.*''waf''" "$root/install/schema.sql" \
	|| fail "job_kind kennt die Auftragsart waf nicht"
grep -q "MODIFY COLUMN \`action_type\` enum(.*''waf''" "$root/install/schema.sql" \
	|| fail "action_type kennt den Wert waf nicht"
grep -q "ADD COLUMN \`waf_state\` enum(''off'',''detect'',''enforce'')" "$root/install/schema.sql" \
	|| fail "malwatch_site bekommt keine Spalte waf_state"
for col in waf_detail_days waf_stats_days waf_log_keep_days waf_preview_days waf_min_detect_days \
	waf_response_body waf_ingest_max_lines waf_job_deadline_minutes waf_audit_log waf_conf_dir \
	waf_emergency waf_emergency_since; do
	grep -q "ADD COLUMN \`$col\`" "$root/install/schema.sql" \
		|| fail "malwatch_config bekommt keine Spalte $col"
	grep -q "'$col' =>" "$root/interface/lib/malwatch_waf_lib.inc.php" \
		|| fail "waf_settings_defaults() kennt die Spalte $col nicht"
done

# 52. Der Installer legt den Arbeitsbereich der Abwehr an: waf und
#     waf/responses mit der Gruppe des Panels (die Seite liefert
#     Seitenantworten aus), staging und last-good nur fuer root.
for sub in /waf /waf/responses /waf/staging /waf/last-good; do
	grep -q "'$sub'" "$root/install/installer.php" \
		|| fail "der Installer legt <state_dir>$sub nicht an"
done
```

- [ ] **Schritt 2: Prüfungen laufen lassen, sie müssen scheitern**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: schema.sql kennt die Tabelle malwatch_waf_hit nicht` und die übrigen
Meldungen der Prüfungen 51 und 52, Rückgabewert 1

- [ ] **Schritt 3: Schema anhängen**

Am Ende von `ispconfig/install/schema.sql`:

`ispconfig/install/schema.sql` (anhängen):

```sql
-- --------------------------------------------------------
-- Abwehr (WAF): hits from the ModSecurity audit log, day figures, exceptions.
-- Filled by malwatch_waf (server/lib/classes/malwatch_waf.inc.php).
-- --------------------------------------------------------

--
-- One hit per transaction. Holds addresses and request bodies and is kept for
-- waf_detail_days. unique_id is ModSecurity's id of the transaction; a second
-- read of the same line finds its row.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_hit` (
  `hit_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `unique_id` varchar(64) NOT NULL DEFAULT '',
  `seen_at` datetime DEFAULT NULL,
  `client_ip` varchar(45) NOT NULL DEFAULT '',
  `method` varchar(10) NOT NULL DEFAULT '',
  `uri` varchar(2048) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `status` smallint(5) unsigned NOT NULL DEFAULT '0',
  `anomaly_score` smallint(5) unsigned NOT NULL DEFAULT '0',
  `would_block` enum('n','y') NOT NULL DEFAULT 'n',
  `logged_in` enum('n','y') NOT NULL DEFAULT 'n',
  `rules` text,
  `request_headers` text,
  `request_body` mediumtext,
  `response_file` varchar(255) NOT NULL DEFAULT '',
  `response_bytes` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`hit_id`),
  UNIQUE KEY `server_unique` (`server_id`,`unique_id`),
  KEY `site_seen` (`parent_domain_id`,`seen_at`),
  KEY `server_seen` (`server_id`,`seen_at`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Day figures per website, without addresses; kept for waf_stats_days.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_site_day` (
  `site_day_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `day` date NOT NULL,
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block` int(11) unsigned NOT NULL DEFAULT '0',
  `logged_in_hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block_logged_in` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`site_day_id`),
  UNIQUE KEY `day_site` (`day`,`parent_domain_id`),
  KEY `site_day` (`parent_domain_id`,`day`),
  KEY `server_day` (`server_id`,`day`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Day figures per website, rule and path, without addresses; kept for
-- waf_stats_days. Scoring rules (949, 959, 980) are not counted here.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_day` (
  `waf_day_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `day` date NOT NULL,
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `rule_id` varchar(16) NOT NULL DEFAULT '',
  `rule_msg` varchar(255) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `path_hash` char(40) NOT NULL DEFAULT '',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block_hits` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`waf_day_id`),
  UNIQUE KEY `day_site_rule_path` (`day`,`parent_domain_id`,`rule_id`,`path_hash`),
  KEY `site_day` (`parent_domain_id`,`day`),
  KEY `server_day` (`server_id`,`day`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Exceptions created in the panel. The rule id in the file is
-- 10200 + exception_id; the note never reaches a file.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_exception` (
  `exception_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `scope` enum('site','site_path','site_param','all','all_path') NOT NULL DEFAULT 'site',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `rule_id` varchar(16) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `param` varchar(128) NOT NULL DEFAULT '',
  `note` varchar(255) NOT NULL DEFAULT '',
  `exception_state` enum('pending','active','error','removing') NOT NULL DEFAULT 'pending',
  `error_reason` varchar(255) NOT NULL DEFAULT '',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `created_by` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime DEFAULT NULL,
  `activated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`exception_id`),
  KEY `server_state` (`server_id`,`exception_state`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

-- The WAF state per website as the last job confirmed it, since when, and the
-- job that is changing it. The field "nginx directives" stays the truth. One
-- statement for the four columns: it adds all of them or none.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `waf_state` enum(''off'',''detect'',''enforce'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_state_since` datetime DEFAULT NULL, ADD COLUMN `waf_job_id` int(11) unsigned NOT NULL DEFAULT ''0'', ADD COLUMN `waf_pending_state` varchar(16) NOT NULL DEFAULT ''''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'waf_state');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The settings of the page Abwehr; defaults as in waf_settings_defaults().
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_detail_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_stats_days` int(11) unsigned NOT NULL DEFAULT ''90'', ADD COLUMN `waf_log_keep_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_preview_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_min_detect_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_response_body` enum(''full'',''lean'') NOT NULL DEFAULT ''full'', ADD COLUMN `waf_ingest_max_lines` int(11) unsigned NOT NULL DEFAULT ''5000'', ADD COLUMN `waf_job_deadline_minutes` int(11) unsigned NOT NULL DEFAULT ''5'', ADD COLUMN `waf_audit_log` varchar(255) NOT NULL DEFAULT ''/var/log/waf/audit.log'', ADD COLUMN `waf_conf_dir` varchar(255) NOT NULL DEFAULT ''/etc/nginx/waf'', ADD COLUMN `waf_emergency` enum(''n'',''y'') NOT NULL DEFAULT ''n'', ADD COLUMN `waf_emergency_since` datetime DEFAULT NULL',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_detail_days');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- waf carries the jobs of the page Abwehr. The malwatch cron works on them
-- itself (malwatch_waf::run_jobs); the runner never starts one.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'',''upgrade'',''dump'',''waf'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE LIKE '%''waf''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Every WAF job leaves one line in the action log: person, action, result.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_action_log` MODIFY COLUMN `action_type` enum(''notify_admin'',''notify_client'',''disable_site'',''error'',''quarantine'',''waf'') NOT NULL DEFAULT ''notify_admin''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_action_log' AND COLUMN_NAME = 'action_type'
    AND COLUMN_TYPE LIKE '%''waf''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

- [ ] **Schritt 4: Entfernen ergänzen**

`ispconfig/install/uninstall-schema.sql` bekommt direkt unter der Kopfzeile
(`-- ISPConfig extension: malwatch - remove the schema.`) diese Zeilen. Die beiden
Tabellen des Dumps fehlten dort seit 0.17.0:

```sql
DROP TABLE IF EXISTS `malwatch_waf_exception`;
DROP TABLE IF EXISTS `malwatch_waf_day`;
DROP TABLE IF EXISTS `malwatch_waf_site_day`;
DROP TABLE IF EXISTS `malwatch_waf_hit`;
DROP TABLE IF EXISTS `malwatch_database`;
DROP TABLE IF EXISTS `malwatch_dump`;
```

- [ ] **Schritt 5: Verzeichnisse im Installer**

In `ispconfig/install/installer.php`, Methode `prepare_state_dir()`:

Die erste Schleife

```php
		foreach (array('', '/signatures', '/state', '/quarantine') as $sub) {
```

wird zu

```php
		// waf/staging and waf/last-good hold copies of the nginx rules for the
		// WAF jobs and stay root's, like the quarantine.
		foreach (array('', '/signatures', '/state', '/quarantine', '/waf/staging', '/waf/last-good') as $sub) {
```

Die zweite Schleife

```php
		foreach (array('/runs', '/spool', '/dumps') as $sub) {
```

wird zu

```php
		// waf holds the reader position and the lock of the WAF part, and
		// waf/responses the response bodies the page Abwehr shows as text.
		foreach (array('/runs', '/spool', '/dumps', '/waf', '/waf/responses') as $sub) {
```

Die erste Schleife legt `waf` über `mkdir(…, true)` als root:root an, die zweite gibt
ihm danach Modus 02750 und die Panelgruppe.

- [ ] **Schritt 6: Prüfen**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php -l ispconfig/install/installer.php`
Expected: `No syntax errors detected`

Das SQL selbst prüft Aufgabe A9 in einer Wegwerf-Datenbank am Server.

- [ ] **Schritt 7: Commit**

```bash
git add ispconfig/tests/check_wiring.sh ispconfig/install/schema.sql ispconfig/install/uninstall-schema.sql ispconfig/install/installer.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): tables, columns and state directories for the WAF part" -m "uninstall-schema.sql now also drops malwatch_dump and malwatch_database." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A6: Serverklasse, Teil 1 — Einlesen und Aufräumen

Die Klasse `malwatch_waf` liest das Audit-Log in die Tabellen und räumt stündlich auf.
Sie trägt zwei Nahtstellen für den Test: `$paths` (Verzeichnisse außerhalb der
WAF-Dateien) und `$runner` (ersetzt nginx, systemctl, logrotate und
`modsec-rules-check`).

Der Klassentest `waf_class_probe.php` braucht eine echte MariaDB und die
Datenbankklasse von ISPConfig. Er läuft deshalb in Aufgabe A9 am Server gegen eine
Wegwerf-Datenbank; hier wird er geschrieben und syntaktisch geprüft. Er weigert sich,
gegen die Datenbank von ISPConfig zu laufen.

Fakten zur Datenbankklasse von ISPConfig 3.3.1p1 (am Server gelesen): `?` wird je nach
PHP-Typ zu Zahl, `NULL` oder Text in Anführungszeichen, ein Array zu `('a','b')`, `??` zu
einem Namen in Backticks. `queryOneRecord()` hängt `LIMIT 0,1` an, wenn die Abfrage nicht
auf `LIMIT n` endet, und liefert `null` ohne Treffer. `queryAllRecords()` liefert immer
ein Array. Werte kommen als Text. `datalogSave()` schreibt über `$app->db`, nicht über
`$this`. `$app->log()` schreibt ab `$conf['log_priority']` in Datei und `sys_log`.

**Dateien:**
- Neu: `ispconfig/server/lib/classes/malwatch_waf.inc.php`
- Neu: `ispconfig/tests/waf_class_probe.php`
- Ändern: `ispconfig/install/file.list`

**Schnittstellen:**
- Nutzt: alle Funktionen aus A1 bis A4; `malwatch_helper::get_config()`;
  `$app->dbmaster`; `$conf['server_id']`
- Liefert (öffentlich): `ready()`, `settings()`, `ingest($opts)` →
  `array('lines', 'hits', 'new', 'broken', 'unknown', 'unknown_hosts' => host => Zahl,
  'sites' => site_id => Zahl, 'more')`, `ingest_locked()`, `cleanup()` →
  `array('hits', 'days', 'files', 'staging')`, `job($job_id)`, `vhost_state($domain)`,
  `run_command($name, $argument)`, Eigenschaften `$paths` und `$runner`.
  Intern für A7: `state_dir()`, `ensure_dirs()`, `lock($wait)`, `unlock()`, `web_rows()`,
  `vhost_dir()`, `vhost_file($domain)`, `rows($result)`.

- [ ] **Schritt 1: Klassentest schreiben**

`ispconfig/tests/waf_class_probe.php`:

```php
<?php
/**
 * Runs malwatch_waf against a scratch database on the server, as root:
 *
 *   php waf_class_probe.php <stage>/ispconfig <database>
 *
 * The database is a throwaway copy with the malwatch schema and empty copies
 * of web_domain, sys_datalog and sys_log (plan task A9 creates it). The probe
 * refuses the ISPConfig database. Files go below a temporary directory;
 * nginx, systemctl, logrotate and modsec-rules-check are replaced by a
 * recorder, so nothing on the machine changes.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php waf_class_probe.php <stage>/ispconfig <database>\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
$probe_db = $argv[2];

require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require SCRIPT_PATH . '/lib/app.inc.php';

if ($probe_db === $conf['db_database'] || !preg_match('/^mw_[a-z0-9_]+$/', $probe_db)) {
	fwrite(STDERR, "refused: $probe_db is no scratch database\n");
	exit(2);
}
// Nothing of the probe reaches the ISPConfig log.
$conf['log_priority'] = 9;

$clientdb = (string) file_get_contents('/usr/local/ispconfig/server/lib/mysql_clientdb.conf');
preg_match("/clientdb_user\s*=\s*'([^']*)'/", $clientdb, $user);
preg_match("/clientdb_password\s*=\s*'([^']*)'/", $clientdb, $pass);
$db = new db($conf['db_host'], $user[1], $pass[1], $probe_db);
$current = $db->queryOneRecord('SELECT DATABASE() AS name');
if (!is_array($current) || $current['name'] !== $probe_db) {
	fwrite(STDERR, "refused: connected to the wrong database\n");
	exit(2);
}
$app->db = $db;
$app->dbmaster = $db;

require $stage . '/interface/lib/malwatch_waf_lib.inc.php';
require $stage . '/server/lib/classes/malwatch_waf.inc.php';
$app->uses('malwatch_helper');

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function count_rows($sql)
{
	global $db;
	return count($db->queryAllRecords($sql));
}

$server = (int) $conf['server_id'];
$tmp = '/tmp/waf-probe-' . getmypid();
waf_remove_dir($tmp);
foreach (array('state', 'vhosts', 'backups', 'conf.d', 'waf') as $sub) {
	mkdir($tmp . '/' . $sub, 0700, true);
}
// The WAF directory as waf/install.sh leaves it, with main.conf pointing here.
foreach (glob(dirname($stage) . '/waf/conf/*.conf') as $file) {
	$text = str_replace('/etc/nginx/waf/', $tmp . '/waf/', (string) file_get_contents($file));
	file_put_contents($tmp . '/waf/' . basename($file), $text);
}
file_put_contents($tmp . '/conf.d/waf.conf', "modsecurity_rules_file $tmp/waf/main.conf;\n");
copy($stage . '/tests/waf_audit_sample.log', $tmp . '/audit.log');

$db->query('UPDATE malwatch_config SET waf_audit_log = ?, waf_conf_dir = ?, state_dir = ? WHERE config_id = 1',
	$tmp . '/audit.log', $tmp . '/waf', $tmp . '/state');
$db->query('DELETE FROM web_domain');
$db->query('DELETE FROM sys_datalog');
foreach (array(
	array(11, 0, 'vhost', 'beispiel.test', 'www'),
	array(12, 0, 'vhost', 'zweite.test', 'none'),
	array(21, 11, 'alias', 'alias-beispiel.test', 'none'),
) as $row) {
	$db->query('INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, '
		. "sys_groupid, nginx_directives, document_root) VALUES (?, ?, ?, ?, ?, ?, 'y', 1, '', ?)",
		$row[0], $server, $row[1], $row[2], $row[3], $row[4], '/var/www/' . $row[3]);
}

// Stands in for every command; answers are queues per command name.
$calls = array();
$answers = array();
$waf = new malwatch_waf();
$waf->paths = array(
	'vhost_dir' => $tmp . '/vhosts',
	'state_dir' => $tmp . '/state',
	'backup_dir' => $tmp . '/backups',
	'guard_log' => $tmp . '/guard.log',
	'conf_include' => $tmp . '/conf.d/waf.conf',
	'logrotate' => $tmp . '/logrotate-waf',
);
$waf->runner = function ($name, $argument) use (&$calls, &$answers) {
	$calls[] = $name;
	if (isset($answers[$name]) && count($answers[$name]) > 0) {
		return array_shift($answers[$name]);
	}
	return array(0, '');
};
expect_same('ready', $waf->ready(), true);

// --- A6: ingest and cleanup --------------------------------------------------

$stats = $waf->ingest(array());
expect_same('ingest counts', array($stats['lines'], $stats['hits'], $stats['new'], $stats['broken'], $stats['unknown']), array(8, 4, 4, 3, 1));
expect_same('ingest unknown host', $stats['unknown_hosts'], array('fremd.test' => 1));
expect_same('ingest by website', $stats['sites'], array(11 => 2, 12 => 2));
expect_same('hits stored', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 4);
$first = $db->queryOneRecord("SELECT * FROM malwatch_waf_hit WHERE unique_id = '1758049759112233445'");
expect_same('hit fields', array($first['server_id'], $first['parent_domain_id'], $first['domain'], $first['seen_at'],
	$first['would_block'], $first['logged_in'], $first['anomaly_score'], $first['status'], $first['response_file']),
	array((string) $server, '11', 'beispiel.test', '2026-09-16 21:09:19', 'y', 'y', '5', '207', ''));
expect_same('hit without secrets', strpos($first['request_headers'] . $first['request_body'], 'geheim'), false);
expect_same('hit rules', json_decode($first['rules'], true)[0]['param'], 'json.requests.0.path');

$second = $db->queryOneRecord("SELECT * FROM malwatch_waf_hit WHERE unique_id = '1757142300998877665'");
$response = $tmp . '/state/waf/responses/' . $second['response_file'];
expect_same('response stored', array($second['response_bytes'], is_file($response)), array('33', true));
expect_same('response content', gzdecode((string) file_get_contents($response)), '<html><body>Treffer</body></html>');
expect_same('response mode', substr(sprintf('%o', fileperms($response)), -4), '0640');
expect_same('responses directory', substr(sprintf('%o', fileperms($tmp . '/state/waf/responses')), -4), '2750');

expect_same('site days', $db->queryAllRecords('SELECT day, parent_domain_id, domain, hits, would_block, logged_in_hits, '
	. 'would_block_logged_in FROM malwatch_waf_site_day ORDER BY parent_domain_id, day'), array(
	array('day' => '2026-09-06', 'parent_domain_id' => '11', 'domain' => 'beispiel.test', 'hits' => '1', 'would_block' => '0', 'logged_in_hits' => '0', 'would_block_logged_in' => '0'),
	array('day' => '2026-09-16', 'parent_domain_id' => '11', 'domain' => 'beispiel.test', 'hits' => '1', 'would_block' => '1', 'logged_in_hits' => '1', 'would_block_logged_in' => '1'),
	array('day' => '2026-09-16', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'hits' => '2', 'would_block' => '1', 'logged_in_hits' => '0', 'would_block_logged_in' => '0'),
));
expect_same('rule days', $db->queryAllRecords('SELECT day, parent_domain_id, rule_id, rule_msg, path, hits, would_block_hits '
	. 'FROM malwatch_waf_day ORDER BY parent_domain_id, day, rule_id'), array(
	array('day' => '2026-09-06', 'parent_domain_id' => '11', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '1', 'would_block_hits' => '0'),
	array('day' => '2026-09-16', 'parent_domain_id' => '11', 'rule_id' => '942190', 'rule_msg' => 'Detects MSSQL code execution and information gathering attempts', 'path' => '/wp-json/batch/v1', 'hits' => '1', 'would_block_hits' => '1'),
	array('day' => '2026-09-16', 'parent_domain_id' => '12', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'path' => '/seite', 'hits' => '2', 'would_block_hits' => '1'),
));

$reader = json_decode((string) file_get_contents($tmp . '/state/waf/reader.json'), true);
expect_same('reader at the end', $reader['offset'], filesize($tmp . '/audit.log'));
$again = $waf->ingest(array());
expect_same('nothing new', array($again['lines'], $again['new']), array(0, 0));
unlink($tmp . '/state/waf/reader.json');
$again = $waf->ingest(array());
expect_same('read again without doubles', array($again['lines'], $again['hits'], $again['new']), array(8, 4, 0));
expect_same('day figures unchanged', $db->queryOneRecord('SELECT SUM(hits) AS n FROM malwatch_waf_site_day')['n'], '4');

// copytruncate: the file starts over, shorter than the stored offset.
$lines = file($tmp . '/audit.log');
file_put_contents($tmp . '/audit.log', str_replace('1757999160000000002', '1757999160000000003', $lines[7]));
$again = $waf->ingest(array());
expect_same('after copytruncate', array($again['lines'], $again['new']), array(1, 1));

$dry = $waf->ingest(array('dry_run' => true, 'file' => $stage . '/tests/waf_audit_sample.log'));
expect_same('dry run counts', array($dry['lines'], $dry['hits'], $dry['new']), array(8, 4, 0));
expect_same('dry run writes nothing', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 5);

$ingested = $waf->ingest_locked();
expect_same('ingest under the lock', $ingested['lines'], 0);

// Everything is recent except one hit and one day of each table.
$db->query('UPDATE malwatch_waf_hit SET seen_at = NOW()');
$db->query("UPDATE malwatch_waf_hit SET seen_at = DATE_SUB(NOW(), INTERVAL 30 DAY) WHERE unique_id = '1757142300998877665'");
$db->query("UPDATE malwatch_waf_site_day SET day = IF(day = '2026-09-06', DATE_SUB(CURDATE(), INTERVAL 200 DAY), CURDATE())");
$db->query("UPDATE malwatch_waf_day SET day = IF(day = '2026-09-06', DATE_SUB(CURDATE(), INTERVAL 200 DAY), CURDATE())");
file_put_contents($tmp . '/state/waf/responses/orphan.html.gz', 'x');
touch($tmp . '/state/waf/responses/orphan.html.gz', time() - 7200);
file_put_contents($tmp . '/state/waf/responses/fresh.html.gz', 'x');
mkdir($tmp . '/state/waf/staging/999999', 0700, true);
file_put_contents($tmp . '/state/waf/staging/999998-logrotate', 'x');
$counts = $waf->cleanup();
expect_same('cleanup counts', $counts, array('hits' => 1, 'days' => 2, 'files' => 1, 'staging' => 2));
expect_same('old hit gone', $db->queryOneRecord("SELECT hit_id FROM malwatch_waf_hit WHERE unique_id = '1757142300998877665'"), null);
expect_same('its response gone', is_file($response), false);
expect_same('orphan gone, fresh file kept', array(is_file($tmp . '/state/waf/responses/orphan.html.gz'),
	is_file($tmp . '/state/waf/responses/fresh.html.gz')), array(false, true));
expect_same('hits left', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 4);
expect_same('staging emptied', array(is_dir($tmp . '/state/waf/staging/999999'), is_file($tmp . '/state/waf/staging/999998-logrotate')), array(false, false));

// --- summary -----------------------------------------------------------------
waf_remove_dir($tmp);
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_class_probe: alle Prüfungen bestanden\n";
```

- [ ] **Schritt 2: Test prüfen, er muss scheitern**

Run: `php -l ispconfig/tests/waf_class_probe.php && php ispconfig/tests/waf_class_probe.php`
Expected: `No syntax errors detected`, danach die Nutzungszeile
(`usage: php waf_class_probe.php …`) mit Rückgabewert 2. Der eigentliche Lauf folgt in A9;
ohne die Klasse bricht er dort mit „Failed opening required … malwatch_waf.inc.php" ab.

- [ ] **Schritt 3: Klasse schreiben**

`ispconfig/server/lib/classes/malwatch_waf.inc.php`:

```php
<?php

/**
 * The WAF part of malwatch on the server ("Abwehr" in the panel).
 *
 * Reads the ModSecurity audit log into the database, clears out what is past
 * its time and carries out the jobs the panel and waf-switch queue. Runs as
 * root: every minute from the malwatch cron (cleanup once an hour), and from
 * waf-switch and waf-guard.
 *
 * Every change to nginx goes through waf_apply_files() or through
 * ISPConfig's own vhost writer, so the running web server only ever reloads a
 * configuration that passed nginx -t. The decisions live in
 * interface/lib/malwatch_waf_lib.inc.php and are tested there; this class
 * carries the database, the files and the commands.
 *
 * Time arithmetic stays in SQL: ISPConfig runs its server scripts in UTC,
 * the database in the server's local time.
 */
class malwatch_waf
{
	/** Where install/file.list puts the shared functions. */
	const LIB = '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php';

	/**
	 * Paths outside the WAF directory. Public so tests/waf_class_probe.php can
	 * point them at a scratch directory. vhost_dir comes from the ISPConfig
	 * server settings and state_dir from malwatch_config while they are null.
	 */
	public $paths = array(
		'vhost_dir' => null,
		'state_dir' => null,
		'backup_dir' => '/var/backups/waf-switch',
		'guard_log' => '/var/log/waf/guard.log',
		'conf_include' => '/etc/nginx/conf.d/waf.conf',
		'logrotate' => '/etc/logrotate.d/waf',
	);

	/** Takes the place of the real commands when set: function ($name, $argument) returning array(code, output). */
	public $runner = null;

	/** The handle of the lock file while this process holds it. */
	private $lock = null;

	/** Loads the shared functions; false when malwatch is not installed completely. */
	public function ready()
	{
		if (!function_exists('waf_states') && is_file(self::LIB)) {
			require_once self::LIB;
		}
		return function_exists('waf_states');
	}

	/** The WAF settings, with defaults for columns an older schema lacks. */
	public function settings()
	{
		global $app;
		return waf_settings($app->dbmaster->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
	}

	/** One job row, or null. */
	public function job($job_id)
	{
		global $app;
		return $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_job WHERE job_id = ?', (int) $job_id);
	}

	/**
	 * Reads new lines of the audit log into malwatch_waf_hit and the day
	 * tables. With 'dry_run' it only counts: it writes nothing and reads
	 * 'file' (or the configured log) from the start. Returns the counts.
	 * Lines of hosts without a website are counted and left out.
	 */
	public function ingest($opts)
	{
		global $app;

		$settings = $this->settings();
		$dry = !empty($opts['dry_run']);
		$file = ($dry && !empty($opts['file'])) ? (string) $opts['file'] : $settings['waf_audit_log'];
		$stats = array('lines' => 0, 'hits' => 0, 'new' => 0, 'broken' => 0, 'unknown' => 0,
			'unknown_hosts' => array(), 'sites' => array(), 'more' => false);
		clearstatcache();
		$stat = @stat($file);
		if ($stat === false) {
			return $stats;
		}
		if ($dry) {
			$offset = 0;
			$max = 100000;
		} else {
			$reader = $this->reader_state();
			$offset = waf_reader_start($reader['inode'], $reader['offset'], $stat['ino'], $stat['size']);
			$max = $settings['waf_ingest_max_lines'];
		}
		$read = waf_read_lines($file, $offset, $max);
		if ($read === null) {
			return $stats;
		}

		$rows = $this->web_rows();
		$map = waf_host_map($rows);
		$names = array();
		foreach ($rows as $row) {
			if ((string) $row['type'] === 'vhost') {
				$names[(int) $row['domain_id']] = (string) $row['domain'];
			}
		}
		foreach ($read['lines'] as $line) {
			$stats['lines']++;
			$hit = waf_audit_parse_line($line);
			if ($hit === null) {
				$stats['broken']++;
				continue;
			}
			$site = waf_host_lookup($map, $hit['host']);
			if ($site < 1) {
				$host = $hit['host'] === '' ? '?' : $hit['host'];
				$stats['unknown']++;
				$stats['unknown_hosts'][$host] = isset($stats['unknown_hosts'][$host]) ? $stats['unknown_hosts'][$host] + 1 : 1;
				continue;
			}
			$stats['hits']++;
			$stats['sites'][$site] = isset($stats['sites'][$site]) ? $stats['sites'][$site] + 1 : 1;
			if (!$dry && $this->store_hit($site, isset($names[$site]) ? $names[$site] : '', $hit)) {
				$stats['new']++;
			}
		}
		$stats['more'] = $read['more'];

		if (!$dry) {
			$this->save_reader_state($stat['ino'], $read['offset']);
			if ($stats['broken'] > 0 || $stats['unknown'] > 0) {
				$app->log('malwatch: WAF log read, ' . $stats['new'] . ' new hits, ' . $stats['broken']
					. ' unreadable lines, ' . $stats['unknown'] . ' hits for unknown hosts ('
					. implode(', ', array_slice(array_keys($stats['unknown_hosts']), 0, 10)) . ').', LOGLEVEL_DEBUG);
			}
		}
		return $stats;
	}

	/** ingest() under the lock, for waf-switch ingest. Null when the lock or the functions are missing. */
	public function ingest_locked()
	{
		if (!$this->ready() || !$this->lock(true)) {
			return null;
		}
		try {
			return $this->ingest(array());
		} finally {
			$this->unlock();
		}
	}

	/**
	 * The hourly cleanup: hits past waf_detail_days with their response files,
	 * day figures past waf_stats_days, response files without a hit, and the
	 * working directories of jobs that no longer run.
	 */
	public function cleanup()
	{
		global $app, $conf;

		$settings = $this->settings();
		$dir = $this->ensure_dirs();
		$counts = array('hits' => 0, 'days' => 0, 'files' => 0, 'staging' => 0);

		for ($round = 0; $round < 50; $round++) {
			$old = $this->rows($app->dbmaster->queryAllRecords(
				'SELECT hit_id, response_file FROM malwatch_waf_hit WHERE server_id = ? '
				. 'AND seen_at < DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY hit_id LIMIT 1000',
				$conf['server_id'], $settings['waf_detail_days']));
			if (count($old) === 0) {
				break;
			}
			$ids = array();
			foreach ($old as $row) {
				$ids[] = (int) $row['hit_id'];
				$this->remove_response((string) $row['response_file']);
			}
			$app->dbmaster->query('DELETE FROM malwatch_waf_hit WHERE hit_id IN ?', $ids);
			$counts['hits'] += count($ids);
		}

		foreach (array('malwatch_waf_site_day', 'malwatch_waf_day') as $table) {
			$app->dbmaster->query('DELETE FROM ?? WHERE server_id = ? AND day < DATE_SUB(CURDATE(), INTERVAL ? DAY)',
				$table, $conf['server_id'], $settings['waf_stats_days']);
			$counts['days'] += (int) $app->dbmaster->affectedRows();
		}

		$known = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT response_file FROM malwatch_waf_hit WHERE server_id = ? AND response_file != ''",
			$conf['server_id'])) as $row) {
			$known[(string) $row['response_file']] = true;
		}
		$names = @scandir($dir . '/responses');
		foreach (is_array($names) ? $names : array() as $name) {
			$file = $dir . '/responses/' . $name;
			if ($name === '.' || $name === '..' || isset($known[$name]) || !is_file($file)) {
				continue;
			}
			// A younger file may belong to a hit that is being written right now.
			if (filemtime($file) < time() - 3600 && @unlink($file)) {
				$counts['files']++;
			}
		}

		$running = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT job_id FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running'",
			$conf['server_id'])) as $job) {
			$running[(string) (int) $job['job_id']] = true;
		}
		$names = @scandir($dir . '/staging');
		foreach (is_array($names) ? $names : array() as $name) {
			if (!preg_match('/^(\d+)/', $name, $m) || isset($running[$m[1]])) {
				continue;
			}
			$path = $dir . '/staging/' . $name;
			if (is_dir($path) && !is_link($path)) {
				waf_remove_dir($path);
			} else {
				@unlink($path);
			}
			$counts['staging']++;
		}
		return $counts;
	}

	/** What the vhost file of a website shows; 'off' without a file or for an odd name. */
	public function vhost_state($domain)
	{
		$domain = (string) $domain;
		if ($domain === '' || waf_host_normalize($domain) !== strtolower($domain)) {
			return 'off';
		}
		$file = $this->vhost_file($domain);
		return is_file($file) ? waf_vhost_state((string) file_get_contents($file)) : 'off';
	}

	/** Runs one of the few commands the WAF needs; returns array(exit code, output). */
	public function run_command($name, $argument)
	{
		if ($this->runner !== null) {
			return call_user_func($this->runner, $name, $argument);
		}
		$systemctl = $this->binary(array('/usr/bin/systemctl', '/bin/systemctl'));
		switch ($name) {
			case 'rules_check':
				$found = glob('/usr/lib/*/libexec/modsec-rules-check');
				$tool = $this->binary(array_merge(is_array($found) ? $found : array(),
					array('/usr/bin/modsec-rules-check', '/usr/local/bin/modsec-rules-check')));
				if ($tool === '') {
					return array(0, 'modsec-rules-check fehlt, nginx -t entscheidet.');
				}
				$command = escapeshellarg($tool) . ' ' . escapeshellarg($argument);
				break;
			case 'nginx_test':
				$command = escapeshellarg($this->binary(array('/usr/sbin/nginx', '/usr/bin/nginx'))) . ' -t';
				break;
			case 'nginx_reload':
				$command = escapeshellarg($systemctl) . ' reload nginx';
				break;
			case 'nginx_active':
				$command = escapeshellarg($systemctl) . ' is-active --quiet nginx';
				break;
			case 'nginx_start':
				$command = escapeshellarg($systemctl) . ' start nginx';
				break;
			case 'logrotate_check':
				$command = escapeshellarg($this->binary(array('/usr/sbin/logrotate', '/usr/bin/logrotate')))
					. ' -d ' . escapeshellarg($argument);
				break;
			default:
				return array(1, 'Unbekannter Befehl: ' . $name);
		}
		$output = array();
		$code = 0;
		exec($command . ' 2>&1', $output, $code);
		return array((int) $code, implode("\n", $output));
	}

	/** Stores one hit; true when it was new. Only a new hit counts in the day tables. */
	private function store_hit($site, $domain, $hit)
	{
		global $app, $conf;

		$app->dbmaster->query(
			'INSERT IGNORE INTO malwatch_waf_hit (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, method, uri, path, status, '
			. 'anomaly_score, would_block, logged_in, rules, request_headers, request_body) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$conf['server_id'], (int) $site, (string) $domain, $hit['unique_id'], $hit['seen_at'], $hit['client_ip'],
			$hit['method'], $hit['uri'], $hit['path'], (int) $hit['status'], (int) $hit['anomaly_score'],
			$hit['would_block'] ? 'y' : 'n', $hit['logged_in'] ? 'y' : 'n',
			waf_json($hit['rules']), waf_json($hit['headers']), $hit['body']);
		if ((int) $app->dbmaster->affectedRows() !== 1) {
			return false;
		}
		$hit_id = (int) $app->dbmaster->insertID();

		if ($hit['response_body'] !== null && $hit['response_body'] !== '') {
			$name = $this->store_response($hit['unique_id'], $hit['response_body']);
			if ($name !== '') {
				$app->dbmaster->query('UPDATE malwatch_waf_hit SET response_file = ?, response_bytes = ? WHERE hit_id = ?',
					$name, strlen($hit['response_body']), $hit_id);
			}
		}

		$day = substr($hit['seen_at'], 0, 10);
		$block = $hit['would_block'] ? 1 : 0;
		$logged_in = $hit['logged_in'] ? 1 : 0;
		$app->dbmaster->query(
			'INSERT INTO malwatch_waf_site_day (server_id, day, parent_domain_id, domain, hits, would_block, '
			. 'logged_in_hits, would_block_logged_in) VALUES (?, ?, ?, ?, 1, ?, ?, ?) '
			. 'ON DUPLICATE KEY UPDATE hits = hits + 1, would_block = would_block + VALUES(would_block), '
			. 'logged_in_hits = logged_in_hits + VALUES(logged_in_hits), '
			. 'would_block_logged_in = would_block_logged_in + VALUES(would_block_logged_in)',
			$conf['server_id'], $day, (int) $site, (string) $domain, $block, $logged_in, $block * $logged_in);
		foreach ($hit['rules'] as $rule) {
			if (waf_is_scoring_rule($rule['id'])) {
				continue;
			}
			$app->dbmaster->query(
				'INSERT INTO malwatch_waf_day (server_id, day, parent_domain_id, domain, rule_id, rule_msg, path, '
				. 'path_hash, hits, would_block_hits) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?) '
				. 'ON DUPLICATE KEY UPDATE hits = hits + 1, would_block_hits = would_block_hits + VALUES(would_block_hits), '
				. 'rule_msg = VALUES(rule_msg)',
				$conf['server_id'], $day, (int) $site, (string) $domain, $rule['id'], $rule['msg'],
				$hit['path'], sha1($hit['path']), $block);
		}
		return true;
	}

	/** Packs a response body into <state_dir>/waf/responses; returns the file name or ''. */
	private function store_response($unique_id, $body)
	{
		$dir = $this->ensure_dirs() . '/responses';
		$name = preg_replace('/[^A-Za-z0-9._-]/', '_', $unique_id) . '.html.gz';
		$tmp = $dir . '/.' . $name . '.tmp';
		$data = gzencode($body, 6);
		if ($data === false || @file_put_contents($tmp, $data) === false) {
			@unlink($tmp);
			return '';
		}
		// The directory's setgid bit hands the file the panel's group.
		@chmod($tmp, 0640);
		if (!@rename($tmp, $dir . '/' . $name)) {
			@unlink($tmp);
			return '';
		}
		return $name;
	}

	private function remove_response($name)
	{
		$name = basename((string) $name);
		if ($name !== '' && $name !== '.' && $name !== '..') {
			@unlink($this->state_dir() . '/responses/' . $name);
		}
	}

	/** Where the last run stopped reading; a missing file means from the start. */
	private function reader_state()
	{
		$doc = json_decode((string) @file_get_contents($this->ensure_dirs() . '/reader.json'), true);
		return array(
			'inode' => is_array($doc) && isset($doc['inode']) ? (int) $doc['inode'] : 0,
			'offset' => is_array($doc) && isset($doc['offset']) ? (int) $doc['offset'] : 0,
		);
	}

	private function save_reader_state($inode, $offset)
	{
		waf_write_atomic($this->ensure_dirs() . '/reader.json',
			json_encode(array('inode' => (int) $inode, 'offset' => (int) $offset)) . "\n");
	}

	/** <state_dir>/waf. */
	private function state_dir()
	{
		global $app;
		$base = $this->paths['state_dir'];
		if ($base === null) {
			$app->uses('malwatch_helper');
			$config = $app->malwatch_helper->get_config();
			$base = (string) $config['state_dir'];
		}
		return rtrim($base, '/') . '/waf';
	}

	/**
	 * Creates the working directories an update has not created yet and
	 * returns <state_dir>/waf. Existing directories keep what the installer
	 * gave them.
	 */
	private function ensure_dirs()
	{
		$base = $this->state_dir();
		$group = @filegroup(dirname($base));
		foreach (array('', '/responses') as $sub) {
			if (!is_dir($base . $sub)) {
				@mkdir($base . $sub, 02750, true);
				@chmod($base . $sub, 02750);
				if ($group !== false) {
					@chgrp($base . $sub, $group);
				}
			}
		}
		foreach (array('/staging', '/last-good') as $sub) {
			if (!is_dir($base . $sub)) {
				@mkdir($base . $sub, 0750, true);
			}
		}
		return $base;
	}

	/** One WAF worker at a time: the cron, waf-switch and waf-guard share this lock. */
	private function lock($wait)
	{
		if ($this->lock !== null) {
			return true;
		}
		$handle = @fopen($this->ensure_dirs() . '/lock', 'c');
		if ($handle === false) {
			return false;
		}
		if (!flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
			fclose($handle);
			return false;
		}
		$this->lock = $handle;
		return true;
	}

	private function unlock()
	{
		if ($this->lock !== null) {
			flock($this->lock, LOCK_UN);
			fclose($this->lock);
			$this->lock = null;
		}
	}

	/** The web_domain rows of this server that the host map needs. */
	private function web_rows()
	{
		global $app, $conf;
		return $this->rows($app->dbmaster->queryAllRecords(
			'SELECT domain_id, parent_domain_id, type, domain, subdomain, active FROM web_domain WHERE server_id = ?',
			$conf['server_id']));
	}

	/** Where ISPConfig writes the vhost files of this server. */
	private function vhost_dir()
	{
		global $app, $conf;
		$dir = $this->paths['vhost_dir'];
		if ($dir === null) {
			$app->uses('getconf');
			$web = $app->getconf->get_server_config($conf['server_id'], 'web');
			$dir = !empty($web['nginx_vhost_conf_dir']) ? $web['nginx_vhost_conf_dir'] : '/etc/nginx/sites-available';
		}
		return rtrim($dir, '/');
	}

	private function vhost_file($domain)
	{
		return $this->vhost_dir() . '/' . $domain . '.vhost';
	}

	/** The first path that exists and may be run; '' when none does. */
	private function binary($candidates)
	{
		foreach ($candidates as $path) {
			if (is_string($path) && is_file($path) && is_executable($path)) {
				return $path;
			}
		}
		return '';
	}

	private function rows($result)
	{
		return is_array($result) ? $result : array();
	}
}
```

- [ ] **Schritt 4: Syntax prüfen und eintragen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php`
Expected: `No syntax errors detected`

In `ispconfig/install/file.list` nach der Zeile
`c:server/lib/classes/malwatch_actions.inc.php:server/lib/classes/malwatch_actions.inc.php`:

```text
c:server/lib/classes/malwatch_waf.inc.php:server/lib/classes/malwatch_waf.inc.php
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Schritt 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_class_probe.php ispconfig/install/file.list
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): server class reads the audit log and clears old hits" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A7: Serverklasse, Teil 2 — Aufträge, Wächter, Cron

Die Klasse arbeitet die WAF-Aufträge ab: Zustand je Website in zwei Phasen mit Frist und
Rücknahme, Ausnahmen, Notaus (weich und hart), Seitenantwort, Einstellungen, Abgleich.
Dazu der Wächter für `waf-guard`. Der Cron ruft die Klasse jede Minute auf, und die
bestehenden Wege für Prüfaufträge lassen `waf` in Ruhe.

**Dateien:**
- Ändern: `ispconfig/server/lib/classes/malwatch_waf.inc.php` (Methoden vor der letzten
  schließenden Klammer)
- Ändern: `ispconfig/tests/waf_class_probe.php` (Abschnitt A7)
- Ändern: `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php`
- Ändern: `ispconfig/server/lib/classes/malwatch_helper.inc.php`
- Ändern: `ispconfig/server/plugins/malwatch_plugin.inc.php`
- Ändern: `ispconfig/tests/check_wiring.sh` (Prüfung 53)

**Schnittstellen:**
- Nutzt: A1 bis A6; `malwatch_helper::claim_job($job_id)`
- Liefert (öffentlich): `cron_minute()`, `cron_hourly()`, `run_jobs()`, `pass()`,
  `queue($action, $fields, $user)` → `int` (job_id), `execute_now($action, $fields, $user)` →
  Auftragszeile oder `null`, `guard()` → `0` oder `1`, `snapshot()` → bool.
  `job_log` enthält je Website eine Zeile `<domain>: <Ergebnis>`, etwa
  `beispiel.test: mitschreiben bestätigt`. `malwatch_action_log` bekommt je Auftrag eine
  Zeile mit `action_type = 'waf'` und `detail` = `<Person>: <Aktion> erledigt|gescheitert`
  plus `job_log`.

- [ ] **Schritt 1: Prüfung und Klassentest schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 53. WAF-Auftraege gehoeren dem Cron. Das Plugin laesst sie liegen,
#     start_pending und die Zaehlung nehmen sie aus, weder das Einsammeln noch
#     die Zeitsperre fassen sie an. Der Cron laedt malwatch_waf, ruft es jede
#     Minute und stuendlich zum Aufraeumen.
plugin="$root/server/plugins/malwatch_plugin.inc.php"
cron="$root/server/lib/classes/cron.d/560-malwatch.inc.php"
helper="$root/server/lib/classes/malwatch_helper.inc.php"
grep -q "job_kind'\] === 'waf'" "$plugin" \
	|| fail "malwatch_plugin.inc.php laesst WAF-Auftraege nicht liegen"
grep -q "job_kind NOT IN ('vulncheck','waf')" "$cron" \
	|| fail "start_pending nimmt WAF-Auftraege nicht aus"
grep -q "job_kind NOT IN ('vulncheck','waf')" "$helper" \
	|| fail "count_running_jobs zaehlt WAF-Auftraege mit"
[ "$(grep -c "job_kind != 'waf'" "$cron")" -ge 2 ] \
	|| fail "collect_finished oder die Zeitsperre fassen WAF-Auftraege an"
grep -q "uses('[^']*malwatch_waf" "$cron" \
	|| fail "der Cron laedt malwatch_waf nicht"
grep -q 'malwatch_waf->cron_minute()' "$cron" \
	|| fail "der Cron ruft malwatch_waf nicht jede Minute auf"
grep -q 'malwatch_waf->cron_hourly()' "$cron" \
	|| fail "der Cron raeumt die Treffer der WAF nicht auf"
```

In `ispconfig/tests/waf_class_probe.php` vor der Zeile `// --- summary ---`:

`ispconfig/tests/waf_class_probe.php` (Abschnitt vor summary):

```php
// --- A7: jobs ----------------------------------------------------------------

function job_row($id)
{
	global $waf;
	return $waf->job($id);
}

function job_progress($id)
{
	$job = job_row($id);
	$options = json_decode((string) $job['options'], true);
	return isset($options['progress']) ? $options['progress'] : array();
}

function site_row($id)
{
	global $db;
	return $db->queryOneRecord('SELECT waf_state, waf_state_since, waf_pending_state FROM malwatch_site WHERE parent_domain_id = ?', $id);
}

function field($id)
{
	global $db;
	$row = $db->queryOneRecord('SELECT nginx_directives FROM web_domain WHERE domain_id = ?', $id);
	return (string) $row['nginx_directives'];
}

function vhost($domain, $body)
{
	global $tmp;
	file_put_contents($tmp . '/vhosts/' . $domain . '.vhost', "server {\n" . $body . "}\n");
}

function config_value($column)
{
	global $db;
	$row = $db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1');
	return $row[$column];
}

function exception_row($id)
{
	global $db;
	return $db->queryOneRecord('SELECT * FROM malwatch_waf_exception WHERE exception_id = ?', $id);
}

function add_exception($scope, $site, $rule, $path, $param, $note)
{
	global $db, $server;
	$db->query('INSERT INTO malwatch_waf_exception (server_id, scope, parent_domain_id, domain, rule_id, path, param, note, '
		. "exception_state, created_by, created_at) VALUES (?, ?, ?, '', ?, ?, ?, ?, 'pending', 'probe', NOW())",
		$server, $scope, $site, $rule, $path, $param, $note);
	return (int) $db->insertID();
}

function age_job($id)
{
	global $db;
	$db->query('UPDATE malwatch_job SET started_at = DATE_SUB(NOW(), INTERVAL 10 MINUTE) WHERE job_id = ?', $id);
}

$own = "client_max_body_size 64M;\n";
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 11', $own);
vhost('beispiel.test', "    listen 80;\n");
vhost('zweite.test', "    listen 80;\n");
$answers = array();

// Two phases: the field first, the vhost later.
$calls = array();
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'detect'), 'probe');
$waf->pass();
$progress = job_progress($job);
expect_same('set: job waits', job_row($job)['job_status'], 'running');
expect_same('set: entry waits', array($progress[0]['status'], $progress[0]['target']), array('waiting', 'detect'));
expect_same('set: field written', field(11), $own . waf_block_text('detect'));
expect_same('set: backup', file_get_contents($progress[0]['backup']), $own);
expect_same('set: datalog', count_rows("SELECT datalog_id FROM sys_datalog WHERE dbtable = 'web_domain' AND dbidx = 'domain_id:11'"), 1);
expect_same('set: pending state', site_row(11)['waf_pending_state'], 'detect');
expect_same('set: no command yet', $calls, array());

vhost('beispiel.test', "    listen 80;\n    modsecurity on;\n");
$waf->pass();
$site = site_row(11);
expect_same('set: done', job_row($job)['job_status'], 'done');
expect_same('set: one nginx -t', $calls, array('nginx_test'));
expect_same('set: confirmed', array($site['waf_state'], $site['waf_pending_state'], $site['waf_state_since'] !== null), array('detect', '', true));
expect_same('set: job log', job_row($job)['job_log'], 'beispiel.test: mitschreiben bestätigt');
expect_same('set: action log', count_rows("SELECT action_id FROM malwatch_action_log WHERE action_type = 'waf'"), 1);

$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('enforce too early', array(job_row($job)['job_status'], job_progress($job)[0]['reason']), array('done', 'too_early'));
expect_same('enforce too early leaves the field', field(11), $own . waf_block_text('detect'));

// Past the deadline the job takes its change back.
$db->query('UPDATE malwatch_site SET waf_state_since = DATE_SUB(NOW(), INTERVAL 8 DAY) WHERE parent_domain_id = 11');
$calls = array();
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('enforce written', field(11), $own . waf_block_text('enforce'));
age_job($job);
$waf->pass();
$entry = job_progress($job)[0];
expect_same('deadline: failed', array(job_row($job)['job_status'], $entry['reason'], $entry['rollback']), array('error', 'deadline', 'rolled_back'));
expect_same('deadline: field back', field(11), $own . waf_block_text('detect'));
expect_same('deadline: state kept', array(site_row(11)['waf_state'], site_row(11)['waf_pending_state']), array('detect', ''));
expect_same('deadline: no reload', in_array('nginx_reload', $calls, true), false);

// Somebody saved the field in the meantime: it stays.
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
$db->query('UPDATE web_domain SET nginx_directives = CONCAT(nginx_directives, ?) WHERE domain_id = 11', "gzip on;\n");
age_job($job);
$waf->pass();
expect_same('changed meanwhile', job_progress($job)[0]['rollback'], 'changed_meanwhile');
expect_same('changed field stays', field(11), $own . waf_block_text('enforce') . "gzip on;\n");
expect_same('changed meanwhile in the log', strpos(job_row($job)['job_log'], 'zwischenzeitlich geändert') !== false, true);
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 11', $own . waf_block_text('detect'));

// nginx -t fails once the vhost shows the state.
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
vhost('beispiel.test', "    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n");
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] something')));
$waf->pass();
$entry = job_progress($job)[0];
expect_same('nginx -t fails', array(job_row($job)['job_status'], $entry['reason'], $entry['rollback'], $entry['detail']),
	array('error', 'nginx_test', 'rolled_back', 'nginx: [emerg] something'));
expect_same('nginx -t fails: field back', field(11), $own . waf_block_text('detect'));
vhost('beispiel.test', "    modsecurity on;\n");

// ISPConfig refused the vhost and left a .err next to it.
$job = $waf->queue('set_state', array('domain_ids' => array(12), 'state' => 'detect'), 'probe');
$waf->pass();
file_put_contents($tmp . '/vhosts/zweite.test.vhost.err', 'rejected');
$waf->pass();
expect_same('rejected by ISPConfig', array(job_progress($job)[0]['reason'], job_progress($job)[0]['rollback']), array('rejected', 'rolled_back'));
expect_same('rejected: field back', field(12), '');
unlink($tmp . '/vhosts/zweite.test.vhost.err');

$db->query('INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, sys_groupid, '
	. "nginx_directives, document_root) VALUES (13, ?, 0, 'vhost', 'fremd-server.test', 'none', 'y', 1, '', '/var/www/x')", $server + 100);
$job = $waf->queue('set_state', array('domain_ids' => array(13, 999), 'state' => 'detect'), 'probe');
$waf->pass();
$progress = job_progress($job);
expect_same('skips', array(job_row($job)['job_status'], $progress[0]['reason'], $progress[1]['reason']), array('done', 'other_server', 'not_found'));

// Exceptions.
$calls = array();
$exception = add_exception('site_path', 11, '942100', '/wp-admin/admin-ajax.php', '', 'Notiz bleibt draussen');
$job = $waf->queue('exception_add', array('exception_id' => $exception), 'probe');
$waf->pass();
$before = file_get_contents($tmp . '/waf/exclusions-panel-before.conf');
expect_same('exception done', job_row($job)['job_status'], 'done');
expect_same('exception commands', $calls, array('rules_check', 'nginx_test', 'nginx_reload', 'nginx_active'));
expect_same('exception rule id', strpos($before, '"id:' . (10200 + $exception) . ',phase:1') !== false, true);
expect_same('exception hosts', strpos($before, '^(?:alias-beispiel\.test|beispiel\.test|www\.beispiel\.test)') !== false, true);
expect_same('note stays out', strpos($before, 'Notiz'), false);
expect_same('exception active', array(exception_row($exception)['exception_state'], exception_row($exception)['activated_at'] !== null), array('active', true));
expect_same('snapshot taken', file_get_contents($tmp . '/state/waf/last-good/exclusions-panel-before.conf'), $before);

$calls = array();
$bad = add_exception('site', 11, '10010', '', '', '');
$job = $waf->queue('exception_add', array('exception_id' => $bad), 'probe');
$waf->pass();
expect_same('own rule refused', array(job_row($job)['job_status'], exception_row($bad)['exception_state'], exception_row($bad)['error_reason'], $calls),
	array('error', 'error', 'Ungültige Angabe: rule_id', array()));

$failing = add_exception('all_path', 0, '941100', '/xmlrpc.php', '', '');
$calls = array();
$answers = array('rules_check' => array(array(1, 'Rules error. File: exclusions-panel-before.conf')));
$job = $waf->queue('exception_add', array('exception_id' => $failing), 'probe');
$waf->pass();
expect_same('rules check refuses', array(job_row($job)['job_status'], $calls, exception_row($failing)['exception_state']), array('error', array('rules_check'), 'error'));
expect_same('file unchanged after the refusal', file_get_contents($tmp . '/waf/exclusions-panel-before.conf'), $before);

$db->query("UPDATE malwatch_waf_exception SET exception_state = 'removing' WHERE exception_id = ?", $exception);
$job = $waf->queue('exception_remove', array('exception_id' => $exception), 'probe');
$waf->pass();
expect_same('exception removed', array(job_row($job)['job_status'], exception_row($exception)), array('done', null));
expect_same('rule gone', strpos(file_get_contents($tmp . '/waf/exclusions-panel-before.conf'), '# exception ' . $exception . ' '), false);
$calls = array();
$job = $waf->queue('exception_remove', array('exception_id' => $bad), 'probe');
$waf->pass();
expect_same('error row removed without reload', array(job_row($job)['job_status'], exception_row($bad), $calls), array('done', null, array()));

// Emergency stop: rules off, enforcing websites back to detect.
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 12', waf_block_text('enforce'));
$job = $waf->queue('emergency', array('on' => true), 'probe');
$waf->pass();
expect_same('emergency on', array(job_row($job)['job_status'], config_value('waf_emergency'), config_value('waf_emergency_since') !== null), array('done', 'y', true));
expect_same('emergency file', waf_state_file_is_emergency(file_get_contents($tmp . '/waf/state.conf')), true);
$follow = $db->queryOneRecord("SELECT job_id, options FROM malwatch_job WHERE job_kind = 'waf' AND job_status = 'pending' ORDER BY job_id DESC LIMIT 1");
$follow_options = json_decode($follow['options'], true);
expect_same('emergency queues detect', array($follow_options['action'], $follow_options['state'], $follow_options['domain_ids']), array('set_state', 'detect', array(12)));
$waf->pass();
vhost('zweite.test', "    modsecurity on;\n");
$waf->pass();
expect_same('follow-up done', array(job_row((int) $follow['job_id'])['job_status'], field(12)), array('done', waf_block_text('detect')));
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('no enforce during the emergency', job_progress($job)[0]['reason'], 'emergency');
$job = $waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();
expect_same('emergency off', array(job_row($job)['job_status'], config_value('waf_emergency')), array('done', 'n'));
expect_same('emergency file cleared', waf_state_file_is_emergency(file_get_contents($tmp . '/waf/state.conf')), false);

// An emergency stop does not wait for a job that waits for ISPConfig.
$waiting = $waf->queue('set_state', array('domain_ids' => array(12), 'state' => 'off'), 'probe');
$waf->pass();
expect_same('job waits for ISPConfig', job_row($waiting)['job_status'], 'running');
$job = $waf->queue('emergency', array('on' => true), 'probe');
$other = $waf->queue('response_body', array('mode' => 'lean'), 'probe');
$waf->pass();
expect_same('emergency first', array(job_row($job)['job_status'], job_row($other)['job_status']), array('done', 'pending'));
vhost('zweite.test', "    listen 80;\n");
$waf->pass();
expect_same('queue moves on', array(job_row($waiting)['job_status'], job_row($other)['job_status']), array('done', 'done'));
expect_same('lean file', waf_response_body_mode(file_get_contents($tmp . '/waf/response-body.conf')), 'lean');
expect_same('lean setting', config_value('waf_response_body'), 'lean');
$calls = array();
$job = $waf->queue('response_body', array('mode' => 'lean'), 'probe');
$waf->pass();
expect_same('lean again changes nothing', array(job_row($job)['job_status'], $calls), array('done', array()));
$job = $waf->queue('response_body', array('mode' => 'halb'), 'probe');
$waf->pass();
expect_same('odd mode refused', job_row($job)['job_status'], 'error');
$waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();

$db->query('UPDATE malwatch_config SET waf_log_keep_days = 14 WHERE config_id = 1');
$calls = array();
$job = $waf->queue('apply_settings', array(), 'probe');
$waf->pass();
expect_same('settings applied', array(job_row($job)['job_status'], $calls), array('done', array('logrotate_check')));
expect_same('logrotate file', strpos(file_get_contents($tmp . '/logrotate-waf'), "\trotate 14\n") !== false, true);
$answers = array('logrotate_check' => array(array(1, 'error: bad line')));
$db->query('UPDATE malwatch_config SET waf_log_keep_days = 30 WHERE config_id = 1');
$job = $waf->queue('apply_settings', array(), 'probe');
$waf->pass();
expect_same('logrotate refuses', array(job_row($job)['job_status'], strpos(file_get_contents($tmp . '/logrotate-waf'), "\trotate 14\n") !== false), array('error', true));

// Old markers become new ones; states and files are read back.
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 12',
	"# WAF-Anfang (mitschreiben) \xE2\x80\x93 verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n");
$db->query("UPDATE malwatch_site SET waf_state = 'off' WHERE parent_domain_id = 12");
vhost('zweite.test', "    modsecurity on;\n");
file_put_contents($tmp . '/waf/response-body.conf', waf_response_body_text('full'));
$job = $waf->queue('migrate_markers', array(), 'probe');
$waf->pass();
expect_same('migrate done', job_row($job)['job_status'], 'done');
expect_same('marker rewritten', field(12), waf_block_text('detect'));
expect_same('state read back', array(site_row(12)['waf_state'], site_row(11)['waf_state']), array('detect', 'detect'));
expect_same('response body read back', config_value('waf_response_body'), 'full');

$job = $waf->execute_now('response_body', array('mode' => 'full'), 'probe');
expect_same('execute now', array($job['job_status'], strpos($job['job_log'], 'unverändert') !== false), array('done', true));

// Hard stop: include off, vhosts and fields without the module.
$calls = array();
$job = $waf->queue('emergency', array('on' => true, 'hard' => true), 'probe');
$waf->pass();
expect_same('hard stop done', array(job_row($job)['job_status'], $calls), array('done', array('nginx_test', 'nginx_reload')));
expect_same('include renamed', array(is_file($tmp . '/conf.d/waf.conf'), is_file($tmp . '/conf.d/waf.conf.off')), array(false, true));
expect_same('vhosts stripped', array(waf_vhost_state(file_get_contents($tmp . '/vhosts/beispiel.test.vhost')),
	waf_vhost_state(file_get_contents($tmp . '/vhosts/zweite.test.vhost'))), array('off', 'off'));
expect_same('fields cleared', array(field(11), field(12)), array($own, ''));
expect_same('states off', array(site_row(11)['waf_state'], site_row(12)['waf_state']), array('off', 'off'));
expect_same('emergency flag', config_value('waf_emergency'), 'y');
$job = $waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();
expect_same('no soft end of a hard stop', job_row($job)['job_status'], 'error');

// The guard.
$answers = array();
expect_same('guard fine', $waf->guard(), 0);
expect_same('guard log', strpos(file_get_contents($tmp . '/guard.log'), 'nginx -t in Ordnung.') !== false, true);
file_put_contents($tmp . '/waf/exclusions-panel-before.conf', "SecRule broken\n");
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] "modsecurity_rules_file" directive Rules error. File: '
	. $tmp . '/waf/exclusions-panel-before.conf. Line: 1.')));
$calls = array();
expect_same('guard repairs', $waf->guard(), 1);
expect_same('guard put the file back', file_get_contents($tmp . '/waf/exclusions-panel-before.conf'),
	file_get_contents($tmp . '/state/waf/last-good/exclusions-panel-before.conf'));
expect_same('guard reloads after the repair', $calls, array('nginx_test', 'nginx_test', 'nginx_reload'));
rename($tmp . '/conf.d/waf.conf.off', $tmp . '/conf.d/waf.conf');
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] unknown directive "modsecurity" in /etc/nginx/sites-enabled/100-x.vhost:3')));
expect_same('guard stops hard', $waf->guard(), 1);
expect_same('guard renamed the include', is_file($tmp . '/conf.d/waf.conf.off'), true);
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] host not found in upstream "x"')));
$calls = array();
expect_same('guard leaves other errors', array($waf->guard(), $calls), array(1, array('nginx_test')));

// A file job that is still running was cut off.
$answers = array();
$db->query('INSERT INTO malwatch_job (server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, '
	. "options, created_at, started_at) VALUES (?, 0, '', '', 'manual', 'waf', 'running', ?, NOW(), NOW())",
	$server, '{"action":"response_body","mode":"lean","user":"probe"}');
$cut = (int) $db->insertID();
$waf->pass();
expect_same('interrupted job', array(job_row($cut)['job_status'], strpos(job_row($cut)['job_log'], 'unterbrochen') !== false), array('error', true));

$waf->cron_minute();
$waf->cron_hourly();
expect_same('snapshot', $waf->snapshot(), true);
expect_same('no job left behind', count_rows("SELECT job_id FROM malwatch_job WHERE job_status IN ('pending','running')"), 0);
```

- [ ] **Schritt 2: Prüfungen laufen lassen, sie müssen scheitern**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: malwatch_plugin.inc.php laesst WAF-Auftraege nicht liegen` und die übrigen
Meldungen der Prüfung 53

Run: `php -l ispconfig/tests/waf_class_probe.php`
Expected: `No syntax errors detected` (der Lauf folgt in A9)

- [ ] **Schritt 3: Methoden der Klasse schreiben**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` unmittelbar vor der letzten
schließenden Klammer der Klasse:

`ispconfig/server/lib/classes/malwatch_waf.inc.php` (vor Klassenende):

```php
	// --- Entry points --------------------------------------------------------

	/** One cron pass: read the log, then the jobs. Skipped while another worker holds the lock. */
	public function cron_minute()
	{
		global $app;
		if (!$this->ready() || !$this->lock(false)) {
			return;
		}
		try {
			$this->ingest(array());
			$this->run_jobs();
		} catch (Throwable $e) {
			$app->log('malwatch: the WAF pass failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		} finally {
			$this->unlock();
		}
	}

	/** The hourly part of the cron. */
	public function cron_hourly()
	{
		global $app;
		if (!$this->ready() || !$this->lock(false)) {
			return;
		}
		try {
			$this->cleanup();
		} catch (Throwable $e) {
			$app->log('malwatch: the WAF cleanup failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		} finally {
			$this->unlock();
		}
	}

	/** One round of run_jobs() under the lock, for waf-switch set --wait. */
	public function pass()
	{
		if (!$this->ready() || !$this->lock(true)) {
			return;
		}
		try {
			$this->run_jobs();
		} finally {
			$this->unlock();
		}
	}

	/** Queues a WAF job for this server and returns its id. $user names the person in the action log. */
	public function queue($action, $fields, $user)
	{
		global $app, $conf;
		$options = array_merge(is_array($fields) ? $fields : array(),
			array('action' => (string) $action, 'user' => (string) $user));
		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', '', 'manual', 'waf', 'pending', ?, NOW())",
			$conf['server_id'], waf_json($options));
		return (int) $app->dbmaster->insertID();
	}

	/** Queues a job and carries it out at once under the lock; returns the job row afterwards, or null. */
	public function execute_now($action, $fields, $user)
	{
		if (!$this->ready() || !$this->lock(true)) {
			return null;
		}
		try {
			$job_id = $this->queue($action, $fields, $user);
			$this->start_job($this->job($job_id));
			return $this->job($job_id);
		} finally {
			$this->unlock();
		}
	}

	/**
	 * Works on the queue of this server: an emergency stop first, then the
	 * jobs that wait for ISPConfig, then the queued jobs one after the other
	 * as long as none of them keeps waiting. The caller holds the lock.
	 */
	public function run_jobs()
	{
		global $app, $conf;

		$pending = $this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'pending' ORDER BY job_id",
			$conf['server_id']));
		foreach ($pending as $job) {
			if ($this->job_action($job) === 'emergency') {
				$this->start_job($job);
			}
		}

		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running' ORDER BY job_id",
			$conf['server_id'])) as $job) {
			$this->continue_job($job);
		}

		foreach ($pending as $job) {
			if ($this->job_action($job) === 'emergency' || $this->running_count() > 0) {
				continue;
			}
			$this->start_job($job);
		}
	}

	/**
	 * The hourly check behind waf-guard: 0 when nginx -t passes (the jobs get
	 * their pass as well), 1 when something was found, repaired or not.
	 */
	public function guard()
	{
		if (!$this->ready()) {
			return 1;
		}
		if (!$this->lock(true)) {
			$this->guard_log('Sperre nicht erhalten, nichts geprüft.');
			return 1;
		}
		try {
			$test = $this->run_command('nginx_test', '');
			if ($test[0] === 0) {
				$this->guard_log('nginx -t in Ordnung.');
				$this->run_jobs();
				return 0;
			}
			$this->guard_log('nginx -t fehlgeschlagen: ' . preg_replace('/\s+/', ' ', $test[1]));
			$this->guard_repair($test[1]);
			return 1;
		} finally {
			$this->unlock();
		}
	}

	/** Copies the WAF directory to last-good; waf/install.sh calls it after a successful check. */
	public function snapshot()
	{
		if (!$this->ready()) {
			return false;
		}
		$settings = $this->settings();
		waf_snapshot($settings['waf_conf_dir'], $this->ensure_dirs() . '/last-good');
		return true;
	}

	// --- Jobs ----------------------------------------------------------------

	private function start_job($job)
	{
		global $app;
		if (!is_array($job)) {
			return;
		}
		$app->uses('malwatch_helper');
		if (!$app->malwatch_helper->claim_job($job['job_id'])) {
			return;
		}
		$job = $this->job($job['job_id']);
		$options = $this->job_options($job);
		switch ($this->job_action($job)) {
			case 'set_state':
				$this->start_set_state($job, $options, 'set');
				break;
			case 'migrate_markers':
				$this->start_migrate($job, $options);
				break;
			case 'exception_add':
			case 'exception_remove':
				$this->run_exception($job, $options);
				break;
			case 'emergency':
				$this->run_emergency($job, $options);
				break;
			case 'response_body':
				$this->run_response_body($job, $options);
				break;
			case 'apply_settings':
				$this->run_apply_settings($job);
				break;
			default:
				$this->finish($job, false, 'Unbekannte Aktion: ' . $this->job_action($job));
		}
	}

	private function continue_job($job)
	{
		$options = $this->job_options($job);
		if (isset($options['progress']) && is_array($options['progress'])) {
			$this->continue_set_state($job, $options);
			return;
		}
		// Every other job ends within its own pass; one that still runs was cut
		// off. nginx -t says whether the files it may have touched are sound.
		$test = $this->run_command('nginx_test', '');
		if ($test[0] !== 0) {
			$this->guard_repair($test[1]);
		}
		$this->finish($job, false, 'Der Auftrag wurde unterbrochen. '
			. ($test[0] === 0 ? 'nginx -t ist in Ordnung.' : 'nginx -t meldete einen Fehler, siehe ' . $this->paths['guard_log'] . '.'));
	}

	private function running_count()
	{
		global $app, $conf;
		$row = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running'",
			$conf['server_id']);
		return is_array($row) ? (int) $row['n'] : 0;
	}

	/** Phase one: back up and write the field of every website, then look once at the vhosts. */
	private function start_set_state($job, $options, $mode)
	{
		global $app, $conf;

		$settings = $this->settings();
		$target = isset($options['state']) ? (string) $options['state'] : '';
		$ids = isset($options['domain_ids']) && is_array($options['domain_ids']) ? $options['domain_ids'] : array();
		$now = $this->db_value('SELECT NOW() AS value');
		$options['backup_dir'] = $this->backup_dir($job);
		$options['progress'] = array();

		foreach (array_values(array_unique(array_map('intval', $ids))) as $id) {
			$web = $app->dbmaster->queryOneRecord(
				'SELECT domain_id, domain, type, server_id, sys_groupid, nginx_directives FROM web_domain WHERE domain_id = ?', $id);
			$site = $app->dbmaster->queryOneRecord(
				'SELECT waf_state, waf_state_since FROM malwatch_site WHERE parent_domain_id = ?', $id);
			$domain = is_array($web) ? (string) $web['domain'] : '#' . $id;
			$plan = waf_site_plan($web, $site, $target, $mode, $conf['server_id'],
				is_array($web) ? $this->vhost_state($domain) : 'off', $now, $settings);
			$entry = array('domain_id' => $id, 'domain' => $domain, 'target' => $plan['target'], 'status' => 'waiting',
				'reason' => $plan['reason'], 'backup' => '', 'written_hash' => '', 'rollback' => '', 'detail' => '');

			if ($plan['action'] === 'skip') {
				$entry['status'] = 'skipped';
			} elseif ($plan['action'] === 'confirm') {
				if ($plan['target'] !== 'off') {
					$this->ensure_site_row($web);
				}
				$this->confirm_site($id, $plan['target'], $job);
				$entry['status'] = 'confirmed';
			} else {
				$this->ensure_site_row($web);
				if ($plan['action'] === 'write') {
					$entry['backup'] = $this->backup_field($options['backup_dir'], $domain, (string) $web['nginx_directives']);
					if ($entry['backup'] === '') {
						$entry['status'] = 'failed';
						$entry['reason'] = 'backup';
					} else {
						$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $plan['text']), 'domain_id', $id);
					}
				}
				if ($entry['status'] === 'waiting') {
					$entry['written_hash'] = sha1($plan['text']);
					$app->dbmaster->query('UPDATE malwatch_site SET waf_pending_state = ?, waf_job_id = ? WHERE parent_domain_id = ?',
						$plan['target'], (int) $job['job_id'], $id);
				}
			}
			$options['progress'][] = $entry;
			// Saved after every website: a job cut off here still knows what it wrote.
			$this->save_options($job, $options);
		}
		$this->save_options($job, $options);
		$this->continue_set_state($job, $options);
	}

	/** Phase two: which vhosts show their state, which ran out of time; one nginx -t for all confirmations. */
	private function continue_set_state($job, $options)
	{
		global $app;

		$settings = $this->settings();
		$row = $app->dbmaster->queryOneRecord(
			'SELECT UNIX_TIMESTAMP(started_at) AS started, '
			. '(started_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)) AS overdue FROM malwatch_job WHERE job_id = ?',
			$settings['waf_job_deadline_minutes'], (int) $job['job_id']);
		$started = is_array($row) ? (int) $row['started'] : time();
		$overdue = is_array($row) && (int) $row['overdue'] === 1;

		$confirmed = array();
		$waiting = 0;
		foreach ($options['progress'] as $i => $entry) {
			if ($entry['status'] !== 'waiting') {
				continue;
			}
			$file = $this->vhost_file($entry['domain']);
			clearstatcache();
			$rejected = is_file($file . '.err') && filemtime($file . '.err') >= $started;
			$state = waf_site_progress($entry, $this->vhost_state($entry['domain']), $rejected, $overdue);
			if ($state === 'waiting') {
				$waiting++;
			} elseif ($state === 'confirmed') {
				$confirmed[] = $i;
			} else {
				$options['progress'][$i] = $this->fail_site($entry, substr($state, 7), '');
			}
		}

		if (count($confirmed) > 0) {
			$test = $this->run_command('nginx_test', '');
			foreach ($confirmed as $i) {
				$entry = $options['progress'][$i];
				if ($test[0] === 0) {
					$entry['status'] = 'confirmed';
					$this->confirm_site($entry['domain_id'], $entry['target'], $job);
					$options['progress'][$i] = $entry;
				} else {
					$options['progress'][$i] = $this->fail_site($entry, 'nginx_test', $test[1]);
				}
			}
		}
		$this->save_options($job, $options);
		if ($waiting === 0) {
			$this->finish_set_state($job, $options);
		}
	}

	private function finish_set_state($job, $options)
	{
		$lines = array();
		$ok = true;
		foreach ($options['progress'] as $entry) {
			$lines[] = $entry['domain'] . ': ' . $this->entry_text($entry);
			if ($entry['status'] === 'failed') {
				$ok = false;
			}
		}
		if (count($lines) === 0) {
			$lines[] = 'Keine Website betroffen.';
		}
		$this->finish($job, $ok, implode("\n", $lines));
	}

	/** Marks a website as failed and puts its field back where that is safe. */
	private function fail_site($entry, $reason, $detail)
	{
		global $app;
		$entry['status'] = 'failed';
		$entry['reason'] = $reason;
		$entry['detail'] = waf_cut($detail, 500);
		$app->dbmaster->query("UPDATE malwatch_site SET waf_pending_state = '' WHERE parent_domain_id = ?", (int) $entry['domain_id']);
		if ($entry['backup'] === '' || !is_file($entry['backup'])) {
			$entry['rollback'] = 'not_written';
			return $entry;
		}
		$web = $app->dbmaster->queryOneRecord('SELECT nginx_directives FROM web_domain WHERE domain_id = ?', (int) $entry['domain_id']);
		if (!is_array($web) || !waf_rollback_allowed((string) $web['nginx_directives'], $entry['written_hash'])) {
			$entry['rollback'] = 'changed_meanwhile';
			return $entry;
		}
		$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => (string) file_get_contents($entry['backup'])),
			'domain_id', (int) $entry['domain_id']);
		$entry['rollback'] = 'rolled_back';
		return $entry;
	}

	/** The confirmed state; since stays when the state does not change. */
	private function confirm_site($domain_id, $target, $job)
	{
		global $app;
		$app->dbmaster->query(
			'UPDATE malwatch_site SET waf_state_since = IF(waf_state = ? AND waf_state_since IS NOT NULL, waf_state_since, NOW()), '
			. "waf_state = ?, waf_pending_state = '', waf_job_id = ? WHERE parent_domain_id = ?",
			$target, $target, (int) $job['job_id'], (int) $domain_id);
	}

	/**
	 * Rewrites old markers and brings malwatch_site in line with the fields:
	 * every website with a block, or with a state on record, keeps the state
	 * its field names. Response body and emergency flag are read back from
	 * their files.
	 */
	private function start_migrate($job, $options)
	{
		global $app, $conf;

		$settings = $this->settings();
		$mode = waf_response_body_mode((string) @file_get_contents($settings['waf_conf_dir'] . '/response-body.conf'));
		$app->dbmaster->query('UPDATE malwatch_config SET waf_response_body = ? WHERE config_id = 1', $mode);
		$emergency = waf_state_file_is_emergency((string) @file_get_contents($settings['waf_conf_dir'] . '/state.conf'))
			|| is_file($this->paths['conf_include'] . '.off');
		if ($emergency !== ($settings['waf_emergency'] === 'y')) {
			$app->dbmaster->query('UPDATE malwatch_config SET waf_emergency = ?, waf_emergency_since = '
				. ($emergency ? 'NOW()' : 'NULL') . ' WHERE config_id = 1', $emergency ? 'y' : 'n');
		}

		$ids = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT w.domain_id FROM web_domain w LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id '
			. "WHERE w.server_id = ? AND w.type = 'vhost' AND (w.nginx_directives LIKE ? OR s.waf_state IN ('detect','enforce'))",
			$conf['server_id'], '%# WAF-%')) as $row) {
			$ids[] = (int) $row['domain_id'];
		}
		$options['domain_ids'] = $ids;
		$options['state'] = '';
		$this->start_set_state($job, $options, 'keep');
	}

	/** Adds or removes one exception: both panel rule files are written from the active rows and this one. */
	private function run_exception($job, $options)
	{
		global $app, $conf;

		$id = isset($options['exception_id']) ? (int) $options['exception_id'] : 0;
		$remove = $this->job_action($job) === 'exception_remove';
		$row = $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_waf_exception WHERE exception_id = ?', $id);
		if (!is_array($row)) {
			return $this->finish($job, false, 'Die Ausnahme ' . $id . ' gibt es nicht mehr.');
		}
		$reason = $remove ? '' : waf_exception_check($row);
		if ($reason !== '') {
			$this->set_exception($id, 'error', 'Ungültige Angabe: ' . $reason, $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ' abgewiesen, ungültige Angabe: ' . $reason . '. Keine Datei geändert.');
		}

		$rows = $this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_waf_exception WHERE server_id = ? AND exception_state = 'active' AND exception_id != ?",
			$conf['server_id'], $id));
		if (!$remove) {
			$row['exception_state'] = 'pending';
			$rows[] = $row;
		}
		$map = waf_host_map($this->web_rows());
		$hosts = array();
		foreach ($rows as $exception) {
			$site = (int) $exception['parent_domain_id'];
			if ($site > 0 && !isset($hosts[$site])) {
				$hosts[$site] = waf_hosts_of($map, $site);
			}
		}
		$rules = waf_exception_rules($rows, $hosts);
		if (!$remove && isset($rules['skipped'][$id])) {
			$this->set_exception($id, 'error', 'Nicht übernommen: ' . $rules['skipped'][$id], $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ' nicht übernommen: ' . $rules['skipped'][$id] . '. Keine Datei geändert.');
		}

		$result = $this->apply(array(
			'exclusions-panel-before.conf' => $rules['before'],
			'exclusions-panel-after.conf' => $rules['after'],
		), $job);
		if (!$result['ok']) {
			$text = $this->apply_text($result);
			$this->set_exception($id, $remove ? 'active' : 'error', ($remove ? 'Entfernen gescheitert: ' : '') . $text, $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ': ' . $text);
		}
		if ($remove) {
			$app->dbmaster->query('DELETE FROM malwatch_waf_exception WHERE exception_id = ?', $id);
			return $this->finish($job, true, 'Ausnahme ' . $id . ' entfernt. ' . $this->apply_text($result));
		}
		$app->dbmaster->query("UPDATE malwatch_waf_exception SET exception_state = 'active', error_reason = '', "
			. 'activated_at = NOW(), job_id = ? WHERE exception_id = ?', (int) $job['job_id'], $id);
		return $this->finish($job, true, 'Ausnahme ' . $id . ' aktiv. ' . $this->apply_text($result));
	}

	private function set_exception($id, $state, $reason, $job)
	{
		global $app;
		$app->dbmaster->query('UPDATE malwatch_waf_exception SET exception_state = ?, error_reason = ?, job_id = ? WHERE exception_id = ?',
			$state, waf_cut($reason, 255), (int) $job['job_id'], (int) $id);
	}

	/** The soft emergency stop through state.conf; enforcing websites follow with a job of their own. */
	private function run_emergency($job, $options)
	{
		global $app;
		if (!empty($options['hard'])) {
			return $this->run_hard_stop($job);
		}
		$on = !empty($options['on']);
		if (!$on && is_file($this->paths['conf_include'] . '.off')) {
			return $this->finish($job, false, 'Der harte Notaus ist aktiv. Wieder eingeschaltet wird über waf/install.sh.');
		}
		$result = $this->apply(array('state.conf' => waf_state_file_text($on)), $job);
		if (!$result['ok']) {
			return $this->finish($job, false, ($on ? 'Notaus' : 'Ende des Notaus') . ' gescheitert: ' . $this->apply_text($result));
		}
		if (!$on) {
			$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'n', waf_emergency_since = NULL WHERE config_id = 1");
			return $this->finish($job, true, 'Notaus beendet. ' . $this->apply_text($result));
		}
		$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'y', "
			. 'waf_emergency_since = IFNULL(waf_emergency_since, NOW()) WHERE config_id = 1');
		$ids = $this->enforcing_sites();
		if (count($ids) > 0) {
			$this->queue('set_state', array('domain_ids' => $ids, 'state' => 'detect'), $this->job_user($job));
		}
		return $this->finish($job, true, 'Notaus aktiv, die Regeln prüfen nicht mehr. ' . $this->apply_text($result)
			. (count($ids) > 0 ? ' ' . count($ids) . ' Websites wechseln von scharf auf mitschreiben.' : ''));
	}

	/**
	 * The hard emergency stop, for an nginx that lost the module: the include
	 * goes to waf.conf.off, every vhost file loses its modsecurity lines,
	 * every field its block, then one nginx -t and one reload. The vhost files
	 * are edited directly because ISPConfig tests nginx before it keeps a
	 * vhost, and that test fails while any file still names the module.
	 * waf/install.sh switches the rules back on.
	 */
	private function run_hard_stop($job)
	{
		global $app, $conf;

		$lines = array();
		$backup = $this->backup_dir($job);
		@mkdir($backup, 0700, true);

		$include = $this->paths['conf_include'];
		if (is_file($include)) {
			@copy($include, $backup . '/' . basename($include));
			$lines[] = @rename($include, $include . '.off')
				? 'Regeln ausgehängt: ' . $include . '.off'
				: 'Die Einbindung ' . $include . ' ließ sich nicht umbenennen.';
		}

		$files = glob($this->vhost_dir() . '/*.vhost');
		foreach (is_array($files) ? $files : array() as $file) {
			if (is_link($file) || !is_file($file)) {
				continue;
			}
			$stripped = waf_vhost_strip((string) file_get_contents($file));
			if ($stripped[1] === 0) {
				continue;
			}
			@copy($file, $backup . '/' . basename($file));
			waf_write_atomic($file, $stripped[0]);
			$lines[] = basename($file) . ': ' . $stripped[1] . ' Zeilen entfernt';
		}

		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT domain_id, domain, nginx_directives FROM web_domain WHERE server_id = ? AND type = 'vhost' AND nginx_directives LIKE ?",
			$conf['server_id'], '%# WAF-%')) as $row) {
			$old = (string) $row['nginx_directives'];
			$new = waf_block_set($old, 'off');
			if ($new !== $old) {
				$this->backup_field($backup, (string) $row['domain'], $old);
				$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $new), 'domain_id', (int) $row['domain_id']);
			}
		}
		$app->dbmaster->query("UPDATE malwatch_site SET waf_state_since = IF(waf_state = 'off', waf_state_since, NOW()), "
			. "waf_state = 'off', waf_pending_state = '' WHERE server_id = ?", $conf['server_id']);
		$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'y', "
			. 'waf_emergency_since = IFNULL(waf_emergency_since, NOW()) WHERE config_id = 1');

		$test = $this->run_command('nginx_test', '');
		if ($test[0] !== 0) {
			$lines[] = 'nginx -t meldet weiter einen Fehler, kein Reload: ' . waf_cut($test[1], 500);
			return $this->finish($job, false, implode("\n", $lines));
		}
		$this->run_command('nginx_reload', '');
		$lines[] = 'nginx -t in Ordnung, nginx neu geladen. Sicherungen: ' . $backup
			. '. Wieder eingeschaltet wird über waf/install.sh.';
		return $this->finish($job, true, implode("\n", $lines));
	}

	private function enforcing_sites()
	{
		global $app, $conf;
		$ids = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT domain_id, nginx_directives FROM web_domain WHERE server_id = ? AND type = 'vhost'",
			$conf['server_id'])) as $row) {
			if (waf_block_state((string) $row['nginx_directives']) === 'enforce') {
				$ids[] = (int) $row['domain_id'];
			}
		}
		return $ids;
	}

	private function run_response_body($job, $options)
	{
		global $app;
		$mode = isset($options['mode']) ? (string) $options['mode'] : '';
		if (!waf_response_body_valid($mode)) {
			return $this->finish($job, false, 'Unbekannter Modus der Seitenantwort: ' . $mode);
		}
		$result = $this->apply(array('response-body.conf' => waf_response_body_text($mode)), $job);
		if (!$result['ok']) {
			return $this->finish($job, false, 'Seitenantwort nicht umgestellt: ' . $this->apply_text($result));
		}
		$app->dbmaster->query('UPDATE malwatch_config SET waf_response_body = ? WHERE config_id = 1', $mode);
		return $this->finish($job, true, 'Seitenantwort im Audit-Log: ' . ($mode === 'lean' ? 'schlank' : 'vollständig')
			. '. ' . $this->apply_text($result));
	}

	/** Writes the logrotate file from the settings; the other settings act without a file. */
	private function run_apply_settings($job)
	{
		$settings = $this->settings();
		$file = $this->paths['logrotate'];
		$text = waf_logrotate_text($settings['waf_log_keep_days'], $settings['waf_audit_log']);
		if (is_file($file) && (string) file_get_contents($file) === $text) {
			return $this->finish($job, true, 'Einstellungen übernommen, logrotate unverändert.');
		}
		$check = $this->ensure_dirs() . '/staging/' . (int) $job['job_id'] . '-logrotate';
		file_put_contents($check, $text);
		@chmod($check, 0644);
		$result = $this->run_command('logrotate_check', $check);
		@unlink($check);
		if ($result[0] !== 0) {
			return $this->finish($job, false, 'logrotate lehnt die Datei ab, nichts geändert: ' . waf_cut($result[1], 500));
		}
		if (!waf_write_atomic($file, $text)) {
			return $this->finish($job, false, $file . ' ließ sich nicht schreiben.');
		}
		return $this->finish($job, true, 'Einstellungen übernommen, logrotate behält '
			. $settings['waf_log_keep_days'] . ' Stände.');
	}

	/** Takes the WAF out of a failing nginx -t as far as the output points at it. The caller holds the lock. */
	private function guard_repair($output)
	{
		$settings = $this->settings();
		if (preg_match('/unknown directive "modsecurity/i', $output)) {
			$this->guard_log('Das Modul fehlt: Notaus hart.');
			$job_id = $this->queue('emergency', array('on' => true, 'hard' => true), 'waf-guard');
			$this->start_job($this->job($job_id));
			$job = $this->job($job_id);
			$this->guard_log('Notaus hart: ' . (is_array($job)
				? $job['job_status'] . ', ' . preg_replace('/\s+/', ' ', (string) $job['job_log']) : 'kein Auftrag'));
			return;
		}
		if (strpos($output, $settings['waf_conf_dir'] . '/') === false && stripos($output, 'modsecurity') === false) {
			$this->guard_log('Kein Bezug zur WAF, nichts unternommen.');
			return;
		}
		$restored = waf_restore_snapshot($this->ensure_dirs() . '/last-good', $settings['waf_conf_dir']);
		$this->guard_log('Letzter geprüfter Stand zurückgelegt: '
			. (count($restored) > 0 ? implode(', ', $restored) : 'keine Abweichung'));
		$again = $this->run_command('nginx_test', '');
		if ($again[0] === 0) {
			$this->run_command('nginx_reload', '');
			$this->guard_log('nginx -t wieder in Ordnung, nginx neu geladen.');
		} else {
			$this->guard_log('Fehler bleibt bestehen, Eingriff nötig: ' . preg_replace('/\s+/', ' ', $again[1]));
		}
	}

	private function guard_log($text)
	{
		@file_put_contents($this->paths['guard_log'], date('Y-m-d H:i:s') . ' ' . $text . "\n", FILE_APPEND);
	}

	// --- Job helpers ---------------------------------------------------------

	/** Ends a job and leaves one line in the action log: person, action, result. */
	private function finish($job, $ok, $log)
	{
		global $app, $conf;
		$app->dbmaster->query('UPDATE malwatch_job SET job_status = ?, finished_at = NOW(), job_log = ? WHERE job_id = ?',
			$ok ? 'done' : 'error', waf_cut($log, 60000), (int) $job['job_id']);
		$app->dbmaster->query(
			'INSERT INTO malwatch_action_log (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_id, action_type, trigger_severity, trigger_findings, '
			. 'recipient, detail, created_at) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', 0, 'waf', '', 0, '', ?, NOW())",
			$conf['server_id'], waf_cut($this->job_user($job) . ': ' . $this->job_action($job) . ' '
				. ($ok ? 'erledigt' : 'gescheitert') . "\n" . $log, 60000));
		return $ok;
	}

	private function apply($changes, $job)
	{
		$settings = $this->settings();
		$base = $this->ensure_dirs();
		$waf = $this;
		return waf_apply_files(array(
			'conf_dir' => $settings['waf_conf_dir'],
			'staging' => $base . '/staging/' . (int) $job['job_id'],
			'last_good' => $base . '/last-good',
		), $changes, function ($name, $argument) use ($waf) {
			return $waf->run_command($name, $argument);
		});
	}

	private function apply_text($result)
	{
		$texts = array(
			'' => 'nginx neu geladen.',
			'unchanged' => 'Dateien unverändert, kein Reload.',
			'bad_name' => 'Ungültiger Dateiname, nichts geändert',
			'missing_file' => 'Datei fehlt, erst waf/install.sh ausführen',
			'staging' => 'Arbeitsverzeichnis ließ sich nicht anlegen, nichts geändert',
			'rules_check' => 'Regelprüfung fehlgeschlagen, nichts geändert',
			'nginx_test' => 'nginx -t fehlgeschlagen, alte Dateien zurück, kein Reload',
			'nginx_reload' => 'Reload fehlgeschlagen, alte Dateien zurück',
			'nginx_inactive' => 'nginx lief nach dem Reload nicht, alte Dateien zurück und Start versucht',
		);
		$text = isset($texts[$result['reason']]) ? $texts[$result['reason']] : $result['reason'];
		return $result['detail'] !== '' ? $text . ': ' . $result['detail'] : $text;
	}

	/** One German line per website for job_log. */
	private function entry_text($entry)
	{
		$states = array('off' => 'aus', 'detect' => 'mitschreiben', 'enforce' => 'scharf');
		$reasons = array(
			'not_found' => 'keine Website mit dieser Nummer',
			'other_server' => 'die Website liegt auf einem anderen Server',
			'state' => 'unbekannter Zustand',
			'emergency' => 'der Notaus ist aktiv',
			'not_detect' => 'die Website schreibt noch nicht mit',
			'too_early' => 'die Website schreibt noch nicht lange genug mit',
			'backup' => 'das Feld ließ sich nicht sichern',
			'rejected' => 'ISPConfig hat den vhost verworfen',
			'deadline' => 'der vhost zeigte den Zustand nicht innerhalb der Frist',
			'nginx_test' => 'nginx -t schlug fehl',
		);
		$rollbacks = array(
			'rolled_back' => 'altes Feld zurückgeschrieben',
			'changed_meanwhile' => 'Feld wurde zwischenzeitlich geändert, keine Rücknahme',
			'not_written' => 'Feld war unverändert',
		);
		$state = isset($states[$entry['target']]) ? $states[$entry['target']] : $entry['target'];
		$reason = isset($reasons[$entry['reason']]) ? $reasons[$entry['reason']] : $entry['reason'];
		if ($entry['status'] === 'confirmed') {
			return $state . ' bestätigt';
		}
		if ($entry['status'] === 'skipped') {
			return 'übersprungen, ' . $reason;
		}
		if ($entry['status'] === 'failed') {
			$text = $state . ' gescheitert, ' . $reason;
			if ($entry['rollback'] !== '') {
				$text .= '; ' . (isset($rollbacks[$entry['rollback']]) ? $rollbacks[$entry['rollback']] : $entry['rollback']);
			}
			return $entry['detail'] !== '' ? $text . ' (' . $entry['detail'] . ')' : $text;
		}
		return $state . ' wartet auf ISPConfig';
	}

	private function ensure_site_row($web)
	{
		global $app;
		$app->dbmaster->query(
			'INSERT IGNORE INTO malwatch_site (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. "server_id, parent_domain_id, domain) VALUES (1, ?, 'riud', 'riud', '', ?, ?, ?)",
			(int) $web['sys_groupid'], (int) $web['server_id'], (int) $web['domain_id'], (string) $web['domain']);
	}

	/** Saves the field of one website below the job's backup directory; returns the file or ''. */
	private function backup_field($dir, $domain, $text)
	{
		if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
			return '';
		}
		$file = $dir . '/' . preg_replace('/[^A-Za-z0-9._-]/', '_', $domain) . '.txt';
		if (@file_put_contents($file, $text) === false) {
			return '';
		}
		@chmod($file, 0600);
		return $file;
	}

	private function backup_dir($job)
	{
		return rtrim($this->paths['backup_dir'], '/') . '/'
			. $this->db_value("SELECT DATE_FORMAT(NOW(), '%Y%m%d-%H%i%s') AS value") . '-job' . (int) $job['job_id'];
	}

	private function job_options($job)
	{
		$options = is_array($job) ? json_decode((string) $job['options'], true) : null;
		return is_array($options) ? $options : array();
	}

	private function job_action($job)
	{
		$options = $this->job_options($job);
		return isset($options['action']) ? (string) $options['action'] : '';
	}

	private function job_user($job)
	{
		$options = $this->job_options($job);
		return isset($options['user']) && $options['user'] !== '' ? (string) $options['user'] : 'unbekannt';
	}

	private function save_options($job, $options)
	{
		global $app;
		$app->dbmaster->query('UPDATE malwatch_job SET options = ? WHERE job_id = ?', waf_json($options), (int) $job['job_id']);
	}

	private function db_value($sql)
	{
		global $app;
		$row = $app->dbmaster->queryOneRecord($sql);
		return is_array($row) ? (string) $row['value'] : '';
	}
```

- [ ] **Schritt 4: Cron, Helfer und Plugin anbinden**

`ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php`:

1. In `onRunJob()` wird
   `$app->uses('malwatch_helper,malwatch_runner,malwatch_ingest,malwatch_actions,getconf');`
   zu
   `$app->uses('malwatch_helper,malwatch_runner,malwatch_ingest,malwatch_actions,malwatch_waf,getconf');`
2. In `onRunJob()` direkt vor dem Block, der `$this->start_pending($config);` aufruft:

```php
		// The WAF part reads its log and works on its own jobs, under its own
		// lock; see malwatch_waf. The runner never starts one of them.
		try {
			$app->malwatch_waf->cron_minute();
		} catch (Exception $e) {
			$app->log('malwatch: the WAF pass failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		}

```

3. In `collect_finished()` wird
   `"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'running' ORDER BY job_id ASC LIMIT 20"`
   zu
   `"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_kind != 'waf' ORDER BY job_id ASC LIMIT 20"`
4. In `start_pending()` wird `$this->start_jobs($config, "job_kind != 'vulncheck'", $limit - $running);`
   zu `$this->start_jobs($config, "job_kind NOT IN ('vulncheck','waf')", $limit - $running);`
5. In `housekeeping()` wird
   `"SELECT job_id, pid, domain, result_file FROM malwatch_job WHERE server_id = ? AND job_status = 'running' "`
   zu
   `"SELECT job_id, pid, domain, result_file FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_kind != 'waf' "`
6. In `housekeeping()` direkt nach `$this->collect_databases($config);`:

```php
		// Hits and day figures of the WAF past their time; see malwatch_waf::cleanup().
		$app->malwatch_waf->cron_hourly();
```

`ispconfig/server/lib/classes/malwatch_helper.inc.php`, in `count_running_jobs()`:

```php
		$kind_sql = $kind === 'vulncheck' ? "job_kind = 'vulncheck'" : "job_kind != 'vulncheck'";
```

wird zu

```php
		// WAF jobs take no slot at all: the cron works on them itself.
		$kind_sql = $kind === 'vulncheck' ? "job_kind = 'vulncheck'" : "job_kind NOT IN ('vulncheck','waf')";
```

`ispconfig/server/plugins/malwatch_plugin.inc.php`, in `job_insert()` direkt nach

```php
		if (!is_array($job) || $job['job_status'] !== 'pending') {
			return;
		}
```

einfügen:

```php

		// WAF jobs belong to the cron (malwatch_waf::run_jobs); the runner has
		// nothing to start for them.
		if (isset($job['job_kind']) && $job['job_kind'] === 'waf') {
			return;
		}
```

- [ ] **Schritt 5: Prüfen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php && php -l ispconfig/server/lib/classes/malwatch_helper.inc.php && php -l ispconfig/server/plugins/malwatch_plugin.inc.php && php -l ispconfig/tests/waf_class_probe.php`
Expected: fünfmal `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [ ] **Schritt 6: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_class_probe.php ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php ispconfig/server/lib/classes/malwatch_helper.inc.php ispconfig/server/plugins/malwatch_plugin.inc.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): WAF jobs, guard and the cron hook" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A8: Werkzeuge, Dateien und Umstellung unter `waf/`

`waf-switch`, `waf-guard` und `waf-report` ersetzen die ersten Werkzeuge und rufen die
Klasse und die gemeinsamen Funktionen auf. Die Dateien unter `waf/conf/` tragen die
neuen Namen; wo die Funktionen einen Text erzeugen, prüft der Test, dass die
mitgelieferte Datei genau diesem Text entspricht. `install.sh` stellt einen Server mit den
alten Namen um und darf beliebig oft laufen.

**Dateien:**
- Ändern: `ispconfig/tests/waf_lib_test.php` (Abschnitt A8)
- Ändern: `ispconfig/tests/check_wiring.sh` (Prüfung 54)
- Neu: `waf/conf/settings.conf`, `waf/conf/crs-extra.conf`, `waf/conf/exclusions-before.conf`,
  `waf/conf/exclusions-after.conf`, `waf/conf/exclusions-panel-before.conf`,
  `waf/conf/exclusions-panel-after.conf`, `waf/conf/response-body.conf`, `waf/conf/state.conf`
- Ändern: `waf/conf/main.conf`, `waf/conf/waf.conf`, `waf/conf/logrotate-waf`
- Neu: `waf/waf-switch`, `waf/waf-guard`, `waf/waf-report`, `ispconfig/tests/waf_ingest_dryrun.php`
- Ersetzen: `waf/install.sh`, `waf/README.md`
- Entfernen: `waf/waf-schalter`, `waf/waf-wache`, `waf/waf-bericht`, `waf/lib/`, `waf/tests/`,
  `waf/conf/einstellungen.conf`, `waf/conf/crs-zusatz.conf`, `waf/conf/ausnahmen-vorher.conf`,
  `waf/conf/ausnahmen-nachher.conf`, `waf/conf/zustand.conf`, `waf/conf/antwortrumpf.conf`
- Ändern: `.github/workflows/ci.yml`

**Schnittstellen:**
- Nutzt: die öffentlichen Methoden aus A6 und A7, die Funktionen aus A1 bis A4
- Liefert: `/usr/local/sbin/waf-switch` mit den Befehlen `status`, `set`, `probe`,
  `emergency`, `response-body`, `restore`, `jobs`, `exception list|add|remove`, `ingest`,
  `migrate`, `snapshot`, `guard`;
  `/usr/local/sbin/waf-guard` (Rückgabe 0 oder 1); `/usr/local/sbin/waf-report [log]`.
  `waf-report` liest die Bibliothek aus `$MALWATCH_WAF_LIB`, wenn die Variable gesetzt ist.

- [ ] **Schritt 1: Test und Prüfung schreiben**

`ispconfig/tests/waf_lib_test.php` (Abschnitt vor summary):

```php
// --- A8: shipped files match what the functions write ------------------------

$shipped = __DIR__ . '/../../waf/conf';
$panel = waf_exception_rules(array(), array());
expect_same('shipped panel before', file_get_contents($shipped . '/exclusions-panel-before.conf'), $panel['before']);
expect_same('shipped panel after', file_get_contents($shipped . '/exclusions-panel-after.conf'), $panel['after']);
expect_same('shipped response body', file_get_contents($shipped . '/response-body.conf'), waf_response_body_text('full'));
expect_same('shipped state', file_get_contents($shipped . '/state.conf'), waf_state_file_text(false));
expect_same('shipped logrotate', file_get_contents($shipped . '/logrotate-waf'), waf_logrotate_text(7, '/var/log/waf/audit.log'));
$main = file_get_contents($shipped . '/main.conf');
foreach (array('settings', 'crs-extra', 'exclusions-before', 'exclusions-panel-before', 'exclusions-after',
	'exclusions-panel-after', 'response-body', 'state') as $name) {
	expect_same('main includes ' . $name, strpos($main, "Include /etc/nginx/waf/$name.conf\n") !== false, true);
}
$crs = strpos($main, 'Include /usr/share/modsecurity-crs/rules/*.conf');
expect_same('runtime exclusions before the CRS rules', strpos($main, 'exclusions-panel-before.conf') < $crs, true);
expect_same('configure-time exclusions after the CRS rules', strpos($main, 'exclusions-panel-after.conf') > $crs, true);
expect_same('state comes last', substr(rtrim($main), -strlen('state.conf')), 'state.conf');
```

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 54. Die Werkzeuge unter waf/ tragen die neuen Namen und nutzen die
#     gemeinsame Bibliothek. Die alten Namen stehen nur noch dort, wo
#     install.sh umstellt und README.md davon erzaehlt.
waf_dir="$root/../waf"
if [ -d "$waf_dir" ]; then
	for f in waf-switch waf-guard waf-report install.sh README.md conf/main.conf conf/waf.conf \
		conf/settings.conf conf/crs-extra.conf conf/exclusions-before.conf conf/exclusions-after.conf \
		conf/exclusions-panel-before.conf conf/exclusions-panel-after.conf conf/response-body.conf \
		conf/state.conf conf/logrotate-waf; do
		[ -f "$waf_dir/$f" ] || fail "waf/$f fehlt"
	done
	for f in waf-schalter waf-wache waf-bericht lib tests conf/einstellungen.conf conf/crs-zusatz.conf \
		conf/ausnahmen-vorher.conf conf/ausnahmen-nachher.conf conf/zustand.conf conf/antwortrumpf.conf; do
		if [ -e "$waf_dir/$f" ]; then
			fail "waf/$f gibt es noch; die Umstellung ersetzt die alten Namen"
		fi
	done
	grep -q 'malwatch_waf_lib.inc.php' "$waf_dir/waf-report" \
		|| fail "waf-report bindet malwatch_waf_lib.inc.php nicht ein"
	grep -q "uses('malwatch_helper,malwatch_waf')" "$waf_dir/waf-switch" \
		|| fail "waf-switch laedt malwatch_waf nicht"
	if grep -rlE 'einstellungen\.conf|zustand\.conf|antwortrumpf|waf-schalter|waf-wache|waf-bericht' "$waf_dir" \
		| grep -vE '/(install\.sh|README\.md)$' | grep -q .; then
		fail "unter waf/ nennt eine Datei ausser install.sh und README.md noch alte Namen"
	fi
fi
```

- [ ] **Schritt 2: Test und Prüfung laufen lassen, sie müssen scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `FAIL shipped panel before …` (die Datei fehlt noch), Rückgabewert 1

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: waf/waf-switch fehlt` und weitere Meldungen der Prüfung 54

- [ ] **Schritt 3: Dateien unter `waf/conf/` anlegen**

`waf/conf/main.conf`:

```text
Include /etc/nginx/modsecurity.conf
Include /etc/nginx/waf/settings.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/nginx/waf/crs-extra.conf
Include /etc/nginx/waf/exclusions-before.conf
Include /etc/nginx/waf/exclusions-panel-before.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/nginx/waf/exclusions-after.conf
Include /etc/nginx/waf/exclusions-panel-after.conf
Include /etc/nginx/waf/response-body.conf
Include /etc/nginx/waf/state.conf
```

`waf/conf/waf.conf`:

```text
# Loads the rules once for every server block; each website switches them on in its vhost.
modsecurity_rules_file /etc/nginx/waf/main.conf;
```

`waf/conf/settings.conf`:

```text
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

`waf/conf/crs-extra.conf`:

```text
# CRS 3.3: switch on the WordPress exclusions (REQUEST-903.9002).
SecAction "id:10100,phase:1,pass,nolog,setvar:tx.crs_exclusions_wordpress=1"
```

`waf/conf/exclusions-before.conf`:

```text
# The server's own requests, mostly wp-cron through the OPNsense
SecRule REMOTE_ADDR "@ipMatch 10.50.0.11" \
    "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"

# Login paths: the request body stays out of the audit log
SecRule REQUEST_FILENAME "@rx (?i)(wp-login\.php|xmlrpc\.php|/wp-json/[^?]*(users|application-passwords))" \
    "id:10010,phase:1,pass,nolog,ctl:auditLogParts=-C"

# Uploads: the request body stays out of the audit log
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \
    "id:10011,phase:1,pass,nolog,ctl:auditLogParts=-C"
```

`waf/conf/exclusions-after.conf`:

```text
# Configure-time exclusions for every website, maintained by hand in the
# repository (waf/conf). Exceptions from the panel live in
# exclusions-panel-after.conf. Own rule ids: 10000 to 10199.
```

`waf/conf/exclusions-panel-before.conf`:

```text
# Managed by malwatch (page Abwehr). Every change here is overwritten.
# Included before the CRS rules: runtime exclusions (ctl).
```

`waf/conf/exclusions-panel-after.conf`:

```text
# Managed by malwatch (page Abwehr). Every change here is overwritten.
# Included after the CRS rules: exclusions for every website.
```

`waf/conf/response-body.conf`:

```text
# Response body in the audit log: full
# Managed by malwatch (page Abwehr, waf-switch response-body). Do not edit.
#
# full: CRS rules may write the whole response into the entry. 110 rules set
#       ctl:auditLogParts=+E; a hit then weighs about 125 KB instead of about 4 KB.
# lean: a phase 5 rule takes the response back out after every CRS rule ran.
#       Matches, headers and the request body stay complete.
```

`waf/conf/state.conf`:

```text
# Emergency switch. Empty in normal operation; the emergency stop writes
# SecRuleEngine Off below. Managed by malwatch, do not edit.
```

`waf/conf/logrotate-waf`:

```text
# Managed by malwatch (Abwehr > Einstellungen). Every change here is overwritten.
/var/log/waf/audit.log {
	daily
	rotate 7
	compress
	delaycompress
	missingok
	notifempty
	copytruncate
}
```

Die Einrückung in `logrotate-waf` ist ein Tabulator. Jede Datei endet mit einem
Zeilenumbruch.

- [ ] **Schritt 4: Werkzeuge schreiben**

`waf/waf-switch`:

```php
#!/usr/bin/php
<?php
/**
 * Command line side of the malwatch WAF part ("Abwehr").
 *
 *   waf-switch status
 *   waf-switch set off|detect|enforce <domain ...|--wordpress|--all> [--wait]
 *   waf-switch probe off|detect|enforce <domain ...|--wordpress|--all>
 *   waf-switch emergency on|off [--hard]
 *   waf-switch response-body [full|lean|status]
 *   waf-switch restore <backup directory>
 *   waf-switch jobs
 *   waf-switch exception list
 *   waf-switch exception add <domain|--all> <rule id> [--path=/path] [--param=name] [--note=text]
 *   waf-switch exception remove <number>
 *   waf-switch ingest [--dry-run] [--file=<audit log>]
 *   waf-switch migrate
 *   waf-switch snapshot
 *   waf-switch guard
 *
 * The emergency stop and the response body run at once; set leaves its job
 * to the cron unless --wait is given.
 */
if (php_sapi_name() !== 'cli') {
	exit(2);
}
if (!is_file('/usr/local/ispconfig/server/lib/classes/malwatch_waf.inc.php')) {
	fwrite(STDERR, "malwatch_waf.inc.php fehlt. Erst malwatch 0.19.0 einspielen.\n");
	exit(2);
}

require_once '/usr/local/ispconfig/server/lib/config.inc.php';
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require_once SCRIPT_PATH . '/lib/app.inc.php';

// ISPConfig runs its scripts in UTC; the guard log follows the server's clock.
$zone = trim((string) @file_get_contents('/etc/timezone'));
if ($zone !== '') {
	@date_default_timezone_set($zone);
}

$app->uses('malwatch_helper,malwatch_waf');
$waf = $app->malwatch_waf;
if (!$waf->ready()) {
	fwrite(STDERR, "malwatch_waf_lib.inc.php fehlt. Erst malwatch 0.19.0 einspielen.\n");
	exit(2);
}

$user = 'waf-switch';
if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
	$account = posix_getpwuid(posix_geteuid());
	if (is_array($account)) {
		$user .= ' (' . $account['name'] . ')';
	}
}

function waf_cli_webs()
{
	global $app, $conf;
	$rows = $app->dbmaster->queryAllRecords(
		'SELECT w.domain_id, w.domain, w.document_root, w.nginx_directives, s.waf_state, s.waf_pending_state '
		. 'FROM web_domain w LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id '
		. "WHERE w.server_id = ? AND w.type = 'vhost' AND w.active = 'y' ORDER BY w.domain",
		$conf['server_id']);
	return is_array($rows) ? $rows : array();
}

function waf_cli_is_wordpress($web)
{
	return is_file(rtrim((string) $web['document_root'], '/') . '/web/wp-config.php');
}

function waf_cli_select($webs, $args)
{
	if (in_array('--all', $args, true)) {
		return $webs;
	}
	if (in_array('--wordpress', $args, true)) {
		return array_values(array_filter($webs, 'waf_cli_is_wordpress'));
	}
	$picked = array();
	foreach ($webs as $web) {
		if (in_array($web['domain'], $args, true)) {
			$picked[] = $web;
		}
	}
	return $picked;
}

function waf_cli_report($job)
{
	if (!is_array($job)) {
		fwrite(STDERR, "Der Auftrag ließ sich nicht ausführen: Sperre belegt oder Bibliothek fehlt.\n");
		return 1;
	}
	echo $job['job_log'], "\n";
	return $job['job_status'] === 'done' ? 0 : 1;
}

function waf_cli_wait($waf, $job_id)
{
	$settings = $waf->settings();
	$rounds = ($settings['waf_job_deadline_minutes'] + 2) * 12;
	for ($i = 0; $i < $rounds; $i++) {
		$waf->pass();
		$job = $waf->job($job_id);
		if (is_array($job) && ($job['job_status'] === 'done' || $job['job_status'] === 'error')) {
			return waf_cli_report($job);
		}
		sleep(5);
	}
	echo "Der Auftrag $job_id läuft noch; der Cron führt ihn weiter.\n";
	return 1;
}

function waf_cli_stats($stats)
{
	global $app;
	printf("Zeilen %d, Treffer %d, neu %d, unlesbar %d, unbekannte Hosts %d%s\n", $stats['lines'], $stats['hits'],
		$stats['new'], $stats['broken'], $stats['unknown'], $stats['more'] ? ', weitere Zeilen warten' : '');
	foreach ($stats['sites'] as $site => $count) {
		$row = $app->dbmaster->queryOneRecord('SELECT domain FROM web_domain WHERE domain_id = ?', (int) $site);
		printf("  %-34s %d\n", is_array($row) ? $row['domain'] : '#' . $site, $count);
	}
	arsort($stats['unknown_hosts']);
	foreach ($stats['unknown_hosts'] as $host => $count) {
		printf("  unbekannt %-34s %d\n", $host, $count);
	}
}

function waf_cli_response_mode($waf)
{
	$settings = $waf->settings();
	return waf_response_body_mode((string) @file_get_contents($settings['waf_conf_dir'] . '/response-body.conf'));
}

$args = array_slice($argv, 1);
$command = (string) array_shift($args);

switch ($command) {
	case 'status':
		$settings = $waf->settings();
		printf("%-34s %-10s %-10s %-11s %-10s %s\n", 'Website', 'Feld', 'vhost', 'bestätigt', 'wartet', 'WordPress');
		foreach (waf_cli_webs() as $web) {
			$field = (string) $web['nginx_directives'];
			printf("%-34s %-10s %-10s %-10s %-10s %s\n", $web['domain'],
				waf_block_state($field) . (waf_block_is_old($field) ? '*' : ''),
				$waf->vhost_state($web['domain']),
				$web['waf_state'] === null ? 'off' : $web['waf_state'],
				(string) $web['waf_pending_state'],
				waf_cli_is_wordpress($web) ? 'ja' : '');
		}
		echo "\n* alte Markierung, waf-switch migrate schreibt sie um\n";
		echo 'Notaus: ', $settings['waf_emergency'] === 'y' ? 'aktiv seit ' . $settings['waf_emergency_since'] : 'aus', "\n";
		echo 'Seitenantwort im Audit-Log: ', waf_cli_response_mode($waf), "\n";
		exit(0);

	case 'set':
	case 'probe':
		$state = (string) array_shift($args);
		if (!waf_state_valid($state)) {
			fwrite(STDERR, "Der Zustand heißt off, detect oder enforce.\n");
			exit(2);
		}
		$selected = waf_cli_select(waf_cli_webs(), $args);
		if (count($selected) === 0) {
			fwrite(STDERR, "Keine Website ausgewählt.\n");
			exit(2);
		}
		if ($command === 'probe') {
			foreach ($selected as $web) {
				$old = (string) $web['nginx_directives'];
				$new = waf_block_set($old, $state);
				echo $web['domain'], ': ', $old === $new ? 'unverändert' : strlen($old) . ' -> ' . strlen($new) . ' Zeichen', "\n";
			}
			exit(0);
		}
		$ids = array();
		foreach ($selected as $web) {
			$ids[] = (int) $web['domain_id'];
		}
		$job_id = $waf->queue('set_state', array('domain_ids' => $ids, 'state' => $state), $user);
		echo 'Auftrag ', $job_id, ' eingereiht für ', count($ids), " Websites.\n";
		exit(in_array('--wait', $args, true) ? waf_cli_wait($waf, $job_id) : 0);

	case 'emergency':
		$mode = (string) array_shift($args);
		if ($mode !== 'on' && $mode !== 'off') {
			fwrite(STDERR, "emergency on|off [--hard]\n");
			exit(2);
		}
		exit(waf_cli_report($waf->execute_now('emergency',
			array('on' => $mode === 'on', 'hard' => $mode === 'on' && in_array('--hard', $args, true)), $user)));

	case 'response-body':
		$mode = (string) array_shift($args);
		if ($mode === '' || $mode === 'status') {
			echo 'Seitenantwort im Audit-Log: ', waf_cli_response_mode($waf), "\n";
			exit(0);
		}
		if (!waf_response_body_valid($mode)) {
			fwrite(STDERR, "response-body full|lean|status\n");
			exit(2);
		}
		exit(waf_cli_report($waf->execute_now('response_body', array('mode' => $mode), $user)));

	case 'restore':
		$dir = rtrim((string) array_shift($args), '/');
		if ($dir === '' || !is_dir($dir)) {
			fwrite(STDERR, "Ordner fehlt: $dir\n");
			exit(2);
		}
		$by_name = array();
		foreach (waf_cli_webs() as $web) {
			$by_name[preg_replace('/[^A-Za-z0-9._-]/', '_', $web['domain'])] = $web;
		}
		$files = glob($dir . '/*.txt');
		foreach (is_array($files) ? $files : array() as $file) {
			$name = basename($file, '.txt');
			if (!isset($by_name[$name])) {
				echo $name, ": keine aktive Website dieses Namens, übersprungen\n";
				continue;
			}
			$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => (string) file_get_contents($file)),
				'domain_id', (int) $by_name[$name]['domain_id']);
			echo $name, ": Feldinhalt zurückgeschrieben\n";
		}
		echo 'Abgleich als Auftrag ', $waf->queue('migrate_markers', array(), $user), " eingereiht.\n";
		exit(0);

	case 'jobs':
		$rows = $app->dbmaster->queryAllRecords(
			'SELECT job_id, job_status, options, created_at, job_log FROM malwatch_job '
			. "WHERE server_id = ? AND job_kind = 'waf' ORDER BY job_id DESC LIMIT 20", $conf['server_id']);
		foreach (is_array($rows) ? $rows : array() as $row) {
			$options = json_decode((string) $row['options'], true);
			$lines = preg_split('/\R/', trim((string) $row['job_log']));
			printf("%6d %-8s %-16s %-19s %s\n", $row['job_id'], $row['job_status'],
				is_array($options) && isset($options['action']) ? $options['action'] : '?',
				(string) $row['created_at'], $lines[0]);
		}
		exit(0);

	case 'exception':
		$sub = (string) array_shift($args);
		if ($sub === 'list') {
			$rows = $app->dbmaster->queryAllRecords(
				'SELECT exception_id, scope, domain, rule_id, path, param, exception_state, error_reason '
				. 'FROM malwatch_waf_exception WHERE server_id = ? ORDER BY exception_id', $conf['server_id']);
			foreach (is_array($rows) ? $rows : array() as $row) {
				printf("%5d %-10s %-30s %-8s %-28s %-14s %-8s %s\n", $row['exception_id'], $row['scope'],
					$row['domain'] === '' ? '(alle)' : $row['domain'], $row['rule_id'], $row['path'], $row['param'],
					$row['exception_state'], $row['error_reason']);
			}
			exit(0);
		}
		if ($sub === 'add') {
			$target = (string) array_shift($args);
			$rule = (string) array_shift($args);
			$given = array('path' => '', 'param' => '', 'note' => '');
			foreach ($args as $arg) {
				foreach (array_keys($given) as $key) {
					if (strpos($arg, '--' . $key . '=') === 0) {
						$given[$key] = substr($arg, strlen($key) + 3);
					}
				}
			}
			$site = 0;
			$domain = '';
			if ($target !== '--all') {
				foreach (waf_cli_webs() as $web) {
					if ($web['domain'] === $target) {
						$site = (int) $web['domain_id'];
						$domain = $web['domain'];
					}
				}
				if ($site === 0) {
					fwrite(STDERR, "Keine aktive Website namens $target.\n");
					exit(2);
				}
				$scope = $given['param'] !== '' ? 'site_param' : ($given['path'] !== '' ? 'site_path' : 'site');
			} else {
				$scope = $given['path'] !== '' ? 'all_path' : 'all';
			}
			$wrong = waf_exception_check(array('scope' => $scope, 'parent_domain_id' => $site, 'rule_id' => $rule,
				'path' => $given['path'], 'param' => $given['param']));
			if ($wrong !== '') {
				fwrite(STDERR, "Ungültige Angabe: $wrong\n");
				exit(2);
			}
			$app->dbmaster->query(
				'INSERT INTO malwatch_waf_exception (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, scope, parent_domain_id, domain, rule_id, path, param, note, exception_state, created_by, created_at) '
				. "VALUES (1, 1, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NOW())",
				$conf['server_id'], $scope, $site, $domain, $rule, $given['path'], $given['param'],
				waf_cut($given['note'], 255), waf_cut($user, 64));
			$id = (int) $app->dbmaster->insertID();
			echo 'Ausnahme ', $id, ' angelegt (', $scope, ").\n";
			exit(waf_cli_report($waf->execute_now('exception_add', array('exception_id' => $id), $user)));
		}
		if ($sub === 'remove') {
			$id = (int) array_shift($args);
			$app->dbmaster->query("UPDATE malwatch_waf_exception SET exception_state = 'removing' WHERE exception_id = ? AND server_id = ?",
				$id, $conf['server_id']);
			exit(waf_cli_report($waf->execute_now('exception_remove', array('exception_id' => $id), $user)));
		}
		fwrite(STDERR, "exception list | add <domain|--all> <regel> [--path=/pfad] [--param=name] [--note=text] | remove <nummer>\n");
		exit(2);

	case 'ingest':
		$dry = in_array('--dry-run', $args, true);
		$file = '';
		foreach ($args as $arg) {
			if (strpos($arg, '--file=') === 0) {
				$file = substr($arg, 7);
			}
		}
		if ($file !== '' && !$dry) {
			fwrite(STDERR, "--file gilt nur zusammen mit --dry-run.\n");
			exit(2);
		}
		$stats = $dry ? $waf->ingest(array('dry_run' => true, 'file' => $file)) : $waf->ingest_locked();
		if (!is_array($stats)) {
			fwrite(STDERR, "Die Sperre ist belegt; der nächste Aufruf versucht es erneut.\n");
			exit(1);
		}
		waf_cli_stats($stats);
		exit(0);

	case 'migrate':
		$job_id = $waf->queue('migrate_markers', array(), $user);
		$waf->queue('apply_settings', array(), $user);
		echo 'Abgleich (Auftrag ', $job_id, ") und Einstellungen eingereiht.\n";
		exit(waf_cli_wait($waf, $job_id));

	case 'snapshot':
		exit($waf->snapshot() ? 0 : 1);

	case 'guard':
		exit($waf->guard());
}

fwrite(STDERR, "Befehle: status | set <off|detect|enforce> <domain…|--wordpress|--all> [--wait] | probe … | "
	. "emergency on|off [--hard] | response-body [full|lean|status] | restore <ordner> | jobs | "
	. "exception list|add|remove | "
	. "ingest [--dry-run] [--file=<log>] | migrate | snapshot | guard\n");
exit(2);
```

`waf/waf-guard`:

```bash
#!/bin/bash
# Keeps the nginx configuration valid. Runs hourly through hc-run and ends
# with 0 when nginx -t passes, with 1 when something was found, so
# healthchecks raises it. The details go to /var/log/waf/guard.log.
set -u
if /usr/local/sbin/waf-switch guard > /dev/null 2>> /var/log/waf/guard.log; then
	exit 0
fi
exit 1
```

`waf/waf-report`:

```php
#!/usr/bin/php
<?php
/**
 * Hits per website and rule from the audit log, the most first.
 *
 *   waf-report [audit log]
 *
 * MALWATCH_WAF_LIB points at another copy of the shared functions, for a
 * check outside the server.
 */
$lib = getenv('MALWATCH_WAF_LIB') ?: '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php';
require $lib;

function waf_report_lines($file)
{
	$handle = fopen($file, 'rb');
	while (($line = fgets($handle)) !== false) {
		yield $line;
	}
	fclose($handle);
}

$file = isset($argv[1]) ? $argv[1] : '/var/log/waf/audit.log';
if (!is_readable($file)) {
	fwrite(STDERR, "Audit-Log nicht lesbar: $file\n");
	exit(2);
}
$report = waf_audit_summarize(waf_report_lines($file));
if (count($report) === 0) {
	echo "Keine Treffer im Audit-Log.\n";
	exit(0);
}
printf("%-34s %-8s %-8s %-30s %s\n", 'Website', 'Regel', 'Treffer', 'Beispielpfad', 'Meldung');
foreach ($report as $row) {
	printf("%-34s %-8s %-8d %-30s %s\n", $row['host'], $row['rule_id'], $row['hits'], $row['example'], $row['message']);
}
```

`ispconfig/tests/waf_ingest_dryrun.php`:

```php
<?php
/**
 * Reads an audit log with a staged malwatch against the live website table,
 * as root on the server. Writes nothing.
 *
 *   php waf_ingest_dryrun.php <stage>/ispconfig [audit log]
 */
if (php_sapi_name() !== 'cli' || !isset($argv[1])) {
	fwrite(STDERR, "usage: php waf_ingest_dryrun.php <stage>/ispconfig [audit log]\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
$file = isset($argv[2]) ? $argv[2] : '/var/log/waf/audit.log';

require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require SCRIPT_PATH . '/lib/app.inc.php';
$conf['log_priority'] = 9;

require $stage . '/interface/lib/malwatch_waf_lib.inc.php';
require $stage . '/server/lib/classes/malwatch_waf.inc.php';
$waf = new malwatch_waf();
$stats = $waf->ingest(array('dry_run' => true, 'file' => $file));
printf("Zeilen %d, Treffer %d, unlesbar %d, unbekannte Hosts %d\n",
	$stats['lines'], $stats['hits'], $stats['broken'], $stats['unknown']);
foreach ($stats['sites'] as $site => $count) {
	$row = $app->dbmaster->queryOneRecord('SELECT domain FROM web_domain WHERE domain_id = ?', (int) $site);
	printf("  %-34s %d\n", is_array($row) ? $row['domain'] : '#' . $site, $count);
}
foreach ($stats['unknown_hosts'] as $host => $count) {
	printf("  unbekannt %-34s %d\n", $host, $count);
}
```

- [ ] **Schritt 5: `install.sh` ersetzen**

`waf/install.sh`:

```bash
#!/bin/bash
# Installs the WAF files and tools on the web server and moves the names of
# the first tool (waf-schalter, einstellungen.conf, ...) to the current ones.
# Runs any number of times. nginx only ever loads a checked configuration,
# and the websites keep their state.
set -eu
cd "$(dirname "$0")"

WAF=/etc/nginx/waf
INCLUDE=/etc/nginx/conf.d/waf.conf
LIB=/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php
BACKUP=/var/backups/waf-switch/install-$(date +%Y%m%d-%H%M%S)

say() { echo "waf/install.sh: $*"; }

# Writes a text the shared functions produce: render <function> [arguments]
render() {
	php -r 'require $argv[1]; echo call_user_func_array($argv[2], array_slice($argv, 3));' "$LIB" "$@"
}

if [ ! -f /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]; then
	echo "Das nginx-Modul fehlt. Erst die Pakete einspielen." >&2
	exit 1
fi
if [ ! -f "$LIB" ] || [ ! -f /usr/local/ispconfig/server/lib/classes/malwatch_waf.inc.php ]; then
	echo "malwatch 0.19.0 fehlt. Erst das Addon einspielen." >&2
	exit 1
fi

install -d -o root -g root -m 700 /var/backups/waf-switch
install -d -o root -g root -m 700 "$BACKUP"
if [ -d "$WAF" ]; then cp -a "$WAF" "$BACKUP/waf"; fi
for f in "$INCLUDE" "$INCLUDE.off" /etc/logrotate.d/waf; do
	if [ -f "$f" ]; then cp -a "$f" "$BACKUP/"; fi
done
crontab -l > "$BACKUP/crontab" 2>/dev/null || true
say "Sicherung in $BACKUP"

install -d -o root -g root -m 755 "$WAF"

# 1. The files under their current names, next to the old ones.
for f in settings.conf crs-extra.conf exclusions-before.conf exclusions-after.conf; do
	install -o root -g root -m 644 "conf/$f" "$WAF/$f"
done
if [ ! -f "$WAF/state.conf" ]; then
	emergency=
	if [ -f "$WAF/zustand.conf" ] && grep -qE '^[[:space:]]*SecRuleEngine[[:space:]]+Off' "$WAF/zustand.conf"; then
		emergency=1
	fi
	render waf_state_file_text "$emergency" > "$WAF/state.conf"
	chmod 644 "$WAF/state.conf"
fi
if [ ! -f "$WAF/response-body.conf" ]; then
	mode=full
	if [ -f "$WAF/antwortrumpf.conf" ] && grep -qE '^[^#]*ctl:auditLogParts=-E' "$WAF/antwortrumpf.conf"; then
		mode=lean
	fi
	render waf_response_body_text "$mode" > "$WAF/response-body.conf"
	chmod 644 "$WAF/response-body.conf"
fi
# The panel owns these two; an existing file keeps its exceptions.
for f in exclusions-panel-before.conf exclusions-panel-after.conf; do
	if [ ! -f "$WAF/$f" ]; then
		install -o root -g root -m 644 "conf/$f" "$WAF/$f"
	fi
done

# 2. The new main.conf only after the rules check; nginx -t decides, and on
#    failure the previous one comes back.
reload=
install -o root -g root -m 644 conf/main.conf "$WAF/main.conf.new"
if cmp -s "$WAF/main.conf.new" "$WAF/main.conf"; then
	rm -f "$WAF/main.conf.new"
else
	check=$(ls /usr/lib/*/libexec/modsec-rules-check 2>/dev/null | head -n 1 || true)
	if [ -n "$check" ] && ! "$check" "$WAF/main.conf.new"; then
		rm -f "$WAF/main.conf.new"
		echo "Die Regelprüfung lehnt die neue main.conf ab. Nichts umgestellt." >&2
		exit 1
	fi
	if [ -f "$WAF/main.conf" ]; then cp -p "$WAF/main.conf" "$WAF/main.conf.prev"; fi
	mv "$WAF/main.conf.new" "$WAF/main.conf"
	if ! nginx -t; then
		if [ -f "$WAF/main.conf.prev" ]; then
			mv "$WAF/main.conf.prev" "$WAF/main.conf"
		else
			rm -f "$WAF/main.conf"
		fi
		echo "nginx -t lehnt die neue main.conf ab. Die vorherige liegt wieder an ihrem Platz." >&2
		exit 1
	fi
	reload=1
fi

# 3. The old names go once nothing includes them any more.
rm -f "$WAF/einstellungen.conf" "$WAF/crs-zusatz.conf" "$WAF/ausnahmen-vorher.conf" \
	"$WAF/ausnahmen-nachher.conf" "$WAF/zustand.conf" "$WAF/antwortrumpf.conf" "$WAF/main.conf.prev"

install -d -o www-data -g adm -m 750 /var/log/waf
# The audit log holds form contents and stays root's.
if [ ! -f /var/log/waf/audit.log ]; then install -o root -g adm -m 600 /dev/null /var/log/waf/audit.log; fi
chown root:adm /var/log/waf/audit.log
chmod 600 /var/log/waf/audit.log
install -d -o www-data -g root -m 750 /var/cache/waf
# The settings page rewrites this file; only a file from before malwatch is replaced here.
if ! grep -q 'Managed by malwatch' /etc/logrotate.d/waf 2>/dev/null; then
	install -o root -g root -m 644 conf/logrotate-waf /etc/logrotate.d/waf
fi

# 4. The tools under their current names.
install -o root -g root -m 755 waf-switch /usr/local/sbin/waf-switch
install -o root -g root -m 755 waf-guard /usr/local/sbin/waf-guard
install -o root -g root -m 755 waf-report /usr/local/sbin/waf-report
rm -f /usr/local/sbin/waf-schalter /usr/local/sbin/waf-wache /usr/local/sbin/waf-bericht
rm -rf /usr/local/lib/waf

# 5. The hourly guard in root's crontab; every other line stays as it is.
current=$(crontab -l 2>/dev/null || true)
if printf '%s\n' "$current" | grep -q 'hc-run waf-guard'; then
	wanted=$current
elif printf '%s\n' "$current" | grep -q 'hc-run waf-wache'; then
	wanted=$(printf '%s\n' "$current" | sed 's#hc-run waf-wache -- /usr/local/sbin/waf-wache#hc-run waf-guard -- /usr/local/sbin/waf-guard#')
else
	wanted=$(printf '%s\n%s\n' "$current" '5 * * * * /usr/local/sbin/hc-run waf-guard -- /usr/local/sbin/waf-guard > /dev/null')
fi
if [ "$wanted" != "$current" ]; then
	printf '%s\n' "$wanted" | crontab -
	say "Cron-Zeile auf waf-guard umgestellt."
fi
if [ -f /etc/hc-run.d/waf-wache.url ] && [ ! -f /etc/hc-run.d/waf-guard.url ]; then
	mv /etc/hc-run.d/waf-wache.url /etc/hc-run.d/waf-guard.url
fi

# 6. The include last, so nginx sees the rules once everything is in place.
#    After a hard emergency stop this switches the rules back on.
if ! cmp -s conf/waf.conf "$INCLUDE"; then
	install -o root -g root -m 644 conf/waf.conf "$INCLUDE.new"
	mv "$INCLUDE.new" "$INCLUDE"
	if ! nginx -t; then
		rm -f "$INCLUDE"
		if [ -f "$BACKUP/waf.conf" ]; then cp -a "$BACKUP/waf.conf" "$INCLUDE"; fi
		echo "nginx -t lehnt die Einbindung ab. Der vorherige Stand liegt wieder." >&2
		exit 1
	fi
	reload=1
fi
rm -f "$INCLUDE.off"

/usr/local/sbin/waf-switch snapshot
if [ -n "$reload" ]; then
	systemctl reload nginx
	if ! systemctl is-active --quiet nginx; then
		echo "nginx läuft nach dem Reload nicht. Sofort prüfen: systemctl status nginx" >&2
		exit 1
	fi
	say "nginx neu geladen."
fi

# 7. Old markers, the state per website and the logrotate setting through the jobs.
if ! /usr/local/sbin/waf-switch migrate; then
	say "Der Abgleich läuft über den Cron weiter: waf-switch jobs"
fi
say "Fertig. waf-switch status zeigt den Stand."
```

- [ ] **Schritt 6: README ersetzen**

`waf/README.md`:

````markdown
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
````

- [ ] **Schritt 7: Alte Dateien entfernen, CI ergänzen**

```bash
git rm -r waf/lib waf/tests
git rm waf/waf-schalter waf/waf-wache waf/waf-bericht waf/conf/einstellungen.conf waf/conf/crs-zusatz.conf waf/conf/ausnahmen-vorher.conf waf/conf/ausnahmen-nachher.conf waf/conf/zustand.conf waf/conf/antwortrumpf.conf
```

In `.github/workflows/ci.yml` im Job `php-syntax` nach dem Schritt „WAF functions":

```yaml
      - name: WAF tools
        run: |
          php -l waf/waf-switch
          php -l waf/waf-report
          bash -n waf/waf-guard
          bash -n waf/install.sh
          MALWATCH_WAF_LIB=ispconfig/interface/lib/malwatch_waf_lib.inc.php php waf/waf-report ispconfig/tests/waf_audit_sample.log
```

- [ ] **Schritt 8: Prüfen**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php -l waf/waf-switch && php -l waf/waf-report && php -l ispconfig/tests/waf_ingest_dryrun.php && bash -n waf/waf-guard && bash -n waf/install.sh`
Expected: dreimal `No syntax errors detected`, keine Ausgabe von `bash -n`

Run: `MALWATCH_WAF_LIB=ispconfig/interface/lib/malwatch_waf_lib.inc.php php waf/waf-report ispconfig/tests/waf_audit_sample.log`
Expected:

```text
Website                            Regel    Treffer  Beispielpfad                   Meldung
zweite.test                        941100   2        /seite                         XSS Attack Detected via libinjection
beispiel.test                      942190   1        /wp-json/batch/v1              Detects MSSQL code execution and information gathering attempts
fremd.test                         930130   1        /.env                          Restricted File Access Attempt
www.beispiel.test                  942100   1        /suche                         SQL Injection Attack Detected via libinjection
```

- [ ] **Schritt 9: Commit**

```bash
git add -A waf ispconfig/tests/waf_lib_test.php ispconfig/tests/check_wiring.sh ispconfig/tests/waf_ingest_dryrun.php .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): tools and files under their English names, migration in install.sh" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe A9: Probe am Server, ohne Eingriff

Was sich am Rechner nicht prüfen lässt, prüft diese Aufgabe auf web.herkules: Syntax unter
PHP 7.0, die Regeldateien mit `modsec-rules-check`, das Schema zweimal in einer
Wegwerf-Datenbank, die Klasse mit `waf_class_probe.php` und das Einlesen des echten
Audit-Logs als Probelauf. nginx, ISPConfig und die Datenbank `dbispconfig` bleiben
unberührt; die Wegwerf-Datenbank `mw_waf_probe` verschwindet am Ende wieder.

**Dateien:**
- Neu: `ispconfig/tests/waf_rules_probe.php`
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`

**Schnittstellen:**
- Nutzt: `waf_exception_rules()`, `waf_response_body_text()`, `waf_state_file_text()`,
  `waf_conf_files()`, `waf_remove_dir()`; `ispconfig/tests/waf_class_probe.php`,
  `ispconfig/tests/waf_ingest_dryrun.php`
- Liefert: Befund für Teil B (Probe grün, unbekannte Hosts im echten Log, Laufzeit der
  Klassenprobe ohne Belang)

- [ ] **Schritt 1: Regelprobe schreiben**

`ispconfig/tests/waf_rules_probe.php`:

```php
<?php
/**
 * Checks the WAF files of a stage with modsec-rules-check, as root on the
 * server, without touching /etc/nginx:
 *
 *   php waf_rules_probe.php <stage>
 *
 * <stage> holds ispconfig/ and waf/ of the repository. The probe copies
 * waf/conf next to it, points main.conf at the copy and checks the shipped
 * set, one exception of every scope, both response body modes, the
 * emergency switch, and a broken file that the check has to refuse.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[1])) {
	fwrite(STDERR, "usage: php waf_rules_probe.php <stage>\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
require $stage . '/ispconfig/interface/lib/malwatch_waf_lib.inc.php';

$found = glob('/usr/lib/*/libexec/modsec-rules-check');
if (!is_array($found) || count($found) === 0) {
	fwrite(STDERR, "modsec-rules-check fehlt\n");
	exit(2);
}
$tool = $found[0];
$dir = $stage . '/rules-probe';

function shipped($stage, $dir, $name)
{
	return str_replace('/etc/nginx/waf/', $dir . '/', (string) file_get_contents($stage . '/waf/conf/' . $name));
}

waf_remove_dir($dir);
mkdir($dir, 0700, true);
foreach (waf_conf_files($stage . '/waf/conf') as $file) {
	file_put_contents($dir . '/' . basename($file), shipped($stage, $dir, basename($file)));
}

$hosts = array(11 => array('exact' => array('beispiel.test', 'www.beispiel.test'), 'wildcard' => array('beispiel.test')));
$rows = array(
	array('exception_id' => 1, 'scope' => 'site', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 2, 'scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 3, 'scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => 'filter', 'exception_state' => 'active'),
	array('exception_id' => 4, 'scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '941100', 'path' => '/suche', 'param' => 'json.query[0]', 'exception_state' => 'active'),
	array('exception_id' => 5, 'scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '/xmlrpc.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 6, 'scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '', 'exception_state' => 'active'),
);
$rules = waf_exception_rules($rows, $hosts);
if (count($rules['skipped']) > 0) {
	fwrite(STDERR, "exceptions left out: " . json_encode($rules['skipped']) . "\n");
	exit(1);
}

// name => array(files to replace, expected exit code 0 or not)
$variants = array(
	'shipped' => array(array(), true),
	'exceptions' => array(array('exclusions-panel-before.conf' => $rules['before'], 'exclusions-panel-after.conf' => $rules['after']), true),
	'lean' => array(array('response-body.conf' => waf_response_body_text('lean')), true),
	'emergency' => array(array('state.conf' => waf_state_file_text(true)), true),
	'broken' => array(array('exclusions-panel-before.conf' => "SecRuleBroken 1\n"), false),
);
$failures = 0;
foreach ($variants as $name => $variant) {
	foreach ($variant[0] as $file => $text) {
		file_put_contents($dir . '/' . $file, $text);
	}
	$output = array();
	$code = 0;
	exec(escapeshellarg($tool) . ' ' . escapeshellarg($dir . '/main.conf') . ' 2>&1', $output, $code);
	$passed = $code === 0;
	printf("%-11s %-9s %s\n", $name, $passed ? 'bestanden' : 'abgelehnt', $passed === $variant[1] ? 'wie erwartet' : 'FALSCH');
	if ($passed !== $variant[1]) {
		$failures++;
		echo '  ', implode("\n  ", $output), "\n";
	}
	foreach ($variant[0] as $file => $text) {
		file_put_contents($dir . '/' . $file, shipped($stage, $dir, $file));
	}
}
waf_remove_dir($dir);
exit($failures > 0 ? 1 : 0);
```

Run: `php -l ispconfig/tests/waf_rules_probe.php`
Expected: `No syntax errors detected`

```bash
git add ispconfig/tests/waf_rules_probe.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "test(abwehr): rules probe for the WAF files" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

- [ ] **Schritt 2: Freigabe einholen**

Mathias bekommt vorgelegt: „A9 kopiert den Stand nach `/root/waf-abwehr-stage`, prüft
Syntax, Regeldateien und Klasse und liest das Audit-Log als Probelauf. Dafür entsteht die
Wegwerf-Datenbank `mw_waf_probe`, die am Ende wieder gelöscht wird. nginx, ISPConfig und
`dbispconfig` bleiben unberührt." Weiter erst nach seinem Ja.

- [ ] **Schritt 3: Stand kopieren, Beginn festhalten**

```bash
ssh ispconfig 'date "+%d.%m.%Y, %H:%M:%S %Z"'
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/waf-abwehr-stage && mkdir -p /root/waf-abwehr-stage && tar -x -C /root/waf-abwehr-stage'
```

Die Uhrzeit kommt ins Protokoll.

- [ ] **Schritt 4: Syntax unter PHP 7.0 und 8.3, reine Tests**

```bash
ssh ispconfig 'cd /root/waf-abwehr-stage && for php in php7.0 php; do find ispconfig -name "*.php" -print0 | xargs -0 -n1 $php -l | grep -v "^No syntax errors"; $php -l waf/waf-switch | grep -v "^No syntax errors"; $php -l waf/waf-report | grep -v "^No syntax errors"; done; php ispconfig/tests/waf_lib_test.php && sh ispconfig/tests/check_wiring.sh'
```

Expected: keine Zeile aus den Syntaxprüfungen, dann `waf_lib: alle Prüfungen bestanden` und
`Wiring OK`. Die Prüfungen 37 und 40 setzen aus, weil `cmd/` nicht im Stand liegt.

- [ ] **Schritt 5: Regeldateien prüfen**

```bash
ssh ispconfig 'nice -n 15 php /root/waf-abwehr-stage/ispconfig/tests/waf_rules_probe.php /root/waf-abwehr-stage; echo "exit=$?"'
```

Expected:

```text
shipped     bestanden wie erwartet
exceptions  bestanden wie erwartet
lean        bestanden wie erwartet
emergency   bestanden wie erwartet
broken      abgelehnt wie erwartet
exit=0
```

Lehnt die Prüfung die Ausnahmen ab, stoppt Teil A hier: die Form der Regeln in
`waf_exception_rules()` wird mit Mathias besprochen, bevor es weitergeht.

- [ ] **Schritt 6: Schema und Klasse in der Wegwerf-Datenbank**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
stage=/root/waf-abwehr-stage/ispconfig
mysql -e 'CREATE DATABASE mw_waf_probe CHARACTER SET utf8mb4'
# Twice: the additions must check themselves and do nothing the second time.
mysql mw_waf_probe < "$stage/install/schema.sql"
mysql mw_waf_probe < "$stage/install/schema.sql"
mysql mw_waf_probe -e 'CREATE TABLE web_domain LIKE dbispconfig.web_domain; CREATE TABLE sys_datalog LIKE dbispconfig.sys_datalog; CREATE TABLE sys_log LIKE dbispconfig.sys_log'
mysql -N mw_waf_probe -e "SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'mw_waf_probe' AND ((TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind') OR (TABLE_NAME = 'malwatch_action_log' AND COLUMN_NAME = 'action_type'))"
mysql -N mw_waf_probe -e "SELECT TABLE_NAME, COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'mw_waf_probe' AND TABLE_NAME IN ('malwatch_config', 'malwatch_site') AND COLUMN_NAME LIKE 'waf\_%' GROUP BY TABLE_NAME"
nice -n 15 php "$stage/tests/waf_class_probe.php" "$stage" mw_waf_probe
EOF
```

Expected:
- zwei Aufzählungen, die beide `'waf'` enthalten
- `malwatch_config 12` und `malwatch_site 4`
- `waf_class_probe: alle Prüfungen bestanden`

Scheitert der Klassentest, bleibt die Datenbank für die Fehlersuche stehen; Schritt 8
räumt sie danach ab.

- [ ] **Schritt 7: Das echte Audit-Log als Probelauf**

```bash
ssh ispconfig 'nice -n 15 php /root/waf-abwehr-stage/ispconfig/tests/waf_ingest_dryrun.php /root/waf-abwehr-stage/ispconfig /var/log/waf/audit.log'
```

Expected: `Zeilen N, Treffer M, unlesbar 0, unbekannte Hosts U` mit N gleich der Zeilenzahl
von `wc -l /var/log/waf/audit.log`, die Treffer bei bright-color.de. Unbekannte Hosts und
unlesbare Zeilen kommen mit Anzahl ins Protokoll; Adressen und Anfrageinhalte nicht.

- [ ] **Schritt 8: Aufräumen und prüfen**

```bash
ssh ispconfig 'mysql -e "DROP DATABASE IF EXISTS mw_waf_probe"; rm -rf /root/waf-abwehr-stage /tmp/waf-probe-*; mysql -N -e "SHOW DATABASES LIKE '"'"'mw\_%'"'"'"; ls -d /root/waf-abwehr-stage 2>&1 | tail -1; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: keine Datenbank, `No such file or directory`, die Uhrzeit für das Protokoll.

- [ ] **Schritt 9: Protokoll**

Das Serverprotokoll frisch lesen und den Eintrag als gezielte Einfügung nach seiner
Beginnzeit einsortieren (neueste zuerst, andere Sitzungen schreiben mit). Aufbau wie die
übrigen Einträge:

```markdown
## <Datum>, <Beginn>–<Ende> CEST · Probe malwatch Abwehr, ohne Eingriff in den Betrieb

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, im Auftrag von Mathias |
| Betroffen | `/root/waf-abwehr-stage` und Wegwerf-Datenbank `mw_waf_probe`, beide wieder entfernt |
| Auftrag | Aufgabe A9 des Plans `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-a.md` im malwatch-Repo, Zweig `waf-herkules` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Syntax unter PHP 7.0, Regeldateien, Schema und Serverklasse lassen sich nur am Server prüfen.

### Ablauf

- `php7.0 -l` und `php -l` über alle PHP-Dateien: <Ergebnis>
- `waf_lib_test.php`, `check_wiring.sh`: <Ergebnis>
- `waf_rules_probe.php` mit `modsec-rules-check`: <Ergebnis je Variante>
- `mw_waf_probe`: Schema zweimal geladen, Leerkopien von `web_domain`, `sys_datalog`, `sys_log`; `waf_class_probe.php`: <Ergebnis>
- Probelauf des Audit-Logs: <Zeilen, Treffer, unlesbar, unbekannte Hosts mit Anzahl>

### Prüfung

Datenbank gelöscht, Stand und `/tmp/waf-probe-*` entfernt. nginx, ISPConfig, `dbispconfig`, `/etc/nginx/waf` und die Crontab sind unverändert.

### Rückweg

Nicht nötig, am Betrieb wurde nichts geändert.
```

---

## Abschluss von Teil A

- [ ] Aufgaben A1 bis A9 abgehakt, jede mit eigenem Commit.
- [ ] Lokal grün: `php ispconfig/tests/waf_lib_test.php`, `sh ispconfig/tests/check_wiring.sh`,
  `php -l` über alle geänderten PHP-Dateien, `bash -n` über `waf/waf-guard` und
  `waf/install.sh`.
- [ ] Am Server grün (A9): Syntax unter PHP 7.0 und 8.3, Regelprobe, Klassenprobe in der
  Wegwerf-Datenbank, Probelauf des Audit-Logs; Eintrag im Serverprotokoll.
- [ ] Nichts geschoben, am Betrieb von web.herkules nichts geändert.

Weiter mit `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md`.
