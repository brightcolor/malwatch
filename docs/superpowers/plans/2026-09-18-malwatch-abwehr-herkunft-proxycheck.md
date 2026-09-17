# Herkunft der Adressen über proxycheck.io (Teil B II) — Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Ziel:** Für jede Adresse aus einem Treffer kann der Betreiber proxycheck.io fragen lassen; VPN, Proxy, Rechenzentrum und der Name des Anbieters stehen dann auch dort, wo die lokalen Listen nichts wissen.

**Aufbau:** proxycheck.io ist keine Bereichsdatei, sondern eine Auskunft je Adresse. Die Wahl steckt in derselben Einstellung wie die X4BNet-Listen (`waf_origin_net`: `off`, `x4b`, `proxycheck`). Der Abruf ist ein eigener Schritt in `cron_minute()` nach dem Einlesen: Er nimmt bis zu 100 Adressen im Zustand `pending`, schickt eine einzige Anfrage, trägt die Antwort in `malwatch_waf_ip` ein und führt in `malwatch_waf_origin_source` Buch über die Abfragen des Tages. Das Abbilden der Antwort und die Buchführung über das Tageslimit sind Funktionen ohne Datenbank in `malwatch_waf_origin.inc.php` und damit einzeln prüfbar; die Datenbankarbeit steckt in der Serverklasse und wird von der Klassenprobe auf dem Server geprüft.

**Technik:** PHP ab 7.0, ISPConfig 3.3.1p1, vlibTemplate und tform im Panel, curl für den POST, MariaDB. Tests sind `expect_same()`-Skripte in `ispconfig/tests`, dazu `check_wiring.sh`, `render_pages.php` (nur auf dem Server) und `waf_class_probe.php` (nur auf dem Server, gegen eine Wegwerf-Datenbank).

**Spec:** `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`, Abschnitte 6, 7, 9, 10, 11 und 12, soweit sie den externen Dienst betreffen.

## Feste Vorgaben

- Bezeichner, Dateinamen, Konfigurationsschlüssel und Code-Kommentare auf Englisch. Texte für Menschen auf Deutsch mit echten Umlauten, dazu die englische Fassung in `en_*.lng`.
- PHP ab 7.0: keine typisierten Eigenschaften, kein `??`, kein `str_contains()`, `array()` statt `[]` im Panel- und Serverteil.
- Jede Meldung nennt Ursache und nächsten Schritt. „Anfrage fehlgeschlagen" reicht nicht.
- Schlüssel stehen nie in Auftragsprotokollen, Fehlertexten, Cron-Ausgaben oder im HTML; im Panel höchstens die letzten vier Zeichen über `waf_panel_key_mask()`.
- Keine echten Kundendaten im Repository. Beispielantworten nutzen Adressen aus `192.0.2.0/24`, `198.51.100.0/24` und `2001:db8::/32`.
- Der Webserver darf nicht ausfallen: Der Abruf läuft im Cron unter dem bestehenden Lock, mit 5 s Verbindungs- und 10 s Abrufgrenze, höchstens eine Anfrage je Durchgang.
- Zeiträume und Grenzen sind einstellbar: Das Tageslimit steht als `waf_origin_proxycheck_daily` in den Einstellungen, Vorgabe 500, erlaubt 1 bis 100000.
- Vor jedem Commit bleibt `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` ohne Ausgabe.
- Commit-Nachrichten enden auf `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Geschoben, getaggt und eingespielt wird nur auf Ansage von Mathias.
- Jede Arbeit am Server kommt ins Protokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`, frisch gelesen und gezielt eingefügt.
- Claude meldet sich nie im Panel an und tippt keine Zugangsdaten. Den Schlüssel von proxycheck.io trägt **Mathias selbst** in den Einstellungen ein.

## Ausgangslage: was 0.21.1 schon mitbringt

Diese Teile stehen und werden nur noch ergänzt:

| Stelle | Stand |
|---|---|
| `malwatch_waf_ip` | hat bereits `is_proxy`, `vpn_operator`, `external_state` (`none`, `pending`, `done`, `failed`, `limit`), `external_at`, `external_tries` und den Index `external (server_id, external_state)` |
| `malwatch_waf_origin_source` | eine Zeile je Quelle mit `version`, `checked_at`, `fetched_at`, `entries`, `error`, `error_at`; **`day` und `queries` fehlen noch** |
| Anzeige | `waf_panel_origin()` zeigt die Chips „Tor", „VPN" (mit Anbieter), „Rechenzentrum", „Proxy" und die Zustände „wird geprüft" (`pending`) und „nicht geprüft, Tageslimit" (`limit`); die Texte stehen in `de|en_malwatch_waf.lng` |
| Nachschlagen | `malwatch_waf::origin_lookup()` füllt `malwatch_waf_ip` aus den Bereichsdateien, `cleanup()` löscht verwaiste Zeilen |
| Abruf | `malwatch_waf::fetch()` lädt eine Adresse in eine Datei, mit der Naht `$fetcher` für Tests. Für proxycheck.io fehlt ein POST |
| Aufträge | `origin_update` lädt die lokalen Quellen, `queue_origin_update()` legt ihn an, die Einstellungsseite stößt ihn nach dem Speichern an |
| Prüfungen | `check_wiring.sh` hat 69 Prüfungen, die letzte hält die beiden Wörterbücher der Einstellungsseite zusammen |

## Dateien

| Datei | Aufgabe | Änderung |
|---|---|---|
| `ispconfig/install/schema.sql` | Schema | zwei Spalten in `malwatch_config`, `proxycheck` im enum `waf_origin_net`, `day` und `queries` in `malwatch_waf_origin_source` |
| `ispconfig/interface/lib/malwatch_waf_lib.inc.php` | Einstellungen | Auswahl, Vorgaben, Grenzen, Prüfung der beiden neuen Werte |
| `ispconfig/interface/lib/malwatch_waf_origin.inc.php` | Quellen ohne Datenbank | neu: `waf_origin_external()`, `waf_origin_proxycheck_body()`, `waf_origin_proxycheck_read()`, `waf_origin_proxycheck_facts()`, `waf_origin_mark()`, `waf_origin_quota()` |
| `ispconfig/interface/lib/malwatch_waf_panel.inc.php` | Anzeige | `waf_panel_origin_rows()` nimmt die externe Quelle mit auf |
| `ispconfig/interface/form/malwatch_waf_config.tform.php` | Formular | zwei Felder, `proxycheck` in der Auswahl |
| `ispconfig/interface/malwatch_waf_config_edit.php` | Einstellungsseite | gespeicherter Schlüssel, Löschen-Haken, Pflichtfeld |
| `ispconfig/interface/templates/malwatch_waf_config_edit.htm` | Vorlage | zwei Zeilen und der Datenschutzhinweis |
| `ispconfig/interface/lang/de\|en_malwatch_waf.lng` | Texte | Name der Quelle, Zeile zum Kontingent |
| `ispconfig/interface/lang/de\|en_malwatch_waf_config.lng` | Texte | Felder, Hinweise, Fehlermeldungen |
| `ispconfig/server/lib/classes/malwatch_waf.inc.php` | Cron | `$poster`, `post()`, `origin_external()`, `origin_external_state()`, Anschluss in `cron_minute()`, `origin_lookup()` und `run_origin_update()` |
| `ispconfig/tests/waf_proxycheck_test.php` | Test | neu: die Funktionen ohne Datenbank |
| `ispconfig/tests/fixtures/proxycheck/*.json` | Beispiele | neu: gute Antwort, `denied`, Antwort ohne Felder |
| `ispconfig/tests/waf_lib_test.php`, `waf_panel_test.php`, `waf_panel_post_test.php` | Tests | je ein Abschnitt dazu |
| `ispconfig/tests/waf_class_probe.php` | Probe | Abschnitt C: der Abruf gegen die Wegwerf-Datenbank |
| `ispconfig/tests/check_wiring.sh` | Verdrahtung | Prüfungen 70 bis 73 |
| `.github/workflows/ci.yml` | CI | Schritt „WAF proxycheck" |
| `CHANGELOG.md`, `README.md`, `ispconfig/README.md`, `ispconfig/version`, `internal/version/version.go` | Release | 0.22.0 |

---
### Task C1: Schema und Einstellungen

Die Wahl `proxycheck` und ihre zwei Werte kommen in die Einstellungen und ins Schema. Danach lässt sich die Quelle wählen, auch wenn noch nichts abgefragt wird.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (`waf_origin_choices()`, `waf_settings_defaults()`, `waf_settings_limits()`, `waf_settings()`)
- Modify: `ispconfig/install/schema.sql`
- Test: `ispconfig/tests/waf_lib_test.php`

**Interfaces:**
- Consumes: `waf_settings($row)` und `waf_origin_choices()` aus 0.21.1
- Produces: `$settings['waf_origin_net'] === 'proxycheck'`, `$settings['waf_origin_proxycheck_key']` (Zeichenkette, höchstens 128 Zeichen aus `A-Za-z0-9-`), `$settings['waf_origin_proxycheck_daily']` (ganze Zahl von 1 bis 100000, Vorgabe 500)

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_lib_test.php` ans Ende des Abschnitts zur Herkunft anfügen (er beginnt mit dem Kommentar `// --- The origin of an address`):

```php
// proxycheck.io steht neben den X4BNet-Listen zur Wahl und bringt zwei eigene Werte mit.
$choices = waf_origin_choices();
expect_same('proxycheck may be chosen', $choices['waf_origin_net'], array('off', 'x4b', 'proxycheck'));
$picked = waf_settings(array('waf_origin_net' => 'proxycheck', 'waf_origin_proxycheck_key' => 'ab-12cd',
	'waf_origin_proxycheck_daily' => '2000'));
expect_same('the external source is kept', array($picked['waf_origin_net'], $picked['waf_origin_proxycheck_key'],
	$picked['waf_origin_proxycheck_daily']), array('proxycheck', 'ab-12cd', 2000));
expect_same('a key with a space is dropped',
	waf_settings(array('waf_origin_proxycheck_key' => 'ab 12'))['waf_origin_proxycheck_key'], '');
expect_same('the daily limit stays in its range',
	waf_settings(array('waf_origin_proxycheck_daily' => '999999'))['waf_origin_proxycheck_daily'], 100000);
expect_same('without a row the limit is the default',
	waf_settings(array())['waf_origin_proxycheck_daily'], 500);
expect_same('an unknown value for the network falls back',
	waf_settings(array('waf_origin_net' => 'irgendwas'))['waf_origin_net'], 'off');
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `FAIL proxycheck may be chosen`, dazu die Fehler zu Schlüssel und Tageslimit.

- [x] **Step 3: Die Einstellungen ergänzen**

In `ispconfig/interface/lib/malwatch_waf_lib.inc.php` in `waf_origin_choices()` die Zeile für das Netz ersetzen:

```php
		'waf_origin_net' => array('off', 'x4b', 'proxycheck'),
```

In `waf_settings_defaults()` hinter `'waf_origin_net' => 'off',` einfügen:

```php
		'waf_origin_proxycheck_key' => '',
		'waf_origin_proxycheck_daily' => 500,
```

In `waf_settings_limits()` hinter `'waf_origin_db_hours' => array(1, 720),` einfügen:

```php
		'waf_origin_proxycheck_daily' => array(1, 100000),
```

In `waf_settings()` hinter der Prüfung des MaxMind-Schlüssels einfügen:

```php
	// proxycheck.io vergibt Schlüssel aus Buchstaben, Ziffern und Bindestrichen;
	// der Schlüssel steht später in einer Adresse.
	$settings['waf_origin_proxycheck_key'] = preg_match('/^[A-Za-z0-9-]{0,128}$/', (string) $settings['waf_origin_proxycheck_key'])
		? (string) $settings['waf_origin_proxycheck_key'] : '';
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [x] **Step 5: Schema ergänzen**

In `ispconfig/install/schema.sql` hinter dem Block, der die acht `waf_origin_`-Spalten anlegt (er endet auf `PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;`), einfügen:

```sql
-- proxycheck.io kommt mit 0.22.0 dazu: der Schlüssel, das Tageslimit und der
-- Wert `proxycheck` für die Wahl des Netzes.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_origin_proxycheck_key` varchar(128) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_proxycheck_daily` int(11) unsigned NOT NULL DEFAULT ''500''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_proxycheck_key');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` MODIFY COLUMN `waf_origin_net` enum(''off'',''x4b'',''proxycheck'') NOT NULL DEFAULT ''off''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_net'
    AND COLUMN_TYPE LIKE '%''proxycheck''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Der Tag und die Zahl der Abfragen an diesem Tag; nur proxycheck.io füllt sie.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_waf_origin_source` ADD COLUMN `day` date DEFAULT NULL, ADD COLUMN `queries` int(11) unsigned NOT NULL DEFAULT ''0''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_waf_origin_source' AND COLUMN_NAME = 'day');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

In derselben Datei bekommt `CREATE TABLE IF NOT EXISTS \`malwatch_waf_origin_source\`` die zwei Spalten vor `PRIMARY KEY`, damit eine frische Anlage sie gleich hat:

```sql
  `day` date DEFAULT NULL,
  `queries` int(11) unsigned NOT NULL DEFAULT '0',
```

- [x] **Step 6: Das Schema auf Syntax prüfen**

Run: `php -r "echo preg_match('/proxycheck/', file_get_contents('ispconfig/install/schema.sql')) ? \"gefunden\n\" : \"fehlt\n\";"`
Expected: `gefunden`. Geladen wird das Schema erst auf dem Server (Task C8, Block 1); dort zeigt `SHOW COLUMNS`, ob die drei Änderungen greifen.

- [x] **Step 7: Die Kulisse der Vorschau nachziehen**

`.superpowers/abwehr/harness/fake_db.php` liegt außerhalb des Repositorys und stellt die Konfigurationszeile nach. In der Zeile mit `'waf_origin_maxmind_key' => ''` die zwei Werte ergänzen, sonst rendert die Einstellungsseite in der Vorschau ohne sie:

```php
				'waf_origin_proxycheck_key' => '', 'waf_origin_proxycheck_daily' => '500',
```

- [x] **Step 8: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/install/schema.sql ispconfig/tests/waf_lib_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): proxycheck.io as a choice with key and daily limit" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Expected: `grep` ohne Ausgabe, der Commit gelingt.

---
### Task C2: Die Antwort von proxycheck.io lesen

Alles, was ohne Datenbank und ohne Netz auskommt: die Wahl der externen Quelle, der Rumpf einer Anfrage, das Abbilden der Antwort und die Buchführung über das Tageslimit. Diese Funktionen sind einzeln prüfbar und damit die Stelle, an der die Fehlerfälle aus Abschnitt 12 der Spec festgenagelt werden.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_origin.inc.php` (ans Ende, hinter `waf_origin_stale()`)
- Create: `ispconfig/tests/waf_proxycheck_test.php`
- Create: `ispconfig/tests/fixtures/proxycheck/answer.json`, `denied.json`, `empty.json`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `waf_origin_bytes($ip)` (16 Bytes oder `''`), `waf_origin_cut($text, $bytes)` aus derselben Datei
- Produces:
  - `waf_origin_external($settings)` → `'proxycheck'` oder `''`
  - `waf_origin_mark($value)` → `'y'` oder `'n'`
  - `waf_origin_proxycheck_body($ips)` → `'ips=a,b,c'` oder `''`
  - `waf_origin_proxycheck_facts($entry)` → `array('country', 'asn', 'as_org', 'is_tor', 'is_vpn', 'is_hosting', 'is_proxy', 'vpn_operator')`
  - `waf_origin_proxycheck_read($text)` → `array('ok' => bool, 'error' => string, 'ips' => array(ip => facts))`
  - `waf_origin_quota($row, $today, $daily)` → `array('day', 'queries', 'daily', 'left')`

- [x] **Step 1: Die Beispielantworten anlegen**

`ispconfig/tests/fixtures/proxycheck/answer.json`:

```json
{
	"status": "ok",
	"query_time": "0.02s",
	"192.0.2.10": {
		"detections": {"proxy": true, "vpn": true, "tor": false, "hosting": false},
		"network": {"asn": "AS64496", "range": "192.0.2.0/24", "provider": "Beispiel Netz GmbH", "organisation": "Beispiel Netz GmbH"},
		"location": {"country_code": "DE", "country_name": "Germany", "city": "Berlin"},
		"operator": {"name": "Beispiel VPN", "url": "https://beispiel.test"}
	},
	"198.51.100.7": {
		"detections": {"proxy": false, "vpn": false, "tor": true, "hosting": true},
		"network": {"asn": "AS64497", "organisation": "Zweites Netz"},
		"location": {"country_code": "nl"}
	},
	"2001:db8::5": {
		"detections": {},
		"network": {},
		"location": {}
	}
}
```

`ispconfig/tests/fixtures/proxycheck/denied.json`:

```json
{"status": "denied", "message": "The API key you provided is not valid."}
```

`ispconfig/tests/fixtures/proxycheck/empty.json`:

```json
{"status": "ok", "query_time": "0.01s"}
```

- [x] **Step 2: Den scheiternden Test schreiben**

`ispconfig/tests/waf_proxycheck_test.php`:

```php
<?php
/**
 * Checks how an answer of proxycheck.io becomes the facts of an address and
 * how the queries of a day are counted.
 *
 *   php ispconfig/tests/waf_proxycheck_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_origin.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . PHP_EOL);
	}
}

$fixtures = __DIR__ . '/fixtures/proxycheck';

// --- The choice ---------------------------------------------------------------

expect_same('proxycheck is the external source', waf_origin_external(array('waf_origin_net' => 'proxycheck')), 'proxycheck');
expect_same('the lists are no external source', waf_origin_external(array('waf_origin_net' => 'x4b')), '');
expect_same('nothing chosen, no external source', waf_origin_external(array()), '');
expect_same('proxycheck has no range file', in_array('proxycheck', array_keys(waf_origin_sources()), true), false);

// --- The request --------------------------------------------------------------

expect_same('the body carries the addresses',
	waf_origin_proxycheck_body(array('192.0.2.10', '2001:db8::5')), 'ips=192.0.2.10,2001:db8::5');
expect_same('what is no address is left out',
	waf_origin_proxycheck_body(array('192.0.2.10', 'kein-ip', '', '192.0.2.10')), 'ips=192.0.2.10');
expect_same('nothing to ask', waf_origin_proxycheck_body(array()), '');

// --- The answer ---------------------------------------------------------------

$read = waf_origin_proxycheck_read(file_get_contents($fixtures . '/answer.json'));
expect_same('the answer is read', $read['ok'], true);
expect_same('three addresses, no other key', array_keys($read['ips']), array('192.0.2.10', '198.51.100.7', '2001:db8::5'));
expect_same('a VPN with its operator', array($read['ips']['192.0.2.10']['is_vpn'], $read['ips']['192.0.2.10']['is_proxy'],
	$read['ips']['192.0.2.10']['vpn_operator']), array('y', 'y', 'Beispiel VPN'));
expect_same('country and provider of the first address', array($read['ips']['192.0.2.10']['country'],
	$read['ips']['192.0.2.10']['asn'], $read['ips']['192.0.2.10']['as_org']), array('DE', 64496, 'Beispiel Netz GmbH'));
expect_same('the organisation stands in for a missing provider', $read['ips']['198.51.100.7']['as_org'], 'Zweites Netz');
expect_same('a lower case country becomes upper case', $read['ips']['198.51.100.7']['country'], 'NL');
expect_same('Tor and data centre of the second address', array($read['ips']['198.51.100.7']['is_tor'],
	$read['ips']['198.51.100.7']['is_hosting'], $read['ips']['198.51.100.7']['is_vpn']), array('y', 'y', 'n'));
expect_same('an address without fields stays empty', $read['ips']['2001:db8::5'],
	array('country' => '', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n',
		'is_proxy' => 'n', 'vpn_operator' => ''));

$denied = waf_origin_proxycheck_read(file_get_contents($fixtures . '/denied.json'));
expect_same('a refused key fails', $denied['ok'], false);
expect_same('the text says what to do',
	strpos($denied['error'], 'Bitte den Schlüssel in den Einstellungen der Abwehr prüfen.') !== false, true);
expect_same('no address from a refused answer', $denied['ips'], array());

$empty = waf_origin_proxycheck_read(file_get_contents($fixtures . '/empty.json'));
expect_same('an answer without an address fails', array($empty['ok'],
	strpos($empty['error'], 'keine Adresse') !== false), array(false, true));
$broken = waf_origin_proxycheck_read('<html>kaputt</html>');
expect_same('an answer that is no JSON fails', array($broken['ok'],
	strpos($broken['error'], 'JSON') !== false), array(false, true));

// --- The daily quota ----------------------------------------------------------

expect_same('a new day starts at zero', waf_origin_quota(array('day' => '2026-09-17', 'queries' => 480), '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 0, 'daily' => 500, 'left' => 500));
expect_same('the same day keeps its count', waf_origin_quota(array('day' => '2026-09-18', 'queries' => 480), '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 480, 'daily' => 500, 'left' => 20));
expect_same('the limit is reached',
	waf_origin_quota(array('day' => '2026-09-18', 'queries' => 500), '2026-09-18', 500)['left'], 0);
expect_same('without a row nothing was asked yet', waf_origin_quota(null, '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 0, 'daily' => 500, 'left' => 500));

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_proxycheck: alle Prüfungen bestanden' . PHP_EOL;
```

- [x] **Step 3: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_proxycheck_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_origin_external()`

- [x] **Step 4: Die Funktionen schreiben**

Ans Ende von `ispconfig/interface/lib/malwatch_waf_origin.inc.php`:

```php

// --- proxycheck.io ------------------------------------------------------------

/**
 * The external source the settings chose, '' when there is none. proxycheck.io
 * answers per address, so it is no entry of waf_origin_sources() and never
 * gets a range file.
 */
function waf_origin_external($settings)
{
	$net = isset($settings['waf_origin_net']) ? (string) $settings['waf_origin_net'] : 'off';
	return $net === 'proxycheck' ? 'proxycheck' : '';
}

/** 'y' when the answer marked the address, 'n' otherwise. */
function waf_origin_mark($value)
{
	if ($value === true || $value === 1 || $value === '1') {
		return 'y';
	}
	return is_string($value) && strtolower($value) === 'yes' ? 'y' : 'n';
}

/**
 * The body of one v3 request: the addresses as the field `ips`. Anything that
 * is no address is left out, and '' means there is nothing to ask.
 */
function waf_origin_proxycheck_body($ips)
{
	$clean = array();
	foreach ($ips as $ip) {
		$ip = trim((string) $ip);
		if ($ip !== '' && waf_origin_bytes($ip) !== '' && !in_array($ip, $clean, true)) {
			$clean[] = $ip;
		}
	}
	return count($clean) === 0 ? '' : 'ips=' . implode(',', $clean);
}

/** The facts of one address from its part of a v3 answer. */
function waf_origin_proxycheck_facts($entry)
{
	$detections = isset($entry['detections']) && is_array($entry['detections']) ? $entry['detections'] : array();
	$network = isset($entry['network']) && is_array($entry['network']) ? $entry['network'] : array();
	$location = isset($entry['location']) && is_array($entry['location']) ? $entry['location'] : array();
	$operator = isset($entry['operator']) && is_array($entry['operator']) ? $entry['operator'] : array();
	$provider = isset($network['provider']) ? trim((string) $network['provider']) : '';
	if ($provider === '' && isset($network['organisation'])) {
		$provider = trim((string) $network['organisation']);
	}
	$country = isset($location['country_code']) ? strtoupper(trim((string) $location['country_code'])) : '';
	return array(
		'country' => preg_match('/^[A-Z]{2}$/', $country) ? $country : '',
		'asn' => isset($network['asn']) ? (int) preg_replace('/[^0-9]/', '', (string) $network['asn']) : 0,
		'as_org' => waf_origin_cut($provider, 128),
		'is_tor' => waf_origin_mark(isset($detections['tor']) ? $detections['tor'] : false),
		'is_vpn' => waf_origin_mark(isset($detections['vpn']) ? $detections['vpn'] : false),
		'is_hosting' => waf_origin_mark(isset($detections['hosting']) ? $detections['hosting'] : false),
		'is_proxy' => waf_origin_mark(isset($detections['proxy']) ? $detections['proxy'] : false),
		'vpn_operator' => waf_origin_cut(isset($operator['name']) ? trim((string) $operator['name']) : '', 64),
	);
}

/**
 * Reads one v3 answer. Returns array('ok' => bool, 'error' => text,
 * 'ips' => array(address => facts)). The text names the cause and the next
 * step; it comes from the answer alone and never carries the key.
 */
function waf_origin_proxycheck_read($text)
{
	$data = json_decode((string) $text, true);
	if (!is_array($data)) {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io antwortete nicht in JSON. Der nächste Durchgang fragt erneut.');
	}
	$status = isset($data['status']) ? strtolower((string) $data['status']) : '';
	$message = isset($data['message'])
		? waf_origin_cut(preg_replace('/\s+/', ' ', trim((string) $data['message'])), 150) : '';
	if ($status === 'denied') {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io hat die Anfrage abgelehnt' . ($message === '' ? '.' : ': ' . $message)
				. ' Bitte den Schlüssel in den Einstellungen der Abwehr prüfen.');
	}
	if ($status === 'error') {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io meldet einen Fehler' . ($message === '' ? '.' : ': ' . $message)
				. ' Der nächste Durchgang fragt erneut.');
	}
	$ips = array();
	foreach ($data as $key => $entry) {
		if (is_array($entry) && waf_origin_bytes((string) $key) !== '') {
			$ips[(string) $key] = waf_origin_proxycheck_facts($entry);
		}
	}
	if (count($ips) === 0) {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io nannte in seiner Antwort keine Adresse. Der nächste Durchgang fragt erneut.');
	}
	return array('ok' => true, 'error' => '', 'ips' => $ips);
}

/**
 * The day and the number of queries of the external source, reset when the day
 * turned. $row is the row of malwatch_waf_origin_source, $today a date as
 * Y-m-d and $daily the limit from the settings.
 */
function waf_origin_quota($row, $today, $daily)
{
	$today = (string) $today;
	$day = is_array($row) && isset($row['day']) ? substr((string) $row['day'], 0, 10) : '';
	$queries = is_array($row) && isset($row['queries']) ? (int) $row['queries'] : 0;
	if ($day !== $today) {
		$day = $today;
		$queries = 0;
	}
	$daily = max(1, (int) $daily);
	return array('day' => $day, 'queries' => $queries, 'daily' => $daily, 'left' => max(0, $daily - $queries));
}
```

- [x] **Step 5: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_proxycheck_test.php`
Expected: `waf_proxycheck: alle Prüfungen bestanden`

- [x] **Step 6: Die anderen Prüfreihen laufen lassen**

Run: `php ispconfig/tests/waf_origin_test.php && php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_lib_test.php`
Expected: dreimal `alle Prüfungen bestanden`. Die neuen Funktionen dürfen an den alten nichts ändern.

- [x] **Step 7: Die CI kennt den neuen Test**

In `.github/workflows/ci.yml` hinter dem Schritt „WAF origin sources" einfügen:

```yaml
      - name: WAF proxycheck
        run: php ispconfig/tests/waf_proxycheck_test.php
```

- [x] **Step 8: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_origin.inc.php ispconfig/tests/waf_proxycheck_test.php ispconfig/tests/fixtures/proxycheck .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): read an answer of proxycheck.io into facts of an address" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task C3: Der Stand der externen Quelle im Panel

Die Einstellungsseite und die Übersicht zeigen bisher nur Quellen mit Bereichsdatei. proxycheck.io braucht eine eigene Zeile: wie viele Abfragen heute rausgingen, wie viele Adressen geprüft sind und was zuletzt schiefging.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (`waf_panel_origin_rows()`, `waf_panel_origin_line()`, neu `waf_panel_origin_external_row()`)
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng`
- Modify: `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng`
- Modify: `ispconfig/tests/check_wiring.sh` (Schlüsselliste der Prüfung 69)
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_origin_external($settings)` und `waf_origin_quota($row, $today, $daily)` aus Task C2
- Produces: jede Zeile von `waf_panel_origin_rows()` hat jetzt zusätzlich `'kind'` (`'ranges'` oder `'addresses'`); die Zeile der externen Quelle hat `'source' => 'proxycheck'`

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_panel_test.php` hinter der Zeile mit `expect_same('the line with everything off', …)` einfügen:

```php
// proxycheck.io steht neben den Bereichsdateien: eine Zeile mit dem Kontingent.
$external_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'off', 'waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_daily' => 500);
$external_rows = array(
	'dbip_country' => array('version' => '2026-09', 'entries' => 512345, 'fetched_at' => '2026-09-17 06:00:00', 'error' => ''),
	'dbip_asn' => array('version' => '2026-09', 'entries' => 410000, 'fetched_at' => '2026-09-17 06:00:00', 'error' => ''),
	'proxycheck' => array('version' => '', 'entries' => 128, 'fetched_at' => '2026-09-18 08:00:00', 'error' => '',
		'day' => '2026-09-18', 'queries' => 240),
);
$external_view = waf_panel_origin_rows($wb, $external_settings, $external_rows, '2026-09-18 09:00:00');
expect_same('the external source gets its own row', array_column($external_view, 'source'),
	array('dbip_country', 'dbip_asn', 'proxycheck'));
expect_same('the external source in words', $external_view[2]['label'], 'proxycheck.io');
expect_same('queries of the day and checked addresses', $external_view[2]['state'],
	'heute 240 von 500 Abfragen, 128 Adressen geprüft');
expect_same('a new day starts at zero',
	waf_panel_origin_rows($wb, $external_settings, $external_rows, '2026-09-19 09:00:00')[2]['state'],
	'heute 0 von 500 Abfragen, 128 Adressen geprüft');
$failed_rows = array('proxycheck' => array('version' => '', 'entries' => 12, 'fetched_at' => '2026-09-18 08:00:00',
	'error' => 'proxycheck.io hat die Anfrage abgelehnt.', 'day' => '2026-09-18', 'queries' => 12));
$failed_view = waf_panel_origin_rows($wb, array('waf_origin_net' => 'proxycheck', 'waf_origin_proxycheck_daily' => 500),
	$failed_rows, '2026-09-18 09:00:00');
expect_same('an error stands before the numbers', array($failed_view[0]['failed'], $failed_view[0]['state']),
	array(1, 'proxycheck.io hat die Anfrage abgelehnt. heute 12 von 500 Abfragen, 12 Adressen geprüft'));
expect_same('the overview counts addresses, not ranges',
	waf_panel_origin_line($wb, array('waf_origin_net' => 'proxycheck', 'waf_origin_proxycheck_daily' => 500), $failed_rows),
	'Herkunft: proxycheck.io 12 Adressen geprüft.');
expect_same('every row says what it counts', array_column($external_view, 'kind'),
	array('ranges', 'ranges', 'addresses'));
```

Die Sprachtexte des Tests stehen in `$wb`; der Test lädt `de_malwatch_waf.lng`, deshalb greifen die neuen Schlüssel aus Step 4 sofort.

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `FAIL the external source gets its own row: array ('dbip_country', 'dbip_asn'), erwartet array ('dbip_country', 'dbip_asn', 'proxycheck')`

- [x] **Step 3: Die Anzeige ergänzen**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` in `waf_panel_origin_rows()` den Rückgabeteil der Schleife um `'kind'` ergänzen — aus

```php
		$view[] = array(
			'source' => $name,
			'label' => waf_panel_text($wb, 'origin_source_' . $name . '_txt', $name),
			'state' => $state,
			'entries' => $entries,
			'failed' => $error !== '' ? 1 : 0,
		);
```

wird

```php
		$view[] = array(
			'source' => $name,
			'label' => waf_panel_text($wb, 'origin_source_' . $name . '_txt', $name),
			'state' => $state,
			'entries' => $entries,
			'failed' => $error !== '' ? 1 : 0,
			'kind' => 'ranges',
		);
```

Direkt vor `return $view;` derselben Funktion:

```php
	// proxycheck.io lädt keine Datei; seine Zeile nennt das Kontingent des Tages.
	$external = waf_origin_external($settings);
	if ($external !== '') {
		$view[] = waf_panel_origin_external_row($wb, $settings, isset($rows[$external]) ? $rows[$external] : null, $now);
	}
```

Hinter `waf_panel_origin_rows()` die neue Funktion:

```php
/**
 * The state of the external source: the queries of today against the daily
 * limit, how many addresses carry an answer and the last error before them.
 */
function waf_panel_origin_external_row($wb, $settings, $row, $now)
{
	$today = substr((string) $now, 0, 10);
	$quota = waf_origin_quota($row, $today === '' ? gmdate('Y-m-d') : $today,
		isset($settings['waf_origin_proxycheck_daily']) ? $settings['waf_origin_proxycheck_daily'] : 0);
	$entries = is_array($row) ? (int) $row['entries'] : 0;
	$error = is_array($row) ? (string) $row['error'] : '';
	$state = sprintf(waf_panel_text($wb, 'origin_state_external_txt', '%1$s %2$s %3$s'),
		number_format($quota['queries'], 0, ',', '.'), number_format($quota['daily'], 0, ',', '.'),
		number_format($entries, 0, ',', '.'));
	return array(
		'source' => 'proxycheck',
		'label' => waf_panel_text($wb, 'origin_source_proxycheck_txt', 'proxycheck.io'),
		'state' => $error === '' ? $state : $error . ' ' . $state,
		'entries' => $entries,
		'failed' => $error === '' ? 0 : 1,
		'kind' => 'addresses',
	);
}
```

In `waf_panel_origin_line()` die Zeile mit `origin_line_entries_txt` ersetzen:

```php
		$parts[] = $row['label'] . ' ' . ($row['entries'] > 0
			? sprintf(waf_panel_text($wb, $row['kind'] === 'addresses' ? 'origin_line_checked_txt' : 'origin_line_entries_txt', '%s'),
				number_format($row['entries'], 0, ',', '.'))
			: waf_panel_text($wb, 'origin_line_none_txt', ''));
```

Am Kopf derselben Datei sicherstellen, dass die Herkunftsbibliothek geladen ist (steht seit 0.21.0 dort):

```php
require_once __DIR__ . '/malwatch_waf_origin.inc.php';
```

- [x] **Step 4: Die Texte ergänzen**

In `ispconfig/interface/lang/de_malwatch_waf.lng` hinter `$wb['origin_source_x4b_datacenter_txt']`:

```php
$wb['origin_source_proxycheck_txt'] = 'proxycheck.io';
$wb['origin_state_external_txt'] = 'heute %1$s von %2$s Abfragen, %3$s Adressen geprüft';
$wb['origin_line_checked_txt'] = '%s Adressen geprüft';
```

In `ispconfig/interface/lang/en_malwatch_waf.lng` an derselben Stelle:

```php
$wb['origin_source_proxycheck_txt'] = 'proxycheck.io';
$wb['origin_state_external_txt'] = '%1$s of %2$s queries today, %3$s addresses checked';
$wb['origin_line_checked_txt'] = '%s addresses checked';
```

Dieselben drei Zeilen kommen in `de_malwatch_waf_config.lng` und `en_malwatch_waf_config.lng` hinter die Quellennamen, weil die Einstellungsseite ihr eigenes Wörterbuch liest.

- [x] **Step 5: Prüfung 69 kennt die neuen Schlüssel**

In `ispconfig/tests/check_wiring.sh` in der Schlüsselliste der Prüfung 69 hinter `origin_state_keep_txt` ergänzen:

```
origin_source_proxycheck_txt origin_state_external_txt origin_line_checked_txt
```

- [x] **Step 6: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php`
Expected: zweimal `alle Prüfungen bestanden`

Run (im Hintergrund, weil langsam): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [x] **Step 7: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/lang ispconfig/tests/waf_panel_test.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the state of proxycheck.io in the panel" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task C4: Die Einstellungsseite

Der Betreiber wählt proxycheck.io, trägt seinen Schlüssel ein und setzt das Tageslimit. Der Schlüssel verhält sich wie der von MaxMind: verdeckt angezeigt, ein leeres Feld behält ihn, ein Haken löscht ihn. Ohne Schlüssel speichert die Seite nicht.

Die beiden Regeln stecken bisher als Wenn-Ketten in `onSubmit()` und sind dort nur über das Panel prüfbar. Sie ziehen in zwei Funktionen der Panel-Bibliothek um; damit prüft `waf_panel_test.php` sie einzeln, und die Seite bleibt kurz.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (neu `waf_panel_key_keep()`, `waf_panel_origin_missing()`)
- Modify: `ispconfig/interface/form/malwatch_waf_config.tform.php`
- Modify: `ispconfig/interface/malwatch_waf_config_edit.php`
- Modify: `ispconfig/interface/templates/malwatch_waf_config_edit.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng`
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_panel_key_mask($key)` aus dem Panel-Teil, die Einstellungen aus Task C1
- Produces:
  - `waf_panel_key_keep($posted, $stored, $clear)` → der Schlüssel, der gespeichert wird
  - `waf_panel_origin_missing($record)` → Liste der Wörterbuch-Schlüssel der Meldungen, leer wenn nichts fehlt
  - Formularfelder `waf_origin_proxycheck_key` (mit Haken `waf_origin_proxycheck_clear`) und `waf_origin_proxycheck_daily`

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_panel_test.php` hinter den Prüfungen aus Task C3 anfügen:

```php
// Ein Schlüssel im Formular: leer behält, verdeckt behält, der Haken löscht.
expect_same('an empty field keeps the stored key', waf_panel_key_keep('', 'ab-12cd', false), 'ab-12cd');
expect_same('the masked value keeps the stored key',
	waf_panel_key_keep(waf_panel_key_mask('ab-12cd'), 'ab-12cd', false), 'ab-12cd');
expect_same('a new key replaces the stored one', waf_panel_key_keep(' neu-4711 ', 'ab-12cd', false), 'neu-4711');
expect_same('the checkbox removes the key', waf_panel_key_keep('neu-4711', 'ab-12cd', true), '');
expect_same('nothing stored, nothing posted', waf_panel_key_keep('', '', false), '');

// Was die Seite vor dem Speichern vermisst.
expect_same('nothing is missing', waf_panel_origin_missing(array('waf_origin_geo' => 'dbip', 'waf_origin_net' => 'x4b')), array());
expect_same('MaxMind without an account', waf_panel_origin_missing(array('waf_origin_geo' => 'maxmind',
	'waf_origin_maxmind_account' => '', 'waf_origin_maxmind_key' => 'abc')), array('waf_origin_maxmind_missing_error'));
expect_same('proxycheck without a key', waf_panel_origin_missing(array('waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_key' => '')), array('waf_origin_proxycheck_missing_error'));
expect_same('proxycheck with a key', waf_panel_origin_missing(array('waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_key' => 'ab-12cd')), array());
expect_same('both are missing', waf_panel_origin_missing(array('waf_origin_geo' => 'maxmind', 'waf_origin_net' => 'proxycheck')),
	array('waf_origin_maxmind_missing_error', 'waf_origin_proxycheck_missing_error'));
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_panel_key_keep()`

- [x] **Step 3: Die beiden Funktionen schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` hinter `waf_panel_key_mask()`:

```php
/**
 * The key the form wants stored: an empty field and the masked value keep the
 * stored key, the checkbox removes it, anything else is the new key.
 */
function waf_panel_key_keep($posted, $stored, $clear)
{
	$stored = (string) $stored;
	if ($clear) {
		return '';
	}
	$posted = trim((string) $posted);
	return ($posted === '' || $posted === waf_panel_key_mask($stored)) ? $stored : $posted;
}

/**
 * What the settings page is missing before it may save: the wordbook keys of
 * the messages, in the order of the fields. A source that needs a key and has
 * none stops the save.
 */
function waf_panel_origin_missing($record)
{
	$missing = array();
	$geo = isset($record['waf_origin_geo']) ? (string) $record['waf_origin_geo'] : 'off';
	$net = isset($record['waf_origin_net']) ? (string) $record['waf_origin_net'] : 'off';
	$account = isset($record['waf_origin_maxmind_account']) ? trim((string) $record['waf_origin_maxmind_account']) : '';
	$maxmind = isset($record['waf_origin_maxmind_key']) ? trim((string) $record['waf_origin_maxmind_key']) : '';
	$proxycheck = isset($record['waf_origin_proxycheck_key']) ? trim((string) $record['waf_origin_proxycheck_key']) : '';
	if ($geo === 'maxmind' && ($account === '' || $maxmind === '')) {
		$missing[] = 'waf_origin_maxmind_missing_error';
	}
	if ($net === 'proxycheck' && $proxycheck === '') {
		$missing[] = 'waf_origin_proxycheck_missing_error';
	}
	return $missing;
}
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [x] **Step 5: Das Formular ergänzen**

In `ispconfig/interface/form/malwatch_waf_config.tform.php` die Auswahl des Netzes ersetzen und die zwei Felder anhängen:

```php
		'waf_origin_net' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'x4b' => 'origin_net_x4b_txt',
				'proxycheck' => 'origin_net_proxycheck_txt'
			)
		),
		'waf_origin_proxycheck_key' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9-]{0,128}$/',
					'errmsg' => 'waf_origin_proxycheck_key_error'
				)
			),
			'value' => '',
			'width' => '30',
			'maxlength' => '128'
		),
		'waf_origin_proxycheck_daily' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '500',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:100000',
					'errmsg' => 'waf_origin_proxycheck_daily_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
```

- [x] **Step 6: Die Seite auf die Funktionen umstellen**

In `ispconfig/interface/malwatch_waf_config_edit.php` hinter `private $waf_stored_key = '';`:

```php
	/** The stored key of proxycheck.io, read in onLoad() before the form overwrites it. */
	private $waf_stored_proxycheck = '';
```

In `onLoad()` die Abfrage des gespeicherten Schlüssels ersetzen:

```php
		$stored = $app->db->queryOneRecord(
			'SELECT waf_origin_maxmind_key, waf_origin_proxycheck_key FROM malwatch_config WHERE config_id = 1');
		$this->waf_stored_key = is_array($stored) && isset($stored['waf_origin_maxmind_key'])
			? (string) $stored['waf_origin_maxmind_key'] : '';
		$this->waf_stored_proxycheck = is_array($stored) && isset($stored['waf_origin_proxycheck_key'])
			? (string) $stored['waf_origin_proxycheck_key'] : '';
```

In `onSubmit()` den ganzen Block zwischen `$wb = $this->waf_wb;` und `parent::onSubmit();` ersetzen:

```php
		$this->dataRecord['waf_origin_maxmind_key'] = waf_panel_key_keep(
			isset($this->dataRecord['waf_origin_maxmind_key']) ? $this->dataRecord['waf_origin_maxmind_key'] : '',
			$this->waf_stored_key,
			isset($this->dataRecord['waf_origin_key_clear']) && (string) $this->dataRecord['waf_origin_key_clear'] === '1');
		$this->dataRecord['waf_origin_proxycheck_key'] = waf_panel_key_keep(
			isset($this->dataRecord['waf_origin_proxycheck_key']) ? $this->dataRecord['waf_origin_proxycheck_key'] : '',
			$this->waf_stored_proxycheck,
			isset($this->dataRecord['waf_origin_proxycheck_clear'])
				&& (string) $this->dataRecord['waf_origin_proxycheck_clear'] === '1');
		foreach (waf_panel_origin_missing($this->dataRecord) as $message) {
			$app->tform->errorMessage .= $wb[$message] . '<br />';
		}
```

Der Kommentar über `onSubmit()` bekommt einen Satz dazu: „Dasselbe gilt für den Schlüssel von proxycheck.io."

In `onShowEnd()` hinter der Zeile, die den MaxMind-Schlüssel verdeckt setzt:

```php
		$app->tpl->setVar('waf_origin_proxycheck_key',
			$app->functions->htmlentities(waf_panel_key_mask($this->waf_stored_proxycheck)));
		$app->tpl->setVar('origin_proxycheck_stored', $this->waf_stored_proxycheck === '' ? 0 : 1);
```

- [x] **Step 7: Die Vorlage ergänzen**

In `ispconfig/interface/templates/malwatch_waf_config_edit.htm` hinter dem Block der Auswahl `waf_origin_net` einfügen:

```html
<div class="form-group">
	<label for="waf_origin_proxycheck_key" class="col-sm-3 control-label">{tmpl_var name='waf_origin_proxycheck_key_txt'}</label>
	<div class="col-sm-9">
		<input type="text" name="waf_origin_proxycheck_key" id="waf_origin_proxycheck_key" value="{tmpl_var name='waf_origin_proxycheck_key'}" class="form-control" autocomplete="off" maxlength="128" />
		<span class="help-block">{tmpl_var name='waf_origin_proxycheck_key_hint_txt'}</span>
		<tmpl_if name="origin_proxycheck_stored">
		<label class="mw-wafcfg-clear"><input type="checkbox" name="waf_origin_proxycheck_clear" value="1" /> {tmpl_var name='origin_key_clear_txt'}</label>
		</tmpl_if>
		<p class="mw-wafcfg-note">{tmpl_var name='origin_proxycheck_privacy_txt'}</p>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_proxycheck_daily" class="col-sm-3 control-label">{tmpl_var name='waf_origin_proxycheck_daily_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="100000" step="1" name="waf_origin_proxycheck_daily" id="waf_origin_proxycheck_daily" value="{tmpl_var name='waf_origin_proxycheck_daily'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_origin_proxycheck_daily_hint_txt'}</span>
	</div>
</div>
```

- [x] **Step 8: Die Texte ergänzen**

In `ispconfig/interface/lang/de_malwatch_waf_config.lng` hinter `$wb['waf_origin_net_hint_txt']`:

```php
$wb['origin_net_proxycheck_txt'] = 'proxycheck.io (Schlüssel nötig)';
$wb['waf_origin_proxycheck_key_txt'] = 'proxycheck.io: Schlüssel';
$wb['waf_origin_proxycheck_key_hint_txt'] = 'Buchstaben, Ziffern und Bindestriche. Ein gespeicherter Schlüssel steht hier verdeckt; ein leeres Feld behält ihn.';
$wb['waf_origin_proxycheck_daily_txt'] = 'proxycheck.io: Abfragen je Tag';
$wb['waf_origin_proxycheck_daily_hint_txt'] = 'So viele Adressen fragt der Server höchstens an einem Tag ab. Ist die Zahl erreicht, warten die übrigen Adressen bis zum nächsten Tag.';
$wb['origin_proxycheck_privacy_txt'] = 'Jede neue Adresse aus einem Treffer geht an proxycheck.io. Prüfe die Datenschutzbedingungen des Dienstes, bevor du ihn einschaltest.';
$wb['waf_origin_proxycheck_key_error'] = 'proxycheck.io: Schlüssel: Erlaubt sind Buchstaben, Ziffern und Bindestriche, höchstens 128 Zeichen. Bitte den Schlüssel aus dem Konto bei proxycheck.io einsetzen.';
$wb['waf_origin_proxycheck_daily_error_range'] = 'proxycheck.io: Abfragen je Tag: Erlaubt sind ganze Zahlen von 1 bis 100000. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_origin_proxycheck_missing_error'] = 'proxycheck.io braucht einen Schlüssel. Bitte den Schlüssel eintragen oder bei „VPN und Rechenzentrum“ eine andere Quelle wählen.';
```

In `ispconfig/interface/lang/en_malwatch_waf_config.lng` an derselben Stelle:

```php
$wb['origin_net_proxycheck_txt'] = 'proxycheck.io (key needed)';
$wb['waf_origin_proxycheck_key_txt'] = 'proxycheck.io: key';
$wb['waf_origin_proxycheck_key_hint_txt'] = 'Letters, digits and hyphens. A stored key is shown masked here; an empty field keeps it.';
$wb['waf_origin_proxycheck_daily_txt'] = 'proxycheck.io: queries per day';
$wb['waf_origin_proxycheck_daily_hint_txt'] = 'At most this many addresses are asked for in one day. Once the number is reached, the other addresses wait for the next day.';
$wb['origin_proxycheck_privacy_txt'] = 'Every new address of a hit goes to proxycheck.io. Please check the privacy terms of the service before switching it on.';
$wb['waf_origin_proxycheck_key_error'] = 'proxycheck.io: key: letters, digits and hyphens are allowed, at most 128 characters. Please paste the key from your account at proxycheck.io.';
$wb['waf_origin_proxycheck_daily_error_range'] = 'proxycheck.io: queries per day: whole numbers from 1 to 100000 are allowed. Please adjust the value and save again.';
$wb['waf_origin_proxycheck_missing_error'] = 'proxycheck.io needs a key. Please enter the key or choose another source under "VPN and data centre".';
```

Dazu bekommt `waf_origin_net_hint_txt` in beiden Sprachen einen Satz über den Unterschied der beiden Quellen:

```php
$wb['waf_origin_net_hint_txt'] = 'Die Listen von X4BNet nennen bekannte VPN-Netze und Rechenzentren; sie werden heruntergeladen, Adressen bleiben auf dem Server. proxycheck.io beantwortet jede Adresse einzeln und bekommt sie dafür übermittelt.';
```

```php
$wb['waf_origin_net_hint_txt'] = 'The lists of X4BNet name known VPN networks and data centres; they are downloaded, addresses stay on the server. proxycheck.io answers per address and is given that address.';
```

- [x] **Step 9: Alle Prüfreihen und die Vorschau**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_proxycheck_test.php`
Expected: viermal `alle Prüfungen bestanden`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`

Run: `grep -c 'waf_origin_proxycheck_key\|proxycheck.io: Abfragen je Tag\|Prüfe die Datenschutzbedingungen' .superpowers/abwehr/harness/out_cfg.html`
Expected: mindestens `3` — Feld, Tageslimit und Datenschutzhinweis stehen auf der Seite.

- [x] **Step 10: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/form/malwatch_waf_config.tform.php ispconfig/interface/malwatch_waf_config_edit.php ispconfig/interface/templates/malwatch_waf_config_edit.htm ispconfig/interface/lang ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the settings page takes the key and the daily limit of proxycheck.io" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task C5: Der Abruf im Cron

Der Schritt, der proxycheck.io fragt: Adressen im Zustand `pending` sammeln, eine Anfrage schicken, die Antwort in `malwatch_waf_ip` eintragen, das Kontingent des Tages fortschreiben und bei einem Fehler sauber wieder herauskommen.

Die Klasse braucht eine Datenbank und läuft deshalb nur auf dem Server. Der Test dafür ist `waf_class_probe.php`; er wird hier geschrieben und in Task C7, Block 1 auf dem Server gegen eine Wegwerf-Datenbank ausgeführt. Lokal prüfen `php -l`, `check_wiring.sh` und die Prüfreihen ohne Datenbank.

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_waf.inc.php`
- Modify: `ispconfig/tests/waf_class_probe.php`
- Modify: `ispconfig/tests/check_wiring.sh`

**Interfaces:**
- Consumes: `waf_origin_external()`, `waf_origin_proxycheck_body()`, `waf_origin_proxycheck_read()`, `waf_origin_quota()` aus Task C2
- Produces:
  - `malwatch_waf::$poster` — Naht für Tests: `function ($url, $body, $limit)` liefert `array(ok, text)`
  - `malwatch_waf::post($url, $body, $limit)` → `array(ok, text)`
  - `malwatch_waf::origin_external($limit = 100)` → Zahl der Adressen mit Antwort
  - `malwatch_waf::origin_external_state($name, $quota, $error, $now)` (privat)

- [x] **Step 1: Die Probe schreiben, die noch scheitert**

In `ispconfig/tests/waf_class_probe.php` hinter dem Abschnitt „B6: the addresses of the hits" anfügen:

```php
// --- C5: proxycheck.io --------------------------------------------------------

// Der Dienst ist die Naht: die Probe antwortet aus einer Beispieldatei und hält
// fest, wonach gefragt wurde.
$asked = array();
$answer_file = $stage . '/tests/fixtures/proxycheck/answer.json';
$waf->poster = function ($url, $body, $limit) use (&$asked, $answer_file) {
	$asked[] = array($url, $body);
	return array(true, file_get_contents($answer_file));
};
$db->query("UPDATE malwatch_config SET waf_origin_net = 'proxycheck', waf_origin_proxycheck_key = 'probe-key', "
	. 'waf_origin_proxycheck_daily = 3 WHERE config_id = 1');
$db->query("UPDATE malwatch_waf_ip SET external_state = 'none', external_tries = 0, external_at = NULL");
$db->query("DELETE FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");

// Das Nachschlagen stellt jede Adresse ohne Antwort in die Schlange.
$waf->origin_lookup(10);
expect_same('every address waits for the service',
	count_rows("SELECT ip FROM malwatch_waf_ip WHERE external_state = 'pending'"), 3);

expect_same('two of three addresses get an answer', $waf->origin_external(100), 2);
expect_same('one request with every address', count($asked), 1);
expect_same('the key travels in the address', strpos($asked[0][0], 'key=probe-key') !== false, true);
expect_same('the body names the addresses', substr($asked[0][1], 0, 4), 'ips=');
$vpn = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('the service marks VPN, proxy and its operator',
	array($vpn['is_vpn'], $vpn['is_proxy'], $vpn['vpn_operator'], $vpn['external_state']),
	array('y', 'y', 'Beispiel VPN', 'done'));
expect_same('country and provider come from the service because the local one is off',
	array($vpn['country'], (int) $vpn['asn'], $vpn['as_org']), array('DE', 64496, 'Beispiel Netz GmbH'));
expect_same('the Tor list keeps its own answer', $vpn['is_tor'], 'y');
$miss = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '198.51.100.9'");
expect_same('an address the answer left out is tried again later',
	array($miss['external_state'], (int) $miss['external_tries']), array('failed', 1));
$state = $db->queryOneRecord("SELECT * FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");
expect_same('the state counts queries and answers',
	array((int) $state['queries'], (int) $state['entries'], $state['error']), array(3, 2, ''));

// Das Tageslimit ist erreicht: wartende Adressen kommen morgen dran.
$db->query("UPDATE malwatch_waf_ip SET external_state = 'pending' WHERE ip = '198.51.100.9'");
$asked = array();
expect_same('nothing is asked past the daily limit', $waf->origin_external(100), 0);
expect_same('no request went out', count($asked), 0);
expect_same('the address waits for the next day',
	$db->queryOneRecord("SELECT external_state FROM malwatch_waf_ip WHERE ip = '198.51.100.9'")['external_state'], 'limit');

// Ein höheres Limit holt die Adresse zurück, eine abgelehnte Anfrage lässt sie scheitern.
$db->query('UPDATE malwatch_config SET waf_origin_proxycheck_daily = 10 WHERE config_id = 1');
$waf->poster = function ($url, $body, $limit) use (&$asked, $stage) {
	$asked[] = array($url, $body);
	return array(true, file_get_contents($stage . '/tests/fixtures/proxycheck/denied.json'));
};
expect_same('a refused answer gives no address', $waf->origin_external(100), 0);
$failed = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '198.51.100.9'");
expect_same('the address failed once more', array($failed['external_state'], (int) $failed['external_tries']),
	array('failed', 2));
$state = $db->queryOneRecord("SELECT * FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");
expect_same('the error stands in the state, without the key',
	array(strpos($state['error'], 'abgelehnt') !== false, strpos($state['error'], 'probe-key')),
	array(true, false));

// Wird der Dienst abgeschaltet, gehen seine Merkmale und seine Zeile.
$db->query("UPDATE malwatch_config SET waf_origin_net = 'off' WHERE config_id = 1");
$waf->queue('origin_update', array(), 'probe');
$waf->pass();
expect_same('the state of the service is gone',
	count_rows("SELECT source FROM malwatch_waf_origin_source WHERE source = 'proxycheck'"), 0);
$cleared = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('its marks left the addresses',
	array($cleared['is_proxy'], $cleared['vpn_operator'], $cleared['external_state']), array('n', '', 'none'));
```

Der Abschnitt steht vor dem bisherigen Ende des Abschnitts B6 (`$db->query("DELETE FROM malwatch_waf_hit WHERE unique_id = 'probe-origin'");`), damit der Treffer, den B6 angelegt hat, noch da ist.

- [x] **Step 2: Die Probe auf Syntax prüfen**

Run: `php -l ispconfig/tests/waf_class_probe.php`
Expected: `No syntax errors detected`. Der Lauf selbst braucht root und eine Wegwerf-Datenbank; er kommt in Task C7, Block 1.

- [x] **Step 3: Die Naht und den POST schreiben**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` hinter der Eigenschaft `$fetcher`:

```php
	/**
	 * Takes the place of the request to an external service when set:
	 * function ($url, $body, $limit) returning array(ok, text).
	 */
	public $poster = null;
```

Hinter der Methode `fetch()`:

```php
	/**
	 * Sends one request to an external service and returns array(ok, text).
	 * The text is the answer or, when the request failed, the reason; the key
	 * of the service travels in the address and never in this text.
	 */
	public function post($url, $body, $limit)
	{
		if ($this->poster !== null) {
			return call_user_func($this->poster, $url, $body, $limit);
		}
		if (!function_exists('curl_init')) {
			return array(false, 'Die PHP-Erweiterung curl fehlt. Bitte php-curl nachinstallieren; ohne sie fragt der Server keinen Dienst.');
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($curl, CURLOPT_TIMEOUT, 10);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt($curl, CURLOPT_USERAGENT, 'malwatch/' . $this->version());
		$text = curl_exec($curl);
		$status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
		$error = curl_error($curl);
		curl_close($curl);
		if ($text === false) {
			return array(false, 'Die Anfrage scheiterte: ' . waf_cut(preg_replace('/\s+/', ' ', $error), 150)
				. ' Der nächste Durchgang fragt erneut.');
		}
		if ($status >= 400) {
			return array(false, 'Der Dienst antwortete mit ' . $status . '. Der nächste Durchgang fragt erneut.');
		}
		return array(true, waf_cut((string) $text, (int) $limit));
	}
```

- [x] **Step 4: Den Abruf schreiben**

Hinter `origin_lookup()` in derselben Datei:

```php
	/**
	 * Asks the external service about the addresses that wait for an answer.
	 * One pass sends at most one request with $limit addresses and never goes
	 * past the daily limit of the settings. Returns how many addresses got an
	 * answer. The log of the source names numbers and reasons, never the key
	 * and never an address.
	 */
	public function origin_external($limit = 100)
	{
		global $app, $conf;

		$settings = $this->settings();
		$name = waf_origin_external($settings);
		if ($name === '') {
			return 0;
		}
		$now = $this->now();
		$row = $app->dbmaster->queryOneRecord(
			'SELECT * FROM malwatch_waf_origin_source WHERE server_id = ? AND source = ?', $conf['server_id'], $name);
		$quota = waf_origin_quota($row, substr($now, 0, 10), $settings['waf_origin_proxycheck_daily']);
		// An answer that failed comes back in line after an hour, three times in all.
		$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'pending' WHERE server_id = ? "
			. "AND external_state = 'failed' AND external_tries < 3 AND (external_at IS NULL OR external_at < ?)",
			$conf['server_id'], gmdate('Y-m-d H:i:s', strtotime($now) - 3600));
		if ($quota['left'] <= 0) {
			$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'limit' WHERE server_id = ? "
				. "AND external_state = 'pending'", $conf['server_id']);
			$this->origin_external_state($name, $quota, 'Das Tageslimit von ' . $quota['daily']
				. ' Abfragen ist erreicht. Die übrigen Adressen kommen am nächsten Tag an die Reihe.', $now);
			return 0;
		}
		// There is room again, so what waited for the limit joins the queue.
		$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'pending' WHERE server_id = ? "
			. "AND external_state = 'limit'", $conf['server_id']);
		$key = (string) $settings['waf_origin_proxycheck_key'];
		if ($key === '') {
			$this->origin_external_state($name, $quota, 'Für proxycheck.io fehlt der Schlüssel. Bitte ihn in den '
				. 'Einstellungen der Abwehr eintragen.', $now);
			return 0;
		}
		$take = min(max(1, (int) $limit), $quota['left']);
		$ips = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords("SELECT ip FROM malwatch_waf_ip WHERE server_id = ? "
			. "AND external_state = 'pending' ORDER BY ip LIMIT ?", $conf['server_id'], $take)) as $one) {
			$ips[] = (string) $one['ip'];
		}
		$body = waf_origin_proxycheck_body($ips);
		if ($body === '') {
			return 0;
		}
		$answer = $this->post('https://proxycheck.io/v3/?key=' . rawurlencode($key), $body, 2 * 1024 * 1024);
		$read = $answer[0] ? waf_origin_proxycheck_read($answer[1])
			: array('ok' => false, 'error' => $answer[1], 'ips' => array());
		$quota['queries'] += count($ips);
		if (!$read['ok']) {
			$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'failed', external_at = ?, "
				. 'external_tries = external_tries + 1 WHERE server_id = ? AND ip IN ?', $now, $conf['server_id'], $ips);
			$this->origin_external_state($name, $quota, $read['error'], $now);
			return 0;
		}
		// The service replaces VPN, data centre and proxy. Country, provider and
		// Tor stay with the local lists as long as one of them is chosen.
		$with_geo = (string) $settings['waf_origin_geo'] === 'off';
		$with_tor = (string) $settings['waf_origin_tor'] === 'off';
		$done = 0;
		foreach ($ips as $ip) {
			if (!isset($read['ips'][$ip])) {
				$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'failed', external_at = ?, "
					. 'external_tries = external_tries + 1 WHERE server_id = ? AND ip = ?',
					$now, $conf['server_id'], $ip);
				continue;
			}
			$facts = $read['ips'][$ip];
			$fields = 'is_vpn = ?, is_hosting = ?, is_proxy = ?, vpn_operator = ?';
			$values = array($facts['is_vpn'], $facts['is_hosting'], $facts['is_proxy'], $facts['vpn_operator']);
			if ($with_geo) {
				$fields .= ', country = ?, asn = ?, as_org = ?';
				$values[] = $facts['country'];
				$values[] = $facts['asn'];
				$values[] = $facts['as_org'];
			}
			if ($with_tor) {
				$fields .= ', is_tor = ?';
				$values[] = $facts['is_tor'];
			}
			$values[] = $now;
			$values[] = $conf['server_id'];
			$values[] = $ip;
			call_user_func_array(array($app->dbmaster, 'query'), array_merge(array('UPDATE malwatch_waf_ip SET '
				. $fields . ", external_state = 'done', external_at = ?, external_tries = 0 "
				. 'WHERE server_id = ? AND ip = ?'), $values));
			$done++;
		}
		$this->origin_external_state($name, $quota, '', $now);
		return $done;
	}

	/**
	 * Writes the state of the external source: the queries of the day, how many
	 * addresses carry an answer and what went wrong last. The text comes from
	 * the answer and never carries the key.
	 */
	private function origin_external_state($name, $quota, $error, $now)
	{
		global $app, $conf;

		$known = $app->dbmaster->queryOneRecord("SELECT COUNT(*) AS n FROM malwatch_waf_ip WHERE server_id = ? "
			. "AND external_state = 'done'", $conf['server_id']);
		$entries = is_array($known) ? (int) $known['n'] : 0;
		$error = waf_cut((string) $error, 255);
		$app->dbmaster->query('INSERT INTO malwatch_waf_origin_source (server_id, source, version, checked_at, '
			. "fetched_at, entries, error, error_at, day, queries) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?) "
			. 'ON DUPLICATE KEY UPDATE checked_at = VALUES(checked_at), entries = VALUES(entries), '
			. 'error = VALUES(error), error_at = VALUES(error_at), day = VALUES(day), queries = VALUES(queries), '
			. "fetched_at = IF(VALUES(error) = '', VALUES(checked_at), fetched_at)",
			$conf['server_id'], $name, $now, $error === '' ? $now : null, $entries, $error,
			$error === '' ? null : $now, $quota['day'], $quota['queries']);
	}
```

- [x] **Step 5: Den Abruf anschließen**

In `cron_minute()` hinter `$this->origin_lookup();` einfügen:

```php
			$this->origin_external();
```

In `origin_lookup()` direkt hinter `$settings = $this->settings();` einfügen, also vor jedem vorzeitigen `return`:

```php
		// A new address goes to the external service as soon as one is chosen.
		if (waf_origin_external($settings) !== '') {
			$app->dbmaster->query("UPDATE malwatch_waf_ip SET external_state = 'pending' WHERE server_id = ? "
				. "AND external_state = 'none'", $conf['server_id']);
		}
```

In `run_origin_update()` die Schleife über die abgewählten Quellen ersetzen:

```php
		$chosen = waf_origin_chosen($settings);
		$external = waf_origin_external($settings);
		foreach ($states as $name => $row) {
			if (in_array($name, $chosen, true) || $name === $external) {
				continue;
			}
			if ($name === 'proxycheck') {
				// The service is off: its marks and its state leave the addresses.
				$app->dbmaster->query("UPDATE malwatch_waf_ip SET is_proxy = 'n', vpn_operator = '', "
					. "external_state = 'none', external_at = NULL, external_tries = 0 WHERE server_id = ?",
					$conf['server_id']);
			} else {
				@unlink($dir . '/' . $name . '.bin');
				$app->dbmaster->query('UPDATE malwatch_waf_ip SET local_at = NULL WHERE server_id = ?',
					$conf['server_id']);
			}
			$app->dbmaster->query('DELETE FROM malwatch_waf_origin_source WHERE server_id = ? AND source = ?',
				$conf['server_id'], $name);
			$notes[] = $name . ': abgeschaltet, Daten entfernt';
		}
```

- [x] **Step 6: Syntax prüfen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/tests/waf_class_probe.php`
Expected: zweimal `No syntax errors detected`

- [x] **Step 7: Die Verdrahtung prüfen**

In `ispconfig/tests/check_wiring.sh` vor dem abschließenden `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 70. proxycheck.io answers per address, so it is no source with a range file.
#     An entry in waf_origin_sources() would make origin_update download it.
origin_lib="$root/interface/lib/malwatch_waf_origin.inc.php"
if [ -f "$origin_lib" ]; then
	grep -q 'function waf_origin_external(' "$origin_lib" \
		|| fail "malwatch_waf_origin.inc.php has no waf_origin_external(); nothing names the external source"
	if sed -n '/function waf_origin_sources(/,/^}/p' "$origin_lib" | grep -q 'proxycheck'; then
		fail "waf_origin_sources() names proxycheck; the external service has no range file"
	fi
fi

# 71. The external step runs in the cron of every minute, right after the local
#     lookup, and the class keeps the seam a probe replaces.
if [ -f "$waf_class" ]; then
	grep -q 'public \$poster' "$waf_class" \
		|| fail "malwatch_waf.inc.php has no \$poster; a probe cannot answer for proxycheck.io"
	sed -n '/public function cron_minute(/,/^\t}/p' "$waf_class" | grep -q 'origin_external(' \
		|| fail "cron_minute() never asks the external service"
	grep -q 'https://proxycheck.io/v3/' "$waf_class" \
		|| fail "malwatch_waf.inc.php never calls the v3 address of proxycheck.io"
fi

# 72. The key travels in the address of the request and nowhere else: never in a
#     job log, never in the log of ISPConfig, never in the state of the source.
if [ -f "$waf_class" ]; then
	if grep -n '\$key' "$waf_class" | grep -qE 'finish\(|app->log\(|origin_external_state\('; then
		fail "malwatch_waf.inc.php puts the key into a log; it belongs into the address alone"
	fi
fi
```

Die Zeile `waf_class="$root/server/lib/classes/malwatch_waf.inc.php"` steht bereits weiter oben in der Datei; die Prüfungen 70 bis 72 nutzen sie.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [x] **Step 8: Alle Prüfreihen**

Run: `php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_rules_catalog_test.php && php ispconfig/tests/waf_origin_test.php && php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_proxycheck_test.php`
Expected: siebenmal `alle Prüfungen bestanden`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`

- [x] **Step 9: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_class_probe.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): ask proxycheck.io about the addresses of the hits" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task C6: Release 0.22.0

Version, Changelog und die beiden README-Dateien ziehen nach, danach läuft die ganze Prüfstrecke einmal am Stück.

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`
- Modify: `CHANGELOG.md`, `README.md`, `ispconfig/README.md`
- Modify: `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` (Notiz, dass Teil B II umgesetzt ist)

**Interfaces:**
- Consumes: alles aus C1 bis C5
- Produces: den Stand `0.22.0` auf dem Zweig `waf-herkules`

- [x] **Step 1: Version hochziehen**

In `internal/version/version.go`:

```go
var Version = "0.22.0"
```

In `ispconfig/version`:

```
0.22.0
```

- [x] **Step 2: Changelog**

In `CHANGELOG.md` über den Eintrag `## [0.21.1]`; das Datum ist der Tag, an dem Block 2 läuft:

```markdown
## [0.22.0] – 2026-09-18

### Neu

**proxycheck.io als Quelle für VPN, Proxy und Rechenzentrum.** Unter **Security >
Abwehr > Einstellungen** steht bei „VPN und Rechenzentrum“ neben den X4BNet-Listen
jetzt proxycheck.io. Der Dienst beantwortet jede Adresse einzeln: Er nennt VPN,
Proxy, Rechenzentrum und den Namen des Anbieters, dazu Land und Netz, wenn keine
lokale Quelle dafür gewählt ist. Die Seite nimmt Schlüssel und Tageslimit entgegen
und weist darauf hin, dass jede neue Adresse aus einem Treffer an den Dienst geht.

**Kontingent im Blick.** Der Abwehr-Cron fragt je Durchgang höchstens eine Anfrage
mit 100 Adressen und bleibt unter dem Tageslimit. Die Einstellungsseite zeigt „heute
n von m Abfragen, k Adressen geprüft“. Ist das Limit erreicht, warten die übrigen
Adressen auf den nächsten Tag; eine gescheiterte Anfrage wird nach einer Stunde
erneut versucht, höchstens dreimal.

**Beim Abschalten geht alles mit.** Wird proxycheck.io abgewählt, löscht der nächste
Auftrag „Herkunft der Adressen“ die Merkmale des Dienstes aus den Adressen und seine
Zeile aus dem Stand der Quellen.
```

- [x] **Step 3: README nachziehen**

In `README.md` und `ispconfig/README.md` den Absatz zur Herkunft der Adressen um einen Satz ergänzen:

```markdown
Für VPN, Proxy und Rechenzentrum steht neben den X4BNet-Listen proxycheck.io zur
Wahl; der Dienst braucht einen Schlüssel und bekommt die Adressen der Treffer
übermittelt.
```

- [x] **Step 4: Die Spec bekommt eine Notiz**

In `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` unter Abschnitt 6 hinter dem Satz „Die Spalten `waf_origin_proxycheck_key` und `waf_origin_proxycheck_daily` und der Wert `proxycheck` in `waf_origin_net` kommen mit dem Release für proxycheck.io."

```markdown
Umgesetzt mit 0.22.0 (Plan `docs/superpowers/plans/2026-09-18-malwatch-abwehr-herkunft-proxycheck.md`).
```

- [x] **Step 5: Die ganze Prüfstrecke**

Run: `gofmt -l . && go vet ./... && go build ./... && echo "Go: ok"`
Expected: `Go: ok`. Unter Windows scheitern zwei Go-Tests aus Gründen der Umgebung (Schwelle des Scanners, Defender blockt die angelegte Testdatei); die Linux-CI ist der Maßstab.

Run: `find ispconfig -name '*.php' -o -name '*.lng' | xargs -n1 php -l | grep -v '^No syntax errors' ; echo "Syntax geprüft"`
Expected: nur `Syntax geprüft`

Run: `php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_rules_catalog_test.php && php ispconfig/tests/waf_origin_test.php && php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_proxycheck_test.php`
Expected: siebenmal `alle Prüfungen bestanden`

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`

- [x] **Step 6: Commit**

```bash
git add internal/version/version.go ispconfig/version CHANGELOG.md README.md ispconfig/README.md docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "release: 0.22.0, proxycheck.io for VPN, proxy and data centre" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
git status --short
```

Expected: `grep` ohne Ausgabe, der Commit gelingt, `git status --short` zeigt keine Datei aus `ispconfig/`, `internal/` oder `docs/`.

---
**Notizen aus der Umsetzung (18.09.2026):**

- `waf_lib_test.php` nutzte `proxycheck` bisher als Beispiel für einen *ungültigen* Wert von `waf_origin_net`; die Stelle steht jetzt auf `vielleicht`, und die Erwartung zu `waf_origin_choices()` nennt die dritte Wahl.
- `waf_panel_test.php` leitet seine Erwartungen an das Formular aus `waf_settings_limits()` und `waf_origin_choices()` ab. Task C1 lässt die Reihe deshalb rot zurück, bis C4 die beiden Felder ins Formular bringt: Beide gehören in einen Lauf, und `waf_origin_proxycheck_daily` steht in `waf_settings_limits()` direkt hinter `waf_card_hits`, damit die Reihenfolge zur Reihenfolge der Felder passt. C3 und C4 wurden zusammen committet.
- Den Testhelfer `waf_post_page()` gibt es nicht; die Prüfungen laufen über die beiden neuen Funktionen `waf_panel_key_keep()` und `waf_panel_origin_missing()`, und die Seite ruft sie auf.
- Commits auf `waf-herkules`: `9de60f0` (C1), `48af55a` (C2), `49e730f` (C3 und C4), `81c9574` (C5), `b9c513c` (C6).

### Task C7: Einführung auf web.herkules

malwatch 0.22.0 kommt in vier Blöcken auf den Server, jeder mit eigener Freigabe von Mathias und mit Eintrag im Serverprotokoll:

1. Staging-Kopie, Schema, Klassenprobe und Seiten
2. Veröffentlichen: `main`, CI, Marke `v0.22.0`, Release
3. malwatch 0.22.0 einspielen
4. proxycheck.io einschalten, ersten Abruf beobachten, Sichtprüfung im Panel

Claude meldet sich nie im Panel an und tippt keine Zugangsdaten: **Den Schlüssel von proxycheck.io trägt Mathias selbst ein.** Ohne Konto bei proxycheck.io endet die Einführung nach Block 3 — 0.22.0 läuft dann mit ausgeschaltetem Dienst, alles andere bleibt wie vorher.

**Files:**
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
- Hilfen am Rechner (nicht im Repo): `.superpowers/abwehr/measure.sh`

**Interfaces:**
- Consumes: den Commit aus Task C6 auf `waf-herkules`
- Produces: malwatch 0.22.0 auf web.herkules, proxycheck.io geprüft und protokolliert

#### Messen

Vor dem ersten und nach jedem ändernden Schritt:

```bash
ssh ispconfig 'bash -s' < .superpowers/abwehr/measure.sh
for site in bright-color.de "$ZWEITE" "$DRITTE"; do curl -s -o /dev/null -w "%{http_code} %{time_total}s $site\n" "https://$site/"; done
```

`ZWEITE` und `DRITTE` sind die beiden Kundenwebsites aus den Messtabellen der letzten Einträge im Serverprotokoll; ihre Namen stehen nur dort.

**Abbruch**, sobald eines davon eintritt: `nginx -t` scheitert, nginx ist nicht aktiv, weniger als 2 GB verfügbar, Load (5 Minuten) dauerhaft über 6, eine Website antwortet anders als zu Beginn oder doppelt so langsam, ein neuer Eintrag „exited on signal". Dann: Werte festhalten, Mathias Bescheid geben, erst nach Klärung weiter.

#### Block 1: Staging-Kopie, Schema und Proben

- [x] **Step 1: Freigabe einholen**

Mathias bekommt vorgelegt: „C7, Block 1: Ich kopiere den Stand nach `/root/mw-0220-src` und `/root/mw-0220-stage`, prüfe Syntax und Tests, sichere die Struktur der betroffenen Tabellen und lade das Schema: zwei Spalten in `malwatch_config`, der Wert `proxycheck` in der Auswahl des Netzes und zwei Spalten in `malwatch_waf_origin_source`. Danach läuft die Klassenprobe gegen eine Wegwerf-Datenbank — sie fragt keinen echten Dienst, die Antwort kommt aus einer Beispieldatei — und ich rendere die Seiten der Kopie gegen die echte Datenbank. Zum Schluss lösche ich Kopie und Wegwerf-Datenbank. nginx, die Websites und die laufende Erweiterung bleiben unberührt." Weiter erst nach seinem Ja.

- [x] **Step 2: Ausgangslage**

Beide Messungen, dazu der Stand der Herkunft:

```bash
ssh ispconfig 'mysql -N dbispconfig -e "SELECT waf_origin_geo, waf_origin_tor, waf_origin_net FROM malwatch_config"; mysql -N dbispconfig -e "SELECT source, entries FROM malwatch_waf_origin_source ORDER BY source"; mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_ip"'
```

Expected: `dbip torproject x4b`, fünf Quellen mit ihren Zahlen und die Zahl der Adressen. Diese Werte kommen ins Protokoll und sind der Vergleich für Block 4.

- [x] **Step 3: Kopie, Syntax, Tests**

```bash
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/mw-0220-src /root/mw-0220-stage && mkdir -p /root/mw-0220-src /root/mw-0220-stage/interface/web && tar -x -C /root/mw-0220-src'
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Staging-Kopie"
src=/root/mw-0220-src/ispconfig
stage=/root/mw-0220-stage
ln -s /usr/local/ispconfig/interface/lib "$stage/interface/lib"
cd "$src"
while IFS=: read -r action source target; do
	[ "$action" = c ] || continue
	case "$target" in
		interface/*) mkdir -p "$stage/$(dirname "$target")"; cp "$source" "$stage/$target" ;;
	esac
done < install/file.list
for php in php7.0 php; do
	find . \( -name '*.php' -o -name '*.lng' \) -print0 | xargs -0 -n1 "$php" -l | grep -v '^No syntax errors' || true
done
php tests/waf_lib_test.php
php tests/waf_panel_test.php
php tests/waf_panel_post_test.php
php tests/waf_rules_catalog_test.php
php tests/waf_origin_test.php
php tests/waf_origin_sources_test.php
php tests/waf_proxycheck_test.php
cat version
date "+%H:%M:%S fertig"
EOF
```

Expected: keine Zeile aus den Syntaxprüfungen, siebenmal „alle Prüfungen bestanden", Version 0.22.0.

- [x] **Step 4: Schema laden**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
install -d -m 700 /var/backups/malwatch
mysqldump --no-data dbispconfig malwatch_config malwatch_waf_origin_source > "/var/backups/malwatch/schema-vor-0.22.0-$(date +%Y%m%d-%H%M%S).sql"
date "+%H:%M:%S Schema laden"
mysql dbispconfig < /root/mw-0220-src/ispconfig/install/schema.sql
date "+%H:%M:%S Schema geladen"
mysql -N dbispconfig -e "SELECT COLUMN_NAME, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME LIKE 'waf\_origin\_proxycheck%' ORDER BY COLUMN_NAME"
mysql -N dbispconfig -e "SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_net'"
mysql -N dbispconfig -e "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_waf_origin_source' AND COLUMN_NAME IN ('day','queries') ORDER BY COLUMN_NAME"
mysql -N dbispconfig -e "SELECT waf_origin_net, waf_origin_proxycheck_daily FROM malwatch_config"
EOF
```

Expected: `waf_origin_proxycheck_daily 500` und `waf_origin_proxycheck_key` (leer), `enum('off','x4b','proxycheck')`, die Spalten `day` und `queries`, und die laufende Einstellung steht weiterhin auf `x4b 500`. Danach beide Messungen.

- [x] **Step 5: Klassenprobe und Seiten**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
probe_db=mw_probe_0220
mysql -e "DROP DATABASE IF EXISTS $probe_db; CREATE DATABASE $probe_db"
mysqldump --no-data dbispconfig malwatch_config malwatch_job malwatch_site malwatch_waf_hit malwatch_waf_day malwatch_waf_site_day malwatch_waf_exception malwatch_waf_origin_source malwatch_waf_ip malwatch_action_log web_domain sys_datalog sys_log | mysql "$probe_db"
mysql "$probe_db" -e "INSERT INTO malwatch_config (config_id, sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other) VALUES (1, 1, 1, 'riud', 'riud', '')"
cd /root/mw-0220-src/ispconfig
date "+%H:%M:%S Klassenprobe"
nice -n 15 php tests/waf_class_probe.php /root/mw-0220-src/ispconfig "$probe_db"
mysql -e "DROP DATABASE $probe_db"
export MW_SECURITY_DIR=/root/mw-0220-stage/interface/web/security
id=$(mysql -N dbispconfig -e "SELECT domain_id FROM web_domain WHERE domain = 'bright-color.de' AND type = 'vhost'")
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
date "+%H:%M:%S Seiten"
nice -n 15 php tests/render_pages.php "$rid" 2>&1 | tail -n 34
date "+%H:%M:%S fertig"
EOF
```

Expected: `waf_class_probe: alle Prüfungen bestanden`, jede Seite `ok`, `All pages render.` Die Klassenprobe fragt keinen Dienst: Ihre Naht `$poster` antwortet aus `tests/fixtures/proxycheck/answer.json`.

- [x] **Step 6: Aufräumen und Protokoll**

```bash
ssh ispconfig 'rm -rf /root/mw-0220-src /root/mw-0220-stage; mysql -N -e "SHOW DATABASES LIKE \"mw_probe_0220\""; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: keine Datenbank mehr, die Uhrzeit fürs Protokoll. Danach beide Messungen und der Eintrag ins Serverprotokoll (frisch lesen, gezielt einfügen) mit den Werten der Ausgangslage, dem Ergebnis der Probe und dem Rückweg (die zwei Spalten und der erweiterte enum bleiben folgenlos liegen, solange proxycheck.io aus ist).

Ergebnis am 18.09.2026, 01:18:31–01:19:50 CEST (Protokolleintrag „Schema und Proben für proxycheck.io"): sieben Testreihen und die Klassenprobe im ersten Anlauf bestanden, Schema geladen (`enum('off','x4b','proxycheck')`, Schlüssel leer, Tageslimit 500, `day` und `queries` da), 25 Seiten gerendert, die Einstellungsseite zeigt die drei neuen Texte. Ausgangslage: fünf Quellen, 30 Adressen, Last 1,24, 5.700 MB frei. Danach aufgeräumt; Messwerte unverändert im Rahmen.

#### Block 2: Veröffentlichen

- [x] **Step 7: Freigabe einholen**

Mathias bekommt vorgelegt: „C7, Block 2: Ich bringe `waf-herkules` per Fast-Forward nach `main`, schiebe `main`, warte auf die CI und setze danach die Marke `v0.22.0`." Weiter erst nach seinem Ja.

- [x] **Step 8: main, CI, Marke, Release**

```bash
git fetch origin
git merge-base --is-ancestor origin/main waf-herkules && echo "Fast-Forward möglich"
git checkout main
git merge --ff-only waf-herkules
git push origin main
sha=$(git rev-parse HEAD)
gh run watch "$(gh run list --commit "$sha" --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
git tag v0.22.0
git push origin v0.22.0
gh run watch "$(gh run list --workflow release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view v0.22.0 --json assets --jq '.assets[].name'
git checkout waf-herkules
```

Expected: `Fast-Forward möglich`, CI grün (darunter der neue Schritt „WAF proxycheck"), Release mit `malwatch-linux-amd64`, `malwatch-linux-arm64`, `malwatch.pkg` und `SHA256SUMS`. Scheitert ein Upload wie bei 0.20.0 und 0.21.0 mit „Error creating asset temp dir", hilft `gh run rerun <id> --failed`.

Ergebnis am 18.09.2026: `main` steht auf `2d6b7b3`, CI-Lauf 35287538776 grün mit dem Schritt „WAF proxycheck“, Marke `v0.22.0` gesetzt, Release-Lauf 35287902041 mit allen vier Dateien im ersten Anlauf.

#### Block 3: Einspielen

- [x] **Step 9: Freigabe einholen**

Mathias bekommt vorgelegt: „C7, Block 3: Ich spiele malwatch 0.22.0 ein: Scanner über `install.sh`, Paket nach Prüfsumme, `manual_install.php`, dann `cmp` jeder Kopie und `render_pages.php` live. proxycheck.io bleibt dabei aus, es geht keine Adresse nach außen." Weiter erst nach seinem Ja.

- [x] **Step 10: Einspielen**

Zuerst beide Messungen, dann derselbe Ablauf wie bei 0.21.1, mit `mw-0220-deploy` und `v0.22.0`:

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Beginn"
rm -rf /root/mw-0220-deploy && mkdir -p /root/mw-0220-deploy && cd /root/mw-0220-deploy
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.22.0/malwatch.pkg
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.22.0/SHA256SUMS
grep " malwatch.pkg$" SHA256SUMS | sha256sum -c -
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh 2>&1 | grep -i installed
cd /usr/local/ispconfig/extensions/malwatch && unzip -oq /root/mw-0220-deploy/malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php 2>&1 | grep -E "installed|loaded|Error|error|failed" | head -n 8
echo "Addon $(cat /usr/local/ispconfig/extensions/malwatch/version), Scanner $(/usr/local/bin/malwatch version | head -n 1)"
E=/usr/local/ispconfig/extensions/malwatch; n=0; total=0
while IFS=: read -r a s t; do [ "$a" = c ] || continue; total=$((total+1)); cmp -s "$E/$s" "/usr/local/ispconfig/$t" || { echo "abweichend: $t"; n=$((n+1)); }; done < "$E/install/file.list"
echo "Kopien geprüft: $total, abweichend: $n"
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
nice -n 15 php "$E/tests/render_pages.php" "$rid" 2>&1 | tail -n 34
rm -rf /root/mw-0220-deploy
date "+%H:%M:%S eingespielt"
EOF
```

Expected: `malwatch.pkg: OK`, Addon und Scanner `0.22.0`, `Kopien geprüft: 92, abweichend: 0`, alle Seiten `ok`. Danach beide Messungen und der Protokolleintrag für Blöcke 2 und 3.

Ergebnis am 18.09.2026, 01:42:46–01:43:22 CEST (Protokolleintrag zum Einspielen von 0.22.0): alles wie erwartet — Paket nach Prüfsumme, Addon und Scanner 0.22.0, 92 Kopien ohne Abweichung, alle Seiten ok. Danach unverändert: waf_origin_net steht auf x4b, Tageslimit 500, fünf Bereichsdateien, 31 Adressen mit externem Zustand none. Messwerte: Last 0,51 zu 0,53, frei 5.993 zu 6.022 MB, Websites unverändert.

#### Block 4: proxycheck.io einschalten

- [ ] **Step 11: Freigabe und Schlüssel**

Mathias bekommt vorgelegt: „C7, Block 4: Unter Security > Abwehr > Einstellungen wählst **du** bei „VPN und Rechenzentrum" proxycheck.io, trägst deinen Schlüssel ein und setzt das Tageslimit (Vorgabe 500). Den Schlüssel tippe ich nicht. Nach dem Speichern beobachte ich den ersten Abruf, messe mit und sehe mir die Seiten an. Achtung: Damit geht jede neue Adresse aus einem Treffer an proxycheck.io, und die X4BNet-Listen werden abgeschaltet — ihre Merkmale verschwinden von den Adressen, bis der Dienst sie beantwortet hat." Weiter erst nach seiner Antwort. Ohne Konto bei proxycheck.io endet die Einführung hier.

- [ ] **Step 12: Nach dem Speichern**

```bash
ssh ispconfig 'mysql -N dbispconfig -e "SELECT waf_origin_geo, waf_origin_tor, waf_origin_net, waf_origin_proxycheck_daily, LENGTH(waf_origin_proxycheck_key) FROM malwatch_config"; mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_ip WHERE external_state = \"pending\""; date "+%H:%M:%S"'
```

Expected: `dbip torproject proxycheck 500` und eine Länge über 0 — der Schlüssel steht in der Datenbank, im Protokoll steht nur seine Länge. Dazu die Zahl der Adressen, die auf eine Antwort warten.

- [ ] **Step 13: Ersten Abruf beobachten**

```bash
ssh ispconfig 'for i in $(seq 1 10); do n=$(mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_ip WHERE external_state = \"done\""); echo "$(date +%H:%M:%S) beantwortet: $n"; [ "$n" -gt 0 ] && break; sleep 30; done; mysql dbispconfig -e "SELECT source, entries, queries, day, LEFT(error, 80) AS fehler FROM malwatch_waf_origin_source WHERE source = \"proxycheck\""; mysql dbispconfig -e "SELECT external_state, COUNT(*) FROM malwatch_waf_ip GROUP BY external_state"; mysql dbispconfig -e "SELECT COUNT(*) AS vpn, SUM(is_proxy = \"y\") AS proxy, SUM(vpn_operator != \"\") AS mit_anbieter FROM malwatch_waf_ip WHERE is_vpn = \"y\""'
```

Expected: Die Zahl der beantworteten Adressen steigt, `malwatch_waf_origin_source` hat eine Zeile `proxycheck` mit `queries` gleich der Zahl der gefragten Adressen und ohne Fehler, und die Zustände verteilen sich auf `done` und höchstens wenige `failed`. Dazwischen beide Messungen. Bleibt `queries` bei 0 und steht ein Fehler in der Zeile, wird er wörtlich ins Protokoll übernommen — er nennt nie den Schlüssel.

- [ ] **Step 14: Sichtprüfung im Panel**

Werkzeuge von Claude in Chrome laden, eigener Tab, danach schließen. Die Einstellungsseite wird über das Menü geöffnet, weil der Speichern-Knopf zum Panel-Gerüst gehört; im Panel-Fenster wirkt das Mausrad nicht auf den Inhalt, ein Klick in ein Feld oder `scroll_to` bringt den Abschnitt ins Bild.

| Ablauf | Erwartet |
|---|---|
| Security > Abwehr > Übersicht | Zeile „Herkunft: … proxycheck.io n Adressen geprüft" |
| Website bright-color.de öffnen | an den Adressen die Chips „VPN" mit Anbieter, „Proxy" und „Rechenzentrum"; Adressen ohne Antwort zeigen „wird geprüft" |
| Abwehr > Einstellungen | Abschnitt „Herkunft der Adressen" mit der Zeile „proxycheck.io heute n von m Abfragen, k Adressen geprüft"; der Schlüssel steht verdeckt mit vier Zeichen |

Bildschirmfotos der Karte und der Einstellungen gehen an Mathias.

- [ ] **Step 15: Protokoll**

Frisch lesen, gezielt einfügen: ein Eintrag für Block 4 mit Beginn und Ende, den Freigaben, den Messwerten vor und nach dem ersten Abruf, den Zahlen aus `malwatch_waf_origin_source` und `malwatch_waf_ip`, dem Ergebnis der Sichtprüfung und dem Rückweg (bei „VPN und Rechenzentrum" wieder X4BNet oder „aus" wählen; der nächste Auftrag löscht die Merkmale des Dienstes und seine Zeile). Der Schlüssel steht nicht im Protokoll, auch nicht in Teilen.

- [ ] **Step 16: Erinnerung aktualisieren**

In `waf-web-herkules.md` festhalten: 0.22.0 live seit <Datum>, proxycheck.io ein oder aus, Tageslimit, Zahl der geprüften Adressen am ersten Tag, und dass die X4BNet-Listen mit der Wahl von proxycheck.io abgeschaltet werden. Die Zeile in `MEMORY.md` passend kürzen.

---

## Abschluss von Teil B II

Teil B II ist fertig, wenn:

- C1 bis C6 committet sind, die sieben Prüfreihen bestehen und `sh ispconfig/tests/check_wiring.sh` `Wiring OK` meldet,
- v0.22.0 veröffentlicht ist und die CI grün war,
- web.herkules 0.22.0 zeigt und die Klassenprobe dort bestanden hat,
- das Serverprotokoll die Blöcke 1 bis 4 enthält.

Danach ist die Herkunft der Adressen abgeschlossen. Als Nächstes steht Teil 2 „Sperren" an: Angreiferliste für die OPNsense, fail2ban-Sperren mit Grund und Ende. Er bekommt eine eigene Spec.
