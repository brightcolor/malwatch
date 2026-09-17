# malwatch — Abwehr: Herkunft der Adressen aus lokalen Listen (Teil B I) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Zu jeder Adresse in der Abwehr zeigt das Panel Land, Provider und die Chips „Tor", „VPN" und „Rechenzentrum", aus Listen, die der Server selbst herunterlädt.

**Architecture:** Neue reine Funktionen in `malwatch_waf_origin.inc.php` schreiben und lesen Bereichsdateien: sortierte, überschneidungsfreie Adressbereiche mit einer Wertetabelle, binär durchsucht, ohne PHP-Erweiterung. Ein Auftrag `origin_update` im WAF-Cron lädt die gewählten Quellen, baut daraus Bereichsdateien und tauscht sie erst nach der Plausibilitätsprüfung. Das Einlesen schlägt jede neue Adresse in den Bereichsdateien nach und legt das Ergebnis in `malwatch_waf_ip` ab; die Seiten lesen nur diese Tabelle.

**Tech Stack:** PHP ab 7.0 im ISPConfig-Panel (vlibTemplate, tform) und in der Server-Klasse `malwatch_waf`, MariaDB, `curl` als PHP-Erweiterung, POSIX-sh für `check_wiring.sh`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`, Teil B (Abschnitte 6 bis 13), ohne proxycheck.io. Der externe Dienst bekommt einen eigenen Plan und ein eigenes Release (Teil B II).

## Global Constraints

- PHP-Code läuft ab PHP 7.0; neue PHP-Erweiterungen kommen keine dazu. `curl` und `zlib` sind vorhanden, `zip` prüft der Code vor der MaxMind-Quelle.
- Variablen, Funktionen, Dateinamen, Schlüssel und Code-Kommentare englisch; Oberfläche, Plan und Spec deutsch.
- Zeiträume, Grenzen und Mengen sind Einstellungen mit Vorgabe, nie feste Werte im Code.
- Fehlermeldungen nennen Ursache und nächsten Schritt (Vorgabe vom 17.09.2026).
- Keine echten Kundendaten in Repo, Tests oder Changelog; Beispieladressen aus 192.0.2.0/24, 198.51.100.0/24 und 203.0.113.0/24.
- Lizenzschlüssel und Konto-IDs stehen nie in Auftragsprotokollen, Fehlertexten, Cron-Ausgaben oder im HTML; das Panel zeigt höchstens die letzten vier Zeichen.
- Auftragsprotokolle nennen Quellen und Zahlen, keine Besucheradressen.
- Konkurrenzprodukte werden nie genannt. Vor jedem Commit: `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` bleibt leer.
- Alle Seiten nur für Administratoren; jede Ausgabe läuft durch `$app->functions->htmlentities()`.
- Der Webserver darf niemals ausfallen. Teil B ändert nichts an nginx und an den Regeldateien.
- Serverschritte nur nach Freigabe von Mathias, jeder mit Eintrag im Serverprotokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md` (frisch lesen, gezielt einfügen, neueste zuerst).
- Agenten nur mit Freigabe von Mathias.
- Commits mit ausdrücklichen Pfaden und dem Trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`; gearbeitet wird im Repo `C:\Users\brigh\Claude Workingdir\malwatch` auf dem Zweig `waf-herkules`.
- Unter Windows: PHP braucht `C:/…`-Pfade; das Bash-Werkzeug macht aus `\\n` in Befehlstexten einen Zeilenumbruch, Backslashes in Hilfsskripten deshalb über `chr(92)`.
- `sh ispconfig/tests/check_wiring.sh` läuft lange; im Hintergrund starten.
- Unter Windows scheitern zwei Go-Tests aus Gründen der Umgebung (siehe Teil A, Task A9); maßgeblich ist die CI unter Linux.

## Präzisierungen gegenüber der Spec

Task B8 übernimmt sie in die Spec (Abschnitte 6 bis 9).

1. **Zwei Pläne:** Dieser Plan bringt die lokalen Quellen (DB-IP Lite, MaxMind GeoLite2, Tor-Liste, X4BNet) als Release 0.21.0. proxycheck.io folgt als Teil B II; bis dahin fehlen die Spalten `waf_origin_proxycheck_key` und `waf_origin_proxycheck_daily`, und `waf_origin_net` kennt nur `off` und `x4b`. Die Spalten `external_state`, `external_at` und `external_tries` in `malwatch_waf_ip` entstehen schon hier, damit Teil B II nur noch füllt.
2. **Eigene Datei für die Herkunft:** Die neuen reinen Funktionen stehen in `ispconfig/interface/lib/malwatch_waf_origin.inc.php`. `malwatch_waf_lib.inc.php` hat 1.168 Zeilen; eine zweite Datei hält beides lesbar. Die Server-Klasse lädt sie wie die erste über einen Pfad neben sich.
3. **Format der Bereichsdatei:** Kopf mit Kennung `MWORIG1`, Zahl der Bereiche und Beginn der Wertetabelle; je Bereich 36 Byte (erste Adresse, letzte Adresse, Index des Werts); am Ende die Wertetabelle. Adressen sind die 16 Byte von `inet_pton()`, IPv4 als `::ffff:a.b.c.d`. So trägt ein Byte-Vergleich die Ordnung, und eine Datei hält beide Familien.
4. **Werte:** Land als Kürzel (`DE`), Netz als `AS3320\x1FDeutsche Telekom AG`, Listen ohne Wert (`''`). Die Wertetabelle steht beim Öffnen im Speicher, die Bereiche bleiben auf der Platte.
5. **Abruf ohne Shell:** Der Auftrag lädt mit der PHP-Erweiterung `curl` in eine temporäre Datei. Eine Ablagestelle in der Klasse (`$fetcher`) nimmt im Test die Stelle des Abrufs ein, wie `$runner` für die Befehle.
6. **Reihenfolge der Quellen:** DB-IP und MaxMind liefern sortierte Dateien, sie werden zeilenweise umgebaut. Tor- und X4BNet-Listen sind unsortiert und klein genug, um im Speicher sortiert zu werden.
7. **Nachschlagen beim Einlesen:** Nach jedem Durchgang schlägt die Klasse die neuen Adressen nach. Eine Adresse, deren Zeile älter ist als die jüngste Bereichsdatei, wird beim nächsten Treffer erneut geprüft.

## Dateien

| Datei | Aufgabe |
|---|---|
| `ispconfig/interface/lib/malwatch_waf_origin.inc.php` | neu: Bereichsdateien schreiben und lesen, Quellen einlesen, Werte deuten |
| `ispconfig/tests/waf_origin_test.php` | neu: Bereichsdatei und Adressen |
| `ispconfig/tests/waf_origin_sources_test.php` | neu: Quellen einlesen, Plausibilität |
| `ispconfig/tests/fixtures/origin/*` | neu: kurze Beispieldateien der Quellen |
| `ispconfig/install/schema.sql` | Spalten der Herkunft, Tabellen `malwatch_waf_origin_source` und `malwatch_waf_ip` |
| `ispconfig/interface/lib/malwatch_waf_lib.inc.php` | Einstellungen der Herkunft mit Vorgaben und Grenzen |
| `ispconfig/interface/form/malwatch_waf_config.tform.php`, `templates/malwatch_waf_config_edit.htm`, `lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng` | Abschnitt „Herkunft der Adressen" |
| `ispconfig/interface/malwatch_waf_config_edit.php` | Schlüsselfelder, Auftrag nach dem Speichern |
| `ispconfig/server/lib/classes/malwatch_waf.inc.php` | Auftrag `origin_update`, Nachschlagen beim Einlesen, Aufräumen |
| `ispconfig/interface/lib/malwatch_waf_panel.inc.php` | Herkunft je Adresse für die Anzeige |
| `ispconfig/interface/malwatch_waf_show.php`, `malwatch_waf_list.php`, `templates/*.htm`, `lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` | Anzeige der Herkunft, Namensnennung, Hinweise |
| `ispconfig/tests/check_wiring.sh` | Prüfungen 67 bis 70 |
| `ispconfig/tests/render_pages.php` | Seiten mit und ohne Herkunftsdaten |
| `.github/workflows/ci.yml` | die beiden neuen Tests |
| `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` | Präzisierungen |
| `CHANGELOG.md`, `README.md`, `ispconfig/README.md`, `internal/version/version.go`, `ispconfig/version` | Release 0.21.0 |

---

### Task B1: Bereichsdateien schreiben und lesen

**Files:**
- Create: `ispconfig/interface/lib/malwatch_waf_origin.inc.php`
- Create: `ispconfig/tests/waf_origin_test.php`
- Modify: `ispconfig/install/file.list`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nichts; die Datei steht für sich und braucht keine andere Datei des Addons
- Produces:
  - `waf_origin_bytes($ip)` → 16 Byte der Adresse oder `''`; `waf_origin_text($bytes)` → Adresse als Text
  - `waf_origin_next($bytes)`, `waf_origin_previous($bytes)` → Nachbaradresse oder `''`
  - `waf_origin_cidr($cidr)` → `array(erste, letzte)` oder `null`
  - `waf_origin_writer($file)`, `waf_origin_write($writer, $first, $last, $value)`, `waf_origin_finish($writer)` → `array('ranges' => n, 'values' => n)` oder `null`
  - `waf_origin_open($file)`, `waf_origin_ranges($reader)`, `waf_origin_find($reader, $ip)` → Wert oder `''`, `waf_origin_close($reader)`
  - Konstanten `WAF_ORIGIN_HEAD`, `WAF_ORIGIN_ROW`, `WAF_ORIGIN_MAGIC`

Die Task B2 baut die Quellen damit um, Task B6 schlägt darin nach.

- [ ] **Step 1: Test schreiben**

Neue Datei `ispconfig/tests/waf_origin_test.php`:

```php
<?php
/**
 * Checks the range files of the origin sources: writing, looking up and what
 * a broken file does.
 *
 *   php ispconfig/tests/waf_origin_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_origin.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$dir = sys_get_temp_dir() . '/waf_origin_test_' . getmypid();
@mkdir($dir, 0700, true);

// --- Addresses ----------------------------------------------------------------

expect_same('bytes of an IPv4 address', bin2hex(waf_origin_bytes('192.0.2.7')), '00000000000000000000ffffc0000207');
expect_same('bytes of an IPv6 address', bin2hex(waf_origin_bytes('2001:db8::7')), '20010db8000000000000000000000007');
expect_same('bytes of something else', waf_origin_bytes('192.0.2.300'), '');
expect_same('bytes of a name', waf_origin_bytes('example.test'), '');
expect_same('address as text again', waf_origin_text(waf_origin_bytes('192.0.2.7')), '192.0.2.7');
expect_same('IPv6 as text again', waf_origin_text(waf_origin_bytes('2001:db8::7')), '2001:db8::7');
expect_same('text of too few bytes', waf_origin_text('abc'), '');
expect_same('the next address', waf_origin_text(waf_origin_next(waf_origin_bytes('192.0.2.255'))), '192.0.3.0');
expect_same('the address before', waf_origin_text(waf_origin_previous(waf_origin_bytes('192.0.3.0'))), '192.0.2.255');
expect_same('after the last address', waf_origin_next(str_repeat("\xff", 16)), '');
expect_same('before the first address', waf_origin_previous(str_repeat("\0", 16)), '');

// --- Blocks -------------------------------------------------------------------

$block = waf_origin_cidr('192.0.2.0/24');
expect_same('block of IPv4', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('192.0.2.0', '192.0.2.255'));
$block = waf_origin_cidr('2001:db8::/32');
expect_same('block of IPv6', array(waf_origin_text($block[0]), waf_origin_text($block[1])),
	array('2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'));
$block = waf_origin_cidr('192.0.2.7/32');
expect_same('block of one address', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('192.0.2.7', '192.0.2.7'));
$block = waf_origin_cidr('198.51.100.9');
expect_same('block without a slash', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('198.51.100.9', '198.51.100.9'));
$block = waf_origin_cidr('10.0.0.0/8');
expect_same('block of a whole eight', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('10.0.0.0', '10.255.255.255'));
expect_same('block with too many bits', waf_origin_cidr('192.0.2.0/33'), null);
expect_same('block of something else', waf_origin_cidr('kein-block/24'), null);
expect_same('block without bits', waf_origin_cidr('192.0.2.0/'), null);

// --- Writing and looking up ---------------------------------------------------

$file = $dir . '/country.bin';
$writer = waf_origin_writer($file);
expect_same('writer opens', is_array($writer), true);
$rows = array(
	array('1.0.0.0', '1.255.255.255', 'AU'),
	array('192.0.2.0', '192.0.2.127', 'DE'),
	// Continues the range before with the same value: both become one range.
	array('192.0.2.128', '192.0.2.255', 'DE'),
	array('198.51.100.0', '198.51.100.255', 'FR'),
	array('2001:db8::', '2001:db8::ffff', 'DE'),
);
foreach ($rows as $row) {
	waf_origin_write($writer, waf_origin_bytes($row[0]), waf_origin_bytes($row[1]), $row[2]);
}
$written = waf_origin_finish($writer);
expect_same('written ranges and values', $written, array('ranges' => 4, 'values' => 3));

$reader = waf_origin_open($file);
expect_same('reader opens', is_array($reader), true);
expect_same('ranges of the file', waf_origin_ranges($reader), 4);
expect_same('address in the first range', waf_origin_find($reader, '1.2.3.4'), 'AU');
expect_same('first address of a range', waf_origin_find($reader, '192.0.2.0'), 'DE');
expect_same('address across the joined ranges', waf_origin_find($reader, '192.0.2.200'), 'DE');
expect_same('last address of a range', waf_origin_find($reader, '192.0.2.255'), 'DE');
expect_same('address after a range', waf_origin_find($reader, '192.0.3.0'), '');
expect_same('address before every range', waf_origin_find($reader, '0.0.0.1'), '');
expect_same('address after every range', waf_origin_find($reader, '2001:db9::1'), '');
expect_same('address in the middle range', waf_origin_find($reader, '198.51.100.9'), 'FR');
expect_same('IPv6 address in its range', waf_origin_find($reader, '2001:db8::7'), 'DE');
expect_same('something that is no address', waf_origin_find($reader, 'kein-ip'), '');
waf_origin_close($reader);
expect_same('reader closes', $reader, null);

// --- Order and overlap --------------------------------------------------------

$file2 = $dir . '/overlap.bin';
$writer = waf_origin_writer($file2);
waf_origin_write($writer, waf_origin_bytes('10.0.0.0'), waf_origin_bytes('10.0.0.255'), 'A');
// Starts inside the range before: only the free part counts.
expect_same('overlapping range is cut', waf_origin_write($writer, waf_origin_bytes('10.0.0.200'), waf_origin_bytes('10.0.1.255'), 'B'), true);
// Lies completely inside what was written: left out.
expect_same('range inside the one before', waf_origin_write($writer, waf_origin_bytes('10.0.0.10'), waf_origin_bytes('10.0.0.20'), 'C'), false);
// End before start: left out.
expect_same('range the wrong way round', waf_origin_write($writer, waf_origin_bytes('10.0.9.0'), waf_origin_bytes('10.0.2.0'), 'D'), false);
$written = waf_origin_finish($writer);
expect_same('ranges after the overlap', $written['ranges'], 2);
$reader = waf_origin_open($file2);
expect_same('value before the overlap', waf_origin_find($reader, '10.0.0.199'), 'A');
expect_same('value in the cut range', waf_origin_find($reader, '10.0.1.0'), 'B');
expect_same('value at the cut', waf_origin_find($reader, '10.0.1.255'), 'B');
waf_origin_close($reader);

// --- Empty and broken files ---------------------------------------------------

$empty = $dir . '/empty.bin';
$writer = waf_origin_writer($empty);
expect_same('empty file', waf_origin_finish($writer), array('ranges' => 0, 'values' => 0));
$reader = waf_origin_open($empty);
expect_same('lookup in an empty file', waf_origin_find($reader, '192.0.2.7'), '');
waf_origin_close($reader);

expect_same('file that is missing', waf_origin_open($dir . '/fehlt.bin'), null);
file_put_contents($dir . '/kaputt.bin', 'kein Bereich');
expect_same('file without the magic', waf_origin_open($dir . '/kaputt.bin'), null);
$cut = substr((string) file_get_contents($file), 0, WAF_ORIGIN_HEAD + WAF_ORIGIN_ROW);
file_put_contents($dir . '/kurz.bin', $cut);
expect_same('file that ends too early', waf_origin_open($dir . '/kurz.bin'), null);

// --- A larger file ------------------------------------------------------------

$many = $dir . '/many.bin';
$writer = waf_origin_writer($many);
for ($i = 0; $i < 2000; $i++) {
	$first = waf_origin_bytes('10.' . (int) ($i / 256) . '.' . ($i % 256) . '.0');
	waf_origin_write($writer, $first, waf_origin_next(waf_origin_next($first)), 'AS' . $i);
}
$written = waf_origin_finish($writer);
expect_same('ranges of the larger file', $written, array('ranges' => 2000, 'values' => 2000));
$reader = waf_origin_open($many);
expect_same('first range of the larger file', waf_origin_find($reader, '10.0.0.1'), 'AS0');
expect_same('range in the middle', waf_origin_find($reader, '10.3.232.2'), 'AS1000');
expect_same('last range', waf_origin_find($reader, '10.7.207.0'), 'AS1999');
expect_same('gap between two ranges', waf_origin_find($reader, '10.3.232.9'), '');
waf_origin_close($reader);

foreach (glob($dir . '/*.bin') as $name) {
	@unlink($name);
}
@rmdir($dir);

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_origin: alle Prüfungen bestanden\n";
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_origin_test.php`
Expected: Abbruch mit `Failed opening required` und dem Pfad `interface/lib/malwatch_waf_origin.inc.php`; die Datei gibt es noch nicht.

- [ ] **Step 3: Funktionen schreiben**

Neue Datei `ispconfig/interface/lib/malwatch_waf_origin.inc.php`:

```php
<?php

/**
 * Where an address comes from: the range files of the origin sources and the
 * lookup in them. The panel and the server class share these functions; they
 * run from PHP 7.0 without extra extensions.
 *
 * A range file holds sorted, non-overlapping ranges and a table of values:
 *
 *   header  16 bytes: "MWORIG1" and a zero byte, the number of ranges
 *           (uint32) and the offset of the value table (uint32)
 *   ranges  36 bytes each: first address (16), last address (16), the index
 *           of its value (uint32)
 *   values  the number of values (uint32), then each value as its length
 *           (uint16) and its bytes
 *
 * Addresses are the 16 bytes of inet_pton(); an IPv4 address sits in the
 * mapped range ::ffff:a.b.c.d, so one file holds both families. Everything is
 * big-endian, so comparing the bytes orders the addresses.
 */

/** The bytes of the file header, before the first range. */
define('WAF_ORIGIN_HEAD', 16);

/** The bytes of one range: two addresses and the index of its value. */
define('WAF_ORIGIN_ROW', 36);

/** The first bytes of every range file. */
define('WAF_ORIGIN_MAGIC', "MWORIG1\0");

/** The 16 bytes of an address, IPv4 mapped to ::ffff:a.b.c.d; '' when it is none. */
function waf_origin_bytes($ip)
{
	$packed = @inet_pton(trim((string) $ip));
	if ($packed === false) {
		return '';
	}
	if (strlen($packed) === 4) {
		return str_repeat("\0", 10) . "\xff\xff" . $packed;
	}
	return strlen($packed) === 16 ? $packed : '';
}

/** An address of waf_origin_bytes() as text again; '' when the bytes are none. */
function waf_origin_text($bytes)
{
	if (!is_string($bytes) || strlen($bytes) !== 16) {
		return '';
	}
	if (substr($bytes, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
		$bytes = substr($bytes, 12);
	}
	$text = @inet_ntop($bytes);
	return $text === false ? '' : $text;
}

/** The address one step after $bytes; '' after the last address there is. */
function waf_origin_next($bytes)
{
	for ($i = 15; $i >= 0; $i--) {
		$value = ord($bytes[$i]) + 1;
		$bytes[$i] = chr($value & 0xff);
		if ($value < 256) {
			return $bytes;
		}
	}
	return '';
}

/** The address one step before $bytes; '' before the first address there is. */
function waf_origin_previous($bytes)
{
	for ($i = 15; $i >= 0; $i--) {
		$value = ord($bytes[$i]) - 1;
		$bytes[$i] = chr($value & 0xff);
		if ($value >= 0) {
			return $bytes;
		}
	}
	return '';
}

/**
 * The first and last address of a CIDR block as array(first, last), both 16
 * bytes; null when the block is none. A plain address without a slash covers
 * itself.
 */
function waf_origin_cidr($cidr)
{
	$cidr = trim((string) $cidr);
	$slash = strpos($cidr, '/');
	$address = $slash === false ? $cidr : substr($cidr, 0, $slash);
	$first = waf_origin_bytes($address);
	if ($first === '') {
		return null;
	}
	$v4 = strpos($address, ':') === false;
	$bits = $slash === false ? ($v4 ? 32 : 128) : (int) substr($cidr, $slash + 1);
	if ($slash !== false && (!preg_match('/^\d{1,3}$/', substr($cidr, $slash + 1)) || $bits > ($v4 ? 32 : 128))) {
		return null;
	}
	$bits += $v4 ? 96 : 0;
	$last = $first;
	for ($i = 0; $i < 128; $i++) {
		if ($i < $bits) {
			continue;
		}
		$byte = (int) ($i / 8);
		$mask = 1 << (7 - ($i % 8));
		$first[$byte] = chr(ord($first[$byte]) & ~$mask);
		$last[$byte] = chr(ord($last[$byte]) | $mask);
	}
	return array($first, $last);
}

/**
 * Starts a range file. Ranges are written in order with waf_origin_write(),
 * waf_origin_finish() closes it. Returns the writer or null.
 */
function waf_origin_writer($file)
{
	$handle = @fopen($file, 'wb');
	if ($handle === false) {
		return null;
	}
	if (@fwrite($handle, str_repeat("\0", WAF_ORIGIN_HEAD)) !== WAF_ORIGIN_HEAD) {
		fclose($handle);
		return null;
	}
	return array('handle' => $handle, 'values' => array(), 'texts' => array(), 'ranges' => 0,
		'last_end' => '', 'last_value' => -1, 'failed' => false);
}

/**
 * Adds one range. Ranges come in ascending order; a range that overlaps the
 * one before is cut to the free part, and one that continues it with the same
 * value grows it. Returns false when the range is none or the file fails.
 */
function waf_origin_write(&$writer, $first, $last, $value)
{
	if (!is_array($writer) || $writer['failed'] || strlen($first) !== 16 || strlen($last) !== 16 || strcmp($first, $last) > 0) {
		return false;
	}
	if ($writer['last_end'] !== '') {
		if (strcmp($last, $writer['last_end']) <= 0) {
			return false;
		}
		if (strcmp($first, $writer['last_end']) <= 0) {
			$first = waf_origin_next($writer['last_end']);
			if ($first === '') {
				return false;
			}
		}
	}
	$value = (string) $value;
	if (!isset($writer['values'][$value])) {
		$writer['values'][$value] = count($writer['texts']);
		$writer['texts'][] = $value;
	}
	$index = $writer['values'][$value];
	// A range that continues the one before with the same value grows it.
	if ($writer['ranges'] > 0 && $index === $writer['last_value'] && waf_origin_next($writer['last_end']) === $first) {
		if (@fseek($writer['handle'], -(WAF_ORIGIN_ROW - 16), SEEK_END) !== 0
			|| @fwrite($writer['handle'], $last . pack('N', $index)) !== WAF_ORIGIN_ROW - 16) {
			$writer['failed'] = true;
			return false;
		}
		$writer['last_end'] = $last;
		return true;
	}
	if (@fwrite($writer['handle'], $first . $last . pack('N', $index)) !== WAF_ORIGIN_ROW) {
		$writer['failed'] = true;
		return false;
	}
	$writer['ranges']++;
	$writer['last_end'] = $last;
	$writer['last_value'] = $index;
	return true;
}

/**
 * Writes the value table and the header and closes the file. Returns
 * array('ranges' => n, 'values' => n) or null when something failed.
 */
function waf_origin_finish(&$writer)
{
	if (!is_array($writer)) {
		return null;
	}
	$handle = $writer['handle'];
	$ok = !$writer['failed'];
	$offset = WAF_ORIGIN_HEAD + $writer['ranges'] * WAF_ORIGIN_ROW;
	if ($ok) {
		$table = pack('N', count($writer['texts']));
		foreach ($writer['texts'] as $text) {
			$text = substr($text, 0, 65535);
			$table .= pack('n', strlen($text)) . $text;
		}
		$ok = @fseek($handle, $offset) === 0 && @fwrite($handle, $table) === strlen($table)
			&& @fseek($handle, 0) === 0
			&& @fwrite($handle, WAF_ORIGIN_MAGIC . pack('NN', $writer['ranges'], $offset)) === WAF_ORIGIN_HEAD;
	}
	@fclose($handle);
	$result = array('ranges' => $writer['ranges'], 'values' => count($writer['texts']));
	$writer = null;
	return $ok ? $result : null;
}

/**
 * Opens a range file for lookups. Returns the handle with its number of
 * ranges, or null when the file is missing or its header is broken.
 */
function waf_origin_open($file)
{
	if (!is_file($file) || filesize($file) < WAF_ORIGIN_HEAD) {
		return null;
	}
	$handle = @fopen($file, 'rb');
	if ($handle === false) {
		return null;
	}
	$head = (string) @fread($handle, WAF_ORIGIN_HEAD);
	$size = (int) filesize($file);
	if (strlen($head) !== WAF_ORIGIN_HEAD || substr($head, 0, 8) !== WAF_ORIGIN_MAGIC) {
		fclose($handle);
		return null;
	}
	$parts = unpack('Nranges/Noffset', substr($head, 8));
	$ranges = (int) $parts['ranges'];
	$offset = (int) $parts['offset'];
	if ($offset !== WAF_ORIGIN_HEAD + $ranges * WAF_ORIGIN_ROW || $offset + 4 > $size) {
		fclose($handle);
		return null;
	}
	$values = waf_origin_table($handle, $offset);
	if ($values === null) {
		fclose($handle);
		return null;
	}
	return array('handle' => $handle, 'ranges' => $ranges, 'offset' => $offset, 'values' => $values);
}

/** The value table at $offset as a list; null when it is broken. */
function waf_origin_table($handle, $offset)
{
	if (@fseek($handle, $offset) !== 0) {
		return null;
	}
	$count = (string) @fread($handle, 4);
	if (strlen($count) !== 4) {
		return null;
	}
	$count = unpack('N', $count);
	$count = (int) $count[1];
	$values = array();
	for ($i = 0; $i < $count; $i++) {
		$length = (string) @fread($handle, 2);
		if (strlen($length) !== 2) {
			return null;
		}
		$length = unpack('n', $length);
		$length = (int) $length[1];
		$text = $length === 0 ? '' : (string) @fread($handle, $length);
		if (strlen($text) !== $length) {
			return null;
		}
		$values[] = $text;
	}
	return $values;
}

/** How many ranges the open file holds. */
function waf_origin_ranges($reader)
{
	return is_array($reader) ? (int) $reader['ranges'] : 0;
}

/** Closes a reader of waf_origin_open(). */
function waf_origin_close(&$reader)
{
	if (is_array($reader) && isset($reader['handle'])) {
		@fclose($reader['handle']);
	}
	$reader = null;
}

/** The value of the range that holds $ip, '' when no range does. */
function waf_origin_find($reader, $ip)
{
	if (!is_array($reader) || $reader['ranges'] === 0) {
		return '';
	}
	$needle = waf_origin_bytes($ip);
	if ($needle === '') {
		return '';
	}
	$low = 0;
	$high = $reader['ranges'] - 1;
	while ($low <= $high) {
		$middle = (int) (($low + $high) / 2);
		if (@fseek($reader['handle'], WAF_ORIGIN_HEAD + $middle * WAF_ORIGIN_ROW) !== 0) {
			return '';
		}
		$row = (string) @fread($reader['handle'], WAF_ORIGIN_ROW);
		if (strlen($row) !== WAF_ORIGIN_ROW) {
			return '';
		}
		if (strcmp($needle, substr($row, 0, 16)) < 0) {
			$high = $middle - 1;
			continue;
		}
		if (strcmp($needle, substr($row, 16, 16)) > 0) {
			$low = $middle + 1;
			continue;
		}
		$index = unpack('N', substr($row, 32, 4));
		$index = (int) $index[1];
		return isset($reader['values'][$index]) ? $reader['values'][$index] : '';
	}
	return '';
}
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_origin_test.php && php -l ispconfig/interface/lib/malwatch_waf_origin.inc.php`
Expected: `waf_origin: alle Prüfungen bestanden` und `No syntax errors detected`.

- [ ] **Step 5: Installation und CI**

In `ispconfig/install/file.list` nach der Zeile für `malwatch_waf_panel.inc.php` einfügen:

```text
c:interface/lib/malwatch_waf_origin.inc.php:interface/web/security/lib/malwatch_waf_origin.inc.php
```

In `.github/workflows/ci.yml`, Job `php-syntax`, nach dem Schritt `WAF rule catalog` einfügen:

```yaml
      - name: WAF origin ranges
        run: php ispconfig/tests/waf_origin_test.php
```

- [ ] **Step 6: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_origin.inc.php ispconfig/tests/waf_origin_test.php ispconfig/install/file.list .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): range files for the origin of an address" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B2: Die Quellen einlesen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_origin.inc.php` (Block am Dateiende)
- Create: `ispconfig/tests/waf_origin_sources_test.php`
- Create: `ispconfig/tests/fixtures/origin/` mit neun kurzen Beispieldateien
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: die Schreib- und Lesefunktionen aus Task B1
- Produces:
  - `waf_origin_sources()` → je Quelle Einstellung, Wert, Art, Mindestzahl, Größengrenze und die Einstellung für den Takt
  - `waf_origin_chosen($settings)` → die gewählten Quellen; `waf_origin_urls($name, $month)` → die Adressen einer Quelle
  - `waf_origin_read_dbip_country()`, `waf_origin_read_dbip_asn()`, `waf_origin_read_maxmind_country()`, `waf_origin_read_maxmind_asn()`, `waf_origin_read_list()` → `array('ranges', 'values', 'lines', 'bad', 'skipped')` oder `null`
  - `waf_origin_as_value($number, $name)`, `waf_origin_parts($value)`, `waf_origin_cut($text, $bytes)`
  - `waf_origin_check($name, $counts, $previous)` → `''` oder der Grund, warum der neue Stand liegen bleibt

Task B5 lädt die Dateien und ruft diese Einleser auf.

- [ ] **Step 1: Beispieldateien anlegen**

Das Verzeichnis `ispconfig/tests/fixtures/origin/` anlegen und diese neun Dateien hineinlegen. Jede enthält absichtlich eine unbrauchbare Zeile, damit die Zählung der schlechten Zeilen geprüft wird.

`ispconfig/tests/fixtures/origin/dbip-country.csv`:

```text
1.0.0.0,1.0.0.255,AU
192.0.2.0,192.0.2.255,DE
198.51.100.0,198.51.100.255,FR
203.0.113.0,203.0.113.255,
kaputte,zeile
2001:db8::,2001:db8::ffff,DE
```

`ispconfig/tests/fixtures/origin/dbip-asn.csv`:

```text
1.0.0.0,1.0.0.255,13335,"Beispielnetz, Inc."
192.0.2.0,192.0.2.255,3320,Zweites Beispielnetz
198.51.100.0,198.51.100.255,abc,Ohne Nummer
2001:db8::,2001:db8::ffff,64500,Drittes Beispielnetz
```

`ispconfig/tests/fixtures/origin/maxmind-country-blocks.csv`:

```text
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
1.0.0.0/24,2077456,2077456,,0,0
192.0.2.0/24,,2921044,,0,0
198.51.100.0/24,3017382,3017382,,0,0
203.0.113.0/24,999999,,,0,0
2001:db8::/32,2921044,2921044,,0,0
```

`ispconfig/tests/fixtures/origin/maxmind-country-locations.csv`:

```text
geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
2077456,de,OC,Ozeanien,AU,Australien,0
2921044,de,EU,Europa,DE,Deutschland,1
3017382,de,EU,Europa,FR,Frankreich,1
```

`ispconfig/tests/fixtures/origin/maxmind-country-blocks-ipv6.csv`:

```text
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
2001:db9::/32,3017382,3017382,,0,0
```

`ispconfig/tests/fixtures/origin/maxmind-asn-blocks.csv`:

```text
network,autonomous_system_number,autonomous_system_organization
1.0.0.0/24,13335,"Beispielnetz, Inc."
192.0.2.0/24,3320,Zweites Beispielnetz
198.51.100.0/24,,Ohne Nummer
```

`ispconfig/tests/fixtures/origin/tor.txt`:

```text
# Beispielliste
198.51.100.5
192.0.2.10
192.0.2.11
kein-ip

2001:db8::5
```

`ispconfig/tests/fixtures/origin/x4b-ipv4.txt`:

```text
203.0.113.0/24
192.0.2.128/25
192.0.2.0/25
kaputt/99
```

`ispconfig/tests/fixtures/origin/x4b-ipv6.txt`:

```text
2001:db8:1::/48
```

Dazu die gepackte Fassung der ersten Datei, damit der Test auch `.gz` liest:

```bash
gzip -kf ispconfig/tests/fixtures/origin/dbip-country.csv
```

- [ ] **Step 2: Test schreiben**

Neue Datei `ispconfig/tests/waf_origin_sources_test.php`:

```php
<?php
/**
 * Checks how the origin sources are read into range files and when a fresh
 * file may replace the one in use.
 *
 *   php ispconfig/tests/waf_origin_sources_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_origin.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$fixtures = __DIR__ . '/fixtures/origin';
$dir = sys_get_temp_dir() . '/waf_origin_sources_test_' . getmypid();
@mkdir($dir, 0700, true);

// --- The sources themselves ---------------------------------------------------

expect_same('every source names its setting', array_keys(waf_origin_sources()),
	array('dbip_country', 'dbip_asn', 'maxmind_country', 'maxmind_asn', 'tor', 'x4b_vpn', 'x4b_datacenter'));
expect_same('sources of the settings', waf_origin_chosen(array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject',
	'waf_origin_net' => 'off')), array('dbip_country', 'dbip_asn', 'tor'));
expect_same('sources with everything off', waf_origin_chosen(array()), array());
expect_same('sources with MaxMind and X4BNet', waf_origin_chosen(array('waf_origin_geo' => 'maxmind', 'waf_origin_net' => 'x4b')),
	array('maxmind_country', 'maxmind_asn', 'x4b_vpn', 'x4b_datacenter'));
expect_same('address of DB-IP with the month', waf_origin_urls('dbip_country', '2026-09'),
	array('https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz'));
expect_same('address of DB-IP without a month', count(waf_origin_urls('dbip_asn', 'kein-monat')), 1);
expect_same('two addresses for X4BNet', count(waf_origin_urls('x4b_vpn', '')), 2);
expect_same('address of an unknown source', waf_origin_urls('gibt-es-nicht', ''), array());

// --- DB-IP --------------------------------------------------------------------

$out = $dir . '/dbip_country.bin';
$counts = waf_origin_read_dbip_country($fixtures . '/dbip-country.csv', $out);
expect_same('DB-IP country counts', array($counts['lines'], $counts['bad'], $counts['ranges'], $counts['values']),
	array(6, 2, 4, 3));
$reader = waf_origin_open($out);
expect_same('DB-IP country lookups', array(waf_origin_find($reader, '1.0.0.1'), waf_origin_find($reader, '192.0.2.7'),
	waf_origin_find($reader, '2001:db8::1'), waf_origin_find($reader, '203.0.113.1')), array('AU', 'DE', 'DE', ''));
waf_origin_close($reader);

// The packed file reads like the plain one.
$packed = waf_origin_read_dbip_country($fixtures . '/dbip-country.csv.gz', $dir . '/packed.bin');
expect_same('packed file reads the same', $packed, $counts);

$out = $dir . '/dbip_asn.bin';
$counts = waf_origin_read_dbip_asn($fixtures . '/dbip-asn.csv', $out);
expect_same('DB-IP asn counts', array($counts['lines'], $counts['bad'], $counts['ranges']), array(4, 1, 3));
$reader = waf_origin_open($out);
expect_same('network with a comma in its name', waf_origin_parts(waf_origin_find($reader, '1.0.0.1')),
	array('asn' => 13335, 'as_org' => 'Beispielnetz, Inc.'));
expect_same('second network', waf_origin_parts(waf_origin_find($reader, '192.0.2.7')),
	array('asn' => 3320, 'as_org' => 'Zweites Beispielnetz'));
expect_same('line without a number', waf_origin_find($reader, '198.51.100.7'), '');
waf_origin_close($reader);

// --- MaxMind ------------------------------------------------------------------

$out = $dir . '/maxmind_country.bin';
$counts = waf_origin_read_maxmind_country($fixtures . '/maxmind-country-blocks.csv',
	$fixtures . '/maxmind-country-locations.csv', $out);
expect_same('MaxMind country counts', array($counts['lines'], $counts['bad'], $counts['ranges']), array(5, 1, 4));
$reader = waf_origin_open($out);
expect_same('MaxMind lookups', array(waf_origin_find($reader, '1.0.0.1'), waf_origin_find($reader, '192.0.2.7'),
	waf_origin_find($reader, '198.51.100.7'), waf_origin_find($reader, '2001:db8::1'), waf_origin_find($reader, '203.0.113.1')),
	array('AU', 'DE', 'FR', 'DE', ''));
waf_origin_close($reader);
// GeoLite2 ships IPv4 and IPv6 apart; both files become one range file.
$out = $dir . '/maxmind_both.bin';
$counts = waf_origin_read_maxmind_country(array($fixtures . '/maxmind-country-blocks.csv',
	$fixtures . '/maxmind-country-blocks-ipv6.csv'), $fixtures . '/maxmind-country-locations.csv', $out);
expect_same('MaxMind from two files', array($counts['lines'], $counts['ranges']), array(6, 5));
$reader = waf_origin_open($out);
expect_same('address of the second file', waf_origin_find($reader, '2001:db9::1'), 'FR');
expect_same('address of the first file stays', waf_origin_find($reader, '192.0.2.7'), 'DE');
waf_origin_close($reader);

expect_same('MaxMind without the locations file',
	waf_origin_read_maxmind_country($fixtures . '/maxmind-country-blocks.csv', $dir . '/fehlt.csv', $dir . '/x.bin'), null);

$out = $dir . '/maxmind_asn.bin';
$counts = waf_origin_read_maxmind_asn($fixtures . '/maxmind-asn-blocks.csv', $out);
expect_same('MaxMind asn counts', array($counts['lines'], $counts['bad'], $counts['ranges']), array(3, 1, 2));
$reader = waf_origin_open($out);
expect_same('MaxMind network', waf_origin_parts(waf_origin_find($reader, '192.0.2.7')),
	array('asn' => 3320, 'as_org' => 'Zweites Beispielnetz'));
waf_origin_close($reader);

// --- Lists --------------------------------------------------------------------

$out = $dir . '/tor.bin';
$counts = waf_origin_read_list($fixtures . '/tor.txt', $out);
expect_same('Tor counts', array($counts['lines'], $counts['bad'], $counts['ranges'], $counts['values']), array(5, 1, 3, 1));
$reader = waf_origin_open($out);
expect_same('address of the list', waf_origin_find($reader, '198.51.100.5'), 'y');
expect_same('second address of the list', waf_origin_find($reader, '2001:db8::5'), 'y');
expect_same('address outside the list', waf_origin_find($reader, '192.0.2.99'), '');
waf_origin_close($reader);

// Two files in one range file; the two halves of 192.0.2.0/24 become one range.
$out = $dir . '/x4b.bin';
$counts = waf_origin_read_list(array($fixtures . '/x4b-ipv4.txt', $fixtures . '/x4b-ipv6.txt'), $out);
expect_same('X4BNet counts', array($counts['lines'], $counts['bad'], $counts['ranges']), array(5, 1, 3));
$reader = waf_origin_open($out);
expect_same('address of the joined halves', waf_origin_ranges($reader), 3);
waf_origin_close($reader);
expect_same('list file that is missing', waf_origin_read_list($dir . '/fehlt.txt', $dir . '/y.bin'), null);

// --- Values -------------------------------------------------------------------

expect_same('value of a network', waf_origin_as_value('3320', "  Deutsche\tTelekom AG "), "3320\x1fDeutsche Telekom AG");
expect_same('value of a long name', strlen(waf_origin_parts(waf_origin_as_value('1', str_repeat('a', 300)))['as_org']), 120);
expect_same('parts of a country', waf_origin_parts('DE'), array('country' => 'DE'));
expect_same('parts of nothing', waf_origin_parts(''), array());
expect_same('parts of something else', waf_origin_parts('kein Wert'), array());

// --- Plausibility -------------------------------------------------------------

$good = array('ranges' => 150000, 'values' => 250, 'lines' => 150000, 'bad' => 10, 'skipped' => 0);
expect_same('a plausible file', waf_origin_check('dbip_country', $good, 149000), '');
expect_same('a file with too few ranges',
	strpos(waf_origin_check('dbip_country', array('ranges' => 12, 'values' => 2, 'lines' => 12, 'bad' => 0, 'skipped' => 0), 0),
		'liefert nur 12 Bereiche, erwartet sind mindestens 100000.') !== false, true);
expect_same('a file with too many bad lines',
	strpos(waf_origin_check('tor', array('ranges' => 500, 'values' => 1, 'lines' => 1000, 'bad' => 400, 'skipped' => 0), 0),
		'400 von 1000 Zeilen ergeben keinen Adressbereich') !== false, true);
expect_same('a file that lost half of its ranges',
	strpos(waf_origin_check('dbip_country', $good, 400000), 'vorher waren es 400000') !== false, true);
expect_same('an unknown source', strpos(waf_origin_check('gibt-es-nicht', $good, 0), 'ist unbekannt') !== false, true);
$ende = 'Der bisherige Stand bleibt aktiv, der nächste Abruf versucht es erneut.';
expect_same('every message names what happens next',
	substr(waf_origin_check('tor', array('ranges' => 1, 'values' => 1, 'lines' => 1, 'bad' => 0, 'skipped' => 0), 0), -strlen($ende)), $ende);

foreach (glob($dir . '/*') as $name) {
	@unlink($name);
}
@rmdir($dir);

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_origin_sources: alle Prüfungen bestanden\n";
```

- [ ] **Step 3: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_origin_sources_test.php`
Expected: Abbruch mit `Call to undefined function waf_origin_sources()`.

- [ ] **Step 4: Einleser schreiben**

Am Ende von `ispconfig/interface/lib/malwatch_waf_origin.inc.php` anhängen:

```php
// --- Sources ------------------------------------------------------------------

/**
 * The sources this server can load, keyed by their name in
 * malwatch_waf_origin_source. Each one names the setting that turns it on and
 * its value, how its file is read, the smallest plausible number of ranges and
 * the largest download in bytes.
 */
function waf_origin_sources()
{
	return array(
		'dbip_country' => array('setting' => 'waf_origin_geo', 'value' => 'dbip', 'kind' => 'country',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'dbip_asn' => array('setting' => 'waf_origin_geo', 'value' => 'dbip', 'kind' => 'asn',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'maxmind_country' => array('setting' => 'waf_origin_geo', 'value' => 'maxmind', 'kind' => 'country',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'maxmind_asn' => array('setting' => 'waf_origin_geo', 'value' => 'maxmind', 'kind' => 'asn',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'tor' => array('setting' => 'waf_origin_tor', 'value' => 'torproject', 'kind' => 'list',
			'min' => 100, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_tor_hours'),
		'x4b_vpn' => array('setting' => 'waf_origin_net', 'value' => 'x4b', 'kind' => 'list',
			'min' => 1000, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_list_hours'),
		'x4b_datacenter' => array('setting' => 'waf_origin_net', 'value' => 'x4b', 'kind' => 'list',
			'min' => 1000, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_list_hours'),
	);
}

/** The sources the settings turn on, in the order of waf_origin_sources(). */
function waf_origin_chosen($settings)
{
	$chosen = array();
	foreach (waf_origin_sources() as $name => $source) {
		$setting = isset($settings[$source['setting']]) ? (string) $settings[$source['setting']] : 'off';
		if ($setting === $source['value']) {
			$chosen[] = $name;
		}
	}
	return $chosen;
}

/** The addresses the source is loaded from, one download per entry. */
function waf_origin_urls($name, $month)
{
	$month = preg_match('/^\d{4}-\d{2}$/', (string) $month) ? (string) $month : gmdate('Y-m');
	switch ($name) {
		case 'dbip_country':
			return array('https://download.db-ip.com/free/dbip-country-lite-' . $month . '.csv.gz');
		case 'dbip_asn':
			return array('https://download.db-ip.com/free/dbip-asn-lite-' . $month . '.csv.gz');
		case 'maxmind_country':
			return array('https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip');
		case 'maxmind_asn':
			return array('https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip');
		case 'tor':
			return array('https://check.torproject.org/torbulkexitlist');
		case 'x4b_vpn':
			return array('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
				'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt');
		case 'x4b_datacenter':
			return array('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt',
				'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt');
	}
	return array();
}

/** An empty result of a reader; the readers count their lines into it. */
function waf_origin_result()
{
	return array('ranges' => 0, 'values' => 0, 'lines' => 0, 'bad' => 0, 'skipped' => 0);
}

/**
 * Opens a text file for reading line by line. gzopen() also reads a file that
 * is not packed, so one function covers both. Returns the handle or null.
 */
function waf_origin_lines($file)
{
	$handle = @gzopen($file, 'rb');
	return $handle === false ? null : $handle;
}

/**
 * The CSV of DB-IP Lite: first address, last address, country. Writes the
 * range file and returns the counts, or null when a file fails.
 */
function waf_origin_read_dbip_country($in, $out)
{
	return waf_origin_read_pairs($in, $out, 3, function ($row) {
		$country = strtoupper(trim($row[2]));
		return preg_match('/^[A-Z]{2}$/', $country) ? array($row[0], $row[1], $country) : null;
	});
}

/**
 * The CSV of DB-IP Lite with the networks: first address, last address, AS
 * number, organisation.
 */
function waf_origin_read_dbip_asn($in, $out)
{
	return waf_origin_read_pairs($in, $out, 4, function ($row) {
		$number = trim($row[2]);
		return preg_match('/^\d{1,10}$/', $number) ? array($row[0], $row[1], waf_origin_as_value($number, $row[3])) : null;
	});
}

/**
 * A CSV whose lines carry the first and the last address. $in is one file or
 * a list of files, read one after the other into one range file. $fields is
 * how many columns a line needs, $pick turns a line into array(first, last,
 * value) or null. The files come sorted; a line out of order is left out.
 */
function waf_origin_read_pairs($in, $out, $fields, $pick)
{
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	$counts = waf_origin_result();
	foreach (is_array($in) ? $in : array($in) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			waf_origin_finish($writer);
			return null;
		}
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$counts['lines']++;
			$row = str_getcsv($line, ",", chr(34), chr(92));
			if (count($row) < $fields) {
				$counts['bad']++;
				continue;
			}
			$picked = call_user_func($pick, $row);
			$first = $picked === null ? '' : waf_origin_bytes($picked[0]);
			$last = $picked === null ? '' : waf_origin_bytes($picked[1]);
			if ($first === '' || $last === '') {
				$counts['bad']++;
				continue;
			}
			if (!waf_origin_write($writer, $first, $last, $picked[2])) {
				$counts['skipped']++;
			}
		}
		gzclose($handle);
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/**
 * The blocks CSV of GeoLite2 with the countries. $locations is the CSV that
 * holds a country for every geoname_id.
 */
function waf_origin_read_maxmind_country($in, $locations, $out)
{
	$countries = waf_origin_maxmind_countries($locations);
	if ($countries === null) {
		return null;
	}
	return waf_origin_read_networks($in, $out, function ($row) use ($countries) {
		$id = trim($row[1]) !== '' ? trim($row[1]) : trim($row[2]);
		return isset($countries[$id]) ? $countries[$id] : null;
	});
}

/** The blocks CSV of GeoLite2 with the networks. */
function waf_origin_read_maxmind_asn($in, $out)
{
	return waf_origin_read_networks($in, $out, function ($row) {
		$number = trim($row[1]);
		return preg_match('/^\d{1,10}$/', $number) ? waf_origin_as_value($number, isset($row[2]) ? $row[2] : '') : null;
	});
}

/** geoname_id to country code from the locations CSV of GeoLite2; null when the file fails. */
function waf_origin_maxmind_countries($file)
{
	$handle = waf_origin_lines($file);
	if ($handle === null) {
		return null;
	}
	$countries = array();
	$head = array();
	while (($line = gzgets($handle)) !== false) {
		$line = trim($line);
		if ($line === '') {
			continue;
		}
		$row = str_getcsv($line, ",", chr(34), chr(92));
		if (count($head) === 0) {
			$head = array_flip($row);
			continue;
		}
		if (!isset($head['geoname_id']) || !isset($head['country_iso_code']) || count($row) <= $head['country_iso_code']) {
			continue;
		}
		$code = strtoupper(trim($row[$head['country_iso_code']]));
		if (preg_match('/^[A-Z]{2}$/', $code)) {
			$countries[trim($row[$head['geoname_id']])] = $code;
		}
	}
	gzclose($handle);
	return $countries;
}

/**
 * A blocks CSV of GeoLite2: the first column is the network as CIDR, $pick
 * turns a line into its value or null. The first line of every file names the
 * columns. $in is one file or the list of files of one source; GeoLite2 ships
 * IPv4 and IPv6 apart, and in that order they stay sorted.
 */
function waf_origin_read_networks($in, $out, $pick)
{
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	$counts = waf_origin_result();
	foreach (is_array($in) ? $in : array($in) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			waf_origin_finish($writer);
			return null;
		}
		$first_line = true;
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '') {
				continue;
			}
			if ($first_line) {
				$first_line = false;
				if (strpos($line, 'network') === 0) {
					continue;
				}
			}
			$counts['lines']++;
			$row = str_getcsv($line, ",", chr(34), chr(92));
			$block = waf_origin_cidr(isset($row[0]) ? $row[0] : '');
			$value = count($row) < 2 ? null : call_user_func($pick, $row);
			if ($block === null || $value === null) {
				$counts['bad']++;
				continue;
			}
			if (!waf_origin_write($writer, $block[0], $block[1], $value)) {
				$counts['skipped']++;
			}
		}
		gzclose($handle);
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/**
 * A list with one address or block per line, as the Tor and X4BNet lists come.
 * The lines are unsorted, so they are sorted here before they are written; the
 * ranges carry no value. $files are read one after the other into one file.
 */
function waf_origin_read_list($files, $out)
{
	$counts = waf_origin_result();
	$rows = array();
	foreach (is_array($files) ? $files : array($files) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			return null;
		}
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$counts['lines']++;
			$block = waf_origin_cidr($line);
			if ($block === null) {
				$counts['bad']++;
				continue;
			}
			$rows[] = $block[0] . $block[1];
		}
		gzclose($handle);
	}
	sort($rows, SORT_STRING);
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	foreach ($rows as $row) {
		// The value marks a hit; an address outside every range answers with ''.
		if (!waf_origin_write($writer, substr($row, 0, 16), substr($row, 16, 16), 'y')) {
			$counts['skipped']++;
		}
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/** The value of a network range: its number and its name, kept apart by a unit separator. */
function waf_origin_as_value($number, $name)
{
	$name = trim(preg_replace('/\s+/', ' ', (string) $name));
	return (string) (int) $number . "\x1f" . waf_origin_cut($name, 120);
}

/** A value of a range file as array('asn' => n, 'as_org' => text) or, for a country, array('country' => 'DE'). */
function waf_origin_parts($value)
{
	$value = (string) $value;
	if ($value === '') {
		return array();
	}
	$cut = strpos($value, "\x1f");
	if ($cut === false) {
		return preg_match('/^[A-Z]{2}$/', $value) ? array('country' => $value) : array();
	}
	return array('asn' => (int) substr($value, 0, $cut), 'as_org' => substr($value, $cut + 1));
}

/** Cuts a text to $bytes without breaking a character. */
function waf_origin_cut($text, $bytes)
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

/**
 * Whether a freshly built range file may replace the one in use. $previous is
 * how many ranges the file in use holds, 0 when there is none. Returns '' when
 * it may, else the reason with what happens next.
 */
function waf_origin_check($name, $counts, $previous)
{
	$sources = waf_origin_sources();
	if (!isset($sources[$name]) || !is_array($counts)) {
		return 'Die Quelle ' . $name . ' ist unbekannt. Bitte die Einstellungen der Abwehr prüfen.';
	}
	$keep = ' Der bisherige Stand bleibt aktiv, der nächste Abruf versucht es erneut.';
	if ($counts['lines'] > 0 && $counts['bad'] > $counts['lines'] / 100) {
		return 'Die Datei der Quelle ' . $name . ' ist unlesbar: ' . $counts['bad'] . ' von '
			. $counts['lines'] . ' Zeilen ergeben keinen Adressbereich.' . $keep;
	}
	$min = (int) $sources[$name]['min'];
	if ($counts['ranges'] < $min) {
		return 'Die Quelle ' . $name . ' liefert nur ' . $counts['ranges'] . ' Bereiche, erwartet sind mindestens '
			. $min . '.' . $keep;
	}
	$previous = (int) $previous;
	if ($previous > 0 && $counts['ranges'] < $previous / 2) {
		return 'Die Quelle ' . $name . ' liefert nur noch ' . $counts['ranges'] . ' Bereiche, vorher waren es '
			. $previous . '.' . $keep;
	}
	return '';
}
```

- [ ] **Step 5: Tests laufen lassen**

Run: `php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_origin_test.php && php -l ispconfig/interface/lib/malwatch_waf_origin.inc.php`
Expected: `waf_origin_sources: alle Prüfungen bestanden`, `waf_origin: alle Prüfungen bestanden` und `No syntax errors detected`.

- [ ] **Step 6: CI**

In `.github/workflows/ci.yml`, Job `php-syntax`, nach dem Schritt `WAF origin ranges` einfügen:

```yaml
      - name: WAF origin sources
        run: php ispconfig/tests/waf_origin_sources_test.php
```

- [ ] **Step 7: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_origin.inc.php ispconfig/tests/waf_origin_sources_test.php ispconfig/tests/fixtures/origin .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): read the origin sources into range files" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B3: Einstellungen „Herkunft der Adressen“

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (`waf_settings_defaults()`, `waf_settings_limits()`, `waf_settings()`, neue `waf_origin_choices()`)
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (`waf_panel_key_mask()`)
- Modify: `ispconfig/install/schema.sql` (acht Spalten in `malwatch_config`)
- Modify: `ispconfig/interface/form/malwatch_waf_config.tform.php`, `ispconfig/interface/templates/malwatch_waf_config_edit.htm`
- Modify: `ispconfig/interface/malwatch_waf_config_edit.php` (Schlüsselfeld, Pflichtfelder)
- Modify: `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng`
- Test: `ispconfig/tests/waf_lib_test.php`, `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_settings()` und die Prüfung der Formularfelder aus Teil A
- Produces:
  - Einstellungen `waf_origin_geo` (`off`, `dbip`, `maxmind`), `waf_origin_maxmind_account`, `waf_origin_maxmind_key`, `waf_origin_tor` (`off`, `torproject`), `waf_origin_net` (`off`, `x4b`), `waf_origin_tor_hours` (1 bis 168, Vorgabe 1), `waf_origin_list_hours` (1 bis 720, Vorgabe 24), `waf_origin_db_hours` (1 bis 720, Vorgabe 24)
  - `waf_origin_choices()` → erlaubte Werte je Auswahlfeld
  - `waf_panel_key_mask($key)` → `''` oder `••••` mit den letzten vier Zeichen

Der Abschnitt steht auf der Einstellungsseite der Abwehr zwischen „Anzeige“ und „Cron“. Die Vorgabe ist überall `off`: Ohne Zutun lädt der Server nichts herunter.

- [ ] **Step 1: Tests schreiben**

In `ispconfig/tests/waf_lib_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B3: settings of the origin -----------------------------------------------

$origin = waf_settings(array());
expect_same('origin off by default', array($origin['waf_origin_geo'], $origin['waf_origin_tor'], $origin['waf_origin_net']),
	array('off', 'off', 'off'));
expect_same('hours by default', array($origin['waf_origin_tor_hours'], $origin['waf_origin_list_hours'],
	$origin['waf_origin_db_hours']), array(1, 24, 24));
$origin = waf_settings(array('waf_origin_geo' => 'maxmind', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'x4b',
	'waf_origin_maxmind_account' => '123456', 'waf_origin_maxmind_key' => 'AbC_123', 'waf_origin_tor_hours' => '0',
	'waf_origin_list_hours' => '1000', 'waf_origin_db_hours' => '48'));
expect_same('origin as chosen', array($origin['waf_origin_geo'], $origin['waf_origin_tor'], $origin['waf_origin_net']),
	array('maxmind', 'torproject', 'x4b'));
expect_same('hours inside their limits', array($origin['waf_origin_tor_hours'], $origin['waf_origin_list_hours'],
	$origin['waf_origin_db_hours']), array(1, 720, 48));
expect_same('account and key kept', array($origin['waf_origin_maxmind_account'], $origin['waf_origin_maxmind_key']),
	array('123456', 'AbC_123'));
$origin = waf_settings(array('waf_origin_geo' => 'irgendwas', 'waf_origin_tor' => 'ja', 'waf_origin_net' => 'proxycheck',
	'waf_origin_maxmind_account' => 'abc', 'waf_origin_maxmind_key' => 'schlüssel mit leerzeichen'));
expect_same('unknown choices fall back to off', array($origin['waf_origin_geo'], $origin['waf_origin_tor'],
	$origin['waf_origin_net']), array('off', 'off', 'off'));
expect_same('account and key that fit no pattern', array($origin['waf_origin_maxmind_account'],
	$origin['waf_origin_maxmind_key']), array('', ''));
expect_same('the choices of every field', waf_origin_choices(), array(
	'waf_origin_geo' => array('off', 'dbip', 'maxmind'),
	'waf_origin_tor' => array('off', 'torproject'),
	'waf_origin_net' => array('off', 'x4b'),
));
```

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B3: the key on the settings page -----------------------------------------

expect_same('mask of a key', waf_panel_key_mask('ABCD1234WXYZ'), '••••WXYZ');
expect_same('mask of a short key', waf_panel_key_mask('AB'), '••••AB');
expect_same('mask without a key', waf_panel_key_mask(''), '');
expect_same('mask of something that is no text', waf_panel_key_mask(null), '');
```

Die Prüfung `settings form edits the numbers only` vergleicht die Felder des Formulars mit den Grenzen. Der Abschnitt bringt Felder ohne Grenzen mit, deshalb zählt sie ab jetzt nur die Zahlenfelder. In `ispconfig/tests/waf_panel_test.php` die Zeile

```php
expect_same('settings form edits the numbers only', array_keys($config_tab['fields']), array_keys(waf_settings_limits()));
```

ersetzen durch:

```php
$config_numbers = array();
foreach ($config_tab['fields'] as $key => $field) {
	if (isset($field['validators'][0]['type']) && $field['validators'][0]['type'] === 'RANGE') {
		$config_numbers[] = $key;
	}
}
expect_same('settings form edits the numbers only', $config_numbers, array_keys(waf_settings_limits()));
expect_same('settings form knows every choice', array_keys(waf_origin_choices()),
	array_values(array_intersect(array_keys($config_tab['fields']), array_keys(waf_origin_choices()))));
foreach (waf_origin_choices() as $key => $values) {
	expect_same("settings form choices of $key",
		isset($config_tab['fields'][$key]['value']) ? array_keys($config_tab['fields'][$key]['value']) : array(), $values);
}
```

- [ ] **Step 2: Tests laufen lassen, sie müssen scheitern**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: Abbruch mit `Call to undefined function waf_origin_choices()`.

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_key_mask()`.

- [ ] **Step 3: Vorgaben, Grenzen und Prüfung**

In `ispconfig/interface/lib/malwatch_waf_lib.inc.php`, `waf_settings_defaults()`, nach `'waf_card_hits' => 5000,` einfügen:

```php
		'waf_origin_geo' => 'off',
		'waf_origin_maxmind_account' => '',
		'waf_origin_maxmind_key' => '',
		'waf_origin_tor' => 'off',
		'waf_origin_net' => 'off',
		'waf_origin_tor_hours' => 1,
		'waf_origin_list_hours' => 24,
		'waf_origin_db_hours' => 24,
```

In `waf_settings_limits()` nach `'waf_card_hits' => array(100, 100000),` einfügen:

```php
		'waf_origin_tor_hours' => array(1, 168),
		'waf_origin_list_hours' => array(1, 720),
		'waf_origin_db_hours' => array(1, 720),
```

Vor `function waf_settings_defaults()` einfügen:

```php
/**
 * The values each choice of the origin settings accepts. Anything else falls
 * back to the default, so a row from an older schema or a hand-edited value
 * never turns a source on.
 */
function waf_origin_choices()
{
	return array(
		'waf_origin_geo' => array('off', 'dbip', 'maxmind'),
		'waf_origin_tor' => array('off', 'torproject'),
		'waf_origin_net' => array('off', 'x4b'),
	);
}

```

In `waf_settings()` vor `return $settings;` einfügen:

```php
	foreach (waf_origin_choices() as $key => $values) {
		if (!in_array($settings[$key], $values, true)) {
			$settings[$key] = $defaults[$key];
		}
	}
	// The account is digits, the licence key letters, digits and underscores;
	// MaxMind hands out nothing else, and both go into a URL.
	$settings['waf_origin_maxmind_account'] = preg_match('/^\d{0,32}$/', (string) $settings['waf_origin_maxmind_account'])
		? (string) $settings['waf_origin_maxmind_account'] : '';
	$settings['waf_origin_maxmind_key'] = preg_match('/^[A-Za-z0-9_]{0,128}$/', (string) $settings['waf_origin_maxmind_key'])
		? (string) $settings['waf_origin_maxmind_key'] : '';
```

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` nach `waf_panel_ip_filter()` einfügen:

```php
/** A stored key as the page shows it: four dots and its last four characters. */
function waf_panel_key_mask($key)
{
	$key = is_string($key) ? trim($key) : '';
	return $key === '' ? '' : '••••' . substr($key, -4);
}
```

- [ ] **Step 4: Tests laufen lassen**

Run: `php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php`
Expected: `waf_lib: alle Prüfungen bestanden` und `waf_panel: alle Prüfungen bestanden`; die Prüfungen des Formulars scheitern noch, weil die Felder fehlen (`settings form choices of waf_origin_geo`).

- [ ] **Step 5: Schema**

In `ispconfig/install/schema.sql` vor der Zeile `-- waf carries the jobs of the page Abwehr. The malwatch cron works on them` einfügen:

```sql
-- Where an address comes from: the chosen sources and how often they are checked.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_origin_geo` enum(''off'',''dbip'',''maxmind'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_maxmind_account` varchar(32) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_maxmind_key` varchar(128) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_tor` enum(''off'',''torproject'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_net` enum(''off'',''x4b'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_tor_hours` int(11) unsigned NOT NULL DEFAULT ''1'', ADD COLUMN `waf_origin_list_hours` int(11) unsigned NOT NULL DEFAULT ''24'', ADD COLUMN `waf_origin_db_hours` int(11) unsigned NOT NULL DEFAULT ''24''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_geo');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

```

- [ ] **Step 6: Formular**

In `ispconfig/interface/form/malwatch_waf_config.tform.php` das Feld `waf_card_hits` so abschließen und die neuen Felder anhängen (die Zahlenfelder behalten die Reihenfolge von `waf_settings_limits()`):

```php
		'waf_card_hits' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '100:100000',
					'errmsg' => 'waf_card_hits_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_origin_geo' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'dbip' => 'origin_geo_dbip_txt',
				'maxmind' => 'origin_geo_maxmind_txt'
			)
		),
		'waf_origin_maxmind_account' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^\d{0,32}$/',
					'errmsg' => 'waf_origin_maxmind_account_error'
				)
			),
			'value' => '',
			'width' => '20',
			'maxlength' => '32'
		),
		'waf_origin_maxmind_key' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9_]{0,128}$/',
					'errmsg' => 'waf_origin_maxmind_key_error'
				)
			),
			'value' => '',
			'width' => '30',
			'maxlength' => '128'
		),
		'waf_origin_tor' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'torproject' => 'origin_tor_torproject_txt'
			)
		),
		'waf_origin_net' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'x4b' => 'origin_net_x4b_txt'
			)
		),
		'waf_origin_tor_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:168',
					'errmsg' => 'waf_origin_tor_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_origin_list_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:720',
					'errmsg' => 'waf_origin_list_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_origin_db_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:720',
					'errmsg' => 'waf_origin_db_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		)
	)
);
```

- [ ] **Step 7: Vorlage**

In `ispconfig/interface/templates/malwatch_waf_config_edit.htm` vor `<p class="mw-wafcfg-head">{tmpl_var name='cron_head_txt'}</p>` einfügen:

```html
<p class="mw-wafcfg-head">{tmpl_var name='origin_head_txt'}</p>

<p class="mw-wafcfg-note">{tmpl_var name='origin_intro_txt'}</p>

<div class="form-group">
	<label for="waf_origin_geo" class="col-sm-3 control-label">{tmpl_var name='waf_origin_geo_txt'}</label>
	<div class="col-sm-9">
		<select name="waf_origin_geo" id="waf_origin_geo" class="form-control">{tmpl_var name='waf_origin_geo'}</select>
		<span class="help-block">{tmpl_var name='waf_origin_geo_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_maxmind_account" class="col-sm-3 control-label">{tmpl_var name='waf_origin_maxmind_account_txt'}</label>
	<div class="col-sm-9">
		<input type="text" name="waf_origin_maxmind_account" id="waf_origin_maxmind_account" value="{tmpl_var name='waf_origin_maxmind_account'}" class="form-control" autocomplete="off" inputmode="numeric" maxlength="32" />
		<span class="help-block">{tmpl_var name='waf_origin_maxmind_account_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_maxmind_key" class="col-sm-3 control-label">{tmpl_var name='waf_origin_maxmind_key_txt'}</label>
	<div class="col-sm-9">
		<input type="text" name="waf_origin_maxmind_key" id="waf_origin_maxmind_key" value="{tmpl_var name='waf_origin_maxmind_key'}" class="form-control" autocomplete="off" maxlength="128" />
		<span class="help-block">{tmpl_var name='waf_origin_maxmind_key_hint_txt'}</span>
		<tmpl_if name="origin_key_stored">
		<label class="mw-wafcfg-clear"><input type="checkbox" name="waf_origin_key_clear" value="1" /> {tmpl_var name='origin_key_clear_txt'}</label>
		</tmpl_if>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_tor" class="col-sm-3 control-label">{tmpl_var name='waf_origin_tor_txt'}</label>
	<div class="col-sm-9">
		<select name="waf_origin_tor" id="waf_origin_tor" class="form-control">{tmpl_var name='waf_origin_tor'}</select>
		<span class="help-block">{tmpl_var name='waf_origin_tor_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_net" class="col-sm-3 control-label">{tmpl_var name='waf_origin_net_txt'}</label>
	<div class="col-sm-9">
		<select name="waf_origin_net" id="waf_origin_net" class="form-control">{tmpl_var name='waf_origin_net'}</select>
		<span class="help-block">{tmpl_var name='waf_origin_net_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_tor_hours" class="col-sm-3 control-label">{tmpl_var name='waf_origin_tor_hours_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="168" step="1" name="waf_origin_tor_hours" id="waf_origin_tor_hours" value="{tmpl_var name='waf_origin_tor_hours'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_origin_tor_hours_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_list_hours" class="col-sm-3 control-label">{tmpl_var name='waf_origin_list_hours_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="720" step="1" name="waf_origin_list_hours" id="waf_origin_list_hours" value="{tmpl_var name='waf_origin_list_hours'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_origin_list_hours_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_origin_db_hours" class="col-sm-3 control-label">{tmpl_var name='waf_origin_db_hours_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="720" step="1" name="waf_origin_db_hours" id="waf_origin_db_hours" value="{tmpl_var name='waf_origin_db_hours'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_origin_db_hours_hint_txt'}</span>
	</div>
</div>

```

Im Stilblock derselben Datei nach der Zeile `.mw-wafcfg-num{max-width:14ch}` einfügen:

```css
.mw-wafcfg-note{max-width:80ch;opacity:.8;font-size:13px;margin:0 0 10px}
.mw-wafcfg-clear{display:inline-flex;gap:6px;align-items:center;font-weight:400;margin:4px 0 0}
```

- [ ] **Step 8: Texte**

In `ispconfig/interface/lang/de_malwatch_waf_config.lng` vor `$wb['cron_head_txt'] = 'Cron';` einfügen:

```php
$wb['origin_head_txt'] = 'Herkunft der Adressen';
$wb['origin_intro_txt'] = 'Aus diesen Quellen bestimmt der Server Land, Provider und die Merkmale Tor, VPN und Rechenzentrum. Die Vorgabe ist „aus“: Erst mit einer Wahl lädt der Server eine Liste herunter.';
$wb['origin_off_txt'] = 'aus';
$wb['origin_geo_dbip_txt'] = 'DB-IP Lite (frei, Namensnennung)';
$wb['origin_geo_maxmind_txt'] = 'MaxMind GeoLite2 (Konto nötig)';
$wb['origin_tor_torproject_txt'] = 'Liste des Tor-Projekts';
$wb['origin_net_x4b_txt'] = 'X4BNet-Listen (VPN und Rechenzentren)';
$wb['origin_key_clear_txt'] = 'Lizenzschlüssel löschen';
$wb['waf_origin_geo_txt'] = 'Land und Provider';
$wb['waf_origin_geo_hint_txt'] = 'Die Liste wird heruntergeladen, Adressen bleiben auf dem Server. DB-IP Lite verlangt die Namensnennung „IP Geolocation by DB-IP“, MaxMind ein kostenloses Konto.';
$wb['waf_origin_maxmind_account_txt'] = 'MaxMind: Konto-ID';
$wb['waf_origin_maxmind_account_hint_txt'] = 'Nur Ziffern. Steht im MaxMind-Konto unter „My License Key“.';
$wb['waf_origin_maxmind_key_txt'] = 'MaxMind: Lizenzschlüssel';
$wb['waf_origin_maxmind_key_hint_txt'] = 'Buchstaben, Ziffern und Unterstrich. Ein gespeicherter Schlüssel steht hier verdeckt; ein leeres Feld behält ihn.';
$wb['waf_origin_tor_txt'] = 'Tor';
$wb['waf_origin_tor_hint_txt'] = 'Die öffentliche Liste der Tor-Ausgänge. Die Liste wird heruntergeladen, Adressen bleiben auf dem Server.';
$wb['waf_origin_net_txt'] = 'VPN und Rechenzentrum';
$wb['waf_origin_net_hint_txt'] = 'Die Listen von X4BNet nennen bekannte VPN-Netze und Rechenzentren. Die Listen werden heruntergeladen, Adressen bleiben auf dem Server.';
$wb['waf_origin_tor_hours_txt'] = 'Tor-Liste laden (Stunden)';
$wb['waf_origin_tor_hours_hint_txt'] = 'So oft holt der Cron die Liste der Tor-Ausgänge; sie ändert sich stündlich.';
$wb['waf_origin_list_hours_txt'] = 'X4BNet-Listen laden (Stunden)';
$wb['waf_origin_list_hours_hint_txt'] = 'So oft holt der Cron die Listen für VPN und Rechenzentren.';
$wb['waf_origin_db_hours_txt'] = 'Land und Provider prüfen (Stunden)';
$wb['waf_origin_db_hours_hint_txt'] = 'So oft sieht der Cron nach einem neuen Stand von DB-IP oder MaxMind. Geladen wird nur, wenn es einen gibt.';

```

und am Dateiende nach `$wb['waf_card_hits_error_range']`:

```php
$wb['waf_origin_maxmind_account_error'] = 'MaxMind: Konto-ID: Erlaubt sind bis zu 32 Ziffern. Bitte die Konto-ID aus dem MaxMind-Konto eintragen und erneut speichern.';
$wb['waf_origin_maxmind_key_error'] = 'MaxMind: Lizenzschlüssel: Erlaubt sind Buchstaben, Ziffern und Unterstrich, bis zu 128 Zeichen. Bitte den Schlüssel aus dem MaxMind-Konto eintragen und erneut speichern.';
$wb['waf_origin_maxmind_missing_error'] = 'MaxMind braucht Konto-ID und Lizenzschlüssel. Bitte beide eintragen oder bei „Land und Provider“ eine andere Quelle wählen und erneut speichern.';
$wb['waf_origin_tor_hours_error_range'] = 'Tor-Liste laden (Stunden): Erlaubt sind ganze Zahlen von 1 bis 168. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_origin_list_hours_error_range'] = 'X4BNet-Listen laden (Stunden): Erlaubt sind ganze Zahlen von 1 bis 720. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_origin_db_hours_error_range'] = 'Land und Provider prüfen (Stunden): Erlaubt sind ganze Zahlen von 1 bis 720. Bitte den Wert anpassen und erneut speichern.';
```

In `ispconfig/interface/lang/en_malwatch_waf_config.lng` an denselben Stellen:

```php
$wb['origin_head_txt'] = 'Origin of the addresses';
$wb['origin_intro_txt'] = 'The server works out country, provider and the marks Tor, VPN and data centre from these sources. Everything starts as "off": the server downloads a list only after you pick one.';
$wb['origin_off_txt'] = 'off';
$wb['origin_geo_dbip_txt'] = 'DB-IP Lite (free, attribution)';
$wb['origin_geo_maxmind_txt'] = 'MaxMind GeoLite2 (account needed)';
$wb['origin_tor_torproject_txt'] = 'List of the Tor project';
$wb['origin_net_x4b_txt'] = 'X4BNet lists (VPN and data centres)';
$wb['origin_key_clear_txt'] = 'Delete the licence key';
$wb['waf_origin_geo_txt'] = 'Country and provider';
$wb['waf_origin_geo_hint_txt'] = 'The list is downloaded, addresses stay on the server. DB-IP Lite asks for the attribution "IP Geolocation by DB-IP", MaxMind for a free account.';
$wb['waf_origin_maxmind_account_txt'] = 'MaxMind: account ID';
$wb['waf_origin_maxmind_account_hint_txt'] = 'Digits only. The MaxMind account shows it under "My License Key".';
$wb['waf_origin_maxmind_key_txt'] = 'MaxMind: licence key';
$wb['waf_origin_maxmind_key_hint_txt'] = 'Letters, digits and underscore. A stored key appears masked; an empty field keeps it.';
$wb['waf_origin_tor_txt'] = 'Tor';
$wb['waf_origin_tor_hint_txt'] = 'The public list of Tor exits. The list is downloaded, addresses stay on the server.';
$wb['waf_origin_net_txt'] = 'VPN and data centre';
$wb['waf_origin_net_hint_txt'] = 'The X4BNet lists name known VPN networks and data centres. The lists are downloaded, addresses stay on the server.';
$wb['waf_origin_tor_hours_txt'] = 'Load the Tor list (hours)';
$wb['waf_origin_tor_hours_hint_txt'] = 'How often the cron fetches the list of Tor exits; it changes every hour.';
$wb['waf_origin_list_hours_txt'] = 'Load the X4BNet lists (hours)';
$wb['waf_origin_list_hours_hint_txt'] = 'How often the cron fetches the lists for VPN and data centres.';
$wb['waf_origin_db_hours_txt'] = 'Check country and provider (hours)';
$wb['waf_origin_db_hours_hint_txt'] = 'How often the cron looks for a new release of DB-IP or MaxMind. It downloads only when there is one.';

```

```php
$wb['waf_origin_maxmind_account_error'] = 'MaxMind: account ID: up to 32 digits are allowed. Please enter the account ID from your MaxMind account and save again.';
$wb['waf_origin_maxmind_key_error'] = 'MaxMind: licence key: letters, digits and underscore are allowed, up to 128 characters. Please enter the key from your MaxMind account and save again.';
$wb['waf_origin_maxmind_missing_error'] = 'MaxMind needs an account ID and a licence key. Please enter both or pick another source for "Country and provider" and save again.';
$wb['waf_origin_tor_hours_error_range'] = 'Load the Tor list (hours): whole numbers from 1 to 168 are allowed. Please adjust the value and save again.';
$wb['waf_origin_list_hours_error_range'] = 'Load the X4BNet lists (hours): whole numbers from 1 to 720 are allowed. Please adjust the value and save again.';
$wb['waf_origin_db_hours_error_range'] = 'Check country and provider (hours): whole numbers from 1 to 720 are allowed. Please adjust the value and save again.';
```

- [ ] **Step 9: Seite mit dem Schlüsselfeld**

In `ispconfig/interface/malwatch_waf_config_edit.php` die Klasse um drei Stellen ergänzen.

Nach der Zeile `private $waf_message = '';` einfügen:

```php

	/** The stored licence key, read in onLoad() before the form overwrites it. */
	private $waf_stored_key = '';
```

In `onLoad()` vor `parent::onLoad();` einfügen:

```php
		$stored = $app->db->queryOneRecord('SELECT waf_origin_maxmind_key FROM malwatch_config WHERE config_id = 1');
		$this->waf_stored_key = is_array($stored) && isset($stored['waf_origin_maxmind_key'])
			? (string) $stored['waf_origin_maxmind_key'] : '';

```

Nach `onLoad()` einfügen:

```php
	/**
	 * The licence key never leaves the server in clear text: the form shows it
	 * masked, an empty field keeps the stored key, and the checkbox removes it.
	 * onSubmit() runs before the validators, so a missing key stops the save
	 * with a message at the field.
	 */
	public function onSubmit()
	{
		global $app;
		$wb = $this->waf_wb;

		$posted = isset($this->dataRecord['waf_origin_maxmind_key']) ? trim((string) $this->dataRecord['waf_origin_maxmind_key']) : '';
		$clear = isset($this->dataRecord['waf_origin_key_clear']) && (string) $this->dataRecord['waf_origin_key_clear'] === '1';
		if ($clear) {
			$this->dataRecord['waf_origin_maxmind_key'] = '';
		} elseif ($posted === '' || $posted === waf_panel_key_mask($this->waf_stored_key)) {
			$this->dataRecord['waf_origin_maxmind_key'] = $this->waf_stored_key;
		}
		$account = isset($this->dataRecord['waf_origin_maxmind_account']) ? trim((string) $this->dataRecord['waf_origin_maxmind_account']) : '';
		$geo = isset($this->dataRecord['waf_origin_geo']) ? (string) $this->dataRecord['waf_origin_geo'] : 'off';
		if ($geo === 'maxmind' && ($account === '' || (string) $this->dataRecord['waf_origin_maxmind_key'] === '')) {
			$app->tform->errorMessage .= $wb['waf_origin_maxmind_missing_error'] . '<br />';
		}
		parent::onSubmit();
	}

```

In `onAfterUpdate()` nach der Schleife über `$servers` einfügen:

```php
		foreach ($servers as $server_id) {
			waf_panel_queue($app, $server_id, 'origin_update', array());
		}
```

In `onShowEnd()` vor `parent::onShowEnd();` einfügen:

```php
		// The stored key stays on the server; the form shows it masked.
		$app->tpl->setVar('waf_origin_maxmind_key', $app->functions->htmlentities(waf_panel_key_mask($this->waf_stored_key)));
		$app->tpl->setVar('origin_key_stored', $this->waf_stored_key === '' ? 0 : 1);

```

- [ ] **Step 10: Verdrahtung prüfen**

In `ispconfig/tests/check_wiring.sh` vor dem Block `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 69. The origin starts off. A default that turns a source on would make the
#     server download a list on its own; the operator picks the sources, and
#     the page says what each one means before he does.
lib="$root/interface/lib/malwatch_waf_lib.inc.php"
for key in waf_origin_geo waf_origin_tor waf_origin_net; do
	sed -n '/function waf_settings_defaults/,/^}/p' "$lib" | grep -qF "'$key' => 'off'," \
		|| fail "waf_settings_defaults() does not start $key as off"
done
for lang in de en; do
	for key in origin_intro_txt waf_origin_geo_hint_txt waf_origin_tor_hint_txt waf_origin_net_hint_txt \
		waf_origin_maxmind_key_hint_txt; do
		grep -q "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf_config.lng" \
			|| fail "${lang}_malwatch_waf_config.lng is missing $key"
	done
done

```

- [ ] **Step 11: Prüfungen**

Run: `php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php`
Expected: dreimal `alle Prüfungen bestanden`.

Run: `for f in ispconfig/interface/malwatch_waf_config_edit.php ispconfig/interface/form/malwatch_waf_config.tform.php ispconfig/interface/lang/de_malwatch_waf_config.lng ispconfig/interface/lang/en_malwatch_waf_config.lng; do php -l "$f"; done`
Expected: viermal `No syntax errors detected`.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Im Nachbau `.superpowers/abwehr/harness/fake_db.php` die Beispielzeile der Einstellungen um die neuen Spalten ergänzen, damit die Seite mit Werten rendert; in `queryOneRecord()` die Zeile `'waf_emergency_since' => …);` abschließen mit:

```php
				'waf_emergency_since' => getenv('FAKE_EMERGENCY') ? '2026-09-16 11:00:00' : null,
				'waf_card_hits' => '5000', 'waf_origin_geo' => 'off', 'waf_origin_maxmind_account' => '',
				'waf_origin_maxmind_key' => '', 'waf_origin_tor' => 'off', 'waf_origin_net' => 'off',
				'waf_origin_tor_hours' => '1', 'waf_origin_list_hours' => '24', 'waf_origin_db_hours' => '24');
```

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`. Danach zeigt `out_cfg.html` den Abschnitt: `grep -c 'Herkunft der Adressen' .superpowers/abwehr/harness/out_cfg.html` ergibt `1`.

- [ ] **Step 12: Commit**

```bash
git add ispconfig/tests/check_wiring.sh ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/install/schema.sql ispconfig/interface/form/malwatch_waf_config.tform.php ispconfig/interface/templates/malwatch_waf_config_edit.htm ispconfig/interface/malwatch_waf_config_edit.php ispconfig/interface/lang/de_malwatch_waf_config.lng ispconfig/interface/lang/en_malwatch_waf_config.lng ispconfig/tests/waf_lib_test.php ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): settings for the origin of an address" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B4: Stand der Quellen

**Files:**
- Modify: `ispconfig/install/schema.sql` (Tabelle `malwatch_waf_origin_source`), `ispconfig/install/uninstall-schema.sql`
- Modify: `ispconfig/interface/lib/malwatch_waf_origin.inc.php` (Block am Dateiende)
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (Anzeige des Stands)
- Modify: `ispconfig/interface/malwatch_waf_config_edit.php`, `ispconfig/interface/templates/malwatch_waf_config_edit.htm`
- Modify: `ispconfig/interface/malwatch_waf_list.php`, `ispconfig/interface/templates/malwatch_waf_list.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng`, `de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng`
- Test: `ispconfig/tests/waf_origin_sources_test.php`, `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_origin_sources()`, `waf_origin_chosen()` (B2), die Einstellungen aus B3
- Produces:
  - Tabelle `malwatch_waf_origin_source` (`server_id`, `source`, `version`, `checked_at`, `fetched_at`, `entries`, `error`, `error_at`)
  - `waf_origin_due($name, $row, $settings, $now)` → ob eine Quelle fällig ist
  - `waf_panel_origin_rows($wb, $settings, $rows, $now)` → je gewählter Quelle Name, Stand und Fehler für die Einstellungsseite
  - `waf_panel_origin_line($wb, $settings, $rows)` → die Zeile der Übersicht

- [ ] **Step 1: Tests schreiben**

In `ispconfig/tests/waf_origin_sources_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B4: when a source is due -------------------------------------------------

$settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'off',
	'waf_origin_tor_hours' => 1, 'waf_origin_list_hours' => 24, 'waf_origin_db_hours' => 24);
$now = '2026-09-17 20:00:00';
expect_same('a source without a row is due', waf_origin_due('tor', null, $settings, $now), true);
expect_same('a source checked long ago is due',
	waf_origin_due('tor', array('checked_at' => '2026-09-17 18:30:00'), $settings, $now), true);
expect_same('a source checked just now waits',
	waf_origin_due('tor', array('checked_at' => '2026-09-17 19:30:00'), $settings, $now), false);
expect_same('the database sources follow their own hours',
	waf_origin_due('dbip_country', array('checked_at' => '2026-09-17 08:00:00'), $settings, $now), false);
expect_same('the database sources after a day',
	waf_origin_due('dbip_country', array('checked_at' => '2026-09-16 08:00:00'), $settings, $now), true);
expect_same('a source that is off is never due',
	waf_origin_due('x4b_vpn', null, $settings, $now), false);
expect_same('an unknown source is never due', waf_origin_due('gibt-es-nicht', null, $settings, $now), false);
expect_same('a row without a time is due', waf_origin_due('tor', array('checked_at' => null), $settings, $now), true);
```

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B4: the state of the sources ---------------------------------------------

$origin_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'off',
	'waf_origin_tor_hours' => 1, 'waf_origin_list_hours' => 24, 'waf_origin_db_hours' => 24);
$origin_rows = array(
	'dbip_country' => array('source' => 'dbip_country', 'version' => '2026-09', 'entries' => '512345',
		'fetched_at' => '2026-09-17 06:00:00', 'checked_at' => '2026-09-17 06:00:00', 'error' => '', 'error_at' => null),
	'dbip_asn' => array('source' => 'dbip_asn', 'version' => '2026-09', 'entries' => '410000',
		'fetched_at' => '2026-09-17 06:00:10', 'checked_at' => '2026-09-17 06:00:10',
		'error' => 'Die Quelle dbip_asn liefert nur 12 Bereiche.', 'error_at' => '2026-09-17 18:00:00'),
);
expect_same('a time of the database', waf_panel_time_label('2026-09-17 06:00:00'), '17.09.2026 06:00');
expect_same('a time that is none', waf_panel_time_label('0000-00-00 00:00:00'), '');
$origin_view = waf_panel_origin_rows($wb, $origin_settings, $origin_rows, '2026-09-17 20:00:00');
expect_same('a row for every chosen source', array_column($origin_view, 'source'),
	array('dbip_country', 'dbip_asn', 'tor'));
expect_same('the source in words', $origin_view[0]['label'], 'DB-IP Lite: Land');
expect_same('the state of a loaded source', $origin_view[0]['state'],
	'Stand 2026-09, 512.345 Bereiche, geladen am 17.09.2026 06:00');
expect_same('a source with an error', array($origin_view[1]['failed'], $origin_view[1]['state']),
	array(1, 'Die Quelle dbip_asn liefert nur 12 Bereiche. Es gilt der Stand von 17.09.2026 06:00.'));
expect_same('a source that never loaded', array($origin_view[2]['failed'], $origin_view[2]['state']),
	array(0, 'Noch nicht geladen. Der Cron holt die Liste beim nächsten stündlichen Durchgang.'));
expect_same('the line of the overview', waf_panel_origin_line($wb, $origin_settings, $origin_rows),
	'Herkunft: DB-IP Lite: Land 512.345 Bereiche, DB-IP Lite: Netz 410.000 Bereiche, Tor noch nicht geladen.');
expect_same('the line with everything off', waf_panel_origin_line($wb, array(), array()),
	'Herkunft der Adressen ist aus.');
```

- [ ] **Step 2: Tests laufen lassen, sie müssen scheitern**

Run: `php ispconfig/tests/waf_origin_sources_test.php`
Expected: Abbruch mit `Call to undefined function waf_origin_due()`.

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_origin_rows()`.

- [ ] **Step 3: Fälligkeit**

Am Ende von `ispconfig/interface/lib/malwatch_waf_origin.inc.php` anhängen:

```php

/**
 * Whether a source has to be looked at again. A source the settings leave off
 * is never due; one without a row or without a time always is. $row is its row
 * of malwatch_waf_origin_source, $now the time of the database.
 */
function waf_origin_due($name, $row, $settings, $now)
{
	$sources = waf_origin_sources();
	if (!isset($sources[$name]) || !in_array($name, waf_origin_chosen($settings), true)) {
		return false;
	}
	$checked = is_array($row) && isset($row['checked_at']) ? (string) $row['checked_at'] : '';
	if ($checked === '' || $checked === '0000-00-00 00:00:00') {
		return true;
	}
	$hours = isset($settings[$sources[$name]['hours']]) ? (int) $settings[$sources[$name]['hours']] : 24;
	$hours = $hours < 1 ? 1 : $hours;
	$then = strtotime($checked);
	$point = strtotime((string) $now);
	if ($then === false || $point === false) {
		return true;
	}
	return $point - $then >= $hours * 3600;
}
```

- [ ] **Step 4: Anzeige des Stands**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` nach `waf_panel_key_mask()` einfügen:

```php
/** A time of the database as the pages print it; '' when there is none. */
function waf_panel_time_label($value)
{
	$value = (string) $value;
	$time = $value === '' || $value === '0000-00-00 00:00:00' ? false : strtotime($value);
	return $time === false || $time <= 0 ? '' : date('d.m.Y H:i', $time);
}

/**
 * The state of every chosen source for the settings page: its name, what the
 * last pass found and whether the last attempt failed. $rows are the rows of
 * malwatch_waf_origin_source keyed by source.
 */
function waf_panel_origin_rows($wb, $settings, $rows, $now)
{
	$view = array();
	foreach (waf_origin_chosen($settings) as $name) {
		$row = isset($rows[$name]) ? $rows[$name] : null;
		$entries = is_array($row) ? (int) $row['entries'] : 0;
		$version = is_array($row) ? (string) $row['version'] : '';
		$fetched = is_array($row) ? waf_panel_time_label($row['fetched_at']) : '';
		$error = is_array($row) ? (string) $row['error'] : '';
		if ($fetched === '') {
			$state = waf_panel_text($wb, 'origin_state_none_txt', '');
		} elseif ($version !== '') {
			$state = sprintf(waf_panel_text($wb, 'origin_state_txt', '%1$s %2$s %3$s'), $version,
				number_format($entries, 0, ',', '.'), $fetched);
		} else {
			$state = sprintf(waf_panel_text($wb, 'origin_state_list_txt', '%1$s %2$s'),
				number_format($entries, 0, ',', '.'), $fetched);
		}
		if ($error !== '') {
			$state = $error . ' ' . ($fetched === '' ? waf_panel_text($wb, 'origin_state_none_hint_txt', '')
				: sprintf(waf_panel_text($wb, 'origin_state_keep_txt', '%s'), $fetched));
		}
		$view[] = array(
			'source' => $name,
			'label' => waf_panel_text($wb, 'origin_source_' . $name . '_txt', $name),
			'state' => $state,
			'entries' => $entries,
			'failed' => $error !== '' ? 1 : 0,
		);
	}
	return $view;
}

/** The line of the overview: the chosen sources in short, or that the origin is off. */
function waf_panel_origin_line($wb, $settings, $rows)
{
	$parts = array();
	foreach (waf_panel_origin_rows($wb, $settings, $rows, '') as $row) {
		$parts[] = $row['label'] . ' ' . ($row['entries'] > 0
			? sprintf(waf_panel_text($wb, 'origin_line_entries_txt', '%s'), number_format($row['entries'], 0, ',', '.'))
			: waf_panel_text($wb, 'origin_line_none_txt', ''));
	}
	return count($parts) === 0 ? waf_panel_text($wb, 'origin_line_off_txt', '')
		: sprintf(waf_panel_text($wb, 'origin_line_txt', '%s'), implode(', ', $parts));
}
```

`waf_panel_origin_rows()` braucht `waf_origin_chosen()`. Damit die Datei für sich lesbar bleibt, oben in `malwatch_waf_panel.inc.php` nach der Zeile `require_once __DIR__ . '/malwatch_waf_lib.inc.php';` einfügen:

```php
require_once __DIR__ . '/malwatch_waf_origin.inc.php';
```

- [ ] **Step 5: Texte**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf.lng` anhängen:

```php

// The sources of the origin and their state.
$wb['origin_source_dbip_country_txt'] = 'DB-IP Lite: Land';
$wb['origin_source_dbip_asn_txt'] = 'DB-IP Lite: Netz';
$wb['origin_source_maxmind_country_txt'] = 'GeoLite2: Land';
$wb['origin_source_maxmind_asn_txt'] = 'GeoLite2: Netz';
$wb['origin_source_tor_txt'] = 'Tor';
$wb['origin_source_x4b_vpn_txt'] = 'X4BNet: VPN';
$wb['origin_source_x4b_datacenter_txt'] = 'X4BNet: Rechenzentren';
$wb['origin_state_txt'] = 'Stand %1$s, %2$s Bereiche, geladen am %3$s';
$wb['origin_state_list_txt'] = '%1$s Bereiche, geladen am %2$s';
$wb['origin_state_none_txt'] = 'Noch nicht geladen. Der Cron holt die Liste beim nächsten stündlichen Durchgang.';
$wb['origin_state_none_hint_txt'] = 'Es gibt noch keinen Stand; der Cron versucht es beim nächsten Durchgang erneut.';
$wb['origin_state_keep_txt'] = 'Es gilt der Stand von %s.';
$wb['origin_line_txt'] = 'Herkunft: %s.';
$wb['origin_line_entries_txt'] = '%s Bereiche';
$wb['origin_line_none_txt'] = 'noch nicht geladen';
$wb['origin_line_off_txt'] = 'Herkunft der Adressen ist aus.';
$wb['origin_settings_link_txt'] = 'Einstellungen der Herkunft';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf.lng` anhängen:

```php

// The sources of the origin and their state.
$wb['origin_source_dbip_country_txt'] = 'DB-IP Lite: country';
$wb['origin_source_dbip_asn_txt'] = 'DB-IP Lite: network';
$wb['origin_source_maxmind_country_txt'] = 'GeoLite2: country';
$wb['origin_source_maxmind_asn_txt'] = 'GeoLite2: network';
$wb['origin_source_tor_txt'] = 'Tor';
$wb['origin_source_x4b_vpn_txt'] = 'X4BNet: VPN';
$wb['origin_source_x4b_datacenter_txt'] = 'X4BNet: data centres';
$wb['origin_state_txt'] = 'Release %1$s, %2$s ranges, loaded on %3$s';
$wb['origin_state_list_txt'] = '%1$s ranges, loaded on %2$s';
$wb['origin_state_none_txt'] = 'Not loaded yet. The cron fetches the list with its next hourly pass.';
$wb['origin_state_none_hint_txt'] = 'There is no release yet; the cron tries again with its next pass.';
$wb['origin_state_keep_txt'] = 'The release of %s stays in use.';
$wb['origin_line_txt'] = 'Origin: %s.';
$wb['origin_line_entries_txt'] = '%s ranges';
$wb['origin_line_none_txt'] = 'not loaded yet';
$wb['origin_line_off_txt'] = 'The origin of the addresses is off.';
$wb['origin_settings_link_txt'] = 'Settings of the origin';
```

In `ispconfig/interface/lang/de_malwatch_waf_config.lng` nach `$wb['origin_intro_txt']` einfügen:

```php
$wb['origin_state_head_txt'] = 'Stand der gewählten Quellen';
$wb['origin_state_none_chosen_txt'] = 'Es ist keine Quelle gewählt.';
```

In `ispconfig/interface/lang/en_malwatch_waf_config.lng` an derselben Stelle:

```php
$wb['origin_state_head_txt'] = 'State of the chosen sources';
$wb['origin_state_none_chosen_txt'] = 'No source is chosen.';
```

- [ ] **Step 6: Tabelle**

In `ispconfig/install/schema.sql` vor der Zeile `-- waf carries the jobs of the page Abwehr. The malwatch cron works on them` einfügen:

```sql
--
-- One row per server and origin source: which release is in use, when it was
-- last checked and loaded, how many ranges it holds and what went wrong last.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_origin_source` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `source` varchar(32) NOT NULL DEFAULT '',
  `version` varchar(32) NOT NULL DEFAULT '',
  `checked_at` datetime DEFAULT NULL,
  `fetched_at` datetime DEFAULT NULL,
  `entries` int(11) unsigned NOT NULL DEFAULT '0',
  `error` varchar(255) NOT NULL DEFAULT '',
  `error_at` datetime DEFAULT NULL,
  PRIMARY KEY (`server_id`,`source`)
) DEFAULT CHARSET=utf8mb4 ;

```

In `ispconfig/install/uninstall-schema.sql` nach der Zeile mit `DROP TABLE IF EXISTS \`malwatch_waf_exception\`;` einfügen:

```sql
DROP TABLE IF EXISTS `malwatch_waf_origin_source`;
```

- [ ] **Step 7: Einstellungsseite zeigt den Stand**

In `ispconfig/interface/malwatch_waf_config_edit.php`, `onShowEnd()`, vor `parent::onShowEnd();` einfügen:

```php
		$clock = waf_panel_clock($app);
		$states = array();
		foreach (waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_origin_source')) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$origin_rows = array();
		foreach (waf_panel_origin_rows($this->waf_wb, $settings, $states, $clock['now']) as $row) {
			$origin_rows[] = array(
				'origin_label' => $app->functions->htmlentities($row['label']),
				'origin_state' => $app->functions->htmlentities($row['state']),
				'origin_failed' => $row['failed'],
			);
		}
		$app->tpl->setLoop('origin_states', $origin_rows);
		$app->tpl->setVar('has_origin_states', count($origin_rows) > 0 ? 1 : 0);

```

In `ispconfig/interface/templates/malwatch_waf_config_edit.htm` nach dem Block mit `waf_origin_db_hours` einfügen:

```html
<p class="mw-wafcfg-note"><strong>{tmpl_var name='origin_state_head_txt'}</strong></p>
<tmpl_if name="has_origin_states">
<ul class="mw-wafcfg-states">
	<tmpl_loop name="origin_states"><li><strong>{tmpl_var name='origin_label'}</strong> <span<tmpl_if name="origin_failed"> class="mw-wafcfg-failed"</tmpl_if>>{tmpl_var name='origin_state'}</span></li></tmpl_loop>
</ul>
<tmpl_else>
<p class="mw-wafcfg-note">{tmpl_var name='origin_state_none_chosen_txt'}</p>
</tmpl_if>

```

und im Stilblock nach `.mw-wafcfg-clear`:

```css
.mw-wafcfg-states{margin:0 0 12px;padding-left:18px;font-size:13px;max-width:90ch}
.mw-wafcfg-failed{color:var(--cic-bad-text,#d13f22)}
```

- [ ] **Step 8: Übersicht zeigt die Zeile**

In `ispconfig/interface/malwatch_waf_list.php` nach der Zeile `$app->tpl->setVar('selected_none', …);` einfügen:

```php
$origin_states = array();
foreach (waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_origin_source')) as $row) {
	$origin_states[(string) $row['source']] = $row;
}
$app->tpl->setVar('origin_line', $app->functions->htmlentities(waf_panel_origin_line($wb, $settings, $origin_states)));
```

In `ispconfig/interface/templates/malwatch_waf_list.htm` nach dem Absatz mit `{tmpl_var name='sub_txt'}` einfügen:

```html
<p class="mw-sub">{tmpl_var name='origin_line'} <a href="#" data-load-content="security/malwatch_waf_config_edit.php">{tmpl_var name='origin_settings_link_txt'}</a></p>
```

- [ ] **Step 9: Prüfungen**

Run: `php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_lib_test.php`
Expected: dreimal `alle Prüfungen bestanden`.

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`; `grep -c 'Herkunft der Adressen ist aus' .superpowers/abwehr/harness/out_list.html` ergibt `1`.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 10: Commit**

```bash
git add ispconfig/install/schema.sql ispconfig/install/uninstall-schema.sql ispconfig/interface/lib/malwatch_waf_origin.inc.php ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/malwatch_waf_config_edit.php ispconfig/interface/templates/malwatch_waf_config_edit.htm ispconfig/interface/malwatch_waf_list.php ispconfig/interface/templates/malwatch_waf_list.htm ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/interface/lang/de_malwatch_waf_config.lng ispconfig/interface/lang/en_malwatch_waf_config.lng ispconfig/tests/waf_origin_sources_test.php ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the state of every origin source" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B5: Auftrag `origin_update`

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_waf.inc.php` (Abrufstelle, Verzeichnisse, Auftrag, stündlicher Takt)
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Name des Auftrags)
- Modify: `ispconfig/tests/waf_class_probe.php` (Probe des Auftrags ohne Netz)
- Modify: `ispconfig/tests/check_wiring.sh` (Prüfung 67)

**Interfaces:**
- Consumes: `waf_origin_chosen()`, `waf_origin_due()`, `waf_origin_urls()`, die Einleser und `waf_origin_check()` (B2, B4)
- Produces:
  - Aktion `origin_update` in `malwatch_job` (`job_kind = 'waf'`), angelegt vom stündlichen Cron und nach dem Speichern der Einstellungen
  - Bereichsdateien unter `<state_dir>/waf/origin/<source>.bin`
  - gefüllte Zeilen in `malwatch_waf_origin_source`
  - Ablagestelle `$fetcher` der Klasse: `function ($url, $target, $limit, $auth)` → `array(ok, Fehlertext)`

Der Auftrag lädt nur die fälligen Quellen, prüft jede Datei vor dem Tausch und lässt den bisherigen Stand stehen, wenn etwas fehlschlägt. Schlüssel stehen nie im Auftragsprotokoll.

- [ ] **Step 1: Probe erweitern**

`ispconfig/tests/waf_class_probe.php` fährt die Klasse gegen eine Wegwerf-Datenbank; sie läuft als root auf dem Server, deshalb prüft Task B9 sie dort. Hier wird sie nur geschrieben und mit `php -l` geprüft.

Nach der Zeile `require $stage . '/interface/lib/malwatch_waf_lib.inc.php';` einfügen:

```php
require $stage . '/interface/lib/malwatch_waf_origin.inc.php';
```

Am Ende der Datei vor dem Block `// --- summary` einfügen:

```php
// --- B5: the origin update ----------------------------------------------------

$probe_dir = $tmp . '/origin-probe';
@mkdir($probe_dir . '/waf/origin/tmp', 0700, true);
$waf->paths['state_dir'] = $probe_dir;
$fixtures = $stage . '/tests/fixtures/origin';
// The download is the place where the class talks to the world; the probe puts
// the sample files there instead.
$waf->fetcher = function ($url, $target, $limit, $auth) use ($fixtures) {
	$map = array(
		'dbip-country-lite' => $fixtures . '/dbip-country.csv',
		'dbip-asn-lite' => $fixtures . '/dbip-asn.csv',
		'torbulkexitlist' => $fixtures . '/tor.txt',
		'vpn/ipv4.txt' => $fixtures . '/x4b-ipv4.txt',
		'vpn/ipv6.txt' => $fixtures . '/x4b-ipv6.txt',
	);
	foreach ($map as $mark => $file) {
		if (strpos($url, $mark) !== false) {
			return copy($file, $target) ? array(true, '') : array(false, 'Kopie scheiterte.');
		}
	}
	return array(false, 'Nicht gefunden (404).');
};
$probe_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'x4b',
	'waf_origin_tor_hours' => 1, 'waf_origin_list_hours' => 24, 'waf_origin_db_hours' => 24);
$result = $waf->origin_update_sources($probe_settings, array(), '2026-09-17 20:00:00');
// The sample files are far too short for the real limits, so every source is
// refused and the file in use stays as it is.
expect_same('every chosen source is looked at', count($result), 5);
expect_same('a file with unreadable lines is refused',
	strpos($result['tor']['note'], '1 von 5 Zeilen ergeben keinen Adressbereich') !== false, true);
expect_same('nothing was swapped in', is_file($probe_dir . '/waf/origin/tor.bin'), false);
expect_same('the temporary file is gone', count(glob($probe_dir . '/waf/origin/tmp/*')), 0);
expect_same('a source that is not reachable',
	strpos($result['x4b_datacenter']['note'], 'Nicht gefunden') !== false, true);
```

- [ ] **Step 2: Probe prüfen**

Run: `php -l ispconfig/tests/waf_class_probe.php`
Expected: `No syntax errors detected`. Die Probe selbst läuft in Task B9 auf dem Server; ohne die Methode `origin_update_sources()` bricht sie dort mit `Call to undefined method` ab, deshalb kommt sie vor dem Code.

- [ ] **Step 3: Abruf und Verzeichnisse**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` nach der Zeile

```php
	/** Takes the place of the real commands when set: function ($name, $argument) returning array(code, output). */
	public $runner = null;
```

einfügen:

```php

	/**
	 * Takes the place of the download when set: function ($url, $target,
	 * $limit, $auth) returning array(ok, error). $auth is 'account:key' for
	 * MaxMind and '' for every other source.
	 */
	public $fetcher = null;
```

Die Konstante der zweiten Bibliothek neben `const LIB` einfügen:

```php
	/** The functions of the origin sources, installed next to the shared ones. */
	const LIB_ORIGIN = '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_origin.inc.php';
```

In `ready()` vor `return function_exists('waf_states');` einfügen:

```php
		if (!function_exists('waf_origin_sources') && is_file(self::LIB_ORIGIN)) {
			require_once self::LIB_ORIGIN;
		}
```

In `ensure_dirs()` die Zeile

```php
		foreach (array('/staging', '/last-good') as $sub) {
```

ersetzen durch:

```php
		foreach (array('/staging', '/last-good', '/origin', '/origin/tmp') as $sub) {
```

Nach `run_command()` einfügen:

```php
	/**
	 * Loads one address into $target. Returns array(ok, error); the error text
	 * never carries the licence key. A download larger than $limit bytes is
	 * cut off and counts as failed.
	 */
	public function fetch($url, $target, $limit, $auth)
	{
		if ($this->fetcher !== null) {
			return call_user_func($this->fetcher, $url, $target, $limit, $auth);
		}
		if (!function_exists('curl_init')) {
			return array(false, 'Die PHP-Erweiterung curl fehlt. Bitte php-curl nachinstallieren; ohne sie lädt der Server keine Liste.');
		}
		$handle = @fopen($target, 'wb');
		if ($handle === false) {
			return array(false, 'Die Datei ' . basename($target) . ' ließ sich nicht anlegen. Bitte Platz und Rechte unter dem Arbeitsverzeichnis prüfen.');
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_FILE, $handle);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 10);
		curl_setopt($curl, CURLOPT_TIMEOUT, 120);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt($curl, CURLOPT_USERAGENT, 'malwatch/' . $this->version());
		if ((string) $auth !== '') {
			curl_setopt($curl, CURLOPT_USERPWD, (string) $auth);
			curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		}
		curl_setopt($curl, CURLOPT_NOPROGRESS, false);
		curl_setopt($curl, CURLOPT_PROGRESSFUNCTION, function ($curl, $expected, $loaded) use ($limit) {
			return $loaded > $limit || $expected > $limit ? 1 : 0;
		});
		$ok = curl_exec($curl) !== false;
		$status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
		$error = $ok ? '' : curl_error($curl);
		$aborted = curl_errno($curl) === CURLE_ABORTED_BY_CALLBACK;
		curl_close($curl);
		fclose($handle);
		if ($aborted) {
			@unlink($target);
			return array(false, 'Die Datei ist größer als ' . (int) ($limit / 1048576) . ' MB. Der Abruf wurde abgebrochen.');
		}
		if (!$ok) {
			@unlink($target);
			return array(false, 'Der Abruf scheiterte: ' . waf_cut(preg_replace('/\s+/', ' ', $error), 150));
		}
		if ($status >= 400) {
			@unlink($target);
			return array(false, 'Die Quelle antwortete mit ' . $status . '.');
		}
		return array(true, '');
	}

	/** The version of the addon, for the user agent of a download. */
	private function version()
	{
		$file = '/usr/local/ispconfig/extensions/malwatch/version';
		$version = is_file($file) ? trim((string) file_get_contents($file)) : '';
		return preg_match('/^[0-9.]{1,16}$/', $version) ? $version : '0';
	}
```

- [ ] **Step 4: Der Auftrag**

In `start_job()` nach dem Zweig `case 'apply_settings':` einfügen:

```php
			case 'origin_update':
				$this->run_origin_update($job);
				break;
```

Nach `run_apply_settings()` einfügen:

```php
	/**
	 * Loads every source that is due and swaps its range file in. A source the
	 * settings left off loses its file and its row. The log names sources and
	 * numbers, never a key and never an address.
	 */
	private function run_origin_update($job)
	{
		global $app, $conf;

		$settings = $this->settings();
		$states = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT * FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$notes = array();
		$failed = false;
		$dir = $this->ensure_dirs() . '/origin';

		foreach ($states as $name => $row) {
			if (in_array($name, waf_origin_chosen($settings), true)) {
				continue;
			}
			@unlink($dir . '/' . $name . '.bin');
			$app->dbmaster->query('DELETE FROM malwatch_waf_origin_source WHERE server_id = ? AND source = ?',
				$conf['server_id'], $name);
			$app->dbmaster->query('UPDATE malwatch_waf_ip SET local_at = NULL WHERE server_id = ?', $conf['server_id']);
			$notes[] = $name . ': abgeschaltet, Datei entfernt';
		}

		$results = $this->origin_update_sources($settings, $states, $this->now());
		foreach ($results as $name => $result) {
			$notes[] = $name . ': ' . $result['note'];
			$failed = $failed || !$result['ok'];
		}
		if (count($notes) === 0) {
			return $this->finish($job, true, 'Keine Quelle war fällig.');
		}
		return $this->finish($job, !$failed, waf_cut(implode('; ', $notes), 60000));
	}

	/**
	 * Works through the sources that are due and returns one entry per source
	 * with ok, note and the counts. Public so tests/waf_class_probe.php can
	 * call it with its own fetcher.
	 */
	public function origin_update_sources($settings, $states, $now)
	{
		$results = array();
		$dir = $this->ensure_dirs() . '/origin';
		foreach (waf_origin_chosen($settings) as $name) {
			$row = isset($states[$name]) ? $states[$name] : null;
			if (!waf_origin_due($name, $row, $settings, $now)) {
				continue;
			}
			$results[$name] = $this->origin_update_source($name, $settings, $row, $dir, $now);
		}
		return $results;
	}

	/** One source: load, read, check, swap. Returns array(ok, note, entries, version). */
	private function origin_update_source($name, $settings, $row, $dir, $now)
	{
		$sources = waf_origin_sources();
		$source = $sources[$name];
		$tmp = $dir . '/tmp';
		$target = $dir . '/' . $name . '.bin';
		$previous = is_file($target) ? waf_origin_ranges(waf_origin_open($target)) : 0;
		$version = strpos($name, 'dbip_') === 0 ? gmdate('Y-m', strtotime((string) $now)) : '';
		$auth = '';
		if (strpos($name, 'maxmind_') === 0) {
			if (!class_exists('ZipArchive')) {
				return $this->origin_note($name, false, 'Die PHP-Erweiterung zip fehlt. Bitte php-zip nachinstallieren oder bei „Land und Provider“ DB-IP wählen.', $row, $now);
			}
			if ((string) $settings['waf_origin_maxmind_account'] === '' || (string) $settings['waf_origin_maxmind_key'] === '') {
				return $this->origin_note($name, false, 'Konto-ID oder Lizenzschlüssel fehlt. Bitte beide in den Einstellungen der Abwehr eintragen.', $row, $now);
			}
			$auth = $settings['waf_origin_maxmind_account'] . ':' . $settings['waf_origin_maxmind_key'];
		}
		// DB-IP publishes one file per month; at the turn of the month the new
		// one may be missing, then the one of last month still counts.
		$months = strpos($name, 'dbip_') === 0
			? array($version, gmdate('Y-m', strtotime((string) $now) - 15 * 86400)) : array('');
		$files = array();
		$error = '';
		foreach ($months as $month) {
			$files = array();
			$error = '';
			$version = $month;
			foreach (waf_origin_urls($name, $month) as $index => $url) {
				$file = $tmp . '/' . $name . '-' . $index . '.tmp';
				@unlink($file);
				$loaded = $this->fetch($url, $file, (int) $source['bytes'], $auth);
				if (!$loaded[0]) {
					$error = $loaded[1];
					break;
				}
				$files[] = $file;
			}
			if ($error === '') {
				break;
			}
		}
		if ($error !== '') {
			$this->origin_clean($files);
			if (strpos($name, 'maxmind_') === 0 && strpos($error, '401') !== false) {
				$error = 'MaxMind hat Konto-ID oder Lizenzschlüssel abgelehnt. Bitte beide in den Einstellungen der Abwehr prüfen.';
			}
			return $this->origin_note($name, false, $error, $row, $now);
		}
		if (strpos($name, 'maxmind_') === 0) {
			$unpacked = $this->origin_unzip($name, $files[0], $tmp);
			$this->origin_clean($files);
			if ($unpacked === null) {
				return $this->origin_note($name, false, 'Das Archiv ließ sich nicht entpacken. Der nächste Abruf versucht es erneut.', $row, $now);
			}
			$files = $unpacked['files'];
			$version = $unpacked['version'];
		}
		// A release that is already in use needs no rebuild.
		if ($version !== '' && is_array($row) && (string) $row['version'] === $version && $previous > 0) {
			$this->origin_clean($files);
			return $this->origin_note($name, true, 'Stand ' . $version . ' unverändert, ' . $previous . ' Bereiche.', $row, $now, $version, $previous, true);
		}
		$fresh = $tmp . '/' . $name . '.bin';
		@unlink($fresh);
		$counts = $this->origin_read($name, $files, $fresh);
		$this->origin_clean($files);
		if ($counts === null) {
			@unlink($fresh);
			return $this->origin_note($name, false, 'Die Datei ließ sich nicht umbauen. Bitte Platz unter ' . $dir . ' prüfen.', $row, $now);
		}
		$refused = waf_origin_check($name, $counts, $previous);
		if ($refused !== '') {
			@unlink($fresh);
			return $this->origin_note($name, false, $refused, $row, $now);
		}
		if (!@rename($fresh, $target)) {
			@unlink($fresh);
			return $this->origin_note($name, false, 'Die neue Datei ließ sich nicht an ihren Platz legen. Der bisherige Stand bleibt aktiv.', $row, $now);
		}
		@chmod($target, 0640);
		return $this->origin_note($name, true, $counts['ranges'] . ' Bereiche, ' . $counts['bad'] . ' unbrauchbare Zeilen'
			. ($version === '' ? '' : ', Stand ' . $version) . '.', $row, $now, $version, $counts['ranges']);
	}

	/** Reads the files of one source into the range file $fresh. */
	private function origin_read($name, $files, $fresh)
	{
		switch ($name) {
			case 'dbip_country':
				return waf_origin_read_dbip_country($files, $fresh);
			case 'dbip_asn':
				return waf_origin_read_dbip_asn($files, $fresh);
			case 'maxmind_country':
				$blocks = array();
				$locations = '';
				foreach ($files as $file) {
					if (strpos($file, 'Locations') !== false) {
						$locations = $file;
					} elseif (strpos($file, 'Blocks') !== false) {
						$blocks[] = $file;
					}
				}
				return $locations === '' ? null : waf_origin_read_maxmind_country($blocks, $locations, $fresh);
			case 'maxmind_asn':
				return waf_origin_read_maxmind_asn($files, $fresh);
		}
		return waf_origin_read_list($files, $fresh);
	}

	/** Unpacks the GeoLite2 archive; returns array(files, version) or null. */
	private function origin_unzip($name, $archive, $tmp)
	{
		$zip = new ZipArchive();
		if ($zip->open($archive) !== true) {
			return null;
		}
		$files = array();
		$version = '';
		for ($i = 0; $i < $zip->numFiles; $i++) {
			$inside = (string) $zip->getNameIndex($i);
			if (preg_match('/_(\d{8})\//', $inside, $m)) {
				$version = $m[1];
			}
			if (substr($inside, -4) !== '.csv') {
				continue;
			}
			$plain = basename($inside);
			// The country archive holds the locations in every language; German
			// and English carry the same country codes.
			if (strpos($plain, 'Locations') !== false && strpos($plain, 'Locations-en') === false) {
				continue;
			}
			$file = $tmp . '/' . $name . '-' . $plain;
			$stream = $zip->getStream($inside);
			$out = $stream === false ? false : @fopen($file, 'wb');
			if ($out === false) {
				continue;
			}
			while (!feof($stream)) {
				fwrite($out, (string) fread($stream, 65536));
			}
			fclose($out);
			fclose($stream);
			$files[] = $file;
		}
		$zip->close();
		sort($files, SORT_STRING);
		return count($files) === 0 ? null : array('files' => $files, 'version' => $version);
	}

	/** Removes the temporary files of one source. */
	private function origin_clean($files)
	{
		foreach (is_array($files) ? $files : array() as $file) {
			@unlink($file);
		}
	}

	/** Writes the state of one source and returns what the job log says about it. */
	private function origin_note($name, $ok, $note, $row, $now, $version = '', $entries = 0, $unchanged = false)
	{
		global $app, $conf;

		$keep = is_array($row);
		$fetched = $ok && !$unchanged ? $now : ($keep ? $row['fetched_at'] : null);
		$app->dbmaster->query(
			'INSERT INTO malwatch_waf_origin_source (server_id, source, version, checked_at, fetched_at, entries, error, error_at) '
			. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE version = VALUES(version), '
			. 'checked_at = VALUES(checked_at), fetched_at = VALUES(fetched_at), entries = VALUES(entries), '
			. 'error = VALUES(error), error_at = VALUES(error_at)',
			$conf['server_id'], $name,
			$ok ? $version : ($keep ? (string) $row['version'] : ''),
			$now, $fetched,
			$ok ? (int) $entries : ($keep ? (int) $row['entries'] : 0),
			$ok ? '' : waf_cut($note, 255),
			$ok ? null : $now);
		return array('ok' => $ok, 'note' => $note, 'entries' => (int) $entries, 'version' => (string) $version);
	}

	/** The time of the database, as the jobs write it. */
	private function now()
	{
		global $app;
		$row = $app->dbmaster->queryOneRecord('SELECT NOW() AS now_at');
		return is_array($row) ? (string) $row['now_at'] : date('Y-m-d H:i:s');
	}
```

- [ ] **Step 5: Stündlicher Takt**

In `cron_hourly()` die Zeile

```php
			$this->cleanup();
```

ersetzen durch:

```php
			$this->cleanup();
			$this->queue_origin_update();
```

Nach `cron_hourly()` einfügen:

```php
	/**
	 * Queues origin_update when a chosen source is due and no job of that kind
	 * waits already. The settings page queues one right after a save.
	 */
	private function queue_origin_update()
	{
		global $app, $conf;

		$settings = $this->settings();
		$states = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT * FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$now = $this->now();
		$due = false;
		foreach (waf_origin_chosen($settings) as $name) {
			$due = $due || waf_origin_due($name, isset($states[$name]) ? $states[$name] : null, $settings, $now);
		}
		if (!$due) {
			return;
		}
		$open = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' "
			. "AND job_status IN ('pending','running') AND options LIKE '%\"action\":\"origin_update\"%'",
			$conf['server_id']);
		if (is_array($open) && (int) $open['n'] > 0) {
			return;
		}
		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, server_id, '
			. "parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) "
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', '', 'cron', 'waf', 'pending', ?, ?)",
			$conf['server_id'], waf_json(array('action' => 'origin_update', 'user' => 'cron')), $now);
	}
```

- [ ] **Step 6: Name des Auftrags**

In `ispconfig/interface/lang/de_malwatch_waf.lng` nach `$wb['job_apply_settings_txt'] = 'Einstellungen';` einfügen:

```php
$wb['job_origin_update_txt'] = 'Herkunft der Adressen';
```

In `ispconfig/interface/lang/en_malwatch_waf.lng` an derselben Stelle:

```php
$wb['job_origin_update_txt'] = 'Origin of the addresses';
```

- [ ] **Step 7: Verdrahtung prüfen**

In `ispconfig/tests/check_wiring.sh` vor dem Block `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 67. The origin update keeps keys out of the job log and the state row. The
#     class hands the licence key to curl and nowhere else: a note that names
#     waf_origin_maxmind_key would end up in malwatch_job.job_log, which the
#     panel shows to every administrator.
waf_class="$root/server/lib/classes/malwatch_waf.inc.php"
if [ -f "$waf_class" ]; then
	if sed -n '/private function run_origin_update/,/^	}/p' "$waf_class" | grep -q 'maxmind_key'; then
		fail "malwatch_waf::run_origin_update() names the licence key; the job log must not carry it"
	fi
	if sed -n '/private function origin_note/,/^	}/p' "$waf_class" | grep -q 'maxmind_key'; then
		fail "malwatch_waf::origin_note() names the licence key; the state row must not carry it"
	fi
	grep -q "case 'origin_update':" "$waf_class" \
		|| fail "malwatch_waf::start_job() knows no action origin_update"
	grep -q 'CURLOPT_SSL_VERIFYPEER, true' "$waf_class" \
		|| fail "malwatch_waf::fetch() loads without checking the certificate"
	sed -n '/public function cron_hourly/,/^	}/p' "$waf_class" | grep -q 'queue_origin_update' \
		|| fail "cron_hourly() never queues origin_update"
fi

```

- [ ] **Step 8: Prüfungen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/tests/waf_class_probe.php`
Expected: zweimal `No syntax errors detected`. Die Probe läuft in Task B9 auf dem Server und muss dort `waf_class_probe: alle Prüfungen bestanden` melden.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 9: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/tests/waf_class_probe.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the job that loads the origin sources" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B6: Nachschlagen beim Einlesen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_origin.inc.php` (Block am Dateiende)
- Modify: `ispconfig/install/schema.sql` (Tabelle `malwatch_waf_ip`), `ispconfig/install/uninstall-schema.sql`
- Modify: `ispconfig/server/lib/classes/malwatch_waf.inc.php` (Nachschlagen nach dem Einlesen, Aufräumen)
- Modify: `ispconfig/tests/waf_class_probe.php`
- Test: `ispconfig/tests/waf_origin_sources_test.php`

**Interfaces:**
- Consumes: `waf_origin_open()`, `waf_origin_find()`, `waf_origin_parts()` (B1, B2), `waf_origin_chosen()` (B2)
- Produces:
  - Tabelle `malwatch_waf_ip` mit Land, Netz, den Merkmalen und den Feldern für den späteren externen Dienst
  - `waf_origin_readers($dir, $names)`, `waf_origin_readers_close($readers)`, `waf_origin_facts($readers, $ip)`, `waf_origin_stale($row, $newest)`
  - `malwatch_waf::origin_lookup()`: füllt die Tabelle nach jedem Durchgang

Die Tabelle hält nur Adressen, zu denen es noch einen Treffer gibt; `cleanup()` räumt sie stündlich mit auf. Damit bleiben Herkunftsdaten höchstens so lange wie der Treffer selbst.

- [ ] **Step 1: Test schreiben**

In `ispconfig/tests/waf_origin_sources_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B6: looking up an address ------------------------------------------------

$look = $dir . '/look';
@mkdir($look, 0700, true);
waf_origin_read_dbip_country($fixtures . '/dbip-country.csv', $look . '/dbip_country.bin');
waf_origin_read_dbip_asn($fixtures . '/dbip-asn.csv', $look . '/dbip_asn.bin');
waf_origin_read_list($fixtures . '/tor.txt', $look . '/tor.bin');
waf_origin_read_list(array($fixtures . '/x4b-ipv4.txt', $fixtures . '/x4b-ipv6.txt'), $look . '/x4b_vpn.bin');
$readers = waf_origin_readers($look, array('dbip_country', 'dbip_asn', 'tor', 'x4b_vpn', 'x4b_datacenter'));
expect_same('a source without a file is left out', array_keys($readers),
	array('dbip_country', 'dbip_asn', 'tor', 'x4b_vpn'));
expect_same('facts of an address in every source', waf_origin_facts($readers, '192.0.2.10'), array(
	'country' => 'DE', 'asn' => 3320, 'as_org' => 'Zweites Beispielnetz',
	'is_tor' => 'y', 'is_vpn' => 'y', 'is_hosting' => 'n'));
expect_same('facts of an address only the country knows', waf_origin_facts($readers, '1.0.0.5'), array(
	'country' => 'AU', 'asn' => 13335, 'as_org' => 'Beispielnetz, Inc.',
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n'));
expect_same('facts of an address nobody knows', waf_origin_facts($readers, '203.0.113.9'), array(
	'country' => '', 'asn' => 0, 'as_org' => '',
	'is_tor' => 'n', 'is_vpn' => 'y', 'is_hosting' => 'n'));
expect_same('facts of something that is no address', waf_origin_facts($readers, 'kein-ip')['country'], '');
waf_origin_readers_close($readers);
expect_same('readers are closed', $readers, array());

expect_same('a row without a look', waf_origin_stale(null, '2026-09-17 06:00:00'), true);
expect_same('a row looked at before the load',
	waf_origin_stale(array('local_at' => '2026-09-17 05:00:00'), '2026-09-17 06:00:00'), true);
expect_same('a row looked at after the load',
	waf_origin_stale(array('local_at' => '2026-09-17 07:00:00'), '2026-09-17 06:00:00'), false);
expect_same('a row without any source', waf_origin_stale(array('local_at' => '2026-09-17 07:00:00'), ''), false);

foreach (glob($look . '/*') as $name) {
	@unlink($name);
}
@rmdir($look);

```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_origin_sources_test.php`
Expected: Abbruch mit `Call to undefined function waf_origin_readers()`.

- [ ] **Step 3: Nachschlagen schreiben**

Am Ende von `ispconfig/interface/lib/malwatch_waf_origin.inc.php` anhängen:

```php

// --- Looking up an address ----------------------------------------------------

/**
 * Opens the range files of $names below $dir. A source without a file is left
 * out, so a lookup answers with what is there. waf_origin_readers_close()
 * closes them again.
 */
function waf_origin_readers($dir, $names)
{
	$readers = array();
	foreach ($names as $name) {
		$reader = waf_origin_open(rtrim((string) $dir, '/') . '/' . $name . '.bin');
		if ($reader !== null) {
			$readers[$name] = $reader;
		}
	}
	return $readers;
}

/** Closes the readers of waf_origin_readers(). */
function waf_origin_readers_close(&$readers)
{
	foreach ($readers as $name => $reader) {
		waf_origin_close($reader);
		unset($readers[$name]);
	}
	$readers = array();
}

/**
 * What the open range files say about one address: country, network and the
 * marks of the lists. A field no source answers stays empty, so the caller can
 * store the result as it is.
 */
function waf_origin_facts($readers, $ip)
{
	$facts = array('country' => '', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n');
	foreach ($readers as $name => $reader) {
		$value = waf_origin_find($reader, $ip);
		if ($value === '') {
			continue;
		}
		if ($name === 'tor') {
			$facts['is_tor'] = 'y';
			continue;
		}
		if ($name === 'x4b_vpn') {
			$facts['is_vpn'] = 'y';
			continue;
		}
		if ($name === 'x4b_datacenter') {
			$facts['is_hosting'] = 'y';
			continue;
		}
		$parts = waf_origin_parts($value);
		if (isset($parts['country'])) {
			$facts['country'] = $parts['country'];
		}
		if (isset($parts['asn'])) {
			$facts['asn'] = $parts['asn'];
			$facts['as_org'] = $parts['as_org'];
		}
	}
	return $facts;
}

/**
 * Whether the row of an address has to be looked up again: it has none, or a
 * source was loaded after the last look. $newest is the newest fetched_at of
 * the chosen sources.
 */
function waf_origin_stale($row, $newest)
{
	$looked = is_array($row) && isset($row['local_at']) ? (string) $row['local_at'] : '';
	if ($looked === '' || $looked === '0000-00-00 00:00:00') {
		return true;
	}
	$newest = (string) $newest;
	if ($newest === '') {
		return false;
	}
	return strtotime($newest) > strtotime($looked);
}
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_origin_test.php`
Expected: `waf_origin_sources: alle Prüfungen bestanden` und `waf_origin: alle Prüfungen bestanden`.

- [ ] **Step 5: Tabelle**

In `ispconfig/install/schema.sql` nach dem Block mit `CREATE TABLE IF NOT EXISTS \`malwatch_waf_origin_source\`` einfügen:

```sql
--
-- One row per server and address: what the range files said and, later, what
-- an external service added. cleanup() removes a row as soon as no hit names
-- the address any more, so the origin lives no longer than the hit.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_ip` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `country` varchar(2) NOT NULL DEFAULT '',
  `asn` int(11) unsigned NOT NULL DEFAULT '0',
  `as_org` varchar(128) NOT NULL DEFAULT '',
  `is_tor` enum('n','y') NOT NULL DEFAULT 'n',
  `is_vpn` enum('n','y') NOT NULL DEFAULT 'n',
  `is_hosting` enum('n','y') NOT NULL DEFAULT 'n',
  `is_proxy` enum('n','y') NOT NULL DEFAULT 'n',
  `vpn_operator` varchar(64) NOT NULL DEFAULT '',
  `local_at` datetime DEFAULT NULL,
  `external_state` enum('none','pending','done','failed','limit') NOT NULL DEFAULT 'none',
  `external_at` datetime DEFAULT NULL,
  `external_tries` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`ip`),
  KEY `external` (`server_id`,`external_state`)
) DEFAULT CHARSET=utf8mb4 ;

```

In `ispconfig/install/uninstall-schema.sql` nach der Zeile mit `DROP TABLE IF EXISTS \`malwatch_waf_origin_source\`;` einfügen:

```sql
DROP TABLE IF EXISTS `malwatch_waf_ip`;
```

- [ ] **Step 6: Nachschlagen in der Klasse**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php`, `cron_minute()`, die Zeile

```php
			$this->ingest(array());
```

ersetzen durch:

```php
			$this->ingest(array());
			$this->origin_lookup();
```

Nach `run_origin_update()` einfügen:

```php
	/**
	 * Fills malwatch_waf_ip for the addresses of the stored hits: every address
	 * without a row, and every row that is older than the newest range file.
	 * One pass looks at most at $limit addresses, so a burst of a scanner never
	 * holds the cron.
	 */
	public function origin_lookup($limit = 500)
	{
		global $app, $conf;

		$settings = $this->settings();
		$chosen = waf_origin_chosen($settings);
		if (count($chosen) === 0) {
			return 0;
		}
		$newest = '';
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT source, fetched_at FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			if (in_array((string) $row['source'], $chosen, true) && (string) $row['fetched_at'] > $newest) {
				$newest = (string) $row['fetched_at'];
			}
		}
		if ($newest === '') {
			return 0;
		}
		$rows = $this->rows($app->dbmaster->queryAllRecords(
			'SELECT h.client_ip, p.local_at FROM malwatch_waf_hit h '
			. 'LEFT JOIN malwatch_waf_ip p ON p.server_id = h.server_id AND p.ip = h.client_ip '
			. "WHERE h.server_id = ? AND h.client_ip != '' AND (p.ip IS NULL OR p.local_at IS NULL OR p.local_at < ?) "
			. 'GROUP BY h.client_ip, p.local_at LIMIT ?', $conf['server_id'], $newest, (int) $limit));
		if (count($rows) === 0) {
			return 0;
		}
		$readers = waf_origin_readers($this->ensure_dirs() . '/origin', $chosen);
		$now = $this->now();
		$done = 0;
		foreach ($rows as $row) {
			$ip = (string) $row['client_ip'];
			$facts = waf_origin_facts($readers, $ip);
			$app->dbmaster->query(
				'INSERT INTO malwatch_waf_ip (server_id, ip, country, asn, as_org, is_tor, is_vpn, is_hosting, local_at) '
				. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE country = VALUES(country), '
				. 'asn = VALUES(asn), as_org = VALUES(as_org), is_tor = VALUES(is_tor), is_vpn = VALUES(is_vpn), '
				. 'is_hosting = VALUES(is_hosting), local_at = VALUES(local_at)',
				$conf['server_id'], $ip, $facts['country'], (int) $facts['asn'], $facts['as_org'],
				$facts['is_tor'], $facts['is_vpn'], $facts['is_hosting'], $now);
			$done++;
		}
		waf_origin_readers_close($readers);
		return $done;
	}
```

In `cleanup()` nach dem Block, der `malwatch_waf_site_day` und `malwatch_waf_day` aufräumt, einfügen:

```php
		// The origin of an address lives as long as its last hit.
		$app->dbmaster->query('DELETE p FROM malwatch_waf_ip p LEFT JOIN malwatch_waf_hit h '
			. 'ON h.server_id = p.server_id AND h.client_ip = p.ip WHERE p.server_id = ? AND h.hit_id IS NULL',
			$conf['server_id']);
		$counts['addresses'] = (int) $app->dbmaster->affectedRows();

```

In derselben Methode die Zeile, die die Zählungen anlegt,

```php
		$counts = array('hits' => 0, 'days' => 0, 'files' => 0, 'staging' => 0);
```

ersetzen durch:

```php
		$counts = array('hits' => 0, 'days' => 0, 'files' => 0, 'staging' => 0, 'addresses' => 0);
```

- [ ] **Step 7: Probe erweitern**

In `ispconfig/tests/waf_class_probe.php` am Ende vor dem Block `// --- summary` einfügen:

```php
// --- B6: the addresses of the hits --------------------------------------------

$db->query("INSERT INTO malwatch_waf_origin_source (server_id, source, version, checked_at, fetched_at, entries) "
	. "VALUES (?, 'tor', '', NOW(), NOW(), 3) ON DUPLICATE KEY UPDATE fetched_at = NOW(), entries = 3", $server);
@mkdir($probe_dir . '/waf/origin', 0700, true);
waf_origin_read_list($fixtures . '/tor.txt', $probe_dir . '/waf/origin/tor.bin');
$db->query("INSERT INTO malwatch_waf_hit (server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, method, "
	. "uri, path, status, anomaly_score, would_block, logged_in, rules, request_headers) "
	. "VALUES (?, 11, 'beispiel.test', 'probe-origin', NOW(), '192.0.2.10', 'GET', '/x', '/x', 404, 5, 'n', 'n', '[]', '{}')", $server);
$db->query("UPDATE malwatch_config SET waf_origin_tor = 'torproject' WHERE config_id = 1");
expect_same('every address of the stored hits is looked up', $waf->origin_lookup(10), 3);
$ip_row = $db->queryOneRecord("SELECT is_tor, country, local_at FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('the address is marked as Tor', array($ip_row['is_tor'], $ip_row['country'] === '' ), array('y', true));
expect_same('a second pass finds nothing new', $waf->origin_lookup(10), 0);
$db->query("DELETE FROM malwatch_waf_hit WHERE unique_id = 'probe-origin'");
$waf->cleanup();
expect_same('the address goes with its last hit',
	count_rows("SELECT ip FROM malwatch_waf_ip WHERE ip = '192.0.2.10'"), 0);
```

- [ ] **Step 8: Prüfungen**

Run: `php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_origin_test.php`
Expected: beide `alle Prüfungen bestanden`.

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/tests/waf_class_probe.php`
Expected: zweimal `No syntax errors detected`. Die Probe läuft in Task B9 auf dem Server.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 9: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_origin.inc.php ispconfig/install/schema.sql ispconfig/install/uninstall-schema.sql ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_class_probe.php ispconfig/tests/waf_origin_sources_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): look up the origin of every stored address" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B7: Herkunft an jeder Adresse zeigen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (Anzeige der Herkunft)
- Modify: `ispconfig/interface/malwatch_waf_show.php`, `ispconfig/interface/templates/malwatch_waf_show.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng`
- Modify: `ispconfig/tests/check_wiring.sh` (Prüfung 68)
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `malwatch_waf_ip` (B6), die Einstellungen (B3)
- Produces:
  - `waf_panel_origin($wb, $row, $language)` → Land, Provider, Chips und Zustand einer Adresse
  - `waf_panel_country_name($code, $language)` → Land im Klartext, sonst das Kürzel
  - `waf_panel_origin_credit($wb, $settings)` → Namensnennung der gewählten Quelle
  - `waf_panel_origin_lookup($app, $ips)` → die Zeilen von `malwatch_waf_ip` zu diesen Adressen

- [ ] **Step 1: Tests schreiben**

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- summary` einfügen:

```php
// --- B7: the origin at an address ---------------------------------------------

$origin_row = array('country' => 'de', 'asn' => '3320', 'as_org' => 'Deutsche Telekom AG', 'is_tor' => 'n',
	'is_vpn' => 'y', 'is_hosting' => 'y', 'is_proxy' => 'n', 'vpn_operator' => 'Beispiel VPN', 'external_state' => 'done');
$origin = waf_panel_origin($wb, $origin_row, 'de');
expect_same('country and provider of an address', array($origin['country'], $origin['provider'], $origin['known']),
	array('DE', 'AS3320 Deutsche Telekom AG', true));
expect_same('the marks of an address', $origin['chips'], array('VPN Beispiel VPN', 'Rechenzentrum'));
$long = waf_panel_origin($wb, array('country' => '', 'asn' => '64500', 'as_org' => str_repeat('Name ', 20),
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'pending'), 'de');
expect_same('a long provider is cut', array(strlen($long['provider']), strlen($long['provider_full']) > 40),
	array(40, true));
expect_same('an address that is being checked', $long['state'], 'wird geprüft');
expect_same('an address the limit stopped', waf_panel_origin($wb, array('country' => '', 'asn' => 0, 'as_org' => '',
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'limit'), 'de')['state'], 'nicht geprüft, Tageslimit');
expect_same('an address without a row', array(waf_panel_origin($wb, null, 'de')['known'],
	waf_panel_origin($wb, null, 'de')['chips']), array(false, array()));
expect_same('the country in words', waf_panel_country_name('FR', 'de') !== 'FR', class_exists('Locale'));
expect_same('a country code that is none', waf_panel_country_name('kein-land', 'de'), '');
expect_same('the attribution of DB-IP', waf_panel_origin_credit($wb, array('waf_origin_geo' => 'dbip')),
	array('text' => 'IP-Daten: DB-IP', 'url' => 'https://db-ip.com'));
expect_same('the attribution of MaxMind',
	waf_panel_origin_credit($wb, array('waf_origin_geo' => 'maxmind'))['url'], 'https://www.maxmind.com');
expect_same('no attribution while the source is off', waf_panel_origin_credit($wb, array()),
	array('text' => '', 'url' => ''));
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_origin()`.

- [ ] **Step 3: Funktionen schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` nach `waf_panel_origin_line()` einfügen:

```php
/**
 * The origin of one address, ready for the page: country, provider and the
 * marks as chips. $row is its row of malwatch_waf_ip, null when the address
 * has none. $language picks the language of the country name.
 */
function waf_panel_origin($wb, $row, $language = 'de')
{
	$country = is_array($row) ? strtoupper((string) $row['country']) : '';
	$country = preg_match('/^[A-Z]{2}$/', $country) ? $country : '';
	$asn = is_array($row) ? (int) $row['asn'] : 0;
	$org = is_array($row) ? trim((string) $row['as_org']) : '';
	$provider = $asn > 0 ? 'AS' . $asn . ($org === '' ? '' : ' ' . $org) : $org;
	$chips = array();
	$marks = array('is_tor' => 'origin_chip_tor_txt', 'is_vpn' => 'origin_chip_vpn_txt',
		'is_hosting' => 'origin_chip_hosting_txt', 'is_proxy' => 'origin_chip_proxy_txt');
	foreach ($marks as $field => $key) {
		if (!is_array($row) || !isset($row[$field]) || (string) $row[$field] !== 'y') {
			continue;
		}
		$label = waf_panel_text($wb, $key, '');
		$operator = $field === 'is_vpn' && isset($row['vpn_operator']) ? trim((string) $row['vpn_operator']) : '';
		$chips[] = $operator === '' ? $label : $label . ' ' . waf_cut($operator, 40);
	}
	$state = '';
	$external = is_array($row) && isset($row['external_state']) ? (string) $row['external_state'] : 'none';
	if ($external === 'pending') {
		$state = waf_panel_text($wb, 'origin_pending_txt', '');
	} elseif ($external === 'limit') {
		$state = waf_panel_text($wb, 'origin_limit_txt', '');
	}
	return array(
		'country' => $country,
		'country_name' => waf_panel_country_name($country, $language),
		'provider' => waf_cut($provider, 40),
		'provider_full' => $provider,
		'chips' => $chips,
		'state' => $state,
		'known' => $country !== '' || $provider !== '' || count($chips) > 0,
	);
}

/** The name of a country, as far as the intl extension knows it; else its code. */
function waf_panel_country_name($code, $language)
{
	$code = strtoupper((string) $code);
	if (!preg_match('/^[A-Z]{2}$/', $code)) {
		return '';
	}
	if (!class_exists('Locale')) {
		return $code;
	}
	$language = preg_match('/^[a-z]{2}$/', (string) $language) ? (string) $language : 'en';
	$name = (string) Locale::getDisplayRegion('-' . $code, $language);
	return $name === '' ? $code : $name;
}

/**
 * The attribution the chosen source asks for, as array(text, url). Both stay
 * empty while country and provider are off.
 */
function waf_panel_origin_credit($wb, $settings)
{
	$geo = isset($settings['waf_origin_geo']) ? (string) $settings['waf_origin_geo'] : 'off';
	if ($geo === 'dbip') {
		return array('text' => waf_panel_text($wb, 'origin_credit_dbip_txt', ''), 'url' => 'https://db-ip.com');
	}
	if ($geo === 'maxmind') {
		return array('text' => waf_panel_text($wb, 'origin_credit_maxmind_txt', ''), 'url' => 'https://www.maxmind.com');
	}
	return array('text' => '', 'url' => '');
}

/** The rows of malwatch_waf_ip for these addresses, keyed by address. */
function waf_panel_origin_lookup($app, $ips)
{
	$rows = array();
	$ips = array_values(array_unique(array_filter($ips, 'strlen')));
	if (count($ips) === 0) {
		return $rows;
	}
	foreach (waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_ip WHERE ip IN ?', $ips)) as $row) {
		$rows[(string) $row['ip']] = $row;
	}
	return $rows;
}
```

- [ ] **Step 4: Texte**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf.lng` anhängen:

```php

// The origin at an address.
$wb['origin_chip_tor_txt'] = 'Tor';
$wb['origin_chip_vpn_txt'] = 'VPN';
$wb['origin_chip_hosting_txt'] = 'Rechenzentrum';
$wb['origin_chip_proxy_txt'] = 'Proxy';
$wb['origin_pending_txt'] = 'wird geprüft';
$wb['origin_limit_txt'] = 'nicht geprüft, Tageslimit';
$wb['origin_credit_dbip_txt'] = 'IP-Daten: DB-IP';
$wb['origin_credit_maxmind_txt'] = 'Enthält GeoLite2-Daten von MaxMind';
$wb['origin_off_hint_txt'] = 'Herkunft der Adressen ist aus. Land, Provider, Tor und VPN erscheinen, sobald in den Einstellungen der Abwehr eine Quelle gewählt ist.';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf.lng` anhängen:

```php

// The origin at an address.
$wb['origin_chip_tor_txt'] = 'Tor';
$wb['origin_chip_vpn_txt'] = 'VPN';
$wb['origin_chip_hosting_txt'] = 'Data centre';
$wb['origin_chip_proxy_txt'] = 'Proxy';
$wb['origin_pending_txt'] = 'being checked';
$wb['origin_limit_txt'] = 'not checked, daily limit';
$wb['origin_credit_dbip_txt'] = 'IP data: DB-IP';
$wb['origin_credit_maxmind_txt'] = 'Includes GeoLite2 data from MaxMind';
$wb['origin_off_hint_txt'] = 'The origin of the addresses is off. Country, provider, Tor and VPN appear as soon as a source is chosen in the settings of the Abwehr.';
```

- [ ] **Step 5: Website-Seite**

In `ispconfig/interface/malwatch_waf_show.php` nach der Zeile

```php
$card_hits = waf_panel_rule_hits($wb, $catalog, $card_rows);
```

einfügen:

```php
// The origin of every address the cards show; the stored requests add theirs below.
$card_ips = array();
foreach ($card_hits as $rule) {
	foreach (array_slice($rule['addresses'], 0, 5) as $address) {
		$card_ips[] = $address['key'];
	}
}
$origin_rows = waf_panel_origin_lookup($app, $card_ips);
$origin_credit = waf_panel_origin_credit($wb, $settings);
$app->tpl->setVar('origin_credit', $app->functions->htmlentities($origin_credit['text']));
$app->tpl->setVar('origin_credit_href', $app->functions->htmlentities($origin_credit['url']));
$app->tpl->setVar('origin_off', count(waf_origin_chosen($settings)) === 0 ? 1 : 0);
```

Den Block, der die Adressen einer Regel-Karte füllt,

```php
	$addresses = array();
	foreach (array_slice($seen['addresses'], 0, 5) as $address) {
		$addresses[] = array(
			'address' => $app->functions->htmlentities($address['key']),
			'address_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($address['count'], 0, ',', '.'))),
			'address_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($address['key'])),
		);
	}
```

ersetzen durch:

```php
	$addresses = array();
	foreach (array_slice($seen['addresses'], 0, 5) as $address) {
		$origin = waf_panel_origin($wb, isset($origin_rows[$address['key']]) ? $origin_rows[$address['key']] : null, $language);
		$chips = array();
		foreach ($origin['chips'] as $chip) {
			$chips[] = array('chip' => $app->functions->htmlentities($chip));
		}
		$addresses[] = array(
			'address' => $app->functions->htmlentities($address['key']),
			'address_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($address['count'], 0, ',', '.'))),
			'address_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($address['key'])),
			'address_country' => $app->functions->htmlentities($origin['country']),
			'address_country_name' => $app->functions->htmlentities($origin['country_name']),
			'address_provider' => $app->functions->htmlentities($origin['provider']),
			'address_provider_full' => $app->functions->htmlentities($origin['provider_full']),
			'address_chips' => $chips,
			'address_has_chips' => count($chips) > 0 ? 1 : 0,
		);
	}
```

Nach der Zeile

```php
$app->tpl->setVar('ip_filter', $ip_filter !== '' ? 1 : 0);
```

einfügen:

```php
$hit_ips = array();
foreach (waf_panel_rows($stored_rows) as $row) {
	$hit_ips[] = (string) $row['client_ip'];
}
$origin_rows = array_merge($origin_rows, waf_panel_origin_lookup($app, $hit_ips));
```

Im Block, der einen Einzeltreffer füllt, nach der Zeile

```php
		'hit_ip' => $app->functions->htmlentities($hit['client_ip']),
```

einfügen:

```php
		'hit_country' => $app->functions->htmlentities($hit_origin['country']),
		'hit_country_name' => $app->functions->htmlentities($hit_origin['country_name']),
		'hit_provider' => $app->functions->htmlentities($hit_origin['provider']),
		'hit_provider_full' => $app->functions->htmlentities($hit_origin['provider_full']),
		'hit_origin_state' => $app->functions->htmlentities($hit_origin['state']),
		'hit_chips' => $hit_chips,
		'hit_has_chips' => count($hit_chips) > 0 ? 1 : 0,
```

und vor der Zeile `	$hit_rows[] = array(` einfügen:

```php
	$hit_origin = waf_panel_origin($wb, isset($origin_rows[$hit['client_ip']]) ? $origin_rows[$hit['client_ip']] : null, $language);
	$hit_chips = array();
	foreach ($hit_origin['chips'] as $chip) {
		$hit_chips[] = array('chip' => $app->functions->htmlentities($chip));
	}
```

- [ ] **Step 6: Vorlage**

In `ispconfig/interface/templates/malwatch_waf_show.htm` die Zeile der Adressliste

```html
					<tmpl_loop name="rule_addresses"><li><a class="mw-mono" href="#" data-load-content="{tmpl_var name='address_href'}">{tmpl_var name='address'}</a> <span class="mw-dim">{tmpl_var name='address_hits'}</span></li></tmpl_loop>
```

ersetzen durch:

```html
					<tmpl_loop name="rule_addresses"><li><a class="mw-mono" href="#" data-load-content="{tmpl_var name='address_href'}">{tmpl_var name='address'}</a> <span class="mw-dim">{tmpl_var name='address_hits'}</span><tmpl_if name="address_country"> <span class="mw-origin" title="{tmpl_var name='address_country_name'}">{tmpl_var name='address_country'}</span></tmpl_if><tmpl_if name="address_has_chips"><tmpl_loop name="address_chips"> <span class="mw-chip mw-origin-chip">{tmpl_var name='chip'}</span></tmpl_loop></tmpl_if><tmpl_if name="address_provider"> <span class="mw-dim mw-origin" title="{tmpl_var name='address_provider_full'}">{tmpl_var name='address_provider'}</span></tmpl_if></li></tmpl_loop>
```

Die Zeile der Adresse im zugeklappten Treffer

```html
		<span class="mw-mono mw-hitip">{tmpl_var name='hit_ip'}</span>
```

ersetzen durch:

```html
		<span class="mw-mono mw-hitip">{tmpl_var name='hit_ip'}</span>
		<tmpl_if name="hit_country"><span class="mw-origin" title="{tmpl_var name='hit_country_name'}">{tmpl_var name='hit_country'}</span></tmpl_if>
		<tmpl_if name="hit_has_chips"><tmpl_loop name="hit_chips"><span class="mw-chip mw-origin-chip">{tmpl_var name='chip'}</span></tmpl_loop></tmpl_if>
		<tmpl_if name="hit_provider"><span class="mw-dim mw-origin" title="{tmpl_var name='hit_provider_full'}">{tmpl_var name='hit_provider'}</span></tmpl_if>
		<tmpl_if name="hit_origin_state"><span class="mw-dim">{tmpl_var name='hit_origin_state'}</span></tmpl_if>
```

Nach dem Block der Regel-Karten, also nach

```html
<tmpl_else>
<p class="mw-sub">{tmpl_var name='rules_none_txt'}</p>
</tmpl_if>
```

einfügen:

```html
<tmpl_if name="origin_off"><p class="mw-sub">{tmpl_var name='origin_off_hint_txt'} <a href="#" data-load-content="security/malwatch_waf_config_edit.php">{tmpl_var name='origin_settings_link_txt'}</a></p></tmpl_if>
<tmpl_if name="origin_credit"><p class="mw-sub"><a href="{tmpl_var name='origin_credit_href'}" target="_blank" rel="noopener">{tmpl_var name='origin_credit'}</a></p></tmpl_if>
```

Im Stilblock nach der Zeile mit `.mw-hitip` einfügen:

```css
#mw-wafsite .mw-origin{font-size:12px}
#mw-wafsite .mw-chip.mw-origin-chip{text-transform:none;letter-spacing:0;font-weight:600}
```

- [ ] **Step 7: Verdrahtung prüfen**

In `ispconfig/tests/check_wiring.sh` vor dem Block `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 68. The website page names the origin only from the table the cron fills and
#     shows the attribution of the chosen source. A page that read a range file
#     itself would open a file of the server from the panel; that is the job of
#     the cron alone.
show_page="$root/interface/malwatch_waf_show.php"
if [ -f "$show_page" ]; then
	grep -q 'waf_panel_origin_lookup(' "$show_page" \
		|| fail "malwatch_waf_show.php shows no origin; waf_panel_origin_lookup() reads it"
	if grep -q 'waf_origin_open(\|waf_origin_find(' "$show_page"; then
		fail "malwatch_waf_show.php reads a range file itself; the cron fills malwatch_waf_ip"
	fi
	grep -q 'waf_panel_origin_credit(' "$show_page" \
		|| fail "malwatch_waf_show.php leaves out the attribution of the origin source"
fi
for lang in de en; do
	for key in origin_credit_dbip_txt origin_credit_maxmind_txt origin_off_hint_txt; do
		grep -q "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf.lng" \
			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
done

```

- [ ] **Step 8: Prüfungen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php -l ispconfig/interface/malwatch_waf_show.php`
Expected: zweimal `alle Prüfungen bestanden` und `No syntax errors detected`.

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`. Ohne Herkunftsdaten zeigt `out_show.html` den Hinweis: `grep -c 'Herkunft der Adressen ist aus' .superpowers/abwehr/harness/out_show.html` ergibt `1`.

Damit der Nachbau auch die gefüllte Anzeige zeigt, in `.superpowers/abwehr/harness/fake_db.php` in `queryAllRecords()` vor dem Zweig `if (strpos($sql, 'FROM malwatch_waf_hit') !== false) {` einfügen:

```php
		// The origin of the addresses the pages show.
		if (strpos($sql, 'FROM malwatch_waf_ip') !== false) {
			return array(
				array('ip' => '198.51.100.7', 'country' => 'FR', 'asn' => '64500', 'as_org' => 'Beispielnetz SAS',
					'is_tor' => 'n', 'is_vpn' => 'y', 'is_hosting' => 'y', 'is_proxy' => 'n', 'vpn_operator' => '',
					'local_at' => '2026-09-16 12:00:00', 'external_state' => 'none', 'external_at' => null, 'external_tries' => '0'),
				array('ip' => '192.0.2.10', 'country' => 'DE', 'asn' => '3320', 'as_org' => 'Zweites Beispielnetz',
					'is_tor' => 'y', 'is_vpn' => 'n', 'is_hosting' => 'n', 'is_proxy' => 'n', 'vpn_operator' => '',
					'local_at' => '2026-09-16 12:00:00', 'external_state' => 'none', 'external_at' => null, 'external_tries' => '0'),
			);
		}
```

und in der Beispielzeile der Einstellungen `'waf_origin_geo' => 'off'` auf `'waf_origin_geo' => 'dbip'` setzen. Dann noch einmal bauen und nachsehen:

```bash
bash .superpowers/abwehr/harness/build_all.sh .
grep -o 'class="mw-origin" title="[^"]*">[A-Z][A-Z]<' .superpowers/abwehr/harness/out_show.html | sort | uniq -c
grep -o 'class="mw-chip mw-origin-chip">[^<]*<' .superpowers/abwehr/harness/out_show.html | sort | uniq -c
grep -c 'IP-Daten: DB-IP' .superpowers/abwehr/harness/out_show.html
grep -c 'mw-origin-chip"><' .superpowers/abwehr/harness/out_show.html
```

Expected: je einmal `title="Deutschland">DE` und `title="Frankreich">FR`, die Chips `Tor`, `VPN` und `Rechenzentrum` je einmal, einmal die Namensnennung und `0` leere Chips. Der Schalter `address_has_chips` sorgt für die letzte Zeile: Eine leere Schleife rendert in vlibTemplate sonst einen leeren Durchgang.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 9: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/malwatch_waf_show.php ispconfig/interface/templates/malwatch_waf_show.htm ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/tests/check_wiring.sh ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): country, provider and marks at every address" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task B8: Version 0.21.0, Changelog, Dokumentation und Spec

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`
- Modify: `CHANGELOG.md` (neuer Abschnitt oben)
- Modify: `README.md`, `ispconfig/README.md` (Abschnitt „Abwehr“)
- Modify: `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` (Präzisierungen aus dem Kopf dieses Plans)

**Interfaces:**
- Consumes: den Stand nach B1 bis B7
- Produces: malwatch 0.21.0 auf dem Zweig `waf-herkules`, vollständig geprüft und committet. Push, Tag und Release folgen in Task B9 nach Freigabe von Mathias.

- [ ] **Step 1: Version**

In `internal/version/version.go` die Zeile

```go
var Version = "0.20.0"
```

ersetzen durch

```go
var Version = "0.21.0"
```

`ispconfig/version` enthält danach genau die Zeile `0.21.0`:

```bash
printf '0.21.0\n' > ispconfig/version
```

- [ ] **Step 2: Changelog**

In `CHANGELOG.md` direkt nach der Zeile `Alle nennenswerten Änderungen an diesem Projekt.` und ihrer Leerzeile einfügen:

```markdown
## [0.21.0] – <Datum des Releases>

### Neu

**Herkunft der Adressen.** Die Seiten der Abwehr zeigen zu jeder Adresse Land,
Provider und die Chips „Tor“, „VPN“ und „Rechenzentrum“. Die Angaben kommen aus
Listen, die der Server selbst herunterlädt: DB-IP Lite oder MaxMind GeoLite2 für
Land und Provider, die Liste des Tor-Projekts, die X4BNet-Listen für VPN-Netze und
Rechenzentren.

**Jede Quelle einzeln wählbar.** Unter **Security > Abwehr > Einstellungen** steht
der Abschnitt „Herkunft der Adressen“. Alles beginnt auf „aus“: Erst mit einer Wahl
lädt der Server eine Liste. Der Abschnitt nennt je Quelle den Stand, die Zahl der
Bereiche, den letzten Abruf und einen Fehler mit dem, was jetzt gilt. Für MaxMind
nimmt die Seite Konto-ID und Lizenzschlüssel entgegen; der Schlüssel erscheint
danach nur noch verdeckt.

**Auftrag „Herkunft der Adressen“.** Der stündliche Cron legt ihn an, sobald eine
Quelle fällig ist, und nach dem Speichern der Einstellungen sofort. Er lädt jede
fällige Liste, baut sie in eine Bereichsdatei um und tauscht sie erst nach der
Prüfung: Die Datei muss sich lesen lassen, genug Bereiche enthalten und darf nicht
auf die Hälfte des bisherigen Stands fallen. Sonst bleibt der bisherige Stand
aktiv, und die Einstellungsseite nennt den Grund.

### Geändert

**Adressen in der Datenbank.** Zu jeder Adresse eines gespeicherten Treffers hält
`malwatch_waf_ip` Land, Netz und die Merkmale. Die Zeile verschwindet mit dem
letzten Treffer der Adresse, also spätestens nach der eingestellten Aufbewahrung.
Die Listen selbst enthalten keine Besucheradressen, und der Server schickt keine
Adresse nach außen.
```

- [ ] **Step 3: README und Spec**

In `README.md`, Abschnitt „Abwehr“, die Zeilen

```markdown
ihr Audit-Log aus: Treffer je Website und Tag, Regeln mit Erklärung, Auslöser,
Einordnung und den Adressen ihrer Treffer, einzelne Anfragen und die Vorschau, was
```

ersetzen durch:

```markdown
ihr Audit-Log aus: Treffer je Website und Tag, Regeln mit Erklärung, Auslöser,
Einordnung und den Adressen ihrer Treffer samt Land, Provider und den Merkmalen
Tor, VPN und Rechenzentrum, einzelne Anfragen und die Vorschau, was
```

In `ispconfig/README.md` die Zeilen

```markdown
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zahl der Einzeltreffer für die Regel-Karten, Zeilen je Durchgang, Frist für den
  vhost.
```

ersetzen durch:

```markdown
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zahl der Einzeltreffer für die Regel-Karten, Herkunft der Adressen, Zeilen je
  Durchgang, Frist für den vhost.
```

und nach dem Absatz, der mit `Die Erklärungen der Regeln stehen in` beginnt, einfügen:

```markdown

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
```

In `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`, Abschnitt 2, nach der Zeile, die mit `| Adressfilter |` beginnt, einfügen:

```markdown
| Reihenfolge in Teil B | erst die lokalen Listen als 0.21.0, proxycheck.io danach als eigenes Release |
| Format der Bereichsdateien | eigene Datei je Quelle: sortierte Bereiche mit 16-Byte-Adressen und einer Wertetabelle, binär durchsucht |
```

In Abschnitt 6 vor der Tabelle mit den Spalten einfügen:

```markdown
Release 0.21.0 bringt die lokalen Quellen. Die Spalten `waf_origin_proxycheck_key`
und `waf_origin_proxycheck_daily` und der Wert `proxycheck` in `waf_origin_net`
kommen mit dem Release für proxycheck.io.

```

In Abschnitt 9 vor dem ersten Aufzählungspunkt einfügen:

```markdown
Die Felder `external_state`, `external_at`, `external_tries`, `is_proxy` und
`vpn_operator` entstehen schon mit 0.21.0 und bleiben leer, bis proxycheck.io dazu
kommt.

```

- [ ] **Step 4: Alle Prüfungen**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go build ./... && echo "Go: ok"
go test ./... 2>&1 | grep -vE '^(ok|\?) '
find ispconfig -name '*.php' -print0 | xargs -0 -n1 php -l | grep -v '^No syntax errors' ; echo "Syntax geprüft"
sh ispconfig/tests/check_constants.sh
for t in upgrade_helpers_test upgrade_offers_test panel_helpers_test waf_lib_test waf_panel_test waf_panel_post_test waf_rules_catalog_test waf_origin_test waf_origin_sources_test; do php "ispconfig/tests/$t.php" | tail -n 1; done
php -l waf/waf-switch && php -l waf/waf-report && bash -n waf/waf-guard && bash -n waf/install.sh && echo "Werkzeuge: ok"
cat ispconfig/version; grep -n 'var Version' internal/version/version.go
```

Expected:
- `Go: ok`; unter Windows scheitern dieselben zwei Go-Tests wie in Teil A, unter Linux laufen sie durch
- nach `find` nur `Syntax geprüft`
- `Constants OK: …`
- neun Zeilen, jede endet auf `OK` oder `alle Prüfungen bestanden`
- `Werkzeuge: ok`
- `0.21.0` und `5:var Version = "0.21.0"`

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`.

- [ ] **Step 5: Commit**

```bash
git add internal/version/version.go ispconfig/version CHANGELOG.md README.md ispconfig/README.md docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "release: 0.21.0, the origin of an address from local lists" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
git status --short
```

Expected: `grep` gibt nichts aus, der Commit gelingt, `git status --short` zeigt keine Datei aus `ispconfig/`, `internal/`, `waf/` oder `docs/`.

---

### Task B9: Einführung auf web.herkules

malwatch 0.21.0 kommt in fünf Blöcken auf den Server, jeder mit eigener Freigabe von Mathias und mit Eintrag im Serverprotokoll:

1. Probeabruf aller Quellen in ein Probeverzeichnis unter `/root`, mit Messung
2. Staging-Kopie, Schema, Probe der Klasse und der Seiten
3. Veröffentlichen: `main`, CI, Tag `v0.21.0`, Release
4. malwatch 0.21.0 einspielen
5. Quellen einschalten, ersten Auftrag beobachten, Sichtprüfung im Panel

Claude meldet sich nie im Panel an und tippt keine Zugangsdaten. Im Chrome arbeitet Claude in einem eigenen Tab und schließt ihn am Ende.

**Files:**
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
- Hilfen am Rechner (nicht im Repo): `.superpowers/abwehr/measure.sh`

**Interfaces:**
- Consumes: den Commit aus Task B8 auf `waf-herkules`
- Produces: malwatch 0.21.0 auf web.herkules mit DB-IP Lite, Tor-Liste und X4BNet-Listen in Betrieb, geprüft und protokolliert

#### Messen

Vor dem ersten und nach jedem ändernden Schritt:

```bash
ssh ispconfig 'bash -s' < .superpowers/abwehr/measure.sh
for site in bright-color.de "$ZWEITE" "$DRITTE"; do curl -s -o /dev/null -w "%{http_code} %{time_total}s $site\n" "https://$site/"; done
```

`ZWEITE` und `DRITTE` sind die beiden Kundenwebsites aus den Messtabellen der letzten Einträge im Serverprotokoll; ihre Namen stehen nur dort.

**Abbruch**, sobald eines davon eintritt: `nginx -t` scheitert, nginx ist nicht aktiv, weniger als 2 GB verfügbar, Load (5 Minuten) dauerhaft über 6, eine Website antwortet anders als zu Beginn oder doppelt so langsam, die Platte unter `/var` füllt sich um mehr als 2 GB, ein neuer Eintrag „exited on signal“. Dann: Werte festhalten, Mathias Bescheid geben, erst nach Klärung weiter.

#### Block 1: Probeabruf der Quellen

- [x] **Step 1: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 1: Ich lade die drei freien Quellen einmal von Hand in ein Probeverzeichnis unter `/root/mw-origin-probe` — DB-IP Lite (Land und Netz), die Tor-Liste und die X4BNet-Listen —, baue sie mit den neuen Funktionen in Bereichsdateien um und messe Laufzeit, Speicher und Größe. So wissen wir vor dem ersten Auftrag, was der Server dabei tut. Danach lösche ich das Verzeichnis. Die Datenbank, nginx und die Websites bleiben unberührt; die Erweiterung bleibt auf 0.20.0.“ Weiter erst nach seinem Ja.

- [x] **Step 2: Ausgangslage**

Beide Messungen, dazu:

```bash
ssh ispconfig 'df -h /var /root | tail -n 2; php -r "echo \"curl: \", (int) function_exists(\"curl_init\"), \", zip: \", (int) class_exists(\"ZipArchive\"), \", zlib: \", (int) function_exists(\"gzopen\"), \", intl: \", (int) class_exists(\"Locale\"), PHP_EOL;"'
```

Expected: der freie Platz und eine Zeile mit vier Einsen; `zip` braucht nur MaxMind, `intl` nur der Klartext des Landes.

- [x] **Step 3: Probeabruf**

```bash
git archive --format=tar HEAD ispconfig | ssh ispconfig 'rm -rf /root/mw-origin-probe && mkdir -p /root/mw-origin-probe/src && tar -x -C /root/mw-origin-probe/src'
ssh ispconfig 'cat > /root/mw-origin-probe/probe.php' <<'EOF'
<?php
// Loads the free origin sources once and reports what the rebuild costs:
//   php probe.php <directory>
require '/root/mw-origin-probe/src/ispconfig/interface/lib/malwatch_waf_origin.inc.php';
$dir = rtrim($argv[1], '/');
$month = gmdate('Y-m');
$jobs = array(
	'dbip_country' => array('urls' => waf_origin_urls('dbip_country', $month), 'read' => 'country'),
	'dbip_asn' => array('urls' => waf_origin_urls('dbip_asn', $month), 'read' => 'asn'),
	'tor' => array('urls' => waf_origin_urls('tor', ''), 'read' => 'list'),
	'x4b_vpn' => array('urls' => waf_origin_urls('x4b_vpn', ''), 'read' => 'list'),
	'x4b_datacenter' => array('urls' => waf_origin_urls('x4b_datacenter', ''), 'read' => 'list'),
);
foreach ($jobs as $name => $job) {
	$files = array();
	$started = microtime(true);
	$ok = true;
	foreach ($job['urls'] as $index => $url) {
		$file = $dir . '/' . $name . '-' . $index . '.raw';
		$command = 'curl -fsS --connect-timeout 10 --max-time 120 -A malwatch/probe -o ' . escapeshellarg($file)
			. ' ' . escapeshellarg($url) . ' 2>&1';
		$output = array();
		$code = 0;
		exec($command, $output, $code);
		if ($code !== 0) {
			printf("%-16s Abruf scheiterte: %s\n", $name, substr(implode(' ', $output), 0, 120));
			$ok = false;
			break;
		}
		$files[] = $file;
	}
	if (!$ok) {
		continue;
	}
	$loaded = microtime(true);
	$bytes = 0;
	foreach ($files as $file) {
		$bytes += (int) filesize($file);
	}
	$out = $dir . '/' . $name . '.bin';
	if ($job['read'] === 'country') {
		$counts = waf_origin_read_dbip_country($files, $out);
	} elseif ($job['read'] === 'asn') {
		$counts = waf_origin_read_dbip_asn($files, $out);
	} else {
		$counts = waf_origin_read_list($files, $out);
	}
	$done = microtime(true);
	printf("%-16s geladen %5.1f MB in %5.1f s, umgebaut in %5.1f s, %8d Bereiche, %6d unbrauchbar, Datei %5.1f MB, Speicher %4.0f MB, Prüfung: %s\n",
		$name, $bytes / 1048576, $loaded - $started, $done - $loaded, $counts === null ? 0 : $counts['ranges'],
		$counts === null ? 0 : $counts['bad'], (int) @filesize($out) / 1048576, memory_get_peak_usage(true) / 1048576,
		$counts === null ? 'Umbau scheiterte' : (waf_origin_check($name, $counts, 0) === '' ? 'bestanden' : waf_origin_check($name, $counts, 0)));
	foreach ($files as $file) {
		@unlink($file);
	}
	$reader = waf_origin_open($out);
	printf("%-16s Nachschlagen: %s\n", $name, $reader === null ? 'Datei unlesbar' : 'ok, ' . waf_origin_ranges($reader) . ' Bereiche');
	waf_origin_close($reader);
}
EOF
ssh ispconfig 'cd /root/mw-origin-probe && nice -n 15 php probe.php /root/mw-origin-probe; du -sh /root/mw-origin-probe; date "+%H:%M:%S"'
```

Expected je Quelle eine Zeile „geladen … umgebaut … Bereiche … Prüfung: bestanden“ und „Nachschlagen: ok“. Die Werte kommen ins Protokoll. Scheitert eine Quelle, hält der Befund den Block an: Der Auftrag würde dasselbe erleben.

- [x] **Step 4: Aufräumen und Protokoll**

```bash
ssh ispconfig 'rm -rf /root/mw-origin-probe; ls -d /root/mw-origin-probe 2>&1 | tail -n 1; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: `No such file or directory` und die Uhrzeit. Danach beide Messungen und der Eintrag ins Serverprotokoll (frisch lesen, gezielt einfügen) mit den Messwerten des Probeabrufs, dem freien Platz und dem Befund je Quelle.

Ergebnis am 17.09.2026, 21:50:30–21:50:37 CEST (Protokolleintrag „malwatch 0.21.0: Probeabruf der Herkunftsquellen“): fünf Quellen, je „Prüfung: bestanden“ und „Nachschlagen: ok“, keine unbrauchbare Zeile.

| Quelle | geladen | Umbau | Bereiche | Bereichsdatei |
|---|---|---|---|---|
| dbip_country | 4,3 MB in 0,1 s | 3,0 s | 717.169 | 25.819.108 B |
| dbip_asn | 6,6 MB in 0,2 s | 2,6 s | 473.272 | 19.737.903 B |
| tor | 0,04 MB in 0,5 s | 0,0 s | 685 | 24.683 B |
| x4b_vpn | 0,2 MB in 0,2 s | 0,0 s | 6.966 | 250.799 B |
| x4b_datacenter | 0,8 MB in 0,2 s | 0,3 s | 35.414 | 1.274.927 B |

Zusammen 47.107.420 B, Spitzenbedarf 17 MB Arbeitsspeicher für den ganzen Lauf. Diese 17 MB sind der Vergleichswert für Block 2 und Block 5.

#### Block 2: Staging-Kopie, Schema und Proben

- [x] **Step 5: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 2: Ich kopiere den Stand nach `/root/mw-0210-src` und `/root/mw-0210-stage`, prüfe Syntax und Tests, sichere die Struktur der betroffenen Tabellen und lade das Schema: zwei neue Tabellen (`malwatch_waf_origin_source`, `malwatch_waf_ip`) und acht Spalten in `malwatch_config`, alle mit Vorgabe `off`. Danach lasse ich die Klassenprobe gegen eine Wegwerf-Datenbank laufen und rendere die Seiten der Kopie gegen die echte Datenbank. Zum Schluss lösche ich Kopie und Wegwerf-Datenbank. nginx, die Websites und die laufende Erweiterung bleiben unberührt.“ Weiter erst nach seinem Ja.

- [x] **Step 6: Kopie, Syntax, Tests**

```bash
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/mw-0210-src /root/mw-0210-stage && mkdir -p /root/mw-0210-src /root/mw-0210-stage/interface/web && tar -x -C /root/mw-0210-src'
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Staging-Kopie"
src=/root/mw-0210-src/ispconfig
stage=/root/mw-0210-stage
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
cat version
date "+%H:%M:%S fertig"
EOF
```

Expected: keine Zeile aus den Syntaxprüfungen, sechsmal „alle Prüfungen bestanden“, Version 0.21.0.

- [x] **Step 7: Schema laden**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
install -d -m 700 /var/backups/malwatch
mysqldump --no-data dbispconfig malwatch_config > "/var/backups/malwatch/schema-vor-0.21.0-$(date +%Y%m%d-%H%M%S).sql"
date "+%H:%M:%S Schema laden"
mysql dbispconfig < /root/mw-0210-src/ispconfig/install/schema.sql
date "+%H:%M:%S Schema geladen"
mysql -N dbispconfig -e "SELECT COLUMN_NAME, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME LIKE 'waf\_origin\_%' ORDER BY COLUMN_NAME"
mysql -N dbispconfig -e "SHOW TABLES LIKE 'malwatch\_waf\_%'"
mysql -N dbispconfig -e "SELECT waf_origin_geo, waf_origin_tor, waf_origin_net FROM malwatch_config"
EOF
```

Expected: acht Spalten mit ihren Vorgaben (`off`, leer, `1`, `24`, `24`), die Tabellen `malwatch_waf_day`, `malwatch_waf_exception`, `malwatch_waf_hit`, `malwatch_waf_ip`, `malwatch_waf_origin_source`, `malwatch_waf_site_day` und eine Zeile `off off off`. Danach beide Messungen.

- [x] **Step 8: Klassenprobe und Seiten**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
probe_db=mw_probe_0210
mysql -e "DROP DATABASE IF EXISTS $probe_db; CREATE DATABASE $probe_db"
mysqldump --no-data dbispconfig malwatch_config malwatch_job malwatch_site malwatch_waf_hit malwatch_waf_day malwatch_waf_site_day malwatch_waf_exception malwatch_waf_origin_source malwatch_waf_ip malwatch_action_log web_domain sys_datalog sys_log | mysql "$probe_db"
mysql "$probe_db" -e "INSERT INTO malwatch_config (config_id, sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other) VALUES (1, 1, 1, 'riud', 'riud', '')"
cd /root/mw-0210-src/ispconfig
nice -n 15 php tests/waf_class_probe.php /root/mw-0210-src/ispconfig "$probe_db"
mysql -e "DROP DATABASE $probe_db"
export MW_SECURITY_DIR=/root/mw-0210-stage/interface/web/security
id=$(mysql -N dbispconfig -e "SELECT domain_id FROM web_domain WHERE domain = 'bright-color.de' AND type = 'vhost'")
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
nice -n 15 php tests/render_pages.php "$rid" 2>&1 | tail -n 34
nice -n 15 php tests/render_pages.php "$id" 'malwatch_waf_show.php?ip=stored'
EOF
```

Expected: `waf_class_probe: alle Prüfungen bestanden`, jede Seite `ok`, `All pages render.`. Die Seiten zeigen den Hinweis „Herkunft der Adressen ist aus“, weil noch keine Quelle gewählt ist.

- [x] **Step 9: Aufräumen und Protokoll**

```bash
ssh ispconfig 'rm -rf /root/mw-0210-src /root/mw-0210-stage; mysql -N -e "SHOW DATABASES LIKE \"mw_probe_0210\""; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: keine Datenbank mehr, die Uhrzeit fürs Protokoll. Danach beide Messungen und der Protokolleintrag für Block 1 und 2.

Ergebnis am 17.09.2026, 21:54:54–22:02:07 CEST (eigener Protokolleintrag „Staging-Kopie, Schema und Proben“): Schema geladen (acht Spalten mit Vorgaben, beide neuen Tabellen, Konfiguration `off off off`), sechs Testreihen bestanden, 25 Seiten gerendert, Hinweis „Herkunft der Adressen ist aus“ genau einmal auf der Website-Seite. Die Klassenprobe lief hier zum ersten Mal überhaupt und deckte vier falsche Erwartungen in der Probe auf (Commits `8a29ace`, `d174e14`); die oben stehenden Codeblöcke sind entsprechend berichtigt. Messwerte davor/danach: Last 0,91 → 0,81, frei 6.013 → 6.174 MB, Websites unverändert.

#### Block 3: Veröffentlichen

- [ ] **Step 10: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 3: Ich bringe `waf-herkules` per Fast-Forward nach `main`, schiebe `main`, warte auf die CI und setze danach den Tag `v0.21.0`.“ Weiter erst nach seinem Ja.

- [ ] **Step 11: main, CI, Tag, Release**

```bash
git fetch origin
git merge-base --is-ancestor origin/main waf-herkules && echo "Fast-Forward möglich"
git checkout main
git merge --ff-only waf-herkules
git push origin main
sha=$(git rev-parse HEAD)
gh run watch "$(gh run list --commit "$sha" --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
git tag v0.21.0
git push origin v0.21.0
gh run watch "$(gh run list --commit "$sha" --workflow release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view v0.21.0 --json assets --jq '.assets[].name'
git checkout waf-herkules
```

Expected: `Fast-Forward möglich`, CI grün (darunter die Schritte „WAF origin ranges“ und „WAF origin sources“), Release mit `malwatch-linux-amd64`, `malwatch-linux-arm64`, `malwatch.pkg` und `SHA256SUMS`. Scheitert ein Upload wie bei 0.20.0, hilft `gh run rerun <id> --failed`.

Ergebnis am 17.09.2026: `main` steht auf `fea2093`, CI-Lauf 35269733047 grün mit beiden neuen Schritten, Tag `v0.21.0` gesetzt. Der Release-Lauf 35270234662 brach beim Hochladen von `malwatch-linux-amd64` mit „Error creating asset temp dir“ ab, genau wie bei 0.20.0; `gh run rerun 35270234662 --failed` lud die Datei nach. Danach liegen alle vier Dateien im Release. Der Fehler tritt jetzt zweimal in Folge auf, das Release-Rezept sollte den Upload selbst wiederholen.

#### Block 4: Einspielen

- [ ] **Step 12: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 4: Ich spiele malwatch 0.21.0 ein: Scanner über `install.sh`, Paket nach Prüfsumme, `manual_install.php`, dann `cmp` jeder Kopie und `render_pages.php` live. Die Quellen bleiben dabei aus, es lädt noch nichts herunter.“ Weiter erst nach seinem Ja.

- [ ] **Step 13: Einspielen**

Zuerst beide Messungen, dann derselbe Ablauf wie bei 0.20.0, mit `mw-0210-deploy` und `v0.21.0`:

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Beginn"
rm -rf /root/mw-0210-deploy && mkdir -p /root/mw-0210-deploy && cd /root/mw-0210-deploy
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.21.0/malwatch.pkg
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.21.0/SHA256SUMS
grep " malwatch.pkg$" SHA256SUMS | sha256sum -c -
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh 2>&1 | grep -i installed
cd /usr/local/ispconfig/extensions && mkdir -p malwatch && cd malwatch && unzip -oq /root/mw-0210-deploy/malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php 2>&1 | grep -E "installed|loaded|Error|error|failed" | head -n 8
echo "Addon $(cat /usr/local/ispconfig/extensions/malwatch/version), Scanner $(/usr/local/bin/malwatch version | head -n 1)"
E=/usr/local/ispconfig/extensions/malwatch; n=0; total=0
while IFS=: read -r a s t; do [ "$a" = c ] || continue; total=$((total+1)); cmp -s "$E/$s" "/usr/local/ispconfig/$t" || { echo "abweichend: $t"; n=$((n+1)); }; done < "$E/install/file.list"
echo "Kopien geprüft: $total, abweichend: $n"
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
nice -n 15 php "$E/tests/render_pages.php" "$rid" 2>&1 | tail -n 34
rm -rf /root/mw-0210-deploy
date "+%H:%M:%S eingespielt"
EOF
```

Expected: `malwatch.pkg: OK`, Addon und Scanner `0.21.0`, `Kopien geprüft: 92, abweichend: 0` (91 aus 0.20.0 plus die neue Bibliothek), alle Seiten `ok`. Danach beide Messungen und der Protokolleintrag für Blöcke 3 und 4.

#### Block 5: Quellen einschalten und ansehen

- [ ] **Step 14: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 5: Unter Security > Abwehr > Einstellungen wählen wir bei „Land und Provider“ DB-IP Lite, bei „Tor“ die Liste des Tor-Projekts und bei „VPN und Rechenzentrum“ die X4BNet-Listen und speichern. Damit legt die Seite sofort den Auftrag „Herkunft der Adressen“ an; der Cron lädt die fünf Listen und baut sie um. Ich beobachte den Auftrag, messe mit und sehe mir danach die Seiten an. Klickst du selbst, oder soll ich es in deinem Chrome tun?“ Weiter erst nach seiner Antwort.

- [ ] **Step 15: Quellen einschalten**

Nach dem Speichern:

```bash
ssh ispconfig 'mysql -N dbispconfig -e "SELECT waf_origin_geo, waf_origin_tor, waf_origin_net, waf_origin_db_hours, waf_origin_tor_hours, waf_origin_list_hours FROM malwatch_config"; mysql -N dbispconfig -e "SELECT job_id, job_status, options FROM malwatch_job WHERE job_kind = \"waf\" ORDER BY job_id DESC LIMIT 2"; date "+%H:%M:%S"'
```

Expected: `dbip torproject x4b 24 1 24` und ein Auftrag mit `"action":"origin_update"`.

- [ ] **Step 16: Ersten Auftrag beobachten**

```bash
ssh ispconfig 'for i in $(seq 1 20); do row=$(mysql -N dbispconfig -e "SELECT job_status FROM malwatch_job WHERE job_kind = \"waf\" ORDER BY job_id DESC LIMIT 1"); [ "$row" = "done" ] || [ "$row" = "error" ] && break; sleep 30; done; mysql -N dbispconfig -e "SELECT job_status, LEFT(job_log, 600) FROM malwatch_job WHERE job_kind = \"waf\" ORDER BY job_id DESC LIMIT 1"; mysql dbispconfig -e "SELECT source, version, entries, fetched_at, LEFT(error, 80) AS fehler FROM malwatch_waf_origin_source"; ls -l /var/lib/malwatch/waf/origin/; du -sh /var/lib/malwatch/waf/origin; date "+%H:%M:%S"'
```

Expected: der Auftrag steht auf `done`, das Protokoll nennt je Quelle die Zahl der Bereiche, `malwatch_waf_origin_source` hat fünf Zeilen ohne Fehler, und unter `origin/` liegen fünf `.bin`-Dateien. Dazwischen beide Messungen: Der Umbau läuft unter `nice`, der Speicher bleibt unter dem Wert aus Block 1.

Danach das Nachschlagen:

```bash
ssh ispconfig 'mysql dbispconfig -e "SELECT COUNT(*) AS adressen, SUM(country != \"\") AS mit_land, SUM(is_tor = \"y\") AS tor, SUM(is_vpn = \"y\") AS vpn, SUM(is_hosting = \"y\") AS rechenzentrum FROM malwatch_waf_ip"; date "+%H:%M:%S"'
```

Expected: so viele Adressen, wie die gespeicherten Treffer haben, die meisten mit Land; die Zahlen kommen ins Protokoll. Ist die Tabelle leer, eine Minute später erneut: Das Nachschlagen läuft im Cron nach dem Einlesen.

- [ ] **Step 17: Sichtprüfung im Panel**

Werkzeuge von Claude in Chrome laden, eigener Tab, danach schließen. Abläufe:

| Ablauf | Erwartet |
|---|---|
| Security > Abwehr > Übersicht | Zeile „Herkunft: DB-IP Lite: Land …“ mit den Zahlen der Quellen |
| Website bright-color.de öffnen | in den Regel-Karten je Adresse das Landeskürzel mit Klartext im Titel, der Provider und die Chips, soweit die Listen sie kennen |
| einen Einzeltreffer ansehen | dieselbe Herkunft in der Zeile des Treffers |
| unter den Karten | „IP-Daten: DB-IP“ mit Link auf db-ip.com |
| Abwehr > Einstellungen | Abschnitt „Herkunft der Adressen“ mit den drei Quellen und je einer Zeile „Stand …, … Bereiche, geladen am …“ |

Bildschirmfotos der Karte und der Einstellungen gehen an Mathias.

- [ ] **Step 18: Protokoll**

Frisch lesen, gezielt einfügen: ein Eintrag für Block 5 mit Beginn und Ende, den Freigaben, den Messwerten vor und nach dem Auftrag, den Zahlen je Quelle, der Größe unter `/var/lib/malwatch/waf/origin`, dem Ergebnis der Sichtprüfung und dem Rückweg (Quellen in den Einstellungen wieder auf „aus“; der nächste Auftrag löscht die Dateien und leert die Felder).

- [ ] **Step 19: Erinnerung aktualisieren**

In `waf-web-herkules.md` festhalten: 0.21.0 live seit <Datum>, Quellen DB-IP Lite, Tor und X4BNet in Betrieb, Bereichsdateien unter `/var/lib/malwatch/waf/origin`, Größe und Laufzeit des ersten Umbaus, proxycheck.io offen. Die Zeile in `MEMORY.md` passend kürzen.

---

## Abschluss von Teil B I

Teil B I ist fertig, wenn:

- B1 bis B8 committet sind und `sh ispconfig/tests/check_wiring.sh` `Wiring OK` meldet,
- v0.21.0 veröffentlicht ist und die CI grün war,
- web.herkules 0.21.0 zeigt, die drei Quellen geladen sind und die Seiten Land, Provider und Chips zeigen,
- das Serverprotokoll die Blöcke 1 bis 5 enthält.

Danach, mit eigener Freigabe: der Plan für Teil B II „proxycheck.io“ (Abschnitte 6, 9 und 12 der Spec, soweit sie den externen Dienst betreffen).
