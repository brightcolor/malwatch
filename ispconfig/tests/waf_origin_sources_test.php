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
	array('dbip_country', 'dbip_asn', 'maxmind_country', 'maxmind_asn', 'tor', 'x4b_vpn', 'x4b_datacenter',
		'searchbots'));
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


// --- The ranges of the search engines -----------------------------------------

expect_same('search engines are a source of their own', isset(waf_origin_sources()['searchbots']), true);
expect_same('the search engines are chosen with their own setting',
	waf_origin_chosen(array('waf_ban_bots' => 'on', 'waf_ban_mode' => 'propose')), array('searchbots'));
expect_same('with the automatic blocking off nothing is downloaded for them',
	waf_origin_chosen(array('waf_ban_bots' => 'on', 'waf_ban_mode' => 'off')), array());
expect_same('two addresses for the search engines', count(waf_origin_urls('searchbots', '')), 2);
$bots = __DIR__ . '/fixtures/bots';
$bots_out = $dir . '/searchbots.bin';
$bot_counts = waf_origin_read_bots(array($bots . '/googlebot.json', $bots . '/bingbot.json'), $bots_out);
expect_same('every prefix became a range', array($bot_counts['ranges'], $bot_counts['bad']), array(5, 0));
$bot_reader = waf_origin_open($bots_out);
expect_same('an address of Google', waf_origin_find($bot_reader, '192.0.2.77'), 'y');
expect_same('an address of Bing', waf_origin_find($bot_reader, '203.0.113.5'), 'y');
expect_same('an address of Bing outside its range', waf_origin_find($bot_reader, '203.0.113.200'), '');
expect_same('an IPv6 address of a search engine', waf_origin_find($bot_reader, '2001:db8:1::9'), 'y');
expect_same('an address of nobody', waf_origin_find($bot_reader, '198.51.100.9'), '');
waf_origin_close($bot_reader);
expect_same('a file that is no JSON gives nothing',
	waf_origin_read_bots(array($bots . '/gibt-es-nicht.json'), $dir . '/leer.bin'), null);

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_origin_sources: alle Prüfungen bestanden\n";
