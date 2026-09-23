<?php
/**
 * Checks who is blocked, for how long and with which reason.
 *
 *   php ispconfig/tests/waf_ban_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_ban.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . PHP_EOL);
	}
}

// Der Server läuft in einer Zone mit Sommerzeit, die Datenbank liefert ihre
// eigene Uhr: Zeiten müssen die Rechnung unverändert überstehen.
date_default_timezone_set('Europe/Berlin');

$settings = array('waf_ban_score' => 50, 'waf_ban_window_minutes' => 10, 'waf_ban_hours_first' => 1,
	'waf_ban_hours_second' => 24, 'waf_ban_hours_third' => 168, 'waf_ban_max' => 5000,
	'waf_ban_keep_days' => 30);
$sites = array(
	11 => array('parent_domain_id' => '11', 'domain' => 'beispiel.test', 'waf_ban_score' => '0', 'waf_ban_trigger' => 'y'),
	12 => array('parent_domain_id' => '12', 'domain' => 'zweite.test', 'waf_ban_score' => '20', 'waf_ban_trigger' => 'y'),
	13 => array('parent_domain_id' => '13', 'domain' => 'dritte.test', 'waf_ban_score' => '0', 'waf_ban_trigger' => 'n'),
);

// --- The threshold of a website -----------------------------------------------

expect_same('a website without a value of its own takes the server value',
	waf_ban_site_score($settings, $sites[11]), 50);
expect_same('a website with its own value', waf_ban_site_score($settings, $sites[12]), 20);
expect_same('a website that never triggers', waf_ban_site_score($settings, $sites[13]), 0);
expect_same('an unknown website takes the server value', waf_ban_site_score($settings, null), 50);

// --- Who crossed it -----------------------------------------------------------

$groups = array(
	array('client_ip' => '192.0.2.10', 'parent_domain_id' => '11', 'score' => '62', 'hits' => '14', 'rule' => '930130'),
	array('client_ip' => '192.0.2.10', 'parent_domain_id' => '12', 'score' => '25', 'hits' => '5', 'rule' => '941100'),
	array('client_ip' => '198.51.100.7', 'parent_domain_id' => '11', 'score' => '30', 'hits' => '6', 'rule' => '920440'),
	array('client_ip' => '198.51.100.9', 'parent_domain_id' => '12', 'score' => '30', 'hits' => '6', 'rule' => '920440'),
	array('client_ip' => '203.0.113.5', 'parent_domain_id' => '13', 'score' => '900', 'hits' => '90', 'rule' => '930130'),
);
$picked = waf_ban_decide($groups, $settings, $sites);
expect_same('two addresses crossed a threshold', array_column($picked, 'ip'),
	array('192.0.2.10', '198.51.100.9'));
expect_same('the website with the most points is named',
	array($picked[0]['domain'], $picked[0]['score'], $picked[0]['hits'], $picked[0]['limit']),
	array('beispiel.test', 62, 14, 50));
expect_same('a website with its own lower value counts too',
	array($picked[1]['domain'], $picked[1]['score'], $picked[1]['limit']), array('zweite.test', 30, 20));
expect_same('nothing crossed, nothing picked', waf_ban_decide(array(
	array('client_ip' => '198.51.100.7', 'parent_domain_id' => '11', 'score' => '5', 'hits' => '1', 'rule' => '')),
	$settings, $sites), array());

// --- Angemeldete Sitzungen ----------------------------------------------------

// Der Fall vom 23.09.2026: Der Seitenbaukasten einer Kundenwebsite löste beim
// Speichern Regeln des CRS aus, sämtliche Treffer kamen aus der angemeldeten
// Sitzung des Redakteurs. Abgewertet bleibt die Adresse unter der Schwelle.
$redaktion = array('client_ip' => '203.0.113.77', 'parent_domain_id' => '11', 'score' => '60',
	'score_angemeldet' => '60', 'hits' => '13', 'rule' => '941310');
expect_same('angemeldete Punkte zählen zu einem Zehntel',
	waf_ban_score_angemeldet($redaktion, $settings), 6);
expect_same('der Redakteur wird nicht gesperrt',
	waf_ban_decide(array($redaktion), $settings, $sites), array());

// Wer ein Anmelde-Cookie vortäuscht, kommt damit nicht durch: Seine Punkte
// stammen fast alle aus Anfragen ohne Anmeldung.
$angreifer = array('client_ip' => '203.0.113.9', 'parent_domain_id' => '11', 'score' => '1235',
	'score_angemeldet' => '20', 'hits' => '140', 'rule' => '930130');
$getroffen = waf_ban_decide(array($angreifer), $settings, $sites);
expect_same('der Angreifer bleibt gesperrt',
	array(count($getroffen), $getroffen[0]['score'], $getroffen[0]['score_roh']), array(1, 1217, 1235));
expect_same('der Grund nennt den rohen Stand',
	strpos(waf_ban_reason($getroffen[0], 10, 'Regel 930130'), 'angemeldete Zugriffe abgewertet (roh 1.235)') !== false,
	true);

expect_same('der Anteil kommt aus den Einstellungen',
	waf_ban_score_angemeldet($redaktion, array_merge($settings, array('waf_ban_logged_in_percent' => 50))), 30);
expect_same('mehr angemeldete Punkte als Punkte insgesamt gibt es nicht',
	waf_ban_score_angemeldet(array('score' => '40', 'score_angemeldet' => '999'), $settings), 4);
expect_same('ohne angemeldete Punkte bleibt die Rechnung unverändert',
	waf_ban_score_angemeldet(array('score' => '80'), $settings), 80);
expect_same('ein unsinniger Anteil wird auf 100 Prozent begrenzt',
	waf_ban_score_angemeldet($redaktion, array_merge($settings, array('waf_ban_logged_in_percent' => 500))), 60);

// --- How long -----------------------------------------------------------------

expect_same('the first block', waf_ban_level(0), 1);
expect_same('the second block', waf_ban_level(1), 2);
expect_same('the third and every later one', array(waf_ban_level(2), waf_ban_level(9)), array(3, 3));
expect_same('the hours of every level', array(waf_ban_hours(1, $settings), waf_ban_hours(2, $settings),
	waf_ban_hours(3, $settings)), array(1, 24, 168));
expect_same('the end of a first block', waf_ban_until(1, $settings, '2026-09-18 10:00:00'), '2026-09-18 11:00:00');
expect_same('the end of a third block', waf_ban_until(3, $settings, '2026-09-18 10:00:00'), '2026-09-25 10:00:00');
expect_same('the end keeps the clock of the database',
	waf_ban_until(1, $settings, '2026-09-18 23:30:00'), '2026-09-19 00:30:00');

// --- Why ----------------------------------------------------------------------

expect_same('the reason in one sentence',
	waf_ban_reason($picked[0], 10, 'Zugriff auf geschützte Datei (930130)'),
	'62 Punkte aus 14 Treffern in 10 Minuten auf beispiel.test, meist Zugriff auf geschützte Datei (930130).');
expect_same('a reason without a rule in words',
	waf_ban_reason(array('ip' => '192.0.2.10', 'domain' => 'beispiel.test', 'score' => 1200, 'hits' => 240,
		'rule' => '', 'limit' => 50), 10, ''),
	'1.200 Punkte aus 240 Treffern in 10 Minuten auf beispiel.test.');

// --- The rule that appeared most ----------------------------------------------

$hits = array(
	array('rules' => '["930130","949110"]'),
	array('rules' => '["930130","949110"]'),
	array('rules' => '["941100","949110"]'),
	array('rules' => 'kein json'),
);
expect_same('the rule that appeared most, without the scoring rules', waf_ban_top_rule($hits), '930130');
expect_same('only scoring rules means no rule',
	waf_ban_top_rule(array(array('rules' => '["949110","980130"]'))), '');
expect_same('no hits, no rule', waf_ban_top_rule(array()), '');

// So stehen die Regeln wirklich in malwatch_waf_hit: als Objekte mit id und msg.
$hits_real = array(
	array('rules' => '[{"id":"930130","msg":"Restricted File Access Attempt"},{"id":"949110","msg":"Score"}]'),
	array('rules' => '[{"id":"930130","msg":"Restricted File Access Attempt"}]'),
	array('rules' => '[{"id":"941100","msg":"XSS"},{"id":"949110","msg":"Score"}]'),
);
expect_same('the rules of a hit are objects', waf_ban_top_rule($hits_real), '930130');
expect_same('objects with only scoring rules give none',
	waf_ban_top_rule(array(array('rules' => '[{"id":"949110","msg":"Score"}]'))), '');

// --- What is never blocked ----------------------------------------------------

expect_same('the fixed networks', waf_ban_fixed_allow(), array('127.0.0.0/8', '::1/128', '10.50.0.0/24'));
expect_same('the proxy is protected', waf_ban_allow_match(waf_ban_fixed_allow(), '10.50.0.1'), true);
expect_same('localhost is protected', waf_ban_allow_match(waf_ban_fixed_allow(), '127.0.0.1'), true);
expect_same('a visitor is not', waf_ban_allow_match(waf_ban_fixed_allow(), '192.0.2.10'), false);
expect_same('an address of the list', waf_ban_allow_match(array('203.0.113.0/24', '198.51.100.7'), '203.0.113.99'), true);
expect_same('a single address of the list', waf_ban_allow_match(array('198.51.100.7'), '198.51.100.7'), true);
expect_same('the neighbour of a single address', waf_ban_allow_match(array('198.51.100.7'), '198.51.100.8'), false);
expect_same('IPv6 in a range', waf_ban_allow_match(array('2001:db8::/32'), '2001:db8:1::5'), true);
expect_same('IPv6 outside a range', waf_ban_allow_match(array('2001:db8::/32'), '2001:db9::5'), false);
expect_same('what is no address is never allowed', waf_ban_allow_match(array('0.0.0.0/0'), 'kein-ip'), false);
expect_same('an entry that is no range is skipped',
	waf_ban_allow_match(array('unsinn', '203.0.113.0/24'), '203.0.113.9'), true);
expect_same('the three layers together, without a reader',
	array(waf_ban_allowed('10.50.0.1', array(), null), waf_ban_allowed('203.0.113.9', array('203.0.113.0/24'), null),
		waf_ban_allowed('192.0.2.10', array('203.0.113.0/24'), null)), array(true, true, false));

// --- The file for nginx -------------------------------------------------------

$file = waf_ban_file(array('192.0.2.10', '2001:db8::5'), '2026-09-18 10:00:00', 5000);
expect_same('the file says where it comes from', substr($file, 0, 22), '# von malwatch erzeugt');
expect_same('one line per address', substr_count($file, 'deny '), 2);
expect_same('a line ends with a semicolon', strpos($file, 'deny 192.0.2.10;') !== false, true);
expect_same('IPv6 belongs in there too', strpos($file, 'deny 2001:db8::5;') !== false, true);
expect_same('the file ends with a newline', substr($file, -1), "\n");
expect_same('what is no address never reaches nginx',
	substr_count(waf_ban_file(array('kein-ip', '"; server {', '192.0.2.10'), '2026-09-18 10:00:00', 5000), 'deny '), 1);
expect_same('the limit holds',
	substr_count(waf_ban_file(array('192.0.2.10', '192.0.2.11', '192.0.2.12'), '2026-09-18 10:00:00', 2), 'deny '), 2);
expect_same('an empty list gives a file without a single deny',
	substr_count(waf_ban_file(array(), '2026-09-18 10:00:00', 5000), 'deny '), 0);

// --- The log of the turned away requests --------------------------------------

expect_same('a line of a turned away request',
	waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10 403 beispiel.test "GET /wp-login.php HTTP/1.1"'),
	array('ip' => '192.0.2.10', 'at' => '2026-09-18 10:00:01'));
expect_same('the time comes in the shape of the database',
	waf_ban_log_line('2026-09-18T23:59:59+02:00 192.0.2.10 403 x "GET / HTTP/1.1"')['at'], '2026-09-18 23:59:59');
expect_same('a line without a usable time does not count',
	waf_ban_log_line('kaputt 192.0.2.10 403 x "GET / HTTP/1.1"'), null);
expect_same('another answer does not count',
	waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10 200 beispiel.test "GET / HTTP/1.1"'), null);
expect_same('a line without an address',
	waf_ban_log_line('2026-09-18T10:00:01+02:00 kein-ip 403 x "GET / HTTP/1.1"'), null);
expect_same('an empty line', waf_ban_log_line(''), null);
expect_same('a fragment', waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10'), null);

// --- Wer schon einen Eintrag hat ------------------------------------------------

$since = '2026-09-21 12:00:00';
$fresh = array('state' => 'proposed', 'level' => 1, 'created_at' => '2026-09-21 12:05:00',
	'blocked_at' => null, 'lifted_at' => null);
$stale = array('state' => 'proposed', 'level' => 1, 'created_at' => '2026-09-18 22:03:02',
	'blocked_at' => null, 'lifted_at' => null);
expect_same('a proposal of this window stays quiet while the automatic only proposes',
	waf_ban_keeps_quiet($fresh, $since, 'proposed'), true);
expect_same('an older proposal is renewed with the numbers of the new wave',
	waf_ban_keeps_quiet($stale, $since, 'proposed'), false);
expect_same('a proposal never shields its address from a block',
	array(waf_ban_keeps_quiet($fresh, $since, 'active'), waf_ban_keeps_quiet($stale, $since, 'active')),
	array(false, false));
expect_same('a running block stays as it is',
	waf_ban_keeps_quiet(array('state' => 'active', 'level' => 1, 'created_at' => '2026-09-21 11:00:00',
		'blocked_at' => '2026-09-21 11:00:00', 'lifted_at' => null), $since, 'active'), true);
expect_same('a dismissed proposal stays quiet for the window, then counts again', array(
	waf_ban_keeps_quiet(array('state' => 'dismissed', 'level' => 1, 'created_at' => '2026-09-21 12:01:00',
		'blocked_at' => null, 'lifted_at' => null), $since, 'active'),
	waf_ban_keeps_quiet(array('state' => 'dismissed', 'level' => 1, 'created_at' => '2026-09-21 11:00:00',
		'blocked_at' => null, 'lifted_at' => null), $since, 'active'),
), array(true, false));
expect_same('a block lifted by hand inside the window stays quiet',
	waf_ban_keeps_quiet(array('state' => 'lifted', 'level' => 1, 'created_at' => '2026-09-21 11:00:00',
		'blocked_at' => '2026-09-21 11:00:00', 'lifted_at' => '2026-09-21 12:02:00'), $since, 'active'), true);
expect_same('an ended block does not', waf_ban_keeps_quiet(array('state' => 'expired', 'level' => 1,
	'created_at' => '2026-09-21 10:00:00', 'blocked_at' => '2026-09-21 10:00:00', 'lifted_at' => null),
	$since, 'active'), false);
expect_same('without an entry nothing keeps quiet', waf_ban_keeps_quiet(null, $since, 'active'), false);

// Die Stufe zählt Sperren, keine Vorschläge.
expect_same('the first time is level one', waf_ban_next_level(null), 1);
expect_same('a proposal that becomes a block keeps its level', array(
	waf_ban_next_level($stale),
	waf_ban_next_level(array('state' => 'proposed', 'level' => 2, 'blocked_at' => null)),
), array(1, 2));
expect_same('a dismissed proposal does not climb either',
	waf_ban_next_level(array('state' => 'dismissed', 'level' => 1, 'blocked_at' => null)), 1);
expect_same('an address that was blocked before climbs a level', array(
	waf_ban_next_level(array('state' => 'expired', 'level' => 1, 'blocked_at' => '2026-09-20 10:00:00')),
	waf_ban_next_level(array('state' => 'lifted', 'level' => 2, 'blocked_at' => '2026-09-20 10:00:00')),
	waf_ban_next_level(array('state' => 'expired', 'level' => 3, 'blocked_at' => '2026-09-20 10:00:00')),
), array(2, 3, 3));

// --- Das Ende in der Liste der Kommandozeile ----------------------------------

expect_same('a proposal has no end to show',
	waf_ban_cli_until(array('state' => 'proposed', 'until' => null)), '-');
expect_same('a block without end is permanent',
	waf_ban_cli_until(array('state' => 'active', 'until' => null)), 'dauerhaft');
expect_same('a block with an end shows it',
	waf_ban_cli_until(array('state' => 'active', 'until' => '2026-09-25 15:25:02')), '2026-09-25 15:25:02');

// --- Nur ein neuer Inhalt ist eine Änderung -------------------------------------

// Die erste Zeile trägt die Zeit. Sie allein darf nginx nicht neu laden lassen.
$old = waf_ban_file(array('192.0.2.10', '192.0.2.20'), '2026-09-21 16:14:02', 100);
$new = waf_ban_file(array('192.0.2.10', '192.0.2.20'), '2026-09-21 16:15:02', 100);
expect_same('the files differ in their first line', $old === $new, false);
expect_same('only the time differs: the same file', waf_ban_file_same($old, $new), true);
expect_same('another address: another file',
	waf_ban_file_same($old, waf_ban_file(array('192.0.2.10'), '2026-09-21 16:15:02', 100)), false);
expect_same('two empty lists at different times are the same',
	waf_ban_file_same(waf_ban_file(array(), '2026-09-21 16:14:02', 100),
		waf_ban_file(array(), '2026-09-21 16:15:02', 100)), true);
expect_same('the fallback text of an empty file counts as empty',
	waf_ban_file_same("# von malwatch erzeugt, leer\n", waf_ban_file(array(), '2026-09-21 16:15:02', 100)), true);
expect_same('a missing file is never the same', waf_ban_file_same('', waf_ban_file(array(), 'x', 100)), false);

// --- Herkunft senkt die Schwelle ----------------------------------------------

expect_same('a stored list of countries is read in upper case',
	waf_ban_origin_countries(' fr , be,de '), array('FR', 'BE', 'DE'));
expect_same('what is no country stays out',
	waf_ban_origin_countries('FR, Deutschland, , X, 42'), array('FR'));
expect_same('doubles go', waf_ban_origin_countries('FR,fr,FR'), array('FR'));
expect_same('a stored list of providers holds numbers',
	waf_ban_origin_asns(' AS15169 , 8075,as0 '), array(15169, 8075));
expect_same('a list is stored as one text', waf_ban_origin_store(array('FR', 'BE')), 'FR,BE');
expect_same('an empty list is an empty text', waf_ban_origin_store(array()), '');

$on = array('waf_ban_origin' => 'on', 'waf_ban_origin_countries' => 'FR,CN', 'waf_ban_origin_asn' => '15169',
	'waf_ban_origin_hosting' => 'on', 'waf_ban_origin_vpn' => 'on', 'waf_ban_origin_tor' => 'on');
$fr = array('country' => 'FR', 'asn' => 202425, 'as_org' => 'Bucklog SARL', 'is_tor' => 'n', 'is_vpn' => 'n',
	'is_hosting' => 'n');
$google = array('country' => 'BE', 'asn' => 15169, 'as_org' => 'Google LLC', 'is_tor' => 'n', 'is_vpn' => 'n',
	'is_hosting' => 'y');
$plain = array('country' => 'DE', 'asn' => 3320, 'as_org' => 'Telekom', 'is_tor' => 'n', 'is_vpn' => 'n',
	'is_hosting' => 'n');

expect_same('a country on the list is named', waf_ban_origin_match($fr, $on), 'Land ' . waf_origin_country_word('FR'));
expect_same('the provider comes before the country',
	waf_ban_origin_match($google, $on), 'Anbieter Google LLC');
expect_same('a provider without a name is named by its number',
	waf_ban_origin_match(array('country' => 'BE', 'asn' => 15169, 'as_org' => '', 'is_tor' => 'n',
		'is_vpn' => 'n', 'is_hosting' => 'n'), $on), 'Anbieter AS15169');
expect_same('a data centre alone is enough',
	waf_ban_origin_match(array('country' => 'US', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n',
		'is_hosting' => 'y'), $on), 'Rechenzentrum');
expect_same('so is Tor', waf_ban_origin_match(array('country' => 'US', 'asn' => 0, 'as_org' => '',
	'is_tor' => 'y', 'is_vpn' => 'n', 'is_hosting' => 'n'), $on), 'Tor');
expect_same('so is a VPN', waf_ban_origin_match(array('country' => 'US', 'asn' => 0, 'as_org' => '',
	'is_tor' => 'n', 'is_vpn' => 'y', 'is_hosting' => 'n'), $on), 'VPN');
expect_same('an ordinary visitor stays free', waf_ban_origin_match($plain, $on), '');
expect_same('without an entry in the origin table nothing is known',
	waf_ban_origin_match(null, $on), '');
expect_same('the master switch turns everything off',
	waf_ban_origin_match($google, array_merge($on, array('waf_ban_origin' => 'off'))), '');
expect_same('a criterion that is off does not trigger',
	waf_ban_origin_match(array('country' => 'US', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n',
		'is_hosting' => 'y'), array_merge($on, array('waf_ban_origin_hosting' => 'off'))), '');

// Die Wirkung: eigene Schwelle und Faktor auf die Punkte.
$settings = array('waf_ban_score' => 50, 'waf_ban_origin' => 'on', 'waf_ban_origin_score' => 20,
	'waf_ban_origin_factor' => 200, 'waf_ban_origin_countries' => 'FR', 'waf_ban_origin_asn' => '',
	'waf_ban_origin_hosting' => 'off', 'waf_ban_origin_vpn' => 'off', 'waf_ban_origin_tor' => 'off');
$sites = array(11 => array('domain' => 'beispiel.test', 'waf_ban_score' => 0, 'waf_ban_trigger' => 'y'));
$groups = array(
	array('client_ip' => '192.0.2.10', 'parent_domain_id' => 11, 'score' => 15, 'hits' => 3),
	array('client_ip' => '192.0.2.20', 'parent_domain_id' => 11, 'score' => 15, 'hits' => 3),
);
$origins = array('192.0.2.10' => $fr);
$picked = waf_ban_decide($groups, $settings, $sites, $origins);
expect_same('only the address with the suspicious origin is picked',
	array_map(function ($one) { return $one['ip']; }, $picked), array('192.0.2.10'));
expect_same('the real points stay, the weighted ones decide, the threshold is lowered',
	array($picked[0]['score'], $picked[0]['weighted'], $picked[0]['limit'], $picked[0]['origin']),
	array(15, 30, 20, 'Land ' . waf_origin_country_word('FR')));
$reason = waf_ban_reason($picked[0], 10, 'Regel 930130');
expect_same('the reason tells the real points and how they were weighed', array(
	strpos($reason, '15 Punkte aus 3 Treffern') === 0,
	strpos($reason, 'Herkunft: Land ' . waf_origin_country_word('FR') . ', Punkte mit 200 % gewertet') !== false,
), array(true, true));
$plain = array('ip' => '192.0.2.30', 'domain' => 'beispiel.test', 'score' => 60, 'weighted' => 60, 'hits' => 12,
	'rule' => '', 'limit' => 50, 'origin' => '');
expect_same('without an origin the reason says nothing about weighing',
	strpos(waf_ban_reason($plain, 10, ''), 'gewertet'), false);

$off = array_merge($settings, array('waf_ban_origin' => 'off'));
expect_same('with the mechanism off nothing changes', waf_ban_decide($groups, $off, $sites, $origins), array());
$never = array(11 => array('domain' => 'beispiel.test', 'waf_ban_score' => 0, 'waf_ban_trigger' => 'n'));
expect_same('a website that never triggers stays free, whatever the origin says',
	waf_ban_decide($groups, $settings, $never, $origins), array());
$high = array_merge($settings, array('waf_ban_origin_score' => 0));
expect_same('without an own threshold the normal one counts, the factor stays',
	waf_ban_decide($groups, $high, $sites, $origins), array());

expect_same('the automatic blocks at once only when that is switched on', array(
	waf_ban_origin_at_once('Land FR', array('waf_ban_origin_now' => 'on')),
	waf_ban_origin_at_once('Land FR', array('waf_ban_origin_now' => 'off')),
	waf_ban_origin_at_once('', array('waf_ban_origin_now' => 'on')),
), array(true, false, false));

// --- Die veröffentlichte Liste ------------------------------------------------

$token = waf_ban_token_new();
expect_same('a key has 32 characters from a to f and 0 to 9',
	(bool) preg_match('/^[a-f0-9]{32}$/', $token), true);
expect_same('two keys differ', $token === waf_ban_token_new(), false);
expect_same('the shape of a key is checked', array(
	waf_ban_token_ok($token),
	waf_ban_token_ok(''),
	waf_ban_token_ok(strtoupper($token)),
	waf_ban_token_ok(substr($token, 0, 31)),
	waf_ban_token_ok($token . 'a'),
	waf_ban_token_ok('../../etc/passwd'),
), array(true, false, false, false, false, false));

expect_same('the list holds one address per line and ends with a line break',
	waf_ban_list_text(array('192.0.2.10', '2001:db8::1')), "192.0.2.10\n2001:db8::1\n");
expect_same('doubles go, the rest is sorted',
	waf_ban_list_text(array('192.0.2.20', '192.0.2.10', '192.0.2.20')), "192.0.2.10\n192.0.2.20\n");
expect_same('what is no address stays out',
	waf_ban_list_text(array('192.0.2.10', 'kein-ip', '', '192.0.2.300')), "192.0.2.10\n");
expect_same('an empty list is an empty text', waf_ban_list_text(array()), '');

expect_same('the address names host and key',
	waf_ban_list_url('cp.beispiel.test', $token),
	'https://cp.beispiel.test/security/malwatch_waf_ban_url.php?list=' . $token);
expect_same('a panel on its own port keeps the port',
	waf_ban_list_url('cp.beispiel.test:8080', $token),
	'https://cp.beispiel.test:8080/security/malwatch_waf_ban_url.php?list=' . $token);
expect_same('an IPv6 literal with a port works too',
	waf_ban_list_url('[2001:db8::1]:8080', $token),
	'https://[2001:db8::1]:8080/security/malwatch_waf_ban_url.php?list=' . $token);
expect_same('a name with a path or a port out of range is refused', array(
	waf_ban_list_url('cp.beispiel.test/x', $token),
	waf_ban_list_url('cp.beispiel.test:0', $token),
	waf_ban_list_url('cp.beispiel.test:70000', $token),
	waf_ban_list_url('cp.beispiel.test:', $token),
), array('', '', '', ''));
expect_same('without a key there is no address', waf_ban_list_url('cp.beispiel.test', ''), '');
expect_same('without a host there is no address', waf_ban_list_url('', $token), '');

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_ban: alle Prüfungen bestanden' . PHP_EOL;
