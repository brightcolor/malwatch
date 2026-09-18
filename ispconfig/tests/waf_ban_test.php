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
expect_same('the file ends with a newline', substr($file, -1), "
");
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
	waf_ban_list_text(array('192.0.2.10', '2001:db8::1')), "192.0.2.10
2001:db8::1
");
expect_same('doubles go, the rest is sorted',
	waf_ban_list_text(array('192.0.2.20', '192.0.2.10', '192.0.2.20')), "192.0.2.10
192.0.2.20
");
expect_same('what is no address stays out',
	waf_ban_list_text(array('192.0.2.10', 'kein-ip', '', '192.0.2.300')), "192.0.2.10
");
expect_same('an empty list is an empty text', waf_ban_list_text(array()), '');

expect_same('the address names host and key',
	waf_ban_list_url('cp.beispiel.test', $token),
	'https://cp.beispiel.test/security/malwatch_waf_ban_url.php?list=' . $token);
expect_same('without a key there is no address', waf_ban_list_url('cp.beispiel.test', ''), '');
expect_same('without a host there is no address', waf_ban_list_url('', $token), '');

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_ban: alle Prüfungen bestanden' . PHP_EOL;
