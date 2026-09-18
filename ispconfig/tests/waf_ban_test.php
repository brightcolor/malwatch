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

// --- Why ----------------------------------------------------------------------

expect_same('the reason in one sentence',
	waf_ban_reason($picked[0], 10, 'Zugriff auf geschützte Datei (930130)'),
	'62 Punkte aus 14 Treffern in 10 Minuten auf beispiel.test, meist Zugriff auf geschützte Datei (930130).');
expect_same('a reason without a rule in words',
	waf_ban_reason(array('ip' => '192.0.2.10', 'domain' => 'beispiel.test', 'score' => 1200, 'hits' => 240,
		'rule' => '', 'limit' => 50), 10, ''),
	'1.200 Punkte aus 240 Treffern in 10 Minuten auf beispiel.test.');

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_ban: alle Prüfungen bestanden' . PHP_EOL;
