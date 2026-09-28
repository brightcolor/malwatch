<?php
/**
 * Checks how the server plans the scans of a website from its interval in
 * days (malwatch_site.scan_days, from 0.37.0): the next scan after one ran,
 * and the first scan of a website that gets its settings row from the
 * scheduler.
 *
 *   php ispconfig/tests/scan_days_test.php
 */
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';

date_default_timezone_set('UTC');

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$helper = new malwatch_helper();
$t = gmmktime(12, 0, 0, 9, 28, 2026);
$day = 86400;

// The next scan: the interval after the moment a scan ran or got queued, as a
// Unix time. The queries store it with FROM_UNIXTIME(), so MySQL writes it in
// the zone it compares NOW() in, whatever zone PHP runs in.
expect_same('2 days', $helper->next_run(2, $t), $t + 2 * $day);
expect_same('another interval: 1 day', $helper->next_run(1, $t), $t + $day);
expect_same('another interval: 30 days', $helper->next_run(30, $t), $t + 30 * $day);
expect_same('the number as text, as the database returns it', $helper->next_run('2', $t), $t + 2 * $day);
expect_same('0 days: no scan', $helper->next_run(0, $t), null);
expect_same('a negative number: no scan', $helper->next_run(-3, $t), null);
expect_same('without a time the clock of now', abs($helper->next_run(2) - time() - 2 * $day) <= 2, true);

// The first scan of a website that gets its row now: somewhere within its
// interval, so websites that arrive together do not all scan at once.
$seen = array();
for ($seed = 1; $seed <= 40; $seed++) {
	mt_srand($seed);
	$first = $helper->first_run(2, $t);
	if (!is_int($first) || $first < $t || $first >= $t + 2 * $day) {
		expect_same('the first scan lies within 2 days (seed ' . $seed . ')', $first, 'zwischen ' . $t . ' und '
			. ($t + 2 * $day - 1));
	}
	$seen[(int) floor(($first - $t) / (6 * 3600))] = true;
}
expect_same('forty websites spread over the two days', count($seen) >= 6, true);
mt_srand(7);
$first = $helper->first_run(5, $t);
expect_same('another interval: within 5 days', $first >= $t && $first < $t + 5 * $day, true);
expect_same('0 days: no first scan', $helper->first_run(0, $t), null);

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "scan days OK\n";
