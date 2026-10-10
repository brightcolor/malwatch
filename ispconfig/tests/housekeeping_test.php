<?php
/**
 * Checks the hourly part of the cron job (0.41.0): which open findings it
 * closes because their file is gone, and the settings it runs by - the
 * minute, how long finished jobs and fixed findings stay, and how many open
 * findings one run checks.
 *
 *   php ispconfig/tests/housekeeping_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';

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
$defaults = $helper->config_defaults();

// --- Which findings close ------------------------------------------------------
// Paths as on the server, starting with a slash; on a Windows machine without
// the drive letter, which PHP there reads as the current drive.
$tmp = preg_replace('~^[A-Za-z]:~', '', str_replace('\\', '/', sys_get_temp_dir())) . '/mw_housekeeping_' . getmypid();
mkdir($tmp . '/site/web/wp-content', 0700, true);
file_put_contents($tmp . '/site/web/still.php', 'x');
mkdir($tmp . '/site/web/folder', 0700);

$rows = array(
	array('finding_id' => '1', 'file_path' => $tmp . '/site/web/still.php', 'document_root' => $tmp . '/site'),
	array('finding_id' => '2', 'file_path' => $tmp . '/site/web/wp-content/gone.php', 'document_root' => $tmp . '/site'),
	// The web root of a website that still exists is missing: an unmounted
	// disk or a move in progress, no deleted file.
	array('finding_id' => '3', 'file_path' => $tmp . '/unmounted/web/x.php', 'document_root' => $tmp . '/unmounted'),
	// The website is gone from ISPConfig, and its files with it.
	array('finding_id' => '4', 'file_path' => $tmp . '/deleted/web/x.php', 'document_root' => null),
	// A path the cron cannot judge.
	array('finding_id' => '5', 'file_path' => '', 'document_root' => $tmp . '/site'),
	array('finding_id' => '6', 'file_path' => 'web/relative.php', 'document_root' => $tmp . '/site'),
	// A directory is something that is there.
	array('finding_id' => '7', 'file_path' => $tmp . '/site/web/folder', 'document_root' => $tmp . '/site'),
);
expect_same('closes the findings whose file is gone', $helper->vanished_ids($rows), array(2, 4));
expect_same('no rows, nothing to close', $helper->vanished_ids(array()), array());

// A link that points nowhere is still a file in the web root.
if (@symlink($tmp . '/nowhere.php', $tmp . '/site/web/dangling.php')) {
	expect_same('a dangling link stays open', $helper->vanished_ids(array(
		array('finding_id' => '8', 'file_path' => $tmp . '/site/web/dangling.php', 'document_root' => $tmp . '/site'),
	)), array());
	unlink($tmp . '/site/web/dangling.php');
}

unlink($tmp . '/site/web/still.php');
rmdir($tmp . '/site/web/folder');
rmdir($tmp . '/site/web/wp-content');
rmdir($tmp . '/site/web');
rmdir($tmp . '/site');
rmdir($tmp);

// --- The settings of the hourly part -------------------------------------------
expect_same('minute by default', $helper->housekeeping_value($defaults, 'housekeeping_minute'), 7);
expect_same('jobs kept by default', $helper->housekeeping_value($defaults, 'keep_job_days'), 30);
expect_same('fixed findings kept by default', $helper->housekeeping_value($defaults, 'keep_fixed_days'), 90);
expect_same('rows by default', $helper->housekeeping_value($defaults, 'vanished_check_rows'), 500);
$custom = array_merge($defaults, array(
	'housekeeping_minute' => '0',
	'keep_job_days' => '3',
	'keep_fixed_days' => '365',
	'vanished_check_rows' => '0',
));
expect_same('another minute', $helper->housekeeping_value($custom, 'housekeeping_minute'), 0);
expect_same('jobs kept 3 days', $helper->housekeeping_value($custom, 'keep_job_days'), 3);
expect_same('fixed findings kept a year', $helper->housekeeping_value($custom, 'keep_fixed_days'), 365);
expect_same('0 rows switch the check off', $helper->housekeeping_value($custom, 'vanished_check_rows'), 0);
$broken = array_merge($defaults, array(
	'housekeeping_minute' => '60',
	'keep_job_days' => '0',
	'keep_fixed_days' => 'x',
	'vanished_check_rows' => '20000',
));
expect_same('minute out of bounds gets the default', $helper->housekeeping_value($broken, 'housekeeping_minute'), 7);
expect_same('0 days of jobs gets the default', $helper->housekeeping_value($broken, 'keep_job_days'), 30);
expect_same('no number gets the default', $helper->housekeeping_value($broken, 'keep_fixed_days'), 90);
expect_same('too many rows get the default', $helper->housekeeping_value($broken, 'vanished_check_rows'), 500);
expect_same('a missing value gets the default', $helper->housekeeping_value(array(), 'keep_job_days'), 30);

// --- The panel knows the same defaults and bounds --------------------------------
$panel = malwatch_config_defaults();
foreach (malwatch_housekeeping_settings() as $key => $setting) {
	expect_same('bounds and default of ' . $key, $setting, malwatch_helper::HOUSEKEEPING_SETTINGS[$key]);
	expect_same('panel default of ' . $key, $panel[$key], $setting[2]);
	expect_same('server default of ' . $key, $defaults[$key], $setting[2]);
}
expect_same('the same keys on both sides', array_keys(malwatch_housekeeping_settings()),
	array_keys(malwatch_helper::HOUSEKEEPING_SETTINGS));
expect_same('range', malwatch_housekeeping_range('housekeeping_minute'), '0:59');

// How long a dump stays (0.43.0): it was seven days, fixed in the ingest.
expect_same('dumps kept 7 days by default', $helper->housekeeping_value($defaults, 'keep_dump_days'), 7);
expect_same('dumps kept 2 days', $helper->housekeeping_value(array('keep_dump_days' => '2'), 'keep_dump_days'), 2);
expect_same('dumps kept 30 days', $helper->housekeeping_value(array('keep_dump_days' => '30'), 'keep_dump_days'), 30);
expect_same('0 days of dumps gets the default', $helper->housekeeping_value(array('keep_dump_days' => '0'), 'keep_dump_days'), 7);
expect_same('a dump range of 1 to 90 days', malwatch_housekeeping_range('keep_dump_days'), '1:90');
foreach (array('2', '0', 'x', '91', '') as $raw) {
	expect_same('panel reads keep_dump_days ' . var_export($raw, true) . ' like the server',
		malwatch_housekeeping_value(array('keep_dump_days' => $raw), 'keep_dump_days'),
		$helper->housekeeping_value(array('keep_dump_days' => $raw), 'keep_dump_days'));
}
expect_same('the ingest reads the setting',
	strpos(file_get_contents(__DIR__ . '/../server/lib/classes/malwatch_ingest.inc.php'),
		"housekeeping_value(\$config, 'keep_dump_days')") !== false, true);

if ($failures > 0) {
	exit(1);
}
echo "housekeeping OK\n";
