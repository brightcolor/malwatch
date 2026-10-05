<?php
/**
 * Checks the setting "Reserve der Quarantäne" (quarantine_reserve): the same
 * default and bounds in the scanner, the panel and the server side, the
 * column, field, texts and the switch every job that writes into the
 * quarantine hands to the scanner - quarantine (the automatic measure
 * included), repair and upgrade.
 *
 *   php ispconfig/tests/quarantine_space_test.php
 */
if (!defined('LOGLEVEL_DEBUG')) {
	define('LOGLEVEL_DEBUG', 0);
}
if (!defined('LOGLEVEL_WARN')) {
	define('LOGLEVEL_WARN', 1);
}
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_runner.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$root = dirname(__DIR__);
$repo = dirname($root);

// --- One default, one range: scanner, panel, server ---------------------------
$go = (string) file_get_contents($repo . '/internal/quarantine/space.go');
$go_values = array();
foreach (array('DefaultReserveMiB', 'MinReserveMiB', 'MaxReserveMiB') as $name) {
	$go_values[$name] = preg_match('/^\s*' . $name . '\s*=\s*(\d+)\s*$/m', $go, $m) ? (int) $m[1] : null;
}
expect_same('the scanner names all three values', in_array(null, $go_values, true), false);
$range = array($go_values['MinReserveMiB'], $go_values['MaxReserveMiB'], $go_values['DefaultReserveMiB']);

$panel = malwatch_quarantine_settings();
expect_same('panel: bounds and default as in the scanner', $panel['quarantine_reserve'], $range);
expect_same('panel: default of the row', malwatch_config_defaults()['quarantine_reserve'], $range[2]);
expect_same('panel: range for the form', malwatch_quarantine_range('quarantine_reserve'), $range[0] . ':' . $range[1]);

$helper = new malwatch_helper();
expect_same('server: bounds and default as in the scanner', array_slice(malwatch_helper::QUARANTINE_RESERVE, 0, 3), $range);
expect_same('server: default of the row', $helper->config_defaults()['quarantine_reserve'], $range[2]);

$reserve_go = (string) file_get_contents($repo . '/cmd/malwatch/reserve.go');
$flag = preg_match('/fs\.Int64\("([a-z-]+)", quarantine\.DefaultReserveMiB/', $reserve_go, $m) ? '--' . $m[1] : '';
expect_same('server: the switch is the one the scanner reads', malwatch_helper::QUARANTINE_RESERVE[3], $flag);
expect_same('the help of the scanner names the switch',
	strpos((string) file_get_contents($repo . '/cmd/malwatch/usage.go'), $flag . '=MIB') !== false, true);

// --- What the server hands the scanner ----------------------------------------
expect_same('default without a value', $helper->quarantine_arguments(array()), array('--quarantine-reserve=256'));
expect_same('another value', $helper->quarantine_arguments(array('quarantine_reserve' => '512')), array('--quarantine-reserve=512'));
expect_same('no reserve', $helper->quarantine_arguments(array('quarantine_reserve' => 0)), array('--quarantine-reserve=0'));
expect_same('the upper bound', $helper->quarantine_arguments(array('quarantine_reserve' => '1048576')),
	array('--quarantine-reserve=1048576'));
foreach (array('-1', '1048577', 'viel', '') as $bad) {
	expect_same('out of range "' . $bad . '" gets the default',
		$helper->quarantine_arguments(array('quarantine_reserve' => $bad)), array('--quarantine-reserve=256'));
}

// --- Column, field, page, texts -----------------------------------------------
$schema = (string) file_get_contents($root . '/install/schema.sql');
expect_same('schema.sql adds the column with the default',
	strpos($schema, "ADD COLUMN `quarantine_reserve` int(11) unsigned NOT NULL DEFAULT ''" . $range[2] . "''") !== false, true);

$tform = (string) file_get_contents($root . '/interface/form/malwatch_config.tform.php');
$field = preg_match("/'quarantine_reserve' => array\((.*?)'maxlength'/s", $tform, $m) ? $m[1] : '';
expect_same('the form checks the range',
	strpos($field, "'range' => malwatch_quarantine_range('quarantine_reserve')") !== false
	&& strpos($field, "'errmsg' => 'quarantine_reserve_error_range'") !== false, true);

$page = (string) file_get_contents($root . '/interface/templates/malwatch_config_edit.htm');
foreach (array('name="quarantine_reserve"', "name='quarantine_reserve_hint_txt'", "name='quarantine_head_txt'") as $want) {
	expect_same('the page shows ' . $want, strpos($page, $want) !== false, true);
}

foreach (array('de' => 'von 0 bis 1048576 MiB', 'en' => 'from 0 to 1048576 MiB') as $lang => $bounds) {
	$wb = array();
	include $root . '/interface/lang/' . $lang . '_malwatch_config.lng';
	foreach (array('quarantine_head_txt', 'quarantine_intro_txt', 'quarantine_reserve_txt', 'quarantine_reserve_hint_txt',
		'quarantine_reserve_error_range') as $key) {
		expect_same($lang . ': ' . $key, isset($wb[$key]) && $wb[$key] !== '', true);
	}
	expect_same($lang . ': the error names the bounds of the scanner',
		isset($wb['quarantine_reserve_error_range']) && strpos($wb['quarantine_reserve_error_range'], $bounds) !== false, true);
	expect_same($lang . ': the hint names the switch',
		isset($wb['quarantine_reserve_hint_txt']) && strpos($wb['quarantine_reserve_hint_txt'], $flag) !== false, true);
}

// --- Every job that writes into the quarantine hands the reserve on -----------

/** The server helper with what an upgrade asks of the system answered in place. */
class mw_space_helper extends malwatch_helper
{
	public function get_web($parent_domain_id)
	{
		return array('php' => 'php-fpm', 'system_user' => 'web1', 'system_group' => 'client1', 'ip_address' => '*');
	}

	public function php_cli_binary($web)
	{
		return '/usr/bin/php8.2';
	}

	public function fpm_settle($web)
	{
		return array('seconds' => 3);
	}

	public function upgrade_installs($job, $web, $scan_path, $options)
	{
		return array(array('path' => $scan_path, 'url' => 'https://beispiel.test/', 'elements' => array()));
	}

	public function fail_job($job_id, $message)
	{
		throw new RuntimeException($message);
	}
}

class mw_space_app
{
	public $malwatch_helper;
	public $db;
	public $dbmaster;

	public function uses($classes)
	{
	}
}

/** Answers the runner's question for the last scan of a website: none. */
class mw_space_db
{
	public function queryOneRecord($sql)
	{
		return null;
	}
}

$app = new mw_space_app();
$app->malwatch_helper = new mw_space_helper();
$app->db = new mw_space_db();
$app->dbmaster = $app->db;

$state = sys_get_temp_dir() . '/mw-quarantine-space-' . getmypid();
@mkdir($state . '/runs', 0700, true);
$build = new ReflectionMethod('malwatch_runner', 'build_arguments');
$build->setAccessible(true);
$runner = new malwatch_runner();

$jobs = array(
	'quarantine add (the automatic measure)' => array('quarantine', array('action' => 'add', 'origin' => 'auto', 'files' => array('a.php'))),
	'quarantine restore' => array('quarantine', array('action' => 'restore', 'ids' => array('20261005T101500Z-ab12cd34'))),
	'quarantine export' => array('quarantine', array('action' => 'export', 'ids' => array('20261005T101500Z-ab12cd34'), 'token' => 'abc')),
	'repair' => array('repair', array()),
	'upgrade' => array('upgrade', array()),
);
foreach (array('512' => '--quarantine-reserve=512', '9999999' => '--quarantine-reserve=256') as $stored => $want) {
	$config = array('state_dir' => $state, 'quarantine_reserve' => $stored, 'wp_cli_path' => '');
	foreach ($jobs as $name => $job) {
		list($kind, $options) = $job;
		$args = $build->invoke($runner, array(
			'job_id' => 5, 'job_kind' => $kind, 'parent_domain_id' => 11, 'domain' => 'beispiel.test',
			'scan_path' => $state . '/web', 'options' => json_encode($options),
		), $config, $state . '/web', $state . '/runs/job-5.json');
		expect_same($name . ' with ' . $stored . ' stored hands on ' . $want,
			is_array($args) && in_array($want, $args, true), true);
	}
}
$scan = $build->invoke($runner, array(
	'job_id' => 6, 'job_kind' => 'scan', 'parent_domain_id' => 11, 'domain' => 'beispiel.test',
	'scan_path' => $state . '/web', 'options' => '',
), array('state_dir' => $state, 'quarantine_reserve' => 512, 'default_excludes' => '', 'upload_dirs' => '',
	'scan_max_age' => 0, 'use_clamav' => 'n', 'vuln_scan' => 'n'), $state . '/web', $state . '/runs/job-6.json');
expect_same('a scan writes nothing into the quarantine and gets no reserve',
	count(preg_grep('/^--quarantine-reserve=/', $scan)), 0);

foreach (array_merge(glob($state . '/*/*') ?: array(), glob($state . '/*') ?: array()) as $left) {
	is_dir($left) ? @rmdir($left) : @unlink($left);
}
@rmdir($state);

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "quarantine space OK\n";
