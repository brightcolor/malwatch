<?php
/**
 * Runs the schedule in days (0.37.0) against a scratch database on the server,
 * as root:
 *
 *   php schedule_probe.php <stage>/ispconfig <database>
 *
 * The database holds the tables of a release before 0.37.0, without the column
 * scan_days: an empty copy of the malwatch tables, web_domain and sys_cron of
 * the ISPConfig database, as for waf_class_probe.php, plus the settings row.
 * The probe loads schema.sql of the stage into it twice, the way every update
 * does, and refuses the ISPConfig database. It checks that
 *
 *   - the fixed steps of before become days once, and a later update leaves
 *     days set since then alone,
 *   - the scheduler gives active websites without a row one, with the
 *     interval for new websites and a first scan within it, and none at 0,
 *   - the scheduler queues due websites by scan_days and plans the next scan
 *     that many days ahead.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php schedule_probe.php <stage>/ispconfig <database>\n");
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

$column = $db->queryOneRecord("SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? "
	. "AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'scan_days'", $probe_db);
if (!is_array($column) || (int) $column['n'] !== 0) {
	fwrite(STDERR, "refused: $probe_db already has scan_days; the probe needs the tables from before 0.37.0\n");
	exit(2);
}

$tmp = sys_get_temp_dir() . '/mw_schedule_probe_' . getmypid();
mkdir($tmp, 0700);
$conf['log_file'] = $tmp . '/ispconfig.log';
$conf['log_priority'] = LOGLEVEL_WARN;

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

/** Loads schema.sql of the stage into the scratch database, as an update does. */
function load_schema()
{
	global $stage, $probe_db;
	exec('mysql ' . escapeshellarg($probe_db) . ' < ' . escapeshellarg($stage . '/install/schema.sql') . ' 2>&1', $out, $code);
	expect_same('schema.sql loads', array($code, implode("\n", $out)), array(0, ''));
}

/** scan_days of the probe's rows, by website. */
function days_by_site($db)
{
	$days = array();
	foreach ((array) $db->queryAllRecords('SELECT parent_domain_id, scan_days FROM malwatch_site ORDER BY parent_domain_id') as $row) {
		$days[(int) $row['parent_domain_id']] = (int) $row['scan_days'];
	}
	return $days;
}

$server = (int) $conf['server_id'];
$db->query('INSERT IGNORE INTO malwatch_config (config_id) VALUES (1)');
$db->query('DELETE FROM malwatch_site');
$db->query('DELETE FROM malwatch_job');
$db->query('DELETE FROM web_domain');

// --- The steps of before become days, once ------------------------------------
$db->query("INSERT INTO malwatch_site (server_id, parent_domain_id, domain, schedule) VALUES (?, 21, 's21.test', 'off'), "
	. "(?, 22, 's22.test', 'daily'), (?, 23, 's23.test', 'weekly'), (?, 24, 's24.test', 'monthly')",
	$server, $server, $server, $server);
$db->query("UPDATE malwatch_config SET default_schedule = 'monthly' WHERE config_id = 1");
load_schema();
expect_same('the steps become days', days_by_site($db), array(21 => 0, 22 => 1, 23 => 7, 24 => 30));
$config = $db->queryOneRecord('SELECT default_scan_days, default_schedule FROM malwatch_config WHERE config_id = 1');
expect_same('the step for new websites becomes days', (int) $config['default_scan_days'], 30);
$old = $db->queryOneRecord('SELECT schedule FROM malwatch_site WHERE parent_domain_id = 22');
expect_same('the old columns stay for the way back', array($old['schedule'], $config['default_schedule']),
	array('daily', 'monthly'));

$db->query('UPDATE malwatch_site SET scan_days = 0 WHERE parent_domain_id = 22');
$db->query('UPDATE malwatch_site SET scan_days = 2 WHERE parent_domain_id = 23');
$db->query('UPDATE malwatch_config SET default_scan_days = 5 WHERE config_id = 1');
load_schema();
expect_same('a later update leaves the days alone', days_by_site($db), array(21 => 0, 22 => 0, 23 => 2, 24 => 30));
$config = $db->queryOneRecord('SELECT default_scan_days FROM malwatch_config WHERE config_id = 1');
expect_same('a later update leaves the days for new websites alone', (int) $config['default_scan_days'], 5);
$db->query('DELETE FROM malwatch_site');

// --- The scheduler ---------------------------------------------------------------
require_once SCRIPT_PATH . '/lib/classes/cronjob.inc.php';
require_once $stage . '/server/lib/classes/malwatch_helper.inc.php';
require_once $stage . '/server/lib/classes/cron.d/560-malwatch.inc.php';

/** One pass of the scheduler with the settings as they are now. */
function queue_due_scans()
{
	global $app;
	// get_config() keeps the row for the life of the helper, a cron run long.
	$app->malwatch_helper = new malwatch_helper();
	$method = new ReflectionMethod('cronjob_malwatch', 'queue_due_scans');
	$method->setAccessible(true);
	$method->invoke(new cronjob_malwatch(), $app->malwatch_helper->get_config());
}

/** A website with its web directory below the probe's directory. */
function add_web($db, $id, $type, $active, $server_id)
{
	global $tmp;
	$root = $tmp . '/web' . $id;
	@mkdir($root . '/web', 0700, true);
	$db->query("INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, sys_groupid, "
		. "nginx_directives, document_root) VALUES (?, ?, 0, ?, ?, 'none', ?, 7, '', ?)",
		$id, $server_id, $type, 'w' . $id . '.test', $active, $root);
}

/** Seconds from now to next_run of a website, or null. */
function next_in($db, $id)
{
	$row = $db->queryOneRecord('SELECT TIMESTAMPDIFF(SECOND, NOW(), next_run) AS s FROM malwatch_site WHERE parent_domain_id = ?',
		$id);
	return is_array($row) && $row['s'] !== null ? (int) $row['s'] : null;
}

// Websites without a row get one with the interval for new websites: active
// ones of the types the scanner checks, on this server.
add_web($db, 31, 'vhost', 'y', $server);
add_web($db, 32, 'vhost', 'n', $server);
add_web($db, 33, 'alias', 'y', $server);
add_web($db, 34, 'vhostsubdomain', 'y', $server);
add_web($db, 35, 'vhost', 'y', $server + 1);
$db->query('UPDATE malwatch_config SET default_scan_days = 2 WHERE config_id = 1');
queue_due_scans();
expect_same('rows for the active websites of this server', days_by_site($db), array(31 => 2, 34 => 2));
$first = array(next_in($db, 31), next_in($db, 34));
expect_same('their first scans lie within the two days', array($first[0] >= -5 && $first[0] < 2 * 86400,
	$first[1] >= -5 && $first[1] < 2 * 86400), array(true, true));
$row = $db->queryOneRecord('SELECT sys_groupid, domain, server_id FROM malwatch_site WHERE parent_domain_id = 31');
expect_same('the row belongs to the website', array((int) $row['sys_groupid'], $row['domain'], (int) $row['server_id']),
	array(7, 'w31.test', $server));
$db->query('UPDATE malwatch_site SET scan_days = 5 WHERE parent_domain_id = 31');
queue_due_scans();
expect_same('a row that exists keeps its interval', days_by_site($db), array(31 => 5, 34 => 2));

$db->query('DELETE FROM malwatch_site');
$db->query('UPDATE malwatch_config SET default_scan_days = 0 WHERE config_id = 1');
queue_due_scans();
expect_same('at 0 no website gets a row', days_by_site($db), array());

// Due websites by scan_days: a job and the next scan that many days ahead.
$db->query('DELETE FROM malwatch_job');
add_web($db, 41, 'vhost', 'y', $server);
add_web($db, 42, 'vhost', 'y', $server);
add_web($db, 43, 'vhost', 'y', $server);
add_web($db, 44, 'vhost', 'n', $server);
add_web($db, 45, 'vhost', 'y', $server);
$db->query("INSERT INTO malwatch_site (server_id, parent_domain_id, domain, scan_days, next_run) VALUES "
	. "(?, 41, 'w41.test', 2, NOW() - INTERVAL 1 MINUTE), (?, 42, 'w42.test', 0, NOW() - INTERVAL 1 MINUTE), "
	. "(?, 43, 'w43.test', 3, NOW() + INTERVAL 1 HOUR), (?, 44, 'w44.test', 2, NOW() - INTERVAL 1 MINUTE), "
	. "(?, 45, 'w45.test', 5, NOW() - INTERVAL 1 MINUTE)", $server, $server, $server, $server, $server);
queue_due_scans();
$jobs = array();
foreach ((array) $db->queryAllRecords('SELECT parent_domain_id, job_source, job_kind FROM malwatch_job ORDER BY parent_domain_id') as $job) {
	$jobs[] = (int) $job['parent_domain_id'] . ':' . $job['job_source'] . ':' . $job['job_kind'];
}
expect_same('jobs for the due websites with an interval', $jobs, array('41:schedule:scan', '45:schedule:scan'));
expect_same('the next scan 2 days ahead', abs(next_in($db, 41) - 2 * 86400) < 120, true);
expect_same('another interval: 5 days ahead', abs(next_in($db, 45) - 5 * 86400) < 120, true);
expect_same('0 days: left alone', next_in($db, 42) < 0, true);
expect_same('not due yet: left alone', abs(next_in($db, 43) - 3600) < 120, true);
expect_same('a disabled website: no job, its turn moves on', abs(next_in($db, 44) - 2 * 86400) < 120, true);

// A website whose web directory is gone: a job nobody could run is left out,
// and the log says why in words an operator can act on.
$db->query('DELETE FROM malwatch_job');
$db->query('UPDATE malwatch_site SET next_run = NOW() - INTERVAL 1 MINUTE WHERE parent_domain_id = 41');
exec('rm -rf ' . escapeshellarg($tmp . '/web41'));
queue_due_scans();
$log = (string) @file_get_contents($conf['log_file']);
$count = $db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_job');
expect_same('no job without a web directory', (int) $count['n'], 0);
expect_same('the log names the website and the directory', strpos($log, 'malwatch: w41.test wurde nicht geprüft, das '
	. 'Webverzeichnis ' . $tmp . '/web41/web fehlt.') !== false, true);

$db->query('DELETE FROM malwatch_job');
$db->query('DELETE FROM malwatch_site');
$db->query('DELETE FROM web_domain');
$db->query('UPDATE malwatch_config SET default_scan_days = 7 WHERE config_id = 1');
exec('rm -rf ' . escapeshellarg($tmp));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "schedule_probe: OK\n";
