<?php
/**
 * Lets the malwatch cron job die of a fault no catch reaches and checks that it
 * frees itself, as root on the server:
 *
 *   php cron_guard_probe.php <stage>/ispconfig <database>
 *
 * The probe starts itself a second time as a child with a small memory limit.
 * In the child the WAF part of the job asks for more memory than the limit
 * allows; PHP ends the process at once, and only the shutdown functions still
 * run. ISPConfig marks the job as running before the run, as the probe does
 * here; the guard of 560-malwatch has to clear the mark, set the next run
 * after the pause of the settings and leave a note for the watch.
 *
 * The same scratch database waf_class_probe.php uses, with sys_cron among its
 * tables; the probe refuses the ISPConfig database.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php cron_guard_probe.php <stage>/ispconfig <database>\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
$probe_db = $argv[2];
$child = isset($argv[3]) && $argv[3] === '--child';

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

if ($child) {
	$tmp = $argv[4];
	$conf['log_file'] = $tmp . '/ispconfig.log';
	$conf['log_priority'] = LOGLEVEL_WARN;
	require_once SCRIPT_PATH . '/lib/classes/cronjob.inc.php';
	foreach (array('malwatch_helper', 'malwatch_runner', 'malwatch_ingest', 'malwatch_actions') as $class) {
		require_once $stage . '/server/lib/classes/' . $class . '.inc.php';
		$app->$class = new $class();
	}
	require_once $stage . '/interface/lib/malwatch_waf_lib.inc.php';
	require_once $stage . '/interface/lib/malwatch_waf_origin.inc.php';
	require_once $stage . '/interface/lib/malwatch_waf_ban.inc.php';
	require_once $stage . '/server/lib/classes/malwatch_waf.inc.php';

	/** A WAF part that asks for more memory than the child may use. */
	class probe_hungry_waf extends malwatch_waf
	{
		public function tick_is_fresh()
		{
			$heap = str_repeat('x', 256 * 1024 * 1024);
			return strlen($heap) > 0;
		}
	}
	$waf = new probe_hungry_waf();
	$waf->paths = array('vhost_dir' => $tmp . '/vhosts', 'state_dir' => $tmp . '/state');
	$app->malwatch_waf = $waf;
	require_once $stage . '/server/lib/classes/cron.d/560-malwatch.inc.php';
	$job = new cronjob_malwatch();
	$job->onRunJob();
	echo "child: onRunJob kam zurück\n";
	exit(0);
}

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$tmp = sys_get_temp_dir() . '/mw_guard_probe_' . getmypid();
mkdir($tmp, 0700);
$db->query('INSERT IGNORE INTO malwatch_config (config_id) VALUES (1)');
$saved = $db->queryOneRecord('SELECT binary_path, state_dir, waf_watch_crash_pause FROM malwatch_config WHERE config_id = 1');
// The scanner stays out of it, and the pause is not the default of ten minutes.
$db->query('UPDATE malwatch_config SET binary_path = ?, state_dir = ?, waf_watch_crash_pause = 7 WHERE config_id = 1',
	$tmp . '/kein-scanner', $tmp);
$db->query('DELETE FROM malwatch_job');
$db->query("DELETE FROM sys_cron WHERE name = 'cronjob_malwatch'");
$db->query("INSERT INTO sys_cron (name, last_run, next_run, running) VALUES ('cronjob_malwatch', NOW(), NOW(), 1)");

$command = escapeshellarg(PHP_BINARY) . ' -d memory_limit=128M ' . escapeshellarg(__FILE__) . ' ' . escapeshellarg($stage)
	. ' ' . escapeshellarg($probe_db) . ' --child ' . escapeshellarg($tmp) . ' 2>&1';
exec($command, $output, $code);
$output = implode("\n", $output);

expect_same('the child dies of the memory limit', array($code !== 0, strpos($output, 'Allowed memory size') !== false,
	strpos($output, 'onRunJob kam zurück')), array(true, true, false));
$row = $db->queryOneRecord("SELECT running, TIMESTAMPDIFF(SECOND, NOW(), next_run) AS wait FROM sys_cron WHERE name = 'cronjob_malwatch'");
expect_same('the guard frees the job', (int) $row['running'], 0);
expect_same('the next run waits for the pause of the settings', (int) $row['wait'] >= 6 * 60 && (int) $row['wait'] <= 7 * 60,
	true);
$note = json_decode((string) @file_get_contents($tmp . '/state/waf/cron-crash.json'), true);
expect_same('a note for the watch', array(is_array($note), is_array($note) && strpos($note['text'], 'Allowed memory size') !== false,
	is_array($note) ? (int) $note['pause_until'] - (int) $note['time'] : 0), array(true, true, 420));
$log = (string) @file_get_contents($tmp . '/ispconfig.log');
expect_same('the crash stands in the log', strpos($log, 'Der Cron-Job ist abgestürzt') !== false, true);

$db->query("DELETE FROM sys_cron WHERE name = 'cronjob_malwatch'");
if (is_array($saved)) {
	$db->query('UPDATE malwatch_config SET binary_path = ?, state_dir = ?, waf_watch_crash_pause = ? WHERE config_id = 1',
		$saved['binary_path'], $saved['state_dir'], (int) $saved['waf_watch_crash_pause']);
}
exec('rm -rf ' . escapeshellarg($tmp));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n\n" . $output . "\n");
	exit(1);
}
echo "cron_guard_probe: OK\n";
