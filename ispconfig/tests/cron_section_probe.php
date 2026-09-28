<?php
/**
 * Runs the malwatch cron job against a scratch database with a WAF part that
 * fails, as root:
 *
 *   php cron_section_probe.php <stage>/ispconfig <database>
 *
 * The WAF part throws an Error, the kind PHP raises for an undefined function.
 * Up to 0.35.1 the job caught only Exception: the Error ended cron.php, and
 * ISPConfig kept the job marked as running for 24 hours. The job has to note
 * the failure and carry on with the sections after it.
 *
 * The database is a throwaway copy with the malwatch schema and empty copies
 * of web_domain, sys_datalog and sys_log, the same one waf_class_probe.php
 * uses; the probe refuses the ISPConfig database. The log goes to a temporary
 * file. With empty tables no section starts a scan or touches a website.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php cron_section_probe.php <stage>/ispconfig <database>\n");
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

// Warnings go to a file of the probe and to the scratch database only.
$tmp = sys_get_temp_dir() . '/mw_cron_probe_' . getmypid();
mkdir($tmp, 0700);
$conf['log_file'] = $tmp . '/ispconfig.log';
$conf['log_priority'] = LOGLEVEL_WARN;

require_once SCRIPT_PATH . '/lib/classes/cronjob.inc.php';
foreach (array('malwatch_helper', 'malwatch_runner', 'malwatch_ingest', 'malwatch_actions') as $class) {
	require_once $stage . '/server/lib/classes/' . $class . '.inc.php';
	$app->$class = new $class();
}

/** The WAF part as it failed from 2026-09-26 on. */
class probe_failing_waf
{
	public function tick_is_fresh()
	{
		throw new Error('Probe: Call to undefined function waf_settings()');
	}
}
$app->malwatch_waf = new probe_failing_waf();

require_once $stage . '/server/lib/classes/cron.d/560-malwatch.inc.php';

$failures = 0;

function expect_true($name, $value, $detail = '')
{
	global $failures;
	if ($value !== true) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ($detail !== '' ? ': ' . $detail : '') . "\n");
	}
}

// The scanner stays out of it: the refresh steps of the housekeeping return
// early without an executable binary, and the state directory is the probe's.
$db->query('INSERT IGNORE INTO malwatch_config (config_id) VALUES (1)');
$saved = $db->queryOneRecord('SELECT binary_path, state_dir FROM malwatch_config WHERE config_id = 1');
$db->query('UPDATE malwatch_config SET binary_path = ?, state_dir = ? WHERE config_id = 1',
	$tmp . '/kein-scanner', $tmp);

// The marker for the sections after the WAF part: housekeeping ends a job that
// hangs since long ago. collect_finished before the WAF part leaves it alone,
// it has no result file.
$db->query('DELETE FROM malwatch_job');
$db->query("INSERT INTO malwatch_job (server_id, parent_domain_id, domain, scan_path, job_source, job_kind, "
	. "job_status, options, created_at, started_at, pid) VALUES (?, 0, 'probe.test', '/nonexistent', 'schedule', "
	. "'scan', 'running', '{}', NOW() - INTERVAL 30 DAY, NOW() - INTERVAL 30 DAY, 0)", $conf['server_id']);

ob_start();
try {
	$job = new cronjob_malwatch();
	$job->onRunJob();
	$escaped = '';
} catch (Throwable $e) {
	$escaped = get_class($e) . ': ' . $e->getMessage();
}
ob_end_clean();

expect_true('der Fehler bleibt im Cron-Job', $escaped === '', $escaped);
$log = is_file($conf['log_file']) ? (string) file_get_contents($conf['log_file']) : '';
expect_true('der Fehler steht im Protokoll',
	strpos($log, 'Der WAF-Teil ist gescheitert (Error in cron_section_probe.php') !== false
	&& strpos($log, 'Probe: Call to undefined function waf_settings()') !== false, trim($log));
$left = $db->queryOneRecord("SELECT job_status, job_log FROM malwatch_job WHERE domain = 'probe.test'");
expect_true('die Aufräumarbeiten nach dem WAF-Teil liefen',
	is_array($left) && $left['job_status'] === 'error' && strpos((string) $left['job_log'], 'Abgebrochen: der Lauf dauerte') === 0,
	is_array($left) ? $left['job_status'] . ' / ' . $left['job_log'] : 'Zeile fehlt');

$db->query('DELETE FROM malwatch_job');
if (is_array($saved)) {
	$db->query('UPDATE malwatch_config SET binary_path = ?, state_dir = ? WHERE config_id = 1',
		$saved['binary_path'], $saved['state_dir']);
}
exec('rm -rf ' . escapeshellarg($tmp));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "cron_section_probe: OK\n";
