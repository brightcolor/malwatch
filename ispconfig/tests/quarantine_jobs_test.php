<?php
/**
 * Checks how the runner starts quarantine jobs (0.40.0).
 *
 * Restore, delete and export act on entries of the quarantine store, named by
 * the id the store gave them; the panel queues them without a website folder
 * (malwatch_insert_quarantine_job()). Up to 0.39.0 the runner refused every
 * job without an existing folder, so the buttons "Wiederherstellen", "Löschen"
 * and "Herunterladen" of the quarantine list never reached the scanner.
 *
 *   php ispconfig/tests/quarantine_jobs_test.php
 *
 * The runner starts PHP itself in place of the scanner: the test looks at what
 * start() decides and hands on, the started process has nothing to do.
 */
if (!defined('LOGLEVEL_DEBUG')) {
	define('LOGLEVEL_DEBUG', 0);
}
if (!defined('LOGLEVEL_WARN')) {
	define('LOGLEVEL_WARN', 1);
}
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

/** Records what the runner writes into malwatch_job. */
class mw_test_db
{
	public $queries = array();

	public function query($sql)
	{
		$this->queries[] = array($sql, array_slice(func_get_args(), 1));
		return true;
	}
}

/** Records failed jobs and log lines; the rest is the real server helper. */
class mw_test_helper extends malwatch_helper
{
	public $failed = array();

	public function fail_job($job_id, $message)
	{
		$this->failed[] = $message;
	}

	public function log($message, $level = 0)
	{
	}
}

class mw_test_app
{
	public $dbmaster;
	public $malwatch_helper;

	public function uses($classes)
	{
	}
}

$app = new mw_test_app();
$app->dbmaster = new mw_test_db();
$app->malwatch_helper = new mw_test_helper();
$conf = array();

$state = sys_get_temp_dir() . '/mw-quarantine-jobs-' . getmypid();
@mkdir($state, 0700, true);
$config = array('binary_path' => PHP_BINARY, 'state_dir' => $state);
$runner = new malwatch_runner();

// --- Restore, delete and export need no website folder ---------------------------
foreach (array('restore', 'delete', 'export') as $action) {
	$app->malwatch_helper->failed = array();
	$app->dbmaster->queries = array();
	$job = array(
		'job_id' => 7, 'job_kind' => 'quarantine', 'scan_path' => '', 'domain' => '', 'parent_domain_id' => 0,
		'options' => json_encode(array('action' => $action, 'ids' => array('20260929T102502Z-a03bc765'), 'token' => 'abc')),
	);
	$started = $runner->start($job, $config);
	expect_same($action . ' without a website folder starts', array($started, $app->malwatch_helper->failed), array(true, array()));
	$recorded = count($app->dbmaster->queries) > 0 ? $app->dbmaster->queries[0][1][0] : '';
	expect_same($action . ' records its report file', $recorded, $state . '/runs/job-7.json');
}

// --- Jobs on a website still need its folder, and say which one is missing --------
$missing = $state . '/gibt-es-nicht';
foreach (array(
	'scan' => array(),
	'quarantine' => array('action' => 'add', 'files' => array('a.php')),
) as $kind => $options) {
	$app->malwatch_helper->failed = array();
	$job = array(
		'job_id' => 8, 'job_kind' => $kind, 'scan_path' => $missing, 'domain' => 'beispiel.test', 'parent_domain_id' => 11,
		'options' => json_encode($options),
	);
	$started = $runner->start($job, $config);
	$message = count($app->malwatch_helper->failed) > 0 ? $app->malwatch_helper->failed[0] : '';
	expect_same($kind . ' without its folder is refused', $started, false);
	expect_same($kind . ': the message names the website and the folder',
		strpos($message, 'beispiel.test') !== false && strpos($message, $missing) !== false, true);
}

// A job on a website whose row names no folder at all.
$app->malwatch_helper->failed = array();
$started = $runner->start(array(
	'job_id' => 9, 'job_kind' => 'scan', 'scan_path' => '', 'domain' => 'beispiel.test', 'parent_domain_id' => 11, 'options' => '',
), $config);
$message = count($app->malwatch_helper->failed) > 0 ? $app->malwatch_helper->failed[0] : '';
expect_same('a scan without any folder is refused', $started, false);
expect_same('that message names the website and has no gap', strpos($message, 'beispiel.test') !== false && strpos($message, '  ') === false, true);

foreach (array_merge(glob($state . '/*/*') ?: array(), glob($state . '/*') ?: array()) as $left) {
	is_dir($left) ? @rmdir($left) : @unlink($left);
}
@rmdir($state);

if ($failures > 0) {
	exit(1);
}
echo "quarantine jobs OK\n";
