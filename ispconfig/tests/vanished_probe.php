<?php
/**
 * Runs the part of the malwatch cron job that closes open findings whose file
 * is gone (clean_vanished, 0.41.0) against a scratch database, as root:
 *
 *   php vanished_probe.php <stage>/ispconfig <database>
 *
 * Four websites: one with a file that is still there and one that is gone,
 * one switched off whose web root is missing (an unmounted disk), one
 * ISPConfig no longer has, and a finding of another server. Two findings per
 * run, so the cursor has to carry the second run on and the third back to the
 * start.
 *
 * The database is a throwaway copy with the malwatch schema and an empty copy
 * of web_domain, the same one waf_class_probe.php uses; the probe refuses the
 * ISPConfig database and removes its rows again.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php vanished_probe.php <stage>/ispconfig <database>\n");
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

$tmp = sys_get_temp_dir() . '/mw_vanished_probe_' . getmypid();
mkdir($tmp . '/state', 0700, true);
mkdir($tmp . '/site/web', 0700, true);
file_put_contents($tmp . '/site/web/still.php', 'x');
$conf['log_file'] = $tmp . '/ispconfig.log';
$conf['log_priority'] = LOGLEVEL_DEBUG;

require_once SCRIPT_PATH . '/lib/classes/cronjob.inc.php';
require_once $stage . '/server/lib/classes/malwatch_helper.inc.php';
$app->malwatch_helper = new malwatch_helper();
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

$server = intval($conf['server_id']);
$site_ok = 990001;
$site_off = 990002;
$site_gone = 990003;
$db->query('DELETE FROM web_domain WHERE domain_id IN (?, ?, ?)', $site_ok, $site_off, $site_gone);
$db->query('DELETE FROM malwatch_finding WHERE parent_domain_id IN (?, ?, ?)', $site_ok, $site_off, $site_gone);
$db->query("INSERT INTO web_domain (domain_id, server_id, domain, document_root, type, active) "
	. "VALUES (?, ?, 'probe-ok.test', ?, 'vhost', 'y'), (?, ?, 'probe-off.test', ?, 'vhost', 'n')",
	$site_ok, $server, $tmp . '/site', $site_off, $server, $tmp . '/unmounted');
$web = $db->queryOneRecord('SELECT COUNT(*) AS n FROM web_domain WHERE domain_id IN (?, ?)', $site_ok, $site_off);
expect_true('die Websites der Probe stehen in web_domain', is_array($web) && intval($web['n']) === 2);

$findings = array(
	'still' => array($server, $site_ok, $tmp . '/site/web/still.php'),
	'gone' => array($server, $site_ok, $tmp . '/site/web/gone.php'),
	'unmounted' => array($server, $site_off, $tmp . '/unmounted/web/x.php'),
	'site_gone' => array($server, $site_gone, $tmp . '/deleted/web/y.php'),
	'other_server' => array($server + 1, $site_gone, $tmp . '/deleted/web/z.php'),
);
$ids = array();
foreach ($findings as $name => $row) {
	$db->query("INSERT INTO malwatch_finding (server_id, parent_domain_id, domain, file_path, path_hash, rule_id, "
		. "severity, finding_state, first_seen, last_seen) VALUES (?, ?, 'probe.test', ?, ?, 'probe.rule', 'high', "
		. "'open', NOW(), NOW())", $row[0], $row[1], $row[2], hash('sha256', $row[2]));
	$ids[$name] = intval($db->insertID());
}

$job = new cronjob_malwatch();
$clean = new ReflectionMethod($job, 'clean_vanished');
$clean->setAccessible(true);
$config = array('state_dir' => $tmp, 'vanished_check_rows' => '2');
$cursor_file = $tmp . '/state/vanished.cursor';

$clean->invoke($job, $config);
expect_true('der erste Lauf endet beim zweiten Fund', trim((string) @file_get_contents($cursor_file)) === (string) $ids['gone'],
	trim((string) @file_get_contents($cursor_file)));
$clean->invoke($job, $config);
expect_true('der zweite Lauf setzt dort fort', trim((string) @file_get_contents($cursor_file)) === (string) $ids['site_gone'],
	trim((string) @file_get_contents($cursor_file)));
$clean->invoke($job, $config);
expect_true('der dritte Lauf kommt ans Ende und beginnt wieder vorn', trim((string) @file_get_contents($cursor_file)) === '0',
	trim((string) @file_get_contents($cursor_file)));

$want = array('still' => 'open', 'gone' => 'fixed', 'unmounted' => 'open', 'site_gone' => 'fixed', 'other_server' => 'open');
foreach ($want as $name => $state) {
	$row = $db->queryOneRecord('SELECT finding_state FROM malwatch_finding WHERE finding_id = ?', $ids[$name]);
	expect_true('Fund ' . $name . ' ist ' . $state, is_array($row) && $row['finding_state'] === $state,
		is_array($row) ? $row['finding_state'] : 'Zeile fehlt');
}
$log = is_file($conf['log_file']) ? (string) file_get_contents($conf['log_file']) : '';
expect_true('das Protokoll nennt jeden geschlossenen Fund',
	substr_count($log, 'malwatch: 1 offener Fund geschlossen, weil seine Datei nicht mehr da ist.') === 2, trim($log));

// 0 turns the check off: nothing changes, the cursor stays.
file_put_contents($cursor_file, "5\n");
$db->query("UPDATE malwatch_finding SET finding_state = 'open' WHERE finding_id = ?", $ids['gone']);
$clean->invoke($job, array('state_dir' => $tmp, 'vanished_check_rows' => '0'));
$row = $db->queryOneRecord('SELECT finding_state FROM malwatch_finding WHERE finding_id = ?', $ids['gone']);
expect_true('0 schaltet die Prüfung ab', is_array($row) && $row['finding_state'] === 'open'
	&& trim((string) file_get_contents($cursor_file)) === '5');

$db->query('DELETE FROM malwatch_finding WHERE finding_id IN (' . implode(',', array_map('intval', $ids)) . ')');
$db->query('DELETE FROM web_domain WHERE domain_id IN (?, ?, ?)', $site_ok, $site_off, $site_gone);
exec('rm -rf ' . escapeshellarg($tmp));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "vanished_probe: OK\n";
