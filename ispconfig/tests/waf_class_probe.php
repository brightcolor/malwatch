<?php
/**
 * Runs malwatch_waf against a scratch database on the server, as root:
 *
 *   php waf_class_probe.php <stage>/ispconfig <database>
 *
 * The database is a throwaway copy with the malwatch schema and empty copies
 * of web_domain, sys_datalog and sys_log (plan task A9 creates it). The probe
 * refuses the ISPConfig database. Files go below a temporary directory;
 * nginx, systemctl, logrotate and modsec-rules-check are replaced by a
 * recorder, so nothing on the machine changes.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php waf_class_probe.php <stage>/ispconfig <database>\n");
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
// Nothing of the probe reaches the ISPConfig log.
$conf['log_priority'] = 9;

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

require $stage . '/interface/lib/malwatch_waf_lib.inc.php';
require $stage . '/server/lib/classes/malwatch_waf.inc.php';
$app->uses('malwatch_helper');

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function count_rows($sql)
{
	global $db;
	return count($db->queryAllRecords($sql));
}

$server = (int) $conf['server_id'];
$tmp = '/tmp/waf-probe-' . getmypid();
waf_remove_dir($tmp);
foreach (array('state', 'vhosts', 'backups', 'conf.d', 'waf') as $sub) {
	mkdir($tmp . '/' . $sub, 0700, true);
}
// The WAF directory as waf/install.sh leaves it, with main.conf pointing here.
foreach (glob(dirname($stage) . '/waf/conf/*.conf') as $file) {
	$text = str_replace('/etc/nginx/waf/', $tmp . '/waf/', (string) file_get_contents($file));
	file_put_contents($tmp . '/waf/' . basename($file), $text);
}
file_put_contents($tmp . '/conf.d/waf.conf', "modsecurity_rules_file $tmp/waf/main.conf;\n");
copy($stage . '/tests/waf_audit_sample.log', $tmp . '/audit.log');

$db->query('UPDATE malwatch_config SET waf_audit_log = ?, waf_conf_dir = ?, state_dir = ? WHERE config_id = 1',
	$tmp . '/audit.log', $tmp . '/waf', $tmp . '/state');
$db->query('DELETE FROM web_domain');
$db->query('DELETE FROM sys_datalog');
foreach (array(
	array(11, 0, 'vhost', 'beispiel.test', 'www'),
	array(12, 0, 'vhost', 'zweite.test', 'none'),
	array(21, 11, 'alias', 'alias-beispiel.test', 'none'),
) as $row) {
	$db->query('INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, '
		. "sys_groupid, nginx_directives, document_root) VALUES (?, ?, ?, ?, ?, ?, 'y', 1, '', ?)",
		$row[0], $server, $row[1], $row[2], $row[3], $row[4], '/var/www/' . $row[3]);
}

// Stands in for every command; answers are queues per command name.
$calls = array();
$answers = array();
$waf = new malwatch_waf();
$waf->paths = array(
	'vhost_dir' => $tmp . '/vhosts',
	'state_dir' => $tmp . '/state',
	'backup_dir' => $tmp . '/backups',
	'guard_log' => $tmp . '/guard.log',
	'conf_include' => $tmp . '/conf.d/waf.conf',
	'logrotate' => $tmp . '/logrotate-waf',
);
$waf->runner = function ($name, $argument) use (&$calls, &$answers) {
	$calls[] = $name;
	if (isset($answers[$name]) && count($answers[$name]) > 0) {
		return array_shift($answers[$name]);
	}
	return array(0, '');
};
expect_same('ready', $waf->ready(), true);

// --- A6: ingest and cleanup --------------------------------------------------

$stats = $waf->ingest(array());
expect_same('ingest counts', array($stats['lines'], $stats['hits'], $stats['new'], $stats['broken'], $stats['unknown']), array(8, 4, 4, 3, 1));
expect_same('ingest unknown host', $stats['unknown_hosts'], array('fremd.test' => 1));
expect_same('ingest by website', $stats['sites'], array(11 => 2, 12 => 2));
expect_same('hits stored', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 4);
$first = $db->queryOneRecord("SELECT * FROM malwatch_waf_hit WHERE unique_id = '1758049759112233445'");
expect_same('hit fields', array($first['server_id'], $first['parent_domain_id'], $first['domain'], $first['seen_at'],
	$first['would_block'], $first['logged_in'], $first['anomaly_score'], $first['status'], $first['response_file']),
	array((string) $server, '11', 'beispiel.test', '2026-09-16 21:09:19', 'y', 'y', '5', '207', ''));
expect_same('hit without secrets', strpos($first['request_headers'] . $first['request_body'], 'geheim'), false);
expect_same('hit rules', json_decode($first['rules'], true)[0]['param'], 'json.requests.0.path');

$second = $db->queryOneRecord("SELECT * FROM malwatch_waf_hit WHERE unique_id = '1757142300998877665'");
$response = $tmp . '/state/waf/responses/' . $second['response_file'];
expect_same('response stored', array($second['response_bytes'], is_file($response)), array('33', true));
expect_same('response content', gzdecode((string) file_get_contents($response)), '<html><body>Treffer</body></html>');
expect_same('response mode', substr(sprintf('%o', fileperms($response)), -4), '0640');
expect_same('responses directory', substr(sprintf('%o', fileperms($tmp . '/state/waf/responses')), -4), '2750');

expect_same('site days', $db->queryAllRecords('SELECT day, parent_domain_id, domain, hits, would_block, logged_in_hits, '
	. 'would_block_logged_in FROM malwatch_waf_site_day ORDER BY parent_domain_id, day'), array(
	array('day' => '2026-09-06', 'parent_domain_id' => '11', 'domain' => 'beispiel.test', 'hits' => '1', 'would_block' => '0', 'logged_in_hits' => '0', 'would_block_logged_in' => '0'),
	array('day' => '2026-09-16', 'parent_domain_id' => '11', 'domain' => 'beispiel.test', 'hits' => '1', 'would_block' => '1', 'logged_in_hits' => '1', 'would_block_logged_in' => '1'),
	array('day' => '2026-09-16', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'hits' => '2', 'would_block' => '1', 'logged_in_hits' => '0', 'would_block_logged_in' => '0'),
));
expect_same('rule days', $db->queryAllRecords('SELECT day, parent_domain_id, rule_id, rule_msg, path, hits, would_block_hits '
	. 'FROM malwatch_waf_day ORDER BY parent_domain_id, day, rule_id'), array(
	array('day' => '2026-09-06', 'parent_domain_id' => '11', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '1', 'would_block_hits' => '0'),
	array('day' => '2026-09-16', 'parent_domain_id' => '11', 'rule_id' => '942190', 'rule_msg' => 'Detects MSSQL code execution and information gathering attempts', 'path' => '/wp-json/batch/v1', 'hits' => '1', 'would_block_hits' => '1'),
	array('day' => '2026-09-16', 'parent_domain_id' => '12', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'path' => '/seite', 'hits' => '2', 'would_block_hits' => '1'),
));

$reader = json_decode((string) file_get_contents($tmp . '/state/waf/reader.json'), true);
expect_same('reader at the end', $reader['offset'], filesize($tmp . '/audit.log'));
$again = $waf->ingest(array());
expect_same('nothing new', array($again['lines'], $again['new']), array(0, 0));
unlink($tmp . '/state/waf/reader.json');
$again = $waf->ingest(array());
expect_same('read again without doubles', array($again['lines'], $again['hits'], $again['new']), array(8, 4, 0));
expect_same('day figures unchanged', $db->queryOneRecord('SELECT SUM(hits) AS n FROM malwatch_waf_site_day')['n'], '4');

// copytruncate: the file starts over, shorter than the stored offset.
$lines = file($tmp . '/audit.log');
file_put_contents($tmp . '/audit.log', str_replace('1757999160000000002', '1757999160000000003', $lines[7]));
$again = $waf->ingest(array());
expect_same('after copytruncate', array($again['lines'], $again['new']), array(1, 1));

$dry = $waf->ingest(array('dry_run' => true, 'file' => $stage . '/tests/waf_audit_sample.log'));
expect_same('dry run counts', array($dry['lines'], $dry['hits'], $dry['new']), array(8, 4, 0));
expect_same('dry run writes nothing', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 5);

$ingested = $waf->ingest_locked();
expect_same('ingest under the lock', $ingested['lines'], 0);

// Everything is recent except one hit and one day of each table.
$db->query('UPDATE malwatch_waf_hit SET seen_at = NOW()');
$db->query("UPDATE malwatch_waf_hit SET seen_at = DATE_SUB(NOW(), INTERVAL 30 DAY) WHERE unique_id = '1757142300998877665'");
$db->query("UPDATE malwatch_waf_site_day SET day = IF(day = '2026-09-06', DATE_SUB(CURDATE(), INTERVAL 200 DAY), CURDATE())");
$db->query("UPDATE malwatch_waf_day SET day = IF(day = '2026-09-06', DATE_SUB(CURDATE(), INTERVAL 200 DAY), CURDATE())");
file_put_contents($tmp . '/state/waf/responses/orphan.html.gz', 'x');
touch($tmp . '/state/waf/responses/orphan.html.gz', time() - 7200);
file_put_contents($tmp . '/state/waf/responses/fresh.html.gz', 'x');
mkdir($tmp . '/state/waf/staging/999999', 0700, true);
file_put_contents($tmp . '/state/waf/staging/999998-logrotate', 'x');
$counts = $waf->cleanup();
expect_same('cleanup counts', $counts, array('hits' => 1, 'days' => 2, 'files' => 1, 'staging' => 2));
expect_same('old hit gone', $db->queryOneRecord("SELECT hit_id FROM malwatch_waf_hit WHERE unique_id = '1757142300998877665'"), null);
expect_same('its response gone', is_file($response), false);
expect_same('orphan gone, fresh file kept', array(is_file($tmp . '/state/waf/responses/orphan.html.gz'),
	is_file($tmp . '/state/waf/responses/fresh.html.gz')), array(false, true));
expect_same('hits left', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 4);
expect_same('staging emptied', array(is_dir($tmp . '/state/waf/staging/999999'), is_file($tmp . '/state/waf/staging/999998-logrotate')), array(false, false));

// --- summary -----------------------------------------------------------------
waf_remove_dir($tmp);
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_class_probe: alle Prüfungen bestanden\n";
