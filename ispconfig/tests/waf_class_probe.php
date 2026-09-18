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
require $stage . '/interface/lib/malwatch_waf_origin.inc.php';
require $stage . '/interface/lib/malwatch_waf_ban.inc.php';
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
expect_same('cleanup counts', $counts, array('hits' => 1, 'days' => 2, 'files' => 1, 'staging' => 2, 'addresses' => 0));
expect_same('old hit gone', $db->queryOneRecord("SELECT hit_id FROM malwatch_waf_hit WHERE unique_id = '1757142300998877665'"), null);
expect_same('its response gone', is_file($response), false);
expect_same('orphan gone, fresh file kept', array(is_file($tmp . '/state/waf/responses/orphan.html.gz'),
	is_file($tmp . '/state/waf/responses/fresh.html.gz')), array(false, true));
expect_same('hits left', count_rows('SELECT hit_id FROM malwatch_waf_hit'), 4);
expect_same('staging emptied', array(is_dir($tmp . '/state/waf/staging/999999'), is_file($tmp . '/state/waf/staging/999998-logrotate')), array(false, false));

// --- A7: jobs ----------------------------------------------------------------

function job_row($id)
{
	global $waf;
	return $waf->job($id);
}

function job_progress($id)
{
	$job = job_row($id);
	$options = json_decode((string) $job['options'], true);
	return isset($options['progress']) ? $options['progress'] : array();
}

function site_row($id)
{
	global $db;
	return $db->queryOneRecord('SELECT waf_state, waf_state_since, waf_pending_state FROM malwatch_site WHERE parent_domain_id = ?', $id);
}

function field($id)
{
	global $db;
	$row = $db->queryOneRecord('SELECT nginx_directives FROM web_domain WHERE domain_id = ?', $id);
	return (string) $row['nginx_directives'];
}

function vhost($domain, $body)
{
	global $tmp;
	file_put_contents($tmp . '/vhosts/' . $domain . '.vhost', "server {\n" . $body . "}\n");
}

function config_value($column)
{
	global $db;
	$row = $db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1');
	return $row[$column];
}

function exception_row($id)
{
	global $db;
	return $db->queryOneRecord('SELECT * FROM malwatch_waf_exception WHERE exception_id = ?', $id);
}

function add_exception($scope, $site, $rule, $path, $param, $note)
{
	global $db, $server;
	$db->query('INSERT INTO malwatch_waf_exception (server_id, scope, parent_domain_id, domain, rule_id, path, param, note, '
		. "exception_state, created_by, created_at) VALUES (?, ?, ?, '', ?, ?, ?, ?, 'pending', 'probe', NOW())",
		$server, $scope, $site, $rule, $path, $param, $note);
	return (int) $db->insertID();
}

function age_job($id)
{
	global $db;
	$db->query('UPDATE malwatch_job SET started_at = DATE_SUB(NOW(), INTERVAL 10 MINUTE) WHERE job_id = ?', $id);
}

$own = "client_max_body_size 64M;\n";
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 11', $own);
vhost('beispiel.test', "    listen 80;\n");
vhost('zweite.test', "    listen 80;\n");
$answers = array();

// Two phases: the field first, the vhost later.
$calls = array();
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'detect'), 'probe');
$waf->pass();
$progress = job_progress($job);
expect_same('set: job waits', job_row($job)['job_status'], 'running');
expect_same('set: entry waits', array($progress[0]['status'], $progress[0]['target']), array('waiting', 'detect'));
expect_same('set: field written', field(11), $own . waf_block_text('detect'));
expect_same('set: backup', file_get_contents($progress[0]['backup']), $own);
expect_same('set: datalog', count_rows("SELECT datalog_id FROM sys_datalog WHERE dbtable = 'web_domain' AND dbidx = 'domain_id:11'"), 1);
expect_same('set: pending state', site_row(11)['waf_pending_state'], 'detect');
expect_same('set: no command yet', $calls, array());

vhost('beispiel.test', "    listen 80;\n    modsecurity on;\n");
$waf->pass();
$site = site_row(11);
expect_same('set: done', job_row($job)['job_status'], 'done');
expect_same('set: one nginx -t', $calls, array('nginx_test'));
expect_same('set: confirmed', array($site['waf_state'], $site['waf_pending_state'], $site['waf_state_since'] !== null), array('detect', '', true));
expect_same('set: job log', job_row($job)['job_log'], 'beispiel.test: mitschreiben bestätigt');
expect_same('set: action log', count_rows("SELECT action_id FROM malwatch_action_log WHERE action_type = 'waf'"), 1);

$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('enforce too early', array(job_row($job)['job_status'], job_progress($job)[0]['reason']), array('done', 'too_early'));
expect_same('enforce too early leaves the field', field(11), $own . waf_block_text('detect'));

// Past the deadline the job takes its change back.
$db->query('UPDATE malwatch_site SET waf_state_since = DATE_SUB(NOW(), INTERVAL 8 DAY) WHERE parent_domain_id = 11');
$calls = array();
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('enforce written', field(11), $own . waf_block_text('enforce'));
age_job($job);
$waf->pass();
$entry = job_progress($job)[0];
expect_same('deadline: failed', array(job_row($job)['job_status'], $entry['reason'], $entry['rollback']), array('error', 'deadline', 'rolled_back'));
expect_same('deadline: field back', field(11), $own . waf_block_text('detect'));
expect_same('deadline: state kept', array(site_row(11)['waf_state'], site_row(11)['waf_pending_state']), array('detect', ''));
expect_same('deadline: no reload', in_array('nginx_reload', $calls, true), false);

// Somebody saved the field in the meantime: it stays.
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
$db->query('UPDATE web_domain SET nginx_directives = CONCAT(nginx_directives, ?) WHERE domain_id = 11', "gzip on;\n");
age_job($job);
$waf->pass();
expect_same('changed meanwhile', job_progress($job)[0]['rollback'], 'changed_meanwhile');
expect_same('changed field stays', field(11), $own . waf_block_text('enforce') . "gzip on;\n");
expect_same('changed meanwhile in the log', strpos(job_row($job)['job_log'], 'zwischenzeitlich geändert') !== false, true);
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 11', $own . waf_block_text('detect'));

// nginx -t fails once the vhost shows the state.
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
vhost('beispiel.test', "    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n");
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] something')));
$waf->pass();
$entry = job_progress($job)[0];
expect_same('nginx -t fails', array(job_row($job)['job_status'], $entry['reason'], $entry['rollback'], $entry['detail']),
	array('error', 'nginx_test', 'rolled_back', 'nginx: [emerg] something'));
expect_same('nginx -t fails: field back', field(11), $own . waf_block_text('detect'));
vhost('beispiel.test', "    modsecurity on;\n");

// ISPConfig refused the vhost and left a .err next to it.
$job = $waf->queue('set_state', array('domain_ids' => array(12), 'state' => 'detect'), 'probe');
$waf->pass();
file_put_contents($tmp . '/vhosts/zweite.test.vhost.err', 'rejected');
$waf->pass();
expect_same('rejected by ISPConfig', array(job_progress($job)[0]['reason'], job_progress($job)[0]['rollback']), array('rejected', 'rolled_back'));
expect_same('rejected: field back', field(12), '');
unlink($tmp . '/vhosts/zweite.test.vhost.err');

$db->query('INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, sys_groupid, '
	. "nginx_directives, document_root) VALUES (13, ?, 0, 'vhost', 'fremd-server.test', 'none', 'y', 1, '', '/var/www/x')", $server + 100);
$job = $waf->queue('set_state', array('domain_ids' => array(13, 999), 'state' => 'detect'), 'probe');
$waf->pass();
$progress = job_progress($job);
expect_same('skips', array(job_row($job)['job_status'], $progress[0]['reason'], $progress[1]['reason']), array('done', 'other_server', 'not_found'));

// Exceptions.
$calls = array();
$exception = add_exception('site_path', 11, '942100', '/wp-admin/admin-ajax.php', '', 'Notiz bleibt draussen');
$job = $waf->queue('exception_add', array('exception_id' => $exception), 'probe');
$waf->pass();
$before = file_get_contents($tmp . '/waf/exclusions-panel-before.conf');
expect_same('exception done', job_row($job)['job_status'], 'done');
expect_same('exception commands', $calls, array('rules_check', 'nginx_test', 'nginx_reload', 'nginx_active'));
expect_same('exception rule id', strpos($before, '"id:' . (10200 + $exception) . ',phase:1') !== false, true);
expect_same('exception hosts', strpos($before, '^(?:alias-beispiel\.test|beispiel\.test|www\.beispiel\.test)') !== false, true);
expect_same('note stays out', strpos($before, 'Notiz'), false);
expect_same('exception active', array(exception_row($exception)['exception_state'], exception_row($exception)['activated_at'] !== null), array('active', true));
expect_same('snapshot taken', file_get_contents($tmp . '/state/waf/last-good/exclusions-panel-before.conf'), $before);

$calls = array();
$bad = add_exception('site', 11, '10010', '', '', '');
$job = $waf->queue('exception_add', array('exception_id' => $bad), 'probe');
$waf->pass();
expect_same('own rule refused', array(job_row($job)['job_status'], exception_row($bad)['exception_state'], exception_row($bad)['error_reason'], $calls),
	array('error', 'error', 'Ungültige Angabe: rule_id', array()));

$failing = add_exception('all_path', 0, '941100', '/xmlrpc.php', '', '');
$calls = array();
$answers = array('rules_check' => array(array(1, 'Rules error. File: exclusions-panel-before.conf')));
$job = $waf->queue('exception_add', array('exception_id' => $failing), 'probe');
$waf->pass();
expect_same('rules check refuses', array(job_row($job)['job_status'], $calls, exception_row($failing)['exception_state']), array('error', array('rules_check'), 'error'));
expect_same('file unchanged after the refusal', file_get_contents($tmp . '/waf/exclusions-panel-before.conf'), $before);

$db->query("UPDATE malwatch_waf_exception SET exception_state = 'removing' WHERE exception_id = ?", $exception);
$job = $waf->queue('exception_remove', array('exception_id' => $exception), 'probe');
$waf->pass();
expect_same('exception removed', array(job_row($job)['job_status'], exception_row($exception)), array('done', null));
expect_same('rule gone', strpos(file_get_contents($tmp . '/waf/exclusions-panel-before.conf'), '# exception ' . $exception . ' '), false);
$calls = array();
$job = $waf->queue('exception_remove', array('exception_id' => $bad), 'probe');
$waf->pass();
expect_same('error row removed without reload', array(job_row($job)['job_status'], exception_row($bad), $calls), array('done', null, array()));

// Emergency stop: rules off, enforcing websites back to detect.
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 12', waf_block_text('enforce'));
$job = $waf->queue('emergency', array('on' => true), 'probe');
$waf->pass();
expect_same('emergency on', array(job_row($job)['job_status'], config_value('waf_emergency'), config_value('waf_emergency_since') !== null), array('done', 'y', true));
expect_same('emergency file', waf_state_file_is_emergency(file_get_contents($tmp . '/waf/state.conf')), true);
$follow = $db->queryOneRecord("SELECT job_id, options FROM malwatch_job WHERE job_kind = 'waf' AND job_status = 'pending' ORDER BY job_id DESC LIMIT 1");
$follow_options = json_decode($follow['options'], true);
expect_same('emergency queues detect', array($follow_options['action'], $follow_options['state'], $follow_options['domain_ids']), array('set_state', 'detect', array(12)));
$waf->pass();
vhost('zweite.test', "    modsecurity on;\n");
$waf->pass();
expect_same('follow-up done', array(job_row((int) $follow['job_id'])['job_status'], field(12)), array('done', waf_block_text('detect')));
$job = $waf->queue('set_state', array('domain_ids' => array(11), 'state' => 'enforce'), 'probe');
$waf->pass();
expect_same('no enforce during the emergency', job_progress($job)[0]['reason'], 'emergency');
$job = $waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();
expect_same('emergency off', array(job_row($job)['job_status'], config_value('waf_emergency')), array('done', 'n'));
expect_same('emergency file cleared', waf_state_file_is_emergency(file_get_contents($tmp . '/waf/state.conf')), false);

// An emergency stop does not wait for a job that waits for ISPConfig.
$waiting = $waf->queue('set_state', array('domain_ids' => array(12), 'state' => 'off'), 'probe');
$waf->pass();
expect_same('job waits for ISPConfig', job_row($waiting)['job_status'], 'running');
$job = $waf->queue('emergency', array('on' => true), 'probe');
$other = $waf->queue('response_body', array('mode' => 'lean'), 'probe');
$waf->pass();
expect_same('emergency first', array(job_row($job)['job_status'], job_row($other)['job_status']), array('done', 'pending'));
vhost('zweite.test', "    listen 80;\n");
$waf->pass();
expect_same('queue moves on', array(job_row($waiting)['job_status'], job_row($other)['job_status']), array('done', 'done'));
expect_same('lean file', waf_response_body_mode(file_get_contents($tmp . '/waf/response-body.conf')), 'lean');
expect_same('lean setting', config_value('waf_response_body'), 'lean');
$calls = array();
$job = $waf->queue('response_body', array('mode' => 'lean'), 'probe');
$waf->pass();
expect_same('lean again changes nothing', array(job_row($job)['job_status'], $calls), array('done', array()));
$job = $waf->queue('response_body', array('mode' => 'halb'), 'probe');
$waf->pass();
expect_same('odd mode refused', job_row($job)['job_status'], 'error');
$waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();

$db->query('UPDATE malwatch_config SET waf_log_keep_days = 14 WHERE config_id = 1');
$calls = array();
$job = $waf->queue('apply_settings', array(), 'probe');
$waf->pass();
expect_same('settings applied', array(job_row($job)['job_status'], $calls), array('done', array('logrotate_check')));
expect_same('logrotate file', strpos(file_get_contents($tmp . '/logrotate-waf'), "\trotate 14\n") !== false, true);
$answers = array('logrotate_check' => array(array(1, 'error: bad line')));
$db->query('UPDATE malwatch_config SET waf_log_keep_days = 30 WHERE config_id = 1');
$job = $waf->queue('apply_settings', array(), 'probe');
$waf->pass();
expect_same('logrotate refuses', array(job_row($job)['job_status'], strpos(file_get_contents($tmp . '/logrotate-waf'), "\trotate 14\n") !== false), array('error', true));

// Old markers become new ones; states and files are read back.
$db->query('UPDATE web_domain SET nginx_directives = ? WHERE domain_id = 12',
	"# WAF-Anfang (mitschreiben) \xE2\x80\x93 verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n");
$db->query("UPDATE malwatch_site SET waf_state = 'off' WHERE parent_domain_id = 12");
vhost('zweite.test', "    modsecurity on;\n");
file_put_contents($tmp . '/waf/response-body.conf', waf_response_body_text('full'));
$job = $waf->queue('migrate_markers', array(), 'probe');
$waf->pass();
expect_same('migrate done', job_row($job)['job_status'], 'done');
expect_same('marker rewritten', field(12), waf_block_text('detect'));
expect_same('state read back', array(site_row(12)['waf_state'], site_row(11)['waf_state']), array('detect', 'detect'));
expect_same('response body read back', config_value('waf_response_body'), 'full');

$job = $waf->execute_now('response_body', array('mode' => 'full'), 'probe');
expect_same('execute now', array($job['job_status'], strpos($job['job_log'], 'unverändert') !== false), array('done', true));

// Hard stop: include off, vhosts and fields without the module.
$calls = array();
$job = $waf->queue('emergency', array('on' => true, 'hard' => true), 'probe');
$waf->pass();
expect_same('hard stop done', array(job_row($job)['job_status'], $calls), array('done', array('nginx_test', 'nginx_reload')));
expect_same('include renamed', array(is_file($tmp . '/conf.d/waf.conf'), is_file($tmp . '/conf.d/waf.conf.off')), array(false, true));
expect_same('vhosts stripped', array(waf_vhost_state(file_get_contents($tmp . '/vhosts/beispiel.test.vhost')),
	waf_vhost_state(file_get_contents($tmp . '/vhosts/zweite.test.vhost'))), array('off', 'off'));
expect_same('fields cleared', array(field(11), field(12)), array($own, ''));
expect_same('states off', array(site_row(11)['waf_state'], site_row(12)['waf_state']), array('off', 'off'));
expect_same('emergency flag', config_value('waf_emergency'), 'y');
$job = $waf->queue('emergency', array('on' => false), 'probe');
$waf->pass();
expect_same('no soft end of a hard stop', job_row($job)['job_status'], 'error');

// The guard.
$answers = array();
expect_same('guard fine', $waf->guard(), 0);
expect_same('guard log', strpos(file_get_contents($tmp . '/guard.log'), 'nginx -t in Ordnung.') !== false, true);
file_put_contents($tmp . '/waf/exclusions-panel-before.conf', "SecRule broken\n");
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] "modsecurity_rules_file" directive Rules error. File: '
	. $tmp . '/waf/exclusions-panel-before.conf. Line: 1.')));
$calls = array();
expect_same('guard repairs', $waf->guard(), 1);
expect_same('guard put the file back', file_get_contents($tmp . '/waf/exclusions-panel-before.conf'),
	file_get_contents($tmp . '/state/waf/last-good/exclusions-panel-before.conf'));
expect_same('guard reloads after the repair', $calls, array('nginx_test', 'nginx_test', 'nginx_reload'));
rename($tmp . '/conf.d/waf.conf.off', $tmp . '/conf.d/waf.conf');
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] unknown directive "modsecurity" in /etc/nginx/sites-enabled/100-x.vhost:3')));
expect_same('guard stops hard', $waf->guard(), 1);
expect_same('guard renamed the include', is_file($tmp . '/conf.d/waf.conf.off'), true);
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] host not found in upstream "x"')));
$calls = array();
expect_same('guard leaves other errors', array($waf->guard(), $calls), array(1, array('nginx_test')));

// A file job that is still running was cut off.
$answers = array();
$db->query('INSERT INTO malwatch_job (server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, '
	. "options, created_at, started_at) VALUES (?, 0, '', '', 'manual', 'waf', 'running', ?, NOW(), NOW())",
	$server, '{"action":"response_body","mode":"lean","user":"probe"}');
$cut = (int) $db->insertID();
$waf->pass();
expect_same('interrupted job', array(job_row($cut)['job_status'], strpos(job_row($cut)['job_log'], 'unterbrochen') !== false), array('error', true));

$waf->cron_minute();
$waf->cron_hourly();
expect_same('snapshot', $waf->snapshot(), true);
expect_same('no job left behind', count_rows("SELECT job_id FROM malwatch_job WHERE job_status IN ('pending','running')"), 0);

// --- B5: the origin update ----------------------------------------------------

$probe_dir = $tmp . '/origin-probe';
@mkdir($probe_dir . '/waf/origin/tmp', 0700, true);
$waf->paths['state_dir'] = $probe_dir;
$fixtures = $stage . '/tests/fixtures/origin';
// The download is the place where the class talks to the world; the probe puts
// the sample files there instead.
$waf->fetcher = function ($url, $target, $limit, $auth) use ($fixtures) {
	$map = array(
		'dbip-country-lite' => $fixtures . '/dbip-country.csv',
		'dbip-asn-lite' => $fixtures . '/dbip-asn.csv',
		'torbulkexitlist' => $fixtures . '/tor.txt',
		'vpn/ipv4.txt' => $fixtures . '/x4b-ipv4.txt',
		'vpn/ipv6.txt' => $fixtures . '/x4b-ipv6.txt',
	);
	foreach ($map as $mark => $file) {
		if (strpos($url, $mark) !== false) {
			return copy($file, $target) ? array(true, '') : array(false, 'Kopie scheiterte.');
		}
	}
	return array(false, 'Nicht gefunden (404).');
};
$probe_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'x4b',
	'waf_origin_tor_hours' => 1, 'waf_origin_list_hours' => 24, 'waf_origin_db_hours' => 24);
$result = $waf->origin_update_sources($probe_settings, array(), '2026-09-17 20:00:00');
// The sample files are far too short for the real limits, so every source is
// refused and the file in use stays as it is.
expect_same('every chosen source is looked at', count($result), 5);
expect_same('a file with unreadable lines is refused',
	strpos($result['tor']['note'], '1 von 5 Zeilen ergeben keinen Adressbereich') !== false, true);
expect_same('nothing was swapped in', is_file($probe_dir . '/waf/origin/tor.bin'), false);
expect_same('the temporary file is gone', count(glob($probe_dir . '/waf/origin/tmp/*')), 0);
// The sample files cover the VPN list; the data centre list has none, so its
// download answers like a source that is gone.
expect_same('a source that is not reachable',
	strpos($result['x4b_datacenter']['note'], 'Nicht gefunden') !== false, true);

// --- B6: the addresses of the hits --------------------------------------------

// The refused update above already left a row per source, so the fetch time of
// the Tor list is set on the row that is there.
$db->query("INSERT INTO malwatch_waf_origin_source (server_id, source, version, checked_at, fetched_at, entries) "
	. "VALUES (?, 'tor', '', NOW(), NOW(), 3) ON DUPLICATE KEY UPDATE fetched_at = NOW(), entries = 3", $server);
@mkdir($probe_dir . '/waf/origin', 0700, true);
waf_origin_read_list($fixtures . '/tor.txt', $probe_dir . '/waf/origin/tor.bin');
$db->query("INSERT INTO malwatch_waf_hit (server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, method, "
	. "uri, path, status, anomaly_score, would_block, logged_in, rules, request_headers) "
	. "VALUES (?, 11, 'beispiel.test', 'probe-origin', NOW(), '192.0.2.10', 'GET', '/x', '/x', 404, 5, 'n', 'n', '[]', '{}')", $server);
// The lookup follows the settings of the panel, so the Tor list is switched on
// for it.
$db->query("UPDATE malwatch_config SET waf_origin_tor = 'torproject' WHERE config_id = 1");
expect_same('every address of the stored hits is looked up', $waf->origin_lookup(10), 3);
$ip_row = $db->queryOneRecord("SELECT is_tor, country, local_at FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('the address is marked as Tor', array($ip_row['is_tor'], $ip_row['country'] === '' ), array('y', true));
expect_same('a second pass finds nothing new', $waf->origin_lookup(10), 0);
// --- C5: proxycheck.io --------------------------------------------------------

// Der Dienst ist die Naht: die Probe antwortet aus einer Beispieldatei und hält
// fest, wonach gefragt wurde.
$asked = array();
$answer_file = $stage . '/tests/fixtures/proxycheck/answer.json';
$waf->poster = function ($url, $body, $limit) use (&$asked, $answer_file) {
	$asked[] = array($url, $body);
	return array(true, file_get_contents($answer_file));
};
$db->query("UPDATE malwatch_config SET waf_origin_net = 'proxycheck', waf_origin_proxycheck_key = 'probe-key', "
	. 'waf_origin_proxycheck_daily = 3 WHERE config_id = 1');
$db->query("UPDATE malwatch_waf_ip SET external_state = 'none', external_tries = 0, external_at = NULL");
$db->query("DELETE FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");

// Das Nachschlagen stellt jede Adresse ohne Antwort in die Schlange.
$waf->origin_lookup(10);
expect_same('every address waits for the service',
	count_rows("SELECT ip FROM malwatch_waf_ip WHERE external_state = 'pending'"), 3);

expect_same('two of three addresses get an answer', $waf->origin_external(100), 2);
expect_same('one request with every address', count($asked), 1);
expect_same('the key travels in the address', strpos($asked[0][0], 'key=probe-key') !== false, true);
expect_same('the body names the addresses', substr($asked[0][1], 0, 4), 'ips=');
$vpn = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('the service marks VPN, proxy and its operator',
	array($vpn['is_vpn'], $vpn['is_proxy'], $vpn['vpn_operator'], $vpn['external_state']),
	array('y', 'y', 'Beispiel VPN', 'done'));
expect_same('country and provider come from the service because the local one is off',
	array($vpn['country'], (int) $vpn['asn'], $vpn['as_org']), array('DE', 64496, 'Beispiel Netz GmbH'));
expect_same('the Tor list keeps its own answer', $vpn['is_tor'], 'y');
$miss = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '198.51.100.9'");
expect_same('an address the answer left out is tried again later',
	array($miss['external_state'], (int) $miss['external_tries']), array('failed', 1));
$state = $db->queryOneRecord("SELECT * FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");
expect_same('the state counts queries and answers',
	array((int) $state['queries'], (int) $state['entries'], $state['error']), array(3, 2, ''));

// Das Tageslimit ist erreicht: wartende Adressen kommen am nächsten Tag dran.
$db->query("UPDATE malwatch_waf_ip SET external_state = 'pending', external_at = NULL WHERE ip = '198.51.100.9'");
$asked = array();
expect_same('nothing is asked past the daily limit', $waf->origin_external(100), 0);
expect_same('no request went out', count($asked), 0);
expect_same('the address waits for the next day',
	$db->queryOneRecord("SELECT external_state FROM malwatch_waf_ip WHERE ip = '198.51.100.9'")['external_state'], 'limit');

// Ein höheres Limit holt die Adresse zurück, eine abgelehnte Anfrage lässt sie scheitern.
$db->query('UPDATE malwatch_config SET waf_origin_proxycheck_daily = 10 WHERE config_id = 1');
$waf->poster = function ($url, $body, $limit) use (&$asked, $stage) {
	$asked[] = array($url, $body);
	return array(true, file_get_contents($stage . '/tests/fixtures/proxycheck/denied.json'));
};
expect_same('a refused answer gives no address', $waf->origin_external(100), 0);
$failed = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '198.51.100.9'");
expect_same('the address failed once more', array($failed['external_state'], (int) $failed['external_tries']),
	array('failed', 2));
$state = $db->queryOneRecord("SELECT * FROM malwatch_waf_origin_source WHERE source = 'proxycheck'");
expect_same('the error stands in the state, without the key',
	array(strpos($state['error'], 'abgelehnt') !== false, strpos($state['error'], 'probe-key')),
	array(true, false));

// Wird der Dienst abgeschaltet, gehen seine Merkmale und seine Zeile.
$db->query("UPDATE malwatch_config SET waf_origin_net = 'off' WHERE config_id = 1");
$waf->queue('origin_update', array(), 'probe');
$waf->pass();
expect_same('the state of the service is gone',
	count_rows("SELECT source FROM malwatch_waf_origin_source WHERE source = 'proxycheck'"), 0);
$cleared = $db->queryOneRecord("SELECT * FROM malwatch_waf_ip WHERE ip = '192.0.2.10'");
expect_same('its marks left the addresses',
	array($cleared['is_proxy'], $cleared['vpn_operator'], $cleared['external_state']), array('n', '', 'none'));

// --- D: Sperren ---------------------------------------------------------------

$waf->ban_log = $tmp . '/blocked.log';
$db->query('DELETE FROM malwatch_waf_ban');
$db->query('DELETE FROM malwatch_waf_allow');
$db->query("UPDATE malwatch_config SET waf_ban_mode = 'block', waf_ban_score = 50, "
	. 'waf_ban_window_minutes = 10, waf_ban_max = 3 WHERE config_id = 1');
$db->query("UPDATE malwatch_site SET waf_ban_score = 0, waf_ban_trigger = 'y'");
$db->query('DELETE FROM malwatch_waf_hit');
// Zwei Angreifer und ein Besucher mit einem einzelnen Fehlalarm, dazu der Proxy.
foreach (array(array('192.0.2.50', 12, 5, '["930130"]'), array('198.51.100.50', 2, 5, '["941100"]'),
	array('10.50.0.1', 20, 5, '["930130"]')) as $one) {
	for ($i = 0; $i < $one[1]; $i++) {
		$db->query('INSERT INTO malwatch_waf_hit (server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, '
			. "method, uri, path, status, anomaly_score, would_block, logged_in, rules, request_headers) "
			. "VALUES (?, 11, 'beispiel.test', ?, NOW(), ?, 'GET', '/x', '/x', 404, ?, 'y', 'n', ?, '{}')",
			$server, 'probe-ban-' . $one[0] . '-' . $i, $one[0], $one[2], $one[3]);
	}
}
$calls = array();
expect_same('one address crosses the threshold', $waf->ban_scan(), 1);
$ban = $db->queryOneRecord("SELECT * FROM malwatch_waf_ban WHERE ip = '192.0.2.50'");
expect_same('the block is active at level one',
	array($ban['state'], (int) $ban['level'], $ban['source'], (int) $ban['score'], (int) $ban['hits']),
	array('active', 1, 'auto', 60, 12));
expect_same('the reason names points, hits, window, website and rule',
	strpos($ban['reason'], '60 Punkte aus 12 Treffern in 10 Minuten auf beispiel.test, meist Regel 930130') === 0, true);
expect_same('the end of a block lies behind its beginning',
	$ban['until'] > $ban['blocked_at'], true);
expect_same('the visitor with one false alarm stays free',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '198.51.100.50'"), 0);
expect_same('the proxy is never blocked', count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '10.50.0.1'"), 0);
expect_same('a second pass adds nothing', $waf->ban_scan(), 0);

// Die Datei für nginx entsteht, nginx wird geprüft und neu geladen.
$applied = $waf->ban_apply();
expect_same('the file was written', $applied, array(true, ''));
expect_same('nginx was tested and reloaded', $calls, array('nginx_test', 'nginx_reload'));
expect_same('the address stands in the file',
	strpos((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny 192.0.2.50;') !== false, true);
expect_same('a second run changes nothing', $waf->ban_apply(), array(false, ''));

// Eine Konfiguration, die nginx ablehnt, erreicht den laufenden Server nicht.
$db->query('INSERT INTO malwatch_waf_ban (server_id, ip, state, reason, source, created_at, blocked_at, until) '
	. "VALUES (?, '198.51.100.60', 'active', 'von Hand', 'manual', NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR))",
	$server);
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] invalid parameter')));
$calls = array();
$applied = $waf->ban_apply();
expect_same('a refused file is taken back', array($applied[0], strpos($applied[1], 'abgelehnt') !== false),
	array(false, true));
expect_same('nothing was reloaded', $calls, array('nginx_test'));
expect_same('the old file is back',
	strpos((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny 198.51.100.60;'), false);
$answers = array();
$waf->ban_apply();

// Das Zählen der abgewehrten Versuche.
file_put_contents($tmp . '/blocked.log',
	"2026-09-18T10:00:01+02:00 192.0.2.50 403 beispiel.test \"GET /wp-login.php HTTP/1.1\"\n"
	. "2026-09-18T10:00:02+02:00 192.0.2.50 403 beispiel.test \"GET /.env HTTP/1.1\"\n"
	. "2026-09-18T10:00:03+02:00 198.51.100.50 200 beispiel.test \"GET / HTTP/1.1\"\n");
expect_same('one blocked address was counted', $waf->ban_count(), 1);
expect_same('two attempts were turned away',
	(int) $db->queryOneRecord("SELECT denied FROM malwatch_waf_ban WHERE ip = '192.0.2.50'")['denied'], 2);
expect_same('a second pass counts nothing twice', $waf->ban_count(), 0);

// Ablaufen, Sperren von Hand und die Ausnahme, die eine Sperre beendet.
$db->query("UPDATE malwatch_waf_ban SET until = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE ip = '198.51.100.60'");
expect_same('one block ended', $waf->ban_expire(), 1);
$waf->ban_apply();
expect_same('it left the file',
	strpos((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny 198.51.100.60;'), false);

$waf->queue('ban_add', array('ip' => '203.0.113.7', 'permanent' => 'y'), 'probe');
$waf->pass();
$manual = $db->queryOneRecord("SELECT * FROM malwatch_waf_ban WHERE ip = '203.0.113.7'");
expect_same('a manual block is permanent', array($manual['state'], $manual['source'], $manual['until']),
	array('active', 'manual', null));

$waf->queue('ban_allow_add', array('cidr' => '203.0.113.0/24', 'note' => 'Büro'), 'probe');
$waf->pass();
expect_same('the exception ended the block',
	$db->queryOneRecord("SELECT state FROM malwatch_waf_ban WHERE ip = '203.0.113.7'")['state'], 'lifted');
$waf->queue('ban_add', array('ip' => '203.0.113.9'), 'probe');
$waf->pass();
expect_same('an address of the exception is refused',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '203.0.113.9'"), 0);

$waf->queue('ban_site', array('domain_id' => 11, 'score' => 0, 'trigger' => 'n'), 'probe');
$waf->pass();
expect_same('the website triggers nothing any more',
	$db->queryOneRecord('SELECT waf_ban_trigger FROM malwatch_site WHERE parent_domain_id = 11')['waf_ban_trigger'], 'n');
$db->query("UPDATE malwatch_waf_ban SET state = 'expired' WHERE ip = '192.0.2.50'");
expect_same('and so nothing is found any more', $waf->ban_scan(), 0);

$waf->queue('ban_lift', array('ip' => 'all'), 'probe');
$waf->pass();
expect_same('nothing is blocked any more',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE state = 'active'"), 0);
$waf->ban_apply();
expect_same('and the file is empty',
	substr_count((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny '), 0);
$db->query('DELETE FROM malwatch_waf_hit');

$db->query("DELETE FROM malwatch_waf_hit WHERE unique_id = 'probe-origin'");
$waf->cleanup();
expect_same('the address goes with its last hit',
	count_rows("SELECT ip FROM malwatch_waf_ip WHERE ip = '192.0.2.10'"), 0);

// --- summary -----------------------------------------------------------------
waf_remove_dir($tmp);
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_class_probe: alle Prüfungen bestanden\n";
