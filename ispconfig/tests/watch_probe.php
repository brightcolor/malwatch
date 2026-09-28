<?php
/**
 * Runs the watch over the scanner (malwatch_waf::watch(), waf-switch watch)
 * against a scratch database on the server, as root:
 *
 *   php watch_probe.php <stage>/ispconfig <database>
 *
 * The same scratch database waf_class_probe.php uses, with sys_cron among its
 * tables; the probe refuses the ISPConfig database. The lock file of cron.php,
 * the state of the watch and the log lie in a temporary directory, and mails go
 * to a recorder.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[2])) {
	fwrite(STDERR, "usage: php watch_probe.php <stage>/ispconfig <database>\n");
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

$tmp = sys_get_temp_dir() . '/mw_watch_probe_' . getmypid();
mkdir($tmp, 0700);
$conf['log_file'] = $tmp . '/ispconfig.log';
$conf['log_priority'] = LOGLEVEL_WARN;
// No cron.php of ISPConfig in the probe's world, until a case puts one there.
$conf['temppath'] = $tmp;

// The zones as waf-switch has them: ISPConfig writes the end of a scan in its
// own zone ($conf['timezone']), waf-switch runs in the zone of the server.
$ispconfig_zone = new DateTimeZone((string) $conf['timezone'] !== '' ? (string) $conf['timezone'] : 'UTC');
$server_zone = trim((string) @file_get_contents('/etc/timezone'));
if ($server_zone !== '') {
	date_default_timezone_set($server_zone);
}

/** The Unix time $time as ISPConfig writes the end of a scan. */
function scan_end_text($time)
{
	global $ispconfig_zone;
	$moment = new DateTime('@' . (int) $time);
	$moment->setTimezone($ispconfig_zone);
	return $moment->format('Y-m-d H:i:s');
}

require_once $stage . '/interface/lib/malwatch_waf_lib.inc.php';
require_once $stage . '/interface/lib/malwatch_waf_origin.inc.php';
require_once $stage . '/interface/lib/malwatch_waf_ban.inc.php';
require_once $stage . '/server/lib/classes/malwatch_helper.inc.php';
require_once $stage . '/server/lib/classes/malwatch_waf.inc.php';
$app->malwatch_helper = new malwatch_helper();

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$server = (int) $conf['server_id'];
$db->query('INSERT IGNORE INTO malwatch_config (config_id) VALUES (1)');
$saved = $db->queryOneRecord('SELECT admin_email, sender_email FROM malwatch_config WHERE config_id = 1');
$db->query("UPDATE malwatch_config SET admin_email = 'admin@probe.test', sender_email = 'malwatch@probe.test' WHERE config_id = 1");

$waf = new malwatch_waf();
$waf->paths = array('vhost_dir' => $tmp . '/vhosts', 'state_dir' => $tmp . '/state');
$mails = array();
$waf->mailer = function ($to, $subject, $body) use (&$mails) {
	$mails[] = array('to' => $to, 'subject' => $subject, 'body' => $body);
};

// Everything wrong at once: a lock without a process, a crash, a job waiting
// for five hours, a daily website three days behind.
$db->query("DELETE FROM sys_cron WHERE name = 'cronjob_malwatch'");
$db->query("INSERT INTO sys_cron (name, last_run, next_run, running) VALUES ('cronjob_malwatch', "
	. 'NOW() - INTERVAL 30 MINUTE, NOW() - INTERVAL 29 MINUTE, 1)');
$db->query('DELETE FROM malwatch_job');
$db->query("INSERT INTO malwatch_job (server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, "
	. "options, created_at) VALUES (?, 11, 'spaet.test', '/nonexistent', 'schedule', 'scan', 'pending', '{}', "
	. 'NOW() - INTERVAL 5 HOUR)', $server);
$db->query('DELETE FROM malwatch_site');
$db->query('DELETE FROM web_domain');
$db->query("INSERT INTO web_domain (domain_id, server_id, parent_domain_id, type, domain, subdomain, active, sys_groupid, "
	. "nginx_directives, document_root) VALUES (11, ?, 0, 'vhost', 'spaet.test', 'none', 'y', 1, '', '/var/www/spaet.test')",
	$server);
$scanned = time() - 3 * 86400;
$db->query("INSERT INTO malwatch_site (server_id, parent_domain_id, domain, scan_days, last_run, next_run) VALUES "
	. "(?, 11, 'spaet.test', 1, ?, NOW() - INTERVAL 2 DAY)", $server, scan_end_text($scanned));
expect_same('the guard notes a crash', $waf->record_cron_crash('probe.php:1: Allowed memory size exhausted', 7), true);
// The watch has known the daily interval of the website for a month; a plan it
// had not seen yet would get its full time first.
file_put_contents($tmp . '/state/waf/watch.json', json_encode(array('kinds' => array(), 'since' => 0, 'mailed_at' => 0,
	'crash_reported' => 0, 'plans' => array('spaet.test' => array('days' => 1, 'since' => time() - 30 * 86400)))));

$first = $waf->watch();
$row = $db->queryOneRecord("SELECT running FROM sys_cron WHERE name = 'cronjob_malwatch'");
expect_same('first run: the problems', $first['kinds'], array('stale', 'crash', 'pending', 'overdue'));
expect_same('first run: the lock is free', (int) $row['running'], 0);
expect_same('first run: one mail to the admin address', array(count($mails), $mails[0]['to'], $mails[0]['subject'],
	strpos($mails[0]['body'], 'spaet.test') !== false, $first['mail']),
	array(1, 'admin@probe.test', 'malwatch auf ' . php_uname('n') . ': 4 Probleme mit dem Scanner', true, 'problem'));
$log = (string) @file_get_contents($conf['log_file']);
expect_same('first run: the problems stand in the log', substr_count($log, 'malwatch-Wache: '), 4);
expect_same('first run: the last scan in the clock of the server', strpos(implode("\n", $first['problems']),
	'spaet.test (zuletzt ' . date('d.m.Y H:i', $scanned) . ')') !== false, true);

// The next run: the cron of ISPConfig ran the freed job in the meantime, the
// crash still pauses; nothing new to mail.
$db->query("UPDATE sys_cron SET last_run = NOW(), next_run = NOW() + INTERVAL 1 MINUTE WHERE name = 'cronjob_malwatch'");
$second = $waf->watch();
expect_same('second run: the rest of the problems', $second['kinds'], array('crash', 'pending', 'overdue'));
expect_same('second run: no second mail', array(count($mails), $second['mail']), array(1, ''));

// All well again once the pause is over: the all-clear.
$db->query('DELETE FROM malwatch_job');
$db->query('UPDATE malwatch_site SET last_run = ? WHERE parent_domain_id = 11', scan_end_text(time()));
$db->query("UPDATE sys_cron SET last_run = NOW(), next_run = NOW() + INTERVAL 1 MINUTE, running = 0 WHERE name = 'cronjob_malwatch'");
file_put_contents($tmp . '/state/waf/cron-crash.json', json_encode(array('time' => time() - 3600,
	'text' => 'probe.php:1: Allowed memory size exhausted', 'pause_until' => time() - 3000)));
$third = $waf->watch();
expect_same('third run: all well', array($third['kinds'], strpos($third['lines'][0], 'Alles in Ordnung') === 0), array(array(), true));
expect_same('third run: the all-clear', array(count($mails), $mails[1]['subject'], $third['mail']),
	array(2, 'malwatch auf ' . php_uname('n') . ': Scanner wieder in Ordnung', 'clear'));
$fourth = $waf->watch();
expect_same('fourth run: quiet', array(count($mails), $fourth['mail']), array(2, ''));

// A long run while cron.php of ISPConfig still holds its lock: reported, left alone.
file_put_contents($tmp . '/.ispconfig_cron_lock', (string) getmypid());
$db->query("UPDATE sys_cron SET last_run = NOW() - INTERVAL 30 MINUTE, running = 1 WHERE name = 'cronjob_malwatch'");
$busy = $waf->watch();
$row = $db->queryOneRecord("SELECT running FROM sys_cron WHERE name = 'cronjob_malwatch'");
expect_same('while cron.php works: only a report', array($busy['kinds'], $busy['release'], (int) $row['running']),
	array(array('busy'), false, 1));

// Another limit from the settings: with an hour the same lock is not stuck yet.
$db->query('UPDATE malwatch_config SET waf_watch_stale_minutes = 60 WHERE config_id = 1');
@unlink($tmp . '/.ispconfig_cron_lock');
$patient = $waf->watch();
expect_same('another limit from the settings', $patient['kinds'], array());
$db->query('UPDATE malwatch_config SET waf_watch_stale_minutes = 15 WHERE config_id = 1');

// A new interval gets its full time: every 2 days from now on, the last scan a
// week back, and the watch stays quiet; the state file keeps when it saw it.
$db->query('UPDATE malwatch_site SET scan_days = 2, last_run = ?, next_run = NOW() + INTERVAL 1 DAY WHERE parent_domain_id = 11',
	scan_end_text(time() - 7 * 86400));
$db->query("UPDATE sys_cron SET last_run = NOW(), next_run = NOW() + INTERVAL 1 MINUTE, running = 0 WHERE name = 'cronjob_malwatch'");
$switched = $waf->watch();
$state = json_decode((string) file_get_contents($tmp . '/state/waf/watch.json'), true);
expect_same('a new interval: no alarm', $switched['kinds'], array());
expect_same('a new interval: noted in the state file', array($state['plans']['spaet.test']['days'],
	abs($state['plans']['spaet.test']['since'] - time()) < 60), array(2, true));
// Three days later by the clock of the plan, still without a scan: late.
$state['plans']['spaet.test']['since'] = time() - 3 * 86400;
file_put_contents($tmp . '/state/waf/watch.json', json_encode($state));
expect_same('the new interval ran out without a scan', $waf->watch()['kinds'], array('overdue'));
// A website with 0 days is none of the watch's business.
$db->query('UPDATE malwatch_site SET scan_days = 0 WHERE parent_domain_id = 11');
$off = $waf->watch();
$state = json_decode((string) file_get_contents($tmp . '/state/waf/watch.json'), true);
expect_same('0 days: quiet, and gone from the plans', array($off['kinds'], $state['plans']), array(array(), array()));

$db->query("DELETE FROM sys_cron WHERE name = 'cronjob_malwatch'");
$db->query('DELETE FROM malwatch_job');
$db->query('DELETE FROM malwatch_site');
$db->query('DELETE FROM web_domain');
if (is_array($saved)) {
	$db->query('UPDATE malwatch_config SET admin_email = ?, sender_email = ? WHERE config_id = 1',
		$saved['admin_email'], $saved['sender_email']);
}
exec('rm -rf ' . escapeshellarg($tmp));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "watch_probe: OK\n";
