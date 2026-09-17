<?php
/**
 * Reads an audit log with a staged malwatch against the live website table,
 * as root on the server. Writes nothing.
 *
 *   php waf_ingest_dryrun.php <stage>/ispconfig [audit log]
 */
if (php_sapi_name() !== 'cli' || !isset($argv[1])) {
	fwrite(STDERR, "usage: php waf_ingest_dryrun.php <stage>/ispconfig [audit log]\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
$file = isset($argv[2]) ? $argv[2] : '/var/log/waf/audit.log';

require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require SCRIPT_PATH . '/lib/app.inc.php';
$conf['log_priority'] = 9;

require $stage . '/interface/lib/malwatch_waf_lib.inc.php';
require $stage . '/server/lib/classes/malwatch_waf.inc.php';
$waf = new malwatch_waf();
$stats = $waf->ingest(array('dry_run' => true, 'file' => $file));
printf("Zeilen %d, Treffer %d, unlesbar %d, unbekannte Hosts %d\n",
	$stats['lines'], $stats['hits'], $stats['broken'], $stats['unknown']);
foreach ($stats['sites'] as $site => $count) {
	$row = $app->dbmaster->queryOneRecord('SELECT domain FROM web_domain WHERE domain_id = ?', (int) $site);
	printf("  %-34s %d\n", is_array($row) ? $row['domain'] : '#' . $site, $count);
}
foreach ($stats['unknown_hosts'] as $host => $count) {
	printf("  unbekannt %-34s %d\n", $host, $count);
}
