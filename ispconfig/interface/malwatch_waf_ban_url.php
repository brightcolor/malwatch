<?php

/**
 * The block list for a firewall at the edge, as a plain table of addresses.
 *
 * One door leads here and it takes list=<key>. The key is the whole protection
 * of this address, so a wrong or missing key gets the same answer as a path
 * that does not exist: 404 and one line. Nobody learns from the answer whether
 * a key was close.
 *
 * The answer holds addresses and nothing else. A firewall reads every line as
 * an address, so a comment or a message inside the list would end up as one.
 * Errors therefore never mix into the list; they replace it.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_ban.inc.php';

header('Content-Type: text/plain; charset=us-ascii');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

/** The one answer for everything that is not a valid key. */
function malwatch_ban_url_gone()
{
	header('HTTP/1.1 404 Not Found');
	echo "Diese Adresse gibt es nicht.\n";
	exit;
}

$given = isset($_GET['list']) ? (string) $_GET['list'] : '';

// The shape is checked before the value is compared: a key from a request must
// not reach the database in any other form than the one keys have.
if (!waf_ban_token_ok($given)) {
	malwatch_ban_url_gone();
}

$row = $app->db->queryOneRecord('SELECT waf_ban_token FROM malwatch_config WHERE config_id = 1');
$token = is_array($row) ? (string) $row['waf_ban_token'] : '';
if (!waf_ban_token_ok($token) || !hash_equals($token, $given)) {
	malwatch_ban_url_gone();
}

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/waf/blocked.txt';
if (is_file($file) && is_readable($file)) {
	echo (string) file_get_contents($file);
	exit;
}

// The file is written by the cron. Is it missing - a fresh installation, a
// cleared directory - the addresses come from the database, so the firewall
// never takes an empty list for "nothing is blocked any more".
$ips = array();
$rows = $app->db->queryAllRecords("SELECT ip FROM malwatch_waf_ban WHERE state = 'active' "
	. "AND source IN ('auto','manual') ORDER BY ip");
foreach (is_array($rows) ? $rows : array() as $one) {
	$ips[] = (string) $one['ip'];
}
echo waf_ban_list_text($ips);
