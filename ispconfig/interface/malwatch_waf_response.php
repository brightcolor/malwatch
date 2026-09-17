<?php

/**
 * The stored response of one hit, as plain text. It is what a website sent
 * back to an attacker's request, so the panel never renders it as HTML: the
 * type is text/plain, the browser may not sniff another one, and a content
 * security policy blocks everything a page could load.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	header('HTTP/1.1 403 Forbidden');
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'");
header('Content-Disposition: inline');
header('Cache-Control: no-store');

$hit_id = $app->functions->intval(isset($_GET['hit']) ? $_GET['hit'] : 0);
$row = $hit_id > 0 ? $app->db->queryOneRecord('SELECT response_file FROM malwatch_waf_hit WHERE hit_id = ?', $hit_id) : null;
$name = is_array($row) ? basename((string) $row['response_file']) : '';
$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/waf/responses/' . $name;
if (!preg_match('/^[A-Za-z0-9._-]+\.html\.gz$/', $name) || !is_file($file)) {
	header('HTTP/1.1 404 Not Found');
	echo $wb['response_missing_txt'], "\n";
	exit;
}
$text = gzdecode((string) file_get_contents($file));
if ($text === false) {
	echo $wb['response_broken_txt'], "\n";
	exit;
}
echo $text;
