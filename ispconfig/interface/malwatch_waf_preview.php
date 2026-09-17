<?php

/**
 * The preview of an exception as JSON, for the form on the page of a
 * website: how many hits of the period it would have prevented.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_waf_panel.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

echo json_encode(waf_panel_preview($app, $wb, $_GET));
