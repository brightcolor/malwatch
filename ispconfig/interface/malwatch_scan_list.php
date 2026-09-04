<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('listform_actions');

$list_def_file = 'list/malwatch_scan.list.php';
$app->listform_actions->onLoad();
