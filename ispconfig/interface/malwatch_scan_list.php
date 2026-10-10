<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('listform_actions');
require_once 'lib/malwatch_lib.inc.php';

$list_def_file = 'list/malwatch_scan.list.php';

/**
 * The history of finished scans, the newest first.
 *
 * The custom class writes the finding counts as words ("3 kritisch · 8 hoch").
 */
class list_action extends listform_actions
{
	public function prepareDataRow($rec)
	{
		global $app;

		$counts = malwatch_scan_counts($rec, $app->listform->wordbook);
		$rec = parent::prepareDataRow($rec);
		$rec['counts_label'] = $app->functions->htmlentities($counts);

		return $rec;
	}
}

$app->listform_actions = new list_action();
// A column the operator clicks sorts ahead of this order.
$app->listform_actions->SQLOrderBy = 'ORDER BY finished_at DESC, scan_id DESC';
$app->listform_actions->onLoad();
