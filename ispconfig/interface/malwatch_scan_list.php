<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	require_once 'lib/malwatch_lib.inc.php';
	malwatch_stop($app, 'stop_admin_only_txt');
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

		$words = $app->listform->wordbook;
		$counts = malwatch_scan_counts($rec, $words);
		// The date as on every other page; the numbers with their words for
		// the second line on a phone (0.44.0).
		$finished = malwatch_datetime(isset($rec['finished_at']) ? $rec['finished_at'] : '');
		$files = number_format((int) $rec['files_scanned'], 0, ',', '.');
		$new = (int) $rec['new_findings'];
		$rec = parent::prepareDataRow($rec);
		$rec['counts_label'] = $app->functions->htmlentities($counts);
		$rec['finished_at'] = $app->functions->htmlentities($finished);
		$rec['files_scanned'] = $app->functions->htmlentities($files);
		$rec['files_label'] = $app->functions->htmlentities(sprintf($words['files_count_txt'], $files));
		$rec['new_label'] = $new > 0 ? $app->functions->htmlentities(sprintf($words['new_count_txt'], number_format($new, 0, ',', '.'))) : '';

		return $rec;
	}
}

$app->listform_actions = new list_action();
// A column the operator clicks sorts ahead of this order.
$app->listform_actions->SQLOrderBy = 'ORDER BY finished_at DESC, scan_id DESC';
$app->listform_actions->onLoad();
