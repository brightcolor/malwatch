<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('listform_actions');
require_once 'lib/malwatch_lib.inc.php';

$list_def_file = 'list/malwatch_finding.list.php';

/**
 * The finding list across every website.
 *
 * The only reason for a custom class is the path: shown whole, every row
 * starts with the same twenty characters of /var/www/clients/clientN/webN/
 * and the file name, which is what the reader is looking for, ends up off
 * the right edge of the column.
 */
class list_action extends listform_actions
{
	private $roots = array();

	public function prepareDataRow($rec)
	{
		global $app;

		$rec = parent::prepareDataRow($rec);

		$base = $this->webRoot($app->functions->intval($rec['parent_domain_id']));
		$parts = malwatch_split_path($rec['file_path'], $base);

		$rec['dir'] = $app->functions->htmlentities($parts['dir']);
		$rec['file'] = $app->functions->htmlentities($parts['file']);
		$rec['full_path'] = $app->functions->htmlentities($parts['full']);
		$rec['has_dir'] = $parts['dir'] !== '' ? 1 : 0;
		$rec['severity_class'] = malwatch_severity_class($rec['severity']);
		$rec['has_line'] = $app->functions->intval($rec['line_number']) > 0 ? 1 : 0;

		return $rec;
	}

	/** Caches the scanned directory per website; the list holds many rows. */
	private function webRoot($domain_id)
	{
		global $app;

		if (!isset($this->roots[$domain_id])) {
			$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
			$this->roots[$domain_id] = is_array($web) ? malwatch_scan_path($web) : '';
		}
		return $this->roots[$domain_id];
	}
}

$app->listform_actions = new list_action();
$app->listform_actions->onLoad();
