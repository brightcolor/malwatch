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

	/** The state of each website, see malwatch_site_state(). */
	private $states = array();

	public function prepareDataRow($rec)
	{
		global $app;

		// The class comes from the stored value. parent::prepareDataRow()
		// turns "critical" into the word of the list definition ("kritisch"),
		// which malwatch_severity_class() does not know, and every row came
		// out grey.
		$severity_class = malwatch_severity_class(isset($rec['severity']) ? (string) $rec['severity'] : '');
		// The date as on every other page, "10.10.2026 11:57" (0.44.0).
		$last_seen = malwatch_datetime(isset($rec['last_seen']) ? $rec['last_seen'] : '');

		$rec = parent::prepareDataRow($rec);

		$domain_id = $app->functions->intval($rec['parent_domain_id']);
		$base = $this->webRoot($domain_id);
		$parts = malwatch_split_path($rec['file_path'], $base);

		$rec['dir'] = $app->functions->htmlentities($parts['dir']);
		$rec['file'] = $app->functions->htmlentities($parts['file']);
		$rec['full_path'] = $app->functions->htmlentities($parts['full']);
		$rec['has_dir'] = $parts['dir'] !== '' ? 1 : 0;
		$rec['severity_class'] = $severity_class;
		$rec['has_line'] = $app->functions->intval($rec['line_number']) > 0 ? 1 : 0;
		// A website nobody scans any more keeps its findings as they were.
		$rec['site_inactive'] = $this->states[$domain_id] === 'inactive' ? 1 : 0;
		$rec['site_gone'] = $this->states[$domain_id] === 'gone' ? 1 : 0;
		$rec['last_seen'] = $app->functions->htmlentities($last_seen);
		// The rule id may break after its dots and underscores, nowhere else
		// (0.44.0); it is escaped by the list already.
		$rec['rule_id'] = str_replace(array('.', '_'), array('.<wbr>', '_<wbr>'), (string) $rec['rule_id']);
		// While the filter fixes one state, every row would repeat it.
		$rec['show_state'] = $this->stateFiltered() ? 0 : 1;

		return $rec;
	}

	/** Whether the filter above the list fixes one finding state. */
	private function stateFiltered()
	{
		return isset($_SESSION['search']['malwatch_finding']['search_finding_state'])
			&& (string) $_SESSION['search']['malwatch_finding']['search_finding_state'] !== '';
	}

	/**
	 * Caches the scanned directory and the state of each website; the list
	 * holds many rows.
	 */
	private function webRoot($domain_id)
	{
		global $app;

		if (!isset($this->roots[$domain_id])) {
			$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
			$this->roots[$domain_id] = is_array($web) ? malwatch_scan_path($web) : '';
			$this->states[$domain_id] = malwatch_site_state($web);
		}
		return $this->roots[$domain_id];
	}
}

$app->listform_actions = new list_action();

// What still needs attention leads: open findings by default, and within any
// filter the open ones first, the worst first, the newest first. A column the
// operator clicks sorts ahead of this order; "alle" in the state filter is a
// choice the session keeps.
malwatch_list_default_filter($_SESSION['search'], 'malwatch_finding', 'search_finding_state', 'open');
$app->listform_actions->SQLOrderBy = malwatch_finding_list_order();

$app->listform_actions->onLoad();
