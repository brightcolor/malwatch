<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

// tform_actions::onLoad() reads this from the global scope.
$tform_def_file = 'form/malwatch_config.tform.php';

$app->uses('tpl,tform,tform_actions,functions');
require_once 'lib/malwatch_lib.inc.php';

/**
 * The global settings. There is exactly one record, so the page always edits
 * config_id 1 and creates it when the install SQL never ran.
 */
class page_action extends tform_actions
{
	public function onLoad()
	{
		global $app;

		$row = $app->db->queryOneRecord('SELECT config_id FROM malwatch_config WHERE config_id = 1');
		if (!is_array($row)) {
			$app->db->query('INSERT INTO malwatch_config (config_id, sys_userid, sys_groupid, sys_perm_user, '
				. "sys_perm_group, sys_perm_other) VALUES (1, 1, 1, 'riud', 'riud', '')");
		}

		$this->id = 1;
		$_REQUEST['id'] = 1;

		parent::onLoad();
	}

	public function onShowEnd()
	{
		global $app;

		$config = malwatch_get_config($app);
		$app->tpl->setVar('binary_missing', $config['binary_ready'] ? 0 : 1);
		$app->tpl->setVar('last_signature_update',
			$app->functions->htmlentities(malwatch_datetime(isset($config['last_signature_update']) ? $config['last_signature_update'] : '')));

		$counts = $app->db->queryOneRecord(
			'SELECT (SELECT COUNT(*) FROM malwatch_site) AS sites, '
			. '(SELECT COUNT(*) FROM malwatch_scan) AS scans, '
			. "(SELECT COUNT(*) FROM malwatch_finding WHERE finding_state = 'open') AS findings");

		$app->tpl->setVar('count_sites', is_array($counts) ? $app->functions->intval($counts['sites']) : 0);
		$app->tpl->setVar('count_scans', is_array($counts) ? $app->functions->intval($counts['scans']) : 0);
		$app->tpl->setVar('count_findings', is_array($counts) ? $app->functions->intval($counts['findings']) : 0);

		parent::onShowEnd();
	}

	public function onAfterUpdate()
	{
		global $app;

		// The extension never creates a second settings row. Guarding here
		// keeps a stray insert from producing two rows the server would then
		// read at random.
		$app->db->query('DELETE FROM malwatch_config WHERE config_id != 1');
		parent::onAfterUpdate();
	}
}

$page = new page_action();
$page->onLoad();
