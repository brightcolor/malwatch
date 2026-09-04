<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

// tform_actions::onLoad() reads this from the global scope. Without it the
// form has no definition and the page dies before it renders anything.
$tform_def_file = 'form/malwatch_site.tform.php';

$app->uses('tpl,tform,tform_actions,functions');
require_once 'lib/malwatch_lib.inc.php';

/**
 * Per website settings.
 *
 * The form is keyed by the website, not by its own row: an operator opens the
 * settings of a site that may never have been configured. The page therefore
 * creates the row on first save instead of asking the operator to create one.
 */
class page_action extends tform_actions
{
	private $domain_id = 0;
	private $web = null;

	public function onLoad()
	{
		global $app;

		$this->domain_id = $app->functions->intval(
			isset($_REQUEST['domain_id']) ? $_REQUEST['domain_id'] : 0);

		if ($this->domain_id < 1 && isset($_REQUEST['id'])) {
			$existing = $app->db->queryOneRecord('SELECT parent_domain_id FROM malwatch_site WHERE site_id = ?',
				$app->functions->intval($_REQUEST['id']));
			if (is_array($existing)) {
				$this->domain_id = $app->functions->intval($existing['parent_domain_id']);
			}
		}
		if ($this->domain_id < 1) {
			$app->error('Ungültige Website.');
		}

		$this->web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $this->domain_id);
		if (!is_array($this->web)) {
			$app->error('Die Website wurde nicht gefunden.');
		}

		// If a settings row exists, edit it; otherwise the form runs in insert
		// mode and onBeforeInsert fills in the website reference.
		$existing = $app->db->queryOneRecord('SELECT site_id FROM malwatch_site WHERE parent_domain_id = ?',
			$this->domain_id);
		if (is_array($existing)) {
			$this->id = $app->functions->intval($existing['site_id']);
			$_REQUEST['id'] = $this->id;
		}

		parent::onLoad();
	}

	public function onShowNew()
	{
		// Reached when no settings row exists yet. tform_actions would
		// otherwise refuse because there is no record to show.
		$this->onShowEnd();
	}

	public function onShowEnd()
	{
		global $app;

		$app->tpl->setVar('domain_id', $this->domain_id);
		$app->tpl->setVar('domain', $app->functions->htmlentities($this->web['domain']));
		$app->tpl->setVar('scan_path', $app->functions->htmlentities(malwatch_scan_path($this->web)));

		$config = malwatch_get_config($app);
		$app->tpl->setVar('global_excludes',
			$app->functions->htmlentities((string) $config['default_excludes']));

		parent::onShowEnd();
	}

	public function onBeforeInsert()
	{
		global $app;

		$this->dataRecord['parent_domain_id'] = $this->domain_id;
		$this->dataRecord['domain'] = (string) $this->web['domain'];
		$this->dataRecord['server_id'] = $app->functions->intval($this->web['server_id']);
		$this->dataRecord['sys_groupid'] = $app->functions->intval($this->web['sys_groupid']);

		parent::onBeforeInsert();
	}

	public function onAfterInsert()
	{
		$this->scheduleNextRun();
		parent::onAfterInsert();
	}

	public function onBeforeUpdate()
	{
		global $app;

		// The website reference is not part of the form and must not be
		// changed by a crafted request.
		$this->dataRecord['parent_domain_id'] = $this->domain_id;
		$this->dataRecord['domain'] = (string) $this->web['domain'];
		$this->dataRecord['server_id'] = $app->functions->intval($this->web['server_id']);

		parent::onBeforeUpdate();
	}

	public function onAfterUpdate()
	{
		$this->scheduleNextRun();
		parent::onAfterUpdate();
	}

	/**
	 * Sets the next run after a schedule change.
	 *
	 * Switching a site from off to daily must produce a due date, otherwise
	 * the cron class would never pick it up and the setting would look active
	 * while nothing ever happens.
	 */
	private function scheduleNextRun()
	{
		global $app;

		$row = $app->db->queryOneRecord('SELECT site_id, schedule, next_run FROM malwatch_site WHERE parent_domain_id = ?',
			$this->domain_id);
		if (!is_array($row)) {
			return;
		}

		if ($row['schedule'] === 'off') {
			$app->db->query('UPDATE malwatch_site SET next_run = NULL WHERE site_id = ?',
				$app->functions->intval($row['site_id']));
			return;
		}
		if ($row['next_run'] === null || $row['next_run'] === '' || $row['next_run'] === '0000-00-00 00:00:00') {
			$app->db->query('UPDATE malwatch_site SET next_run = NOW() WHERE site_id = ?',
				$app->functions->intval($row['site_id']));
		}
	}
}

$page = new page_action();
$page->onLoad();
