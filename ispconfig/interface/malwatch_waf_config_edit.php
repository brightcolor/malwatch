<?php

/**
 * Abwehr: the numbers and periods of the WAF on the settings row of malwatch
 * (config_id 1), with a form definition of its own. Paths, response body and
 * emergency stop are shown only. Saving queues apply_settings for every web
 * server, which writes the retention of the audit log into the logrotate
 * file; everything else is read by the cron at its next pass.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

// tform_actions::onLoad() reads this from the global scope.
$tform_def_file = 'form/malwatch_waf_config.tform.php';

$app->uses('tpl,tform,tform_actions,functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';

class page_action extends tform_actions
{
	/** The texts, loaded in onLoad(). */
	private $waf_wb = array();

	/** Set by onAfterUpdate(), shown by onShowEnd(). */
	private $waf_message = '';

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

		// tform loads the same file for its labels; the page needs the texts
		// for its own message.
		$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf_config.lng';
		if (!file_exists($lng_file)) {
			$lng_file = 'lib/lang/en_malwatch_waf_config.lng';
		}
		include $lng_file;
		$this->waf_wb = $wb;

		// After saving the page stays open and says what happens next. The form
		// has one tab, set here as well: tform saves the tab it last showed in
		// this session, and another form page may have changed that meanwhile.
		// The token is left to tform: it checks it while encoding the fields and
		// keeps it valid, and a check here would use it up first.
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			$_REQUEST['next_tab'] = 'waf';
			$_SESSION['s']['form']['tab'] = 'waf';
		}

		parent::onLoad();
	}

	public function onAfterUpdate()
	{
		global $app;
		$wb = $this->waf_wb;

		$servers = waf_panel_web_servers($app);
		foreach ($servers as $server_id) {
			waf_panel_queue($app, $server_id, 'apply_settings', array());
		}
		$this->waf_message = count($servers) > 0 ? $wb['msg_saved_txt'] : $wb['msg_saved_no_server_txt'];

		// The addon keeps exactly one settings row.
		$app->db->query('DELETE FROM malwatch_config WHERE config_id != 1');
		parent::onAfterUpdate();
	}

	public function onShowEnd()
	{
		global $app;
		$wb = $this->waf_wb;

		$settings = waf_panel_settings($app);
		$app->tpl->setVar('waf_audit_log', $app->functions->htmlentities($settings['waf_audit_log']));
		$app->tpl->setVar('waf_conf_dir', $app->functions->htmlentities($settings['waf_conf_dir']));
		$app->tpl->setVar('response_body_line', $app->functions->htmlentities(
			$settings['waf_response_body'] === 'lean' ? $wb['response_lean_txt'] : $wb['response_full_txt']));
		$app->tpl->setVar('emergency_line', $app->functions->htmlentities($settings['waf_emergency'] === 'y'
			? sprintf($wb['emergency_on_txt'], malwatch_datetime($settings['waf_emergency_since']))
			: $wb['emergency_off_txt']));
		$app->tpl->setVar('emergency_on', $settings['waf_emergency'] === 'y' ? 1 : 0);
		// 'error' belongs to tform: onError() puts the messages of the ranges there.
		$app->tpl->setVar('waf_message', $app->functions->htmlentities($this->waf_message));

		parent::onShowEnd();
	}
}

$page = new page_action();
$page->onLoad();
