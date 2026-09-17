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

	/** The stored licence key, read in onLoad() before the form overwrites it. */
	private $waf_stored_key = '';

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

		$stored = $app->db->queryOneRecord('SELECT waf_origin_maxmind_key FROM malwatch_config WHERE config_id = 1');
		$this->waf_stored_key = is_array($stored) && isset($stored['waf_origin_maxmind_key'])
			? (string) $stored['waf_origin_maxmind_key'] : '';

		parent::onLoad();
	}

	/**
	 * The licence key never leaves the server in clear text: the form shows it
	 * masked, an empty field keeps the stored key, and the checkbox removes it.
	 * onSubmit() runs before the validators, so a missing key stops the save
	 * with a message at the field.
	 */
	public function onSubmit()
	{
		global $app;
		$wb = $this->waf_wb;

		$posted = isset($this->dataRecord['waf_origin_maxmind_key']) ? trim((string) $this->dataRecord['waf_origin_maxmind_key']) : '';
		$clear = isset($this->dataRecord['waf_origin_key_clear']) && (string) $this->dataRecord['waf_origin_key_clear'] === '1';
		if ($clear) {
			$this->dataRecord['waf_origin_maxmind_key'] = '';
		} elseif ($posted === '' || $posted === waf_panel_key_mask($this->waf_stored_key)) {
			$this->dataRecord['waf_origin_maxmind_key'] = $this->waf_stored_key;
		}
		$account = isset($this->dataRecord['waf_origin_maxmind_account']) ? trim((string) $this->dataRecord['waf_origin_maxmind_account']) : '';
		$geo = isset($this->dataRecord['waf_origin_geo']) ? (string) $this->dataRecord['waf_origin_geo'] : 'off';
		if ($geo === 'maxmind' && ($account === '' || (string) $this->dataRecord['waf_origin_maxmind_key'] === '')) {
			$app->tform->errorMessage .= $wb['waf_origin_maxmind_missing_error'] . '<br />';
		}
		parent::onSubmit();
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
		foreach ($servers as $server_id) {
			waf_panel_queue($app, $server_id, 'origin_update', array());
		}

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

		// The stored key stays on the server; the form shows it masked.
		$app->tpl->setVar('waf_origin_maxmind_key', $app->functions->htmlentities(waf_panel_key_mask($this->waf_stored_key)));
		$app->tpl->setVar('origin_key_stored', $this->waf_stored_key === '' ? 0 : 1);

		$clock = waf_panel_clock($app);
		$states = array();
		foreach (waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_origin_source')) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$origin_rows = array();
		foreach (waf_panel_origin_rows($this->waf_wb, $settings, $states, $clock['now']) as $row) {
			$origin_rows[] = array(
				'origin_label' => $app->functions->htmlentities($row['label']),
				'origin_state' => $app->functions->htmlentities($row['state']),
				'origin_failed' => $row['failed'],
			);
		}
		$app->tpl->setLoop('origin_states', $origin_rows);
		$app->tpl->setVar('has_origin_states', count($origin_rows) > 0 ? 1 : 0);

		parent::onShowEnd();
	}
}

$page = new page_action();
$page->onLoad();
