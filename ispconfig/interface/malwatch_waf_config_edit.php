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

	/** The stored key of proxycheck.io, read in onLoad() before the form overwrites it. */
	private $waf_stored_proxycheck = '';

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

		$stored = $app->db->queryOneRecord(
			'SELECT waf_origin_maxmind_key, waf_origin_proxycheck_key FROM malwatch_config WHERE config_id = 1');
		$this->waf_stored_key = is_array($stored) && isset($stored['waf_origin_maxmind_key'])
			? (string) $stored['waf_origin_maxmind_key'] : '';
		$this->waf_stored_proxycheck = is_array($stored) && isset($stored['waf_origin_proxycheck_key'])
			? (string) $stored['waf_origin_proxycheck_key'] : '';

		parent::onLoad();
	}

	/**
	 * A key never leaves the server in clear text: the form shows it masked, an
	 * empty field keeps the stored key, and the checkbox removes it. That holds
	 * for the licence key of MaxMind and for the key of proxycheck.io.
	 * onSubmit() runs before the validators, so a missing key stops the save
	 * with a message at the field.
	 */
	public function onSubmit()
	{
		global $app;
		$wb = $this->waf_wb;

		$this->dataRecord['waf_origin_maxmind_key'] = waf_panel_key_keep(
			isset($this->dataRecord['waf_origin_maxmind_key']) ? $this->dataRecord['waf_origin_maxmind_key'] : '',
			$this->waf_stored_key,
			isset($this->dataRecord['waf_origin_key_clear']) && (string) $this->dataRecord['waf_origin_key_clear'] === '1');
		$this->dataRecord['waf_origin_proxycheck_key'] = waf_panel_key_keep(
			isset($this->dataRecord['waf_origin_proxycheck_key']) ? $this->dataRecord['waf_origin_proxycheck_key'] : '',
			$this->waf_stored_proxycheck,
			isset($this->dataRecord['waf_origin_proxycheck_clear'])
				&& (string) $this->dataRecord['waf_origin_proxycheck_clear'] === '1');
		foreach (waf_panel_origin_missing($this->dataRecord) as $message) {
			$app->tform->errorMessage .= $wb[$message] . '<br />';
		}
		// Lists come one entry per line and are stored with commas. A message
		// names each entry that cannot be one; it carries what was typed, so it
		// is escaped.
		$lists = waf_config_lists($wb, $this->dataRecord);
		$this->dataRecord = $lists['record'];
		foreach ($lists['errors'] as $message) {
			$app->tform->errorMessage .= $app->functions->htmlentities($message) . '<br />';
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
		$app->tpl->setVar('waf_origin_proxycheck_key',
			$app->functions->htmlentities(waf_panel_key_mask($this->waf_stored_proxycheck)));
		$app->tpl->setVar('origin_proxycheck_stored', $this->waf_stored_proxycheck === '' ? 0 : 1);

		// The dialog "Änderungen prüfen" compares the form with the stored row:
		// lists one entry per line, keys only as their mask. A removed own
		// network weakens the protection, so the dialog marks it.
		$stored_values = malwatch_form_values($app->tform->formDef['tabs']['waf']['fields'],
			$app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
		foreach (waf_settings_lists() as $key => $kind) {
			if (isset($stored_values[$key])) {
				$stored_values[$key] = waf_list_lines($stored_values[$key]);
			}
		}
		// The two numbers of a source carry the name of their source in the dialog.
		$review_labels = array();
		foreach (waf_origin_sources() as $name => $source) {
			foreach (array('min', 'mb') as $part) {
				$review_labels[$source[$part]] = waf_panel_text($wb, $source['urls'] . '_txt', $name) . ', '
					. waf_panel_text($wb, $source[$part] . '_txt', $part);
			}
		}
		$app->tpl->setVar('review_data', $app->functions->htmlentities(malwatch_review_json($stored_values, array(
			'labels' => $review_labels,
			'secrets' => array(
				'waf_origin_maxmind_key' => array('mask' => waf_panel_key_mask($this->waf_stored_key),
					'clear' => 'waf_origin_key_clear'),
				'waf_origin_proxycheck_key' => array('mask' => waf_panel_key_mask($this->waf_stored_proxycheck),
					'clear' => 'waf_origin_proxycheck_clear'),
			),
			'danger' => array('waf_own_networks'),
			'words' => malwatch_review_words($wb),
		))));

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

		// The title of each section says how it is stored.
		foreach (waf_config_summaries($wb, $settings) as $section => $line) {
			$app->tpl->setVar('state_' . $section, $app->functions->htmlentities($line));
		}
		// Buttons for the choices, the shown value checked; the value shown is
		// the stored one, or after a refused save what was sent.
		foreach (waf_config_choices($app->tform->formDef['tabs']['waf']['fields'], $this->dataRecord, $wb) as $key => $rows) {
			$loop = array();
			foreach ($rows as $row) {
				$loop[] = array(
					'choice_value' => $app->functions->htmlentities($row['choice_value']),
					'choice_label' => $app->functions->htmlentities($row['choice_label']),
					'choice_checked' => $row['choice_checked'],
					'choice_id' => $app->functions->htmlentities($row['choice_id']),
				);
			}
			$app->tpl->setLoop('choice_' . $key, $loop);
		}
		// The limits of every number, as the form checks them.
		foreach (waf_settings_limits() as $key => $limit) {
			$app->tpl->setVar('min_' . $key, (int) $limit[0]);
			$app->tpl->setVar('max_' . $key, (int) $limit[1]);
		}
		// The defaults for the marks of adjusted values, lists one entry per line.
		foreach (waf_config_template_defaults() as $name => $value) {
			$app->tpl->setVar($name, $app->functions->htmlentities($value));
		}
		foreach (waf_settings_lists() as $key => $kind) {
			$app->tpl->setVar('lines_' . $key, $app->functions->htmlentities(
				waf_list_lines(isset($this->dataRecord[$key]) ? $this->dataRecord[$key] : '')));
		}
		// The words the script of the page writes into attributes.
		$app->tpl->setVar(malwatch_attr_texts($wb, array('cfg_default_txt', 'cfg_reset_txt', 'cfg_adjusted_txt',
			'cfg_dirty_one_txt', 'cfg_dirty_many_txt', 'cfg_clean_txt', 'cfg_find_txt')));

		parent::onShowEnd();
	}
}

$page = new page_action();
$page->onLoad();
