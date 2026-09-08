<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
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
 *
 * auto_action and auto_preset_id (the "was soll bei den nächtlichen
 * Prüfungen automatisch passieren" block) are real tform fields and travel
 * through the normal save below like every other column here. Two actions
 * next to that block are not columns at all - creating a named rule
 * selection, and sweeping the existing backlog a chosen selection would
 * cover - and are handled separately, before tform_actions ever sees the
 * request; see onLoad().
 */
class page_action extends tform_actions
{
	/** Set by handle_save_preset()/handle_apply_existing(), read in onShowEnd(). */
	private $malwatch_message = '';
	private $malwatch_error = '';

	/** The $wb loaded in onLoad(), reused in onShowEnd() without loading it twice. */
	private $malwatch_wb = array();

	/** Set by onLoad() for "Zusammenstellung speichern"; read in onUpdate(). */
	private $malwatch_preset_only = false;

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

		// Included rather than fetched through $app->load_language_file() -
		// that method keeps its result in a private property of its own, so
		// $wb would stay unset here (see malwatch_site_show.php and
		// malwatch_quarantine_list.php for the same reasoning). Loaded
		// unconditionally, before the branch below, since both the custom
		// actions and onShowEnd() need it.
		$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_config.lng';
		if (!file_exists($lng_file)) {
			$lng_file = 'lib/lang/en_malwatch_config.lng';
		}
		include $lng_file;
		$this->malwatch_wb = $wb;

		// save_preset and apply_existing are not tform fields - the first
		// inserts a malwatch_auto_preset row, the second reads
		// malwatch_finding and queues quarantine jobs. Both are handled here,
		// ahead of parent::onLoad(), because tform has no field to hang them
		// on.
		//
		// What this block must not do is return. It used to end in
		// $this->onShow() and skip parent::onLoad() entirely, so loadFormDef()
		// never ran and onShowEdit() went on to $app->tform->getHTML() over a
		// form definition that had never been loaded. Falling through fixes
		// that for both actions - what the two do differ in is whether the
		// form is saved along the way, see onUpdate().
		//
		// The token is checked here and only here: auth::csrf_token_check()
		// consumes the token it just accepted, and tform_actions runs no check
		// of its own - a second call in the same request would answer a
		// perfectly valid POST with "CSRF attempt blocked".
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['malwatch_action']) && $_POST['malwatch_action'] !== '') {
			$app->auth->csrf_token_check('POST');
			$action = (string) $_POST['malwatch_action'];
			if ($action === 'save_preset') {
				$this->handle_save_preset($wb);

				// Eine Regelauswahl unter einem Namen sichern heißt genau das
				// und nichts weiter - siehe onUpdate(), das dieser Schalter
				// abbestellt.
				$this->malwatch_preset_only = true;
			} elseif ($action === 'apply_existing') {
				// Runs before the save below, not after: the number in the
				// confirmation the operator just agreed to was counted from
				// the setting as it stands, and the sweep has to cover that
				// same set - not one being changed in the very same click.
				//
				// Hier fällt der Request bewusst bis in den Speichervorgang
				// durch: „auf die bestehenden Funde anwenden" steht unter den
				// Einstellungen, und ein Feld, das der Bediener im selben Zug
				// geändert hat - „Abbruch nach Stunden" von 6 auf 12 - wurde
				// vorher wortlos verworfen.
				$this->handle_apply_existing($wb);

				// next_tab keeps tform_actions::onUpdate() from redirecting to
				// status.php once the save went through; it only redirects when
				// next_tab is empty. Without it the message set further down
				// would be written onto a page nobody ever sees. The form has
				// exactly one tab, so naming it changes nothing else.
				$_REQUEST['next_tab'] = 'settings';
			}
		}

		parent::onLoad();
	}

	/** Creates a new named rule selection from the "eigene Auswahl" checklist. */
	private function handle_save_preset($wb)
	{
		global $app;

		$name = isset($_POST['preset_name']) ? trim((string) $_POST['preset_name']) : '';

		// Whitelisted against the live catalogue: a posted id naming no real
		// rule - stale, or tampered - would otherwise sit in the preset
		// forever, silently matching nothing once it is chosen.
		$known = $app->db->queryAllRecords('SELECT rule_id FROM malwatch_rule');
		$known_ids = array();
		foreach ((array) $known as $row) {
			$known_ids[$row['rule_id']] = true;
		}
		$rule_ids = array();
		if (isset($_POST['rule_ids']) && is_array($_POST['rule_ids'])) {
			foreach ($_POST['rule_ids'] as $id) {
				$id = (string) $id;
				if (isset($known_ids[$id])) {
					$rule_ids[$id] = true;
				}
			}
		}
		$rule_ids = array_keys($rule_ids);

		if ($name === '') {
			$this->malwatch_error = $wb['err_preset_name_empty_txt'];
			return;
		}
		if (count($rule_ids) === 0) {
			$this->malwatch_error = $wb['err_preset_no_rules_txt'];
			return;
		}

		// A plain insert, not datalogInsert: nothing on any server watches
		// this table for changes to sync down - both the cron
		// (malwatch_actions::auto_paths()) and this page read it directly.
		$app->db->query(
			'INSERT INTO malwatch_auto_preset (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
			. 'sys_perm_other, preset_name, rule_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			$app->functions->intval($_SESSION['s']['user']['userid']),
			$app->functions->intval($_SESSION['s']['user']['default_group']),
			'riud', 'r', '', substr($name, 0, 64), implode(',', $rule_ids), date('Y-m-d H:i:s'));

		// Not htmlentities'd here: onShowEnd() escapes the whole message
		// once, below. Escaping the name here too would turn a "&" in it
		// into "&amp;amp;" on screen.
		$this->malwatch_message = sprintf($wb['msg_preset_saved_txt'], $name);
	}

	/**
	 * Sweeps the existing backlog of open findings that the active
	 * automatic-action setting would cover if it reached back further than
	 * new findings - which is exactly what it does not do on its own
	 * (malwatch_actions::auto_paths() reads new_findings() only). This is
	 * the manual bridge the settings text next to the button promises.
	 */
	private function handle_apply_existing($wb)
	{
		global $app;

		$config = malwatch_get_config($app);
		$mode = (string) $config['auto_action'];
		$rule_ids = array();
		if ($mode === 'preset') {
			$preset_id = $app->functions->intval($config['auto_preset_id']);
			$preset = $preset_id > 0 ? $app->db->queryOneRecord(
				'SELECT rule_ids FROM malwatch_auto_preset WHERE preset_id = ?', $preset_id) : null;
			if (!is_array($preset)) {
				// Same fallback auto_paths() itself uses for a preset that no
				// longer exists: move nothing rather than guess.
				$mode = 'none';
			} else {
				foreach (explode(',', (string) $preset['rule_ids']) as $id) {
					$id = trim($id);
					if ($id !== '') {
						$rule_ids[] = $id;
					}
				}
			}
		}

		$by_domain = malwatch_auto_mode_paths_by_domain($app, $mode, $rule_ids);
		if (count($by_domain) === 0) {
			$this->malwatch_error = $wb['err_apply_existing_none_txt'];
			return;
		}

		$queued_files = 0;
		$queued_sites = 0;
		$skipped_sites = 0;
		foreach ($by_domain as $domain_id => $paths) {
			$result = malwatch_queue_quarantine($app, $domain_id, $paths);
			if (is_int($result)) {
				$queued_files += $result;
				$queued_sites++;
			} else {
				$skipped_sites++;
			}
		}

		$this->malwatch_message = sprintf($wb['msg_apply_existing_txt'],
			number_format($queued_files, 0, ',', '.'), number_format($queued_sites, 0, ',', '.'));
		if ($skipped_sites > 0) {
			$this->malwatch_message .= ' ' . sprintf($wb['msg_apply_existing_skipped_txt'],
				number_format($skipped_sites, 0, ',', '.'));
		}
	}

	/**
	 * Saves the form - unless the click that got here was "Zusammenstellung
	 * speichern".
	 *
	 * That button posts the whole page, like every other button in this
	 * panel, and the template's own script has meanwhile set the two hidden
	 * fields to auto_action='preset' and auto_preset_id=0 - that is what
	 * clicking "Eigene Auswahl" means before a selection has a name.
	 * malwatch_actions::auto_paths() reads exactly that pair as "moves
	 * nothing", so saving the form here would switch off the automatic
	 * removal that was running until this click, with nothing anywhere
	 * saying so: the screen shows "Die Zusammenstellung wurde gespeichert",
	 * and the radio still looks selected.
	 *
	 * Whoever saves a rule selection under a name expects a saved rule
	 * selection and nothing else. The settings are shown again from the
	 * database, unchanged, with the new selection below them as its own
	 * choice - ready to be picked and saved on purpose.
	 */
	public function onUpdate()
	{
		if ($this->malwatch_preset_only) {
			$this->onShow();
			return;
		}
		parent::onUpdate();
	}

	public function onBeforeUpdate()
	{
		global $app;

		// A preset the operator never actually pointed the radio at (id 0)
		// and one that has meanwhile been deleted both mean the same thing
		// to auto_paths(): move nothing. Clamping here keeps the stored pair
		// honest instead of quietly pointing at a row that is not there -
		// the template's own script keeps auto_preset_id in step with
		// auto_action on a normal click, this is only for a posted value
		// that did not come from it.
		if (isset($_POST['auto_action']) && $_POST['auto_action'] === 'preset') {
			$preset_id = $app->functions->intval(isset($_POST['auto_preset_id']) ? $_POST['auto_preset_id'] : 0);
			$exists = $preset_id > 0 ? $app->db->queryOneRecord(
				'SELECT preset_id FROM malwatch_auto_preset WHERE preset_id = ?', $preset_id) : null;
			if (!is_array($exists)) {
				$_POST['auto_preset_id'] = 0;
			}
		} else {
			$_POST['auto_preset_id'] = 0;
		}

		parent::onBeforeUpdate();
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

		$this->show_auto_action($config);

		$app->tpl->setVar('message', $app->functions->htmlentities($this->malwatch_message));
		$app->tpl->setVar('error', $app->functions->htmlentities($this->malwatch_error));

		// save_preset and apply_existing check the token themselves (see
		// onLoad()), since both bypass tform_actions' own save path - so a
		// fresh one has to be handed back for the next click, the same way
		// malwatch_site_show.php and malwatch_quarantine_list.php do it.
		$csrf = $app->auth->csrf_token_get('malwatch_config_edit');
		$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
		$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

		parent::onShowEnd();
	}

	/**
	 * Everything the "was soll bei den nächtlichen Prüfungen automatisch
	 * passieren" block needs: which choice is active, how many rules and
	 * how many currently open findings each one covers, the saved presets as
	 * their own choices, the full rule catalogue for building a new one, and
	 * the preview for "auf die bestehenden Funde anwenden".
	 */
	private function show_auto_action($config)
	{
		global $app;
		$wb = $this->malwatch_wb;

		$active_mode = (string) $config['auto_action'];
		$active_preset_id = $app->functions->intval($config['auto_preset_id']);

		$app->tpl->setVar('auto_action', $app->functions->htmlentities($active_mode !== '' ? $active_mode : 'none'));
		$app->tpl->setVar('auto_preset_id', $active_preset_id);
		$app->tpl->setVar('auto_none_checked', ($active_mode === 'none' || $active_mode === '') ? 1 : 0);
		$app->tpl->setVar('auto_safe_checked', $active_mode === 'safe' ? 1 : 0);
		$app->tpl->setVar('auto_critical_checked', $active_mode === 'critical' ? 1 : 0);

		$rule_total_row = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_rule');
		$rule_total = is_array($rule_total_row) ? $app->functions->intval($rule_total_row['n']) : 0;
		$safe_rules_row = $app->db->queryOneRecord("SELECT COUNT(*) AS n FROM malwatch_rule WHERE auto_safe = 'y'");
		$safe_rules = is_array($safe_rules_row) ? $app->functions->intval($safe_rules_row['n']) : 0;
		$critical_rules_row = $app->db->queryOneRecord("SELECT COUNT(*) AS n FROM malwatch_rule WHERE severity = 'critical'");
		$critical_rules = is_array($critical_rules_row) ? $app->functions->intval($critical_rules_row['n']) : 0;

		$app->tpl->setVar('rule_total', $rule_total);
		$app->tpl->setVar('safe_count', $app->functions->htmlentities(sprintf($wb['rule_count_txt'],
			number_format($safe_rules, 0, ',', '.'), number_format($rule_total, 0, ',', '.'),
			number_format(malwatch_auto_mode_finding_count($app, 'safe'), 0, ',', '.'))));
		$app->tpl->setVar('critical_count', $app->functions->htmlentities(sprintf($wb['rule_count_txt'],
			number_format($critical_rules, 0, ',', '.'), number_format($rule_total, 0, ',', '.'),
			number_format(malwatch_auto_mode_finding_count($app, 'critical'), 0, ',', '.'))));

		// --- Saved presets, each its own "Möglichkeit" ------------------------
		$presets = $app->db->queryAllRecords('SELECT * FROM malwatch_auto_preset ORDER BY preset_name ASC, preset_id ASC');
		$preset_rows = array();
		$matched_active_preset = false;
		foreach ((array) $presets as $preset) {
			$preset_id = $app->functions->intval($preset['preset_id']);
			$rule_ids = array();
			foreach (explode(',', (string) $preset['rule_ids']) as $id) {
				$id = trim($id);
				if ($id !== '') {
					$rule_ids[] = $id;
				}
			}

			// Counted against the live catalogue, not the stored list as
			// is: a rule the scanner has since dropped would otherwise
			// inflate "N von 48 Prüfungen" with checks that no longer run.
			$live_rule_count = 0;
			if (count($rule_ids) > 0) {
				$placeholders = implode(',', array_fill(0, count($rule_ids), '?'));
				$live_row = call_user_func_array(array($app->db, 'queryOneRecord'), array_merge(
					array("SELECT COUNT(*) AS n FROM malwatch_rule WHERE rule_id IN ($placeholders)"), $rule_ids));
				$live_rule_count = is_array($live_row) ? $app->functions->intval($live_row['n']) : 0;
			}

			$is_checked = ($active_mode === 'preset' && $preset_id === $active_preset_id);
			if ($is_checked) {
				$matched_active_preset = true;
			}

			$preset_rows[] = array(
				'preset_id' => $preset_id,
				'radio_value' => 'preset_' . $preset_id,
				'name' => $app->functions->htmlentities((string) $preset['preset_name']),
				'count_line' => $app->functions->htmlentities(sprintf($wb['rule_count_txt'],
					number_format($live_rule_count, 0, ',', '.'), number_format($rule_total, 0, ',', '.'),
					number_format(malwatch_auto_mode_finding_count($app, 'preset', $rule_ids), 0, ',', '.'))),
				'is_checked' => $is_checked ? 1 : 0,
			);
		}
		$app->tpl->setLoop('presets', $preset_rows);
		$app->tpl->setVar('has_presets', count($preset_rows) > 0 ? 1 : 0);

		// auto_action=preset with an id that matches no saved preset above
		// (0, or one meanwhile deleted) means the ad-hoc editor itself is
		// what is active - the same state malwatch_auto_mode_paths_by_domain()
		// already treats as "preset with nothing to go by".
		$app->tpl->setVar('preset_new_checked', ($active_mode === 'preset' && !$matched_active_preset) ? 1 : 0);

		// --- Full rule catalogue for the "eigene Auswahl" checklist -----------
		// Ordered by how many open findings a rule has right now, not
		// alphabetically: building a selection is about deciding what to do
		// with what is actually firing today, and that is what belongs in
		// front of the "alle anzeigen" fold.
		$rules = $app->db->queryAllRecords(
			'SELECT r.rule_id, r.title, COALESCE(f.n, 0) AS finding_count FROM malwatch_rule r '
			. 'LEFT JOIN (SELECT rule_id, COUNT(*) AS n FROM malwatch_finding '
			. "WHERE finding_state = 'open' GROUP BY rule_id) f ON f.rule_id = r.rule_id "
			. 'ORDER BY finding_count DESC, r.title ASC, r.rule_id ASC');

		$rule_rows = array();
		$index = 0;
		foreach ((array) $rules as $row) {
			$rule_rows[] = array(
				'rule_id' => $app->functions->htmlentities((string) $row['rule_id']),
				'title' => $app->functions->htmlentities((string) $row['title'] !== '' ? (string) $row['title'] : (string) $row['rule_id']),
				'finding_count' => $app->functions->htmlentities(
					sprintf($wb['rule_finding_count_txt'], number_format($app->functions->intval($row['finding_count']), 0, ',', '.'))),
				// First five visible, the rest behind "alle anzeigen" - the
				// list runs to several dozen rules and showing all of them
				// unconditionally would bury the two-sentence choices above
				// it in checkboxes.
				'is_extra' => $index >= 5 ? 1 : 0,
			);
			$index++;
		}
		$app->tpl->setLoop('rules', $rule_rows);
		$app->tpl->setVar('show_all_rules', $app->functions->htmlentities(sprintf($wb['show_all_rules_txt'], $rule_total)));

		// --- "Auf die bestehenden Funde anwenden" -----------------------------
		$apply_mode = $active_mode;
		$apply_rule_ids = array();
		if ($apply_mode === 'preset') {
			if ($active_preset_id > 0) {
				$apply_preset = $app->db->queryOneRecord(
					'SELECT rule_ids FROM malwatch_auto_preset WHERE preset_id = ?', $active_preset_id);
				if (is_array($apply_preset)) {
					foreach (explode(',', (string) $apply_preset['rule_ids']) as $id) {
						$id = trim($id);
						if ($id !== '') {
							$apply_rule_ids[] = $id;
						}
					}
				} else {
					$apply_mode = 'none';
				}
			} else {
				$apply_mode = 'none';
			}
		}
		$apply_count = $apply_mode !== 'none' ? malwatch_auto_mode_finding_count($app, $apply_mode, $apply_rule_ids) : 0;
		$app->tpl->setVar('has_apply_existing', $apply_count > 0 ? 1 : 0);
		if ($apply_count > 0) {
			$formatted = number_format($apply_count, 0, ',', '.');
			$app->tpl->setVar('apply_existing_intro', $app->functions->htmlentities(sprintf($wb['apply_existing_intro_txt'], $formatted)));
			$app->tpl->setVar('confirm_apply_existing', $app->functions->htmlentities(sprintf($wb['confirm_apply_existing_txt'], $formatted)));
		}
	}
}

$page = new page_action();
$page->onLoad();
