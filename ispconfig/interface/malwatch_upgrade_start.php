<?php

/**
 * The page "Updates" of one website: every WordPress core, plugin and theme
 * with a newer release at wordpress.org, grouped by the folder of its
 * installation, a target version per row, a dry run and the start - for every
 * folder at once or for one.
 *
 * Reached as malwatch_upgrade_start.php?id=<domain_id>, optionally with
 * &software_id=<id> to preselect one row. id=, the name malwatch_site_show.php
 * reads as well (check_wiring.sh, check 34).
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Included, see malwatch_repair_start.php for why load_language_file() would
// leave $wb empty here.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_upgrade.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_upgrade.lng';
}
include $lng_file;

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
if ($domain_id < 1) {
	die($wb['err_invalid_site_txt']);
}
$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
if (!is_array($web)) {
	die($wb['err_site_not_found_txt']);
}
$preselect = $app->functions->intval(isset($_REQUEST['software_id']) ? $_REQUEST['software_id'] : 0);

$message = '';
$error = '';

// --- Actions -----------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';
	if ($action === 'upgrade' || $action === 'upgrade_dry') {
		$choices = array();
		$selected = isset($_POST['selected']) && is_array($_POST['selected']) ? $_POST['selected'] : array();
		$versions = isset($_POST['version']) && is_array($_POST['version']) ? $_POST['version'] : array();
		foreach ($selected as $software_id) {
			$software_id = $app->functions->intval($software_id);
			if ($software_id > 0 && isset($versions[$software_id])) {
				$choices[$software_id] = (string) $versions[$software_id];
			}
		}
		// The buttons of a folder name it; the buttons below every folder
		// leave it empty.
		$folder = isset($_POST['folder']) ? (string) $_POST['folder'] : '';
		// malwatch_queue_upgrade() accepts only versions this page offers.
		$result = malwatch_queue_upgrade($app, $domain_id, $choices, $action === 'upgrade_dry', $wb, $folder);
		if (is_int($result)) {
			$message = sprintf($action === 'upgrade_dry' ? $wb['msg_dry_txt'] : $wb['msg_queued_txt'], $result);
		} else {
			$error = $result;
		}
	}
}

// --- Rows --------------------------------------------------------------------
list($installs, $hidden) = malwatch_upgrade_candidates($app, $domain_id, $wb);
$scan_base = malwatch_scan_path($web);

$blocks = array();
$selected_count = 0;
$row_count = 0;
foreach ($installs as $install) {
	$rows = array();
	$block_count = 0;
	foreach ($install['rows'] as $row) {
		// The options go out as one escaped string: the template loops over
		// installations and rows already, and every value in it is escaped
		// here. The short list only: with every release in every select a
		// large website sent 25,000 options, and select2 kept the page busy
		// for seconds. "Weitere Versionen laden" at its end fetches the rest
		// of this row from malwatch_upgrade_versions.php.
		$options_html = '';
		$default_closes = '';
		foreach ($row['offers']['short'] as $choice) {
			$is_default = $choice['version'] === $row['offers']['default'];
			if ($is_default) {
				$default_closes = $choice['closes'];
			}
			$options_html .= '<option value="' . $app->functions->htmlentities($choice['version']) . '"'
				. ' data-closes="' . $app->functions->htmlentities($choice['closes']) . '"'
				. ($is_default ? ' selected' : '') . '>'
				. $app->functions->htmlentities($choice['label']) . '</option>';
		}
		if ($row['offers']['more']) {
			// A value no row offers: sent by a browser without the script,
			// malwatch_queue_upgrade() leaves the row out.
			$options_html .= '<option value="__more__" data-mw-more="1">'
				. $app->functions->htmlentities($wb['more_versions_txt']) . '</option>';
		}

		$can_update = count($row['offers']['choices']) > 0;
		$checked = malwatch_upgrade_checked($row, $can_update, $preselect);
		if ($can_update) {
			$row_count++;
			$block_count++;
		}
		if ($checked) {
			$selected_count++;
		}
		$note = $row['manual_only'] ? $wb['manual_only_txt'] : $row['offers']['reason'];

		$rows[] = array(
			'software_id' => $row['software_id'],
			'kind_label' => $app->functions->htmlentities(
				isset($wb['kind_' . $row['kind'] . '_txt']) ? $wb['kind_' . $row['kind'] . '_txt'] : $row['kind']),
			'name' => $app->functions->htmlentities($row['name']),
			'installed' => $app->functions->htmlentities($row['installed']),
			'has_vulns' => $row['vuln_count'] > 0 ? 1 : 0,
			'vuln_label' => $app->functions->htmlentities($row['vuln_count'] === 1
				? $wb['vuln_one_txt'] : sprintf($wb['vuln_many_txt'], number_format($row['vuln_count'], 0, ',', '.'))),
			'can_update' => $can_update ? 1 : 0,
			'is_checked' => $checked ? 1 : 0,
			'options_html' => $options_html,
			'closes' => $app->functions->htmlentities($default_closes),
			'has_note' => $note !== '' ? 1 : 0,
			'note' => $app->functions->htmlentities($note),
		);
	}
	// The folder names the installation for the buttons of this block; an
	// installation outside the scan path has none, and its block only
	// takes part in the buttons below every folder.
	$folder = malwatch_install_folder($install['path'], $scan_base);
	$rel = trim((string) substr($install['path'], strlen(rtrim($scan_base, '/'))), '/');
	$blocks[] = array(
		'install_label' => $app->functions->htmlentities($folder === '.' || $rel === '' ? $wb['install_root_txt'] : '/' . $rel),
		'core_version' => $app->functions->htmlentities($install['core_version']),
		'folder' => $app->functions->htmlentities($folder),
		'has_folder' => $folder !== '' ? 1 : 0,
		'has_updatable' => $block_count > 0 ? 1 : 0,
		'folder_template' => $app->functions->htmlentities(
			sprintf($wb['selected_template_txt'], number_format($block_count, 0, ',', '.'))),
		'rows' => $rows,
	);
}

// --- Page --------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_upgrade_start.htm');
$app->tpl->setVar($wb);

// The dialog and the loading of more versions read these from data-mw-*
// attributes; see malwatch_attr_texts().
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_start_txt', 'confirm_start_txt',
	'versions_loading_txt', 'versions_failed_txt')));

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('back_label', sprintf($wb['back_txt'], $app->functions->htmlentities($web['domain'])));
$app->tpl->setVar('has_blocks', count($blocks) > 0 ? 1 : 0);
$app->tpl->setLoop('blocks', $blocks);
$app->tpl->setVar('has_hidden', $hidden > 0 ? 1 : 0);
$app->tpl->setVar('hidden_line', $app->functions->htmlentities(
	sprintf($wb['hidden_txt'], number_format($hidden, 0, ',', '.'))));

// A button stays greyed out while nothing in its reach is ticked, and the
// counters then say what to do; malwatch_selection.htm keeps both current.
$selected_template = sprintf($wb['selected_template_txt'], number_format($row_count, 0, ',', '.'));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_none', $app->functions->htmlentities($wb['selected_none_txt']));
$app->tpl->setVar('selected_line', $app->functions->htmlentities($selected_count > 0
	? str_replace('{n}', (string) $selected_count, $selected_template) : $wb['selected_none_txt']));
$app->tpl->setVar('none_selected', $selected_count > 0 ? 0 : 1);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_upgrade_start');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
