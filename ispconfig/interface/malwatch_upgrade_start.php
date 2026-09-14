<?php

/**
 * The page "Updates" of one website: every WordPress core, plugin and theme
 * with a newer release at wordpress.org, a target version per row, a dry run
 * and the start.
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
		// malwatch_queue_upgrade() accepts only versions this page offers.
		$result = malwatch_queue_upgrade($app, $domain_id, $choices, $action === 'upgrade_dry', $wb);
		if (is_int($result)) {
			$message = sprintf($action === 'upgrade_dry' ? $wb['msg_dry_txt'] : $wb['msg_queued_txt'], $result);
		} else {
			$error = $result;
		}
	}
}

// --- Rows --------------------------------------------------------------------
list($installs, $hidden) = malwatch_upgrade_candidates($app, $domain_id, $wb);
$scan_base = rtrim(malwatch_scan_path($web), '/');
$labels = array('latest' => $wb['offer_latest_txt'], 'minimal' => $wb['offer_minimal_txt']);

$blocks = array();
$selected_count = 0;
$row_count = 0;
foreach ($installs as $install) {
	$rows = array();
	foreach ($install['rows'] as $row) {
		// The options go out as one escaped string: the template loops over
		// installations and rows already, and every value in it is escaped
		// here.
		$options_html = '';
		$default = '';
		$default_closes = '';
		foreach ($labels as $which => $label) {
			$offer = $row['offers'][$which];
			if ($offer === null) {
				continue;
			}
			if ($default === '') {
				$default = $offer['version'];
				$default_closes = $offer['closes'];
			}
			$options_html .= '<option value="' . $app->functions->htmlentities($offer['version']) . '"'
				. ' data-closes="' . $app->functions->htmlentities($offer['closes']) . '"'
				. ($default === $offer['version'] ? ' selected' : '') . '>'
				. $app->functions->htmlentities($offer['version'] . ' · ' . $label) . '</option>';
		}

		$can_update = $default !== '';
		$checked = malwatch_upgrade_checked($row, $can_update, $preselect);
		if ($can_update) {
			$row_count++;
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
	$rel = trim((string) substr($install['path'], strlen($scan_base)), '/');
	$blocks[] = array(
		'install_label' => $app->functions->htmlentities($rel === '' ? $wb['install_root_txt'] : '/' . $rel),
		'core_version' => $app->functions->htmlentities($install['core_version']),
		'rows' => $rows,
	);
}

// --- Page --------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_upgrade_start.htm');
$app->tpl->setVar($wb);

// Both end up inside alert('…') and confirm('…') in an onclick attribute.
foreach (array('err_no_selection_txt', 'confirm_start_txt') as $js_key) {
	if (isset($wb[$js_key])) {
		$app->tpl->setVar($js_key, malwatch_js_text($app, $wb[$js_key]));
	}
}

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('back_label', sprintf($wb['back_txt'], $app->functions->htmlentities($web['domain'])));
$app->tpl->setVar('has_blocks', count($blocks) > 0 ? 1 : 0);
$app->tpl->setLoop('blocks', $blocks);
$app->tpl->setVar('has_hidden', $hidden > 0 ? 1 : 0);
$app->tpl->setVar('hidden_line', $app->functions->htmlentities(
	sprintf($wb['hidden_txt'], number_format($hidden, 0, ',', '.'))));

$selected_template = sprintf($wb['selected_template_txt'], number_format($row_count, 0, ',', '.'));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_line',
	$app->functions->htmlentities(str_replace('{n}', (string) $selected_count, $selected_template)));

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_upgrade_start');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
