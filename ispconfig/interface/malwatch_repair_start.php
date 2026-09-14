<?php

/**
 * The repair page: a real decision instead of the old two-button pair on the
 * site detail page. An operator picks how vendor files get replaced and
 * what happens to elements nobody can download an original for, sees
 * exactly which elements of the last scan that touches, grouped by the folder
 * of their WordPress installation, and only then starts a dry run or the real
 * thing - for every folder at once or for one.
 *
 * Reached as malwatch_repair_start.php?id=<domain_id> - the same parameter
 * name malwatch_site_show.php reads, not domain_id=, which has sent every
 * website into "Ungültige Website." once already (see check_wiring.sh).
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Included rather than fetched through $app->load_language_file() - that
// method keeps its result in a private property of its own, so $wb would
// stay unset here (see malwatch_quarantine_list.php / malwatch_site_show.php
// for the same reasoning). Loaded first of all, ahead of the two checks
// below as well as the actions further down: both used to answer with a
// German sentence written into the code, while the two keys meant for them
// sat in de_/en_malwatch_repair.lng and were read by nothing.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_repair.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_repair.lng';
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

// --- Elements of the last scan ----------------------------------------------
// The element list is malwatch_software as of the last run, not a fresh
// filesystem read: repairing what a scan never saw would let an operator
// approve a table that does not match what actually happens next. WordPress
// only - the repair has an original to fetch for nothing else.
$software = $app->db->queryAllRecords(
	"SELECT * FROM malwatch_software WHERE parent_domain_id = ? AND product = 'wordpress' "
	. "ORDER BY FIELD(software_kind, 'core', 'plugin', 'theme'), slug ASC",
	$domain_id);
$scan_base = malwatch_scan_path($web);

// The --only value each row would contribute, kept alongside the display
// row so the POST handler below can whitelist against exactly what this
// page offered - the same defence malwatch_queue_quarantine() applies to
// file paths, here applied to element filters. Each value names the folder
// of its installation after @: a site with forty installations carries the
// same plugin many times, and a tick repairs it in that one folder.
$known_only = array();
$folders = array();
if (is_array($software)) {
	foreach ($software as $row) {
		$kind = (string) $row['software_kind'];
		$slug = (string) $row['slug'];
		$install = $kind === 'core'
			? (string) $row['install_path'] : malwatch_install_of((string) $row['install_path'], $kind);
		$folder = $install !== '' ? malwatch_install_folder($install, $scan_base) : '';
		// Outside the scan path there is no folder --only could name.
		if ($folder === '') {
			continue;
		}
		$only_value = ($slug !== '' ? $kind . ':' . $slug : $kind) . '@' . $folder;
		$known_only[$only_value] = true;

		// version_unknown is the honest signal available before a repair
		// runs: it means the last scan could not tell what the vendor
		// currently ships, which is exactly when nothing can be fetched to
		// replace this element with - a paid plugin or a hand-built theme.
		$has_original = $row['version_unknown'] !== 'y';

		$name = (string) $row['product'];
		if ($slug !== '') {
			$name .= ' / ' . $slug;
		}

		$folders[$folder][] = array(
			'only_value' => $app->functions->htmlentities($only_value),
			'kind_label' => $app->functions->htmlentities(
				isset($wb['kind_' . $kind . '_txt']) ? $wb['kind_' . $kind . '_txt'] : $kind),
			'name' => $app->functions->htmlentities($name),
			'installed_version' => $app->functions->htmlentities((string) $row['installed_version']),
			'has_original' => $has_original ? 1 : 0,
			// Nothing starts ticked: the operator picks what a repair touches.
			// The script below re-derives the column from every tick.
			'what_label' => $app->functions->htmlentities($wb['what_untouched_txt']),
		);
	}
}

// The web root first, the folders after it by name. A folder named like a
// number comes back from the array as an integer, hence the casts.
uksort($folders, function ($a, $b) {
	$a = (string) $a;
	$b = (string) $b;
	if ($a === '.' || $b === '.') {
		return $a === $b ? 0 : ($a === '.' ? -1 : 1);
	}
	return strcmp($a, $b);
});
$element_blocks = array();
$element_count = 0;
foreach ($folders as $folder => $rows) {
	$folder = (string) $folder;
	$element_count += count($rows);
	$element_blocks[] = array(
		'install_label' => $app->functions->htmlentities($folder === '.' ? $wb['install_root_txt'] : '/' . $folder),
		'folder' => $app->functions->htmlentities($folder),
		'folder_template' => $app->functions->htmlentities(
			sprintf($wb['selected_template_txt'], number_format(count($rows), 0, ',', '.'))),
		'elements' => $rows,
	);
}

$message = '';
$error = '';

// --- Actions -----------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	if ($action === 'repair' || $action === 'repair_dry') {
		$mode = (isset($_POST['mode']) && $_POST['mode'] === 'overlay') ? 'overlay' : 'replace';
		$no_original = (isset($_POST['no_original']) && $_POST['no_original'] === 'quarantine') ? 'quarantine' : 'keep';

		$only = array();
		if (isset($_POST['only']) && is_array($_POST['only'])) {
			foreach ($_POST['only'] as $val) {
				$val = (string) $val;
				if (isset($known_only[$val])) {
					$only[] = $val;
				}
			}
		}
		// The buttons of a folder start the ticked elements of that folder;
		// the buttons below every folder leave the field empty.
		$only = malwatch_only_in_folder($only, isset($_POST['folder']) ? (string) $_POST['folder'] : '');

		if (count($only) === 0) {
			$error = $wb['err_no_selection_txt'];
		} else {
			// Erst einreihen, dann abschalten. Andersherum bliebe die Website
			// aus, wenn das Einreihen scheitert - und es scheitert
			// regelmäßig, weil für die Website gerade eine Prüfung läuft.
			// Genau nach einer Prüfung will man reparieren, also war das der
			// wahrscheinlichste Weg zu einer Website, die aus ist und deren
			// Reparatur nie stattfand.
			$was_active = (string) $web['active'];
			$result = malwatch_queue_repair($app, $domain_id, $action === 'repair_dry', $was_active,
				$mode, $no_original, $only);
			if ($result === true) {
				// Die Website geht für die Dauer aus: eine halb getauschte
				// Installation hat nichts im Netz verloren, und eine
				// Hintertür, die noch erreichbar ist, schreibt währenddessen
				// weiter. Der Auftrag schaltet sie danach wieder ein.
				if ($action === 'repair' && $was_active === 'y') {
					$app->db->datalogUpdate('web_domain', array('active' => 'n'), 'domain_id', $domain_id);
				}
				$message = $action === 'repair_dry' ? $wb['msg_repair_dry_txt'] : $wb['msg_repair_txt'];
			} else {
				$error = $result;
			}
		}
	}
}

// --- Page ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_repair_start.htm');
$app->tpl->setVar($wb);

// Overwritten right after setVar($wb), which passes a sentence on exactly as
// the language file wrote it: the dialog reads these from data-mw-*
// attributes, and a straight double quote would end the attribute. See
// malwatch_attr_texts().
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_start_txt', 'confirm_start_txt',
	'hint_select_txt', 'hint_select_folder_txt',
	'confirm_replace_txt', 'confirm_replace_one_txt', 'confirm_core_one_txt', 'confirm_core_many_txt',
	'confirm_plugin_one_txt', 'confirm_plugin_many_txt', 'confirm_theme_one_txt', 'confirm_theme_many_txt',
	'confirm_list_two_txt', 'confirm_list_three_txt', 'confirm_safety_txt', 'confirm_no_original_txt')));

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities($web['domain']));
$app->tpl->setVar('back_label', sprintf($wb['back_txt'], $app->functions->htmlentities($web['domain'])));
$app->tpl->setVar('has_elements', $element_count > 0 ? 1 : 0);
$app->tpl->setLoop('blocks', $element_blocks);

// {n} stays in place for the live counters of malwatch_selection.htm; the
// totals are fixed for as long as the page is open. Nothing starts ticked, so
// every counter opens on the line that says what to do, and every button
// answers a click with its hint until something is ticked.
$selected_template = sprintf($wb['selected_template_txt'], number_format($element_count, 0, ',', '.'));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_none', $app->functions->htmlentities($wb['selected_none_txt']));

$app->tpl->setVar('quiet_body', sprintf($wb['quiet_body_txt'],
	'<a href="#" data-load-content="security/malwatch_quarantine_list.php">'
	. $app->functions->htmlentities($wb['quiet_quarantine_link_txt']) . '</a>'));

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_repair_start');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
