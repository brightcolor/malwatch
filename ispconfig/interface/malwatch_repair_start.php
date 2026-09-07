<?php

/**
 * The repair page: a real decision instead of the old two-button pair on the
 * site detail page. An operator picks how vendor files get replaced and
 * what happens to elements nobody can download an original for, sees
 * exactly which elements of the last scan that touches, and only then
 * starts a dry run or the real thing.
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
// approve a table that does not match what actually happens next.
$software = $app->db->queryAllRecords(
	"SELECT * FROM malwatch_software WHERE parent_domain_id = ? "
	. "ORDER BY FIELD(software_kind, 'core', 'plugin', 'theme'), product ASC, slug ASC",
	$domain_id);

// The --only value each row would contribute, kept alongside the display
// row so the POST handler below can whitelist against exactly what this
// page offered - the same defence malwatch_queue_quarantine() applies to
// file paths, here applied to element filters.
$known_only = array();
$element_rows = array();
// Not every row starts checked (see is_checked below), so the initial
// "X von Y ausgewählt" cannot just read Y twice - it would claim every
// element is selected on a website where some never are by default.
$initial_checked = 0;
if (is_array($software)) {
	foreach ($software as $row) {
		$kind = (string) $row['software_kind'];
		$slug = (string) $row['slug'];
		$only_value = $slug !== '' ? $kind . ':' . $slug : $kind;
		$known_only[$only_value] = true;

		// version_unknown is the honest signal available before a repair
		// runs: it means the last scan could not tell what the vendor
		// currently ships, which is exactly when nothing can be fetched to
		// replace this element with - a paid plugin or a hand-built theme.
		$has_original = $row['version_unknown'] !== 'y';
		if ($has_original) {
			$initial_checked++;
		}

		$name = (string) $row['product'];
		if ($slug !== '') {
			$name .= ' / ' . $slug;
		}

		$element_rows[] = array(
			'only_value' => $app->functions->htmlentities($only_value),
			'kind_label' => $app->functions->htmlentities(
				isset($wb['kind_' . $kind . '_txt']) ? $wb['kind_' . $kind . '_txt'] : $kind),
			'name' => $app->functions->htmlentities($name),
			'installed_version' => $app->functions->htmlentities((string) $row['installed_version']),
			'has_original' => $has_original ? 1 : 0,
			// Preselected exactly when there is something to replace it
			// with - an element flagged "kein Original" is never chosen
			// for the operator, only by them.
			'is_checked' => $has_original ? 1 : 0,
			// Matches the page's own defaults (mode=replace, checked mirrors
			// has_original) so the column is never blank before the script
			// below re-derives it from whatever the operator actually picks.
			'what_label' => $app->functions->htmlentities($has_original ? $wb['what_replace_txt'] : $wb['what_untouched_txt']),
		);
	}
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

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities($web['domain']));
$app->tpl->setVar('back_label', sprintf($wb['back_txt'], $app->functions->htmlentities($web['domain'])));
$app->tpl->setVar('has_elements', count($element_rows) > 0 ? 1 : 0);
$app->tpl->setLoop('elements', $element_rows);

// {n} stays in place for the script's own live counter; the total is fixed
// for as long as the page is open, so it is the only part filled in twice -
// once for that template, once (with the real starting count, not every
// row - see is_checked above) for what renders before any script runs.
$selected_template = sprintf($wb['selected_template_txt'], number_format(count($element_rows), 0, ',', '.'));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_line',
	$app->functions->htmlentities(str_replace('{n}', (string) $initial_checked, $selected_template)));

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
