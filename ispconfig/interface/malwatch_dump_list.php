<?php

/**
 * Dumps: pack one website with its databases and hand the archive out.
 *
 * The page does two things. On top it takes a website, shows its databases
 * with what the hourly run knows about them and queues a run; below it lists
 * the dumps that lie on disk with their download and their expiry.
 *
 * Deleting takes the row out at once, which stops the link working, and
 * leaves the file to the hourly run: the archive belongs to root, and the
 * panel has no business unlinking files in a directory it may only read.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Included rather than loaded through $app->load_language_file(), the same as
// every other page here: that method keeps the result to itself, and $wb would
// stay unset. Before the actions, because their messages read from it.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_dump.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_dump.lng';
}
include $lng_file;

$message = '';
$error = '';
$domain_id = isset($_REQUEST['id']) ? $app->functions->intval($_REQUEST['id']) : 0;

// --- Actions ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	if ($action === 'dump_start') {
		$web = $domain_id > 0
			? $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ? AND type = 'vhost'", $domain_id)
			: false;
		if (!is_array($web)) {
			$error = $wb['err_site_not_found_txt'];
		} else {
			// One run per website at a time: two runs would write the same
			// files into two archives and read the same databases twice.
			$busy = $app->db->queryOneRecord(
				"SELECT dump_id FROM malwatch_dump WHERE parent_domain_id = ? AND dump_state IN ('pending','running')",
				$domain_id);
			if (is_array($busy)) {
				$error = $wb['err_busy_txt'];
			} else {
				$known = malwatch_dump_known_names(malwatch_dump_databases($app, $web));
				$posted = isset($_POST['databases']) && is_array($_POST['databases']) ? $_POST['databases'] : array();
				$names = malwatch_dump_filter_names($posted, $known);
				$with_logs = !empty($_POST['with_logs']) ? 'y' : 'n';

				if (malwatch_queue_dump($app, $web, $names, $with_logs) > 0) {
					$message = sprintf($wb['msg_queued_txt'], $web['domain']);
				} else {
					$error = $wb['err_invalid_site_txt'];
				}
			}
		}
	} elseif ($action === 'dump_delete') {
		$dump_id = isset($_POST['dump_id']) ? $app->functions->intval($_POST['dump_id']) : 0;
		$row = $dump_id > 0
			? $app->db->queryOneRecord('SELECT dump_id, parent_domain_id FROM malwatch_dump WHERE dump_id = ?', $dump_id)
			: false;
		if (!is_array($row)) {
			$error = $wb['err_not_found_txt'];
		} else {
			$app->db->query('DELETE FROM malwatch_dump WHERE dump_id = ?', $dump_id);
			$message = $wb['msg_deleted_txt'];
			if ($domain_id < 1) {
				$domain_id = $app->functions->intval($row['parent_domain_id']);
			}
		}
	} elseif ($action !== '') {
		$error = $wb['err_unknown_action_txt'];
	}
}

// --- Page ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_dump_list.htm');
$app->tpl->setVar($wb);

// Overwritten right after setVar($wb): the dialog reads these from data-mw-*
// attributes, where a straight double quote would end the attribute. See
// malwatch_attr_texts().
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_create_txt', 'confirm_create_txt',
	'btn_delete_txt', 'confirm_delete_txt', 'hint_select_txt')));

// Every website of the server, by name. The status page shows the ones that
// need attention; a dump is asked for by name, and the one website somebody
// wants to pack is as likely to be the quiet one.
$sites = $app->db->queryAllRecords(
	"SELECT domain_id, domain FROM web_domain WHERE type = 'vhost' AND active = 'y' ORDER BY domain");
$site_rows = array();
foreach ((array) $sites as $site) {
	$id = $app->functions->intval($site['domain_id']);
	if ($domain_id < 1) {
		$domain_id = $id;
	}
	$site_rows[] = array(
		'site_id' => $id,
		'site_domain' => $app->functions->htmlentities((string) $site['domain']),
		'selected' => $id === $domain_id ? 1 : 0,
	);
}
$app->tpl->setLoop('sites', $site_rows);
$app->tpl->setVar('domain_id', $domain_id);

$web = $domain_id > 0
	? $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ? AND type = 'vhost'", $domain_id)
	: false;
$databases = is_array($web) ? malwatch_dump_databases($app, $web) : array();
$db_rows = malwatch_dump_database_rows($databases, $wb);

$pending = 0;
foreach ($db_rows as $row) {
	if ($row['has_marks'] === 0) {
		$pending++;
	}
}
foreach ($db_rows as $i => $row) {
	foreach ($row as $key => $value) {
		if ($key !== 'has_marks') {
			$db_rows[$i][$key] = $app->functions->htmlentities((string) $value);
		}
	}
}
$app->tpl->setLoop('databases', $db_rows);
$app->tpl->setVar('has_databases', count($db_rows) > 0 ? 1 : 0);
$app->tpl->setVar('has_pending', $pending > 0 ? 1 : 0);

// {n} stays for the counter of malwatch_selection.htm; the total is fixed for
// as long as the page is open.
$app->tpl->setVar('selected_template', $app->functions->htmlentities(
	sprintf($wb['selected_template_txt'], number_format(count($db_rows), 0, ',', '.'))));
$app->tpl->setVar('selected_none', $app->functions->htmlentities($wb['selected_none_txt']));

$dumps = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_dump ORDER BY dump_id DESC LIMIT 100');
$dump_rows = malwatch_dump_rows(is_array($dumps) ? $dumps : array(), $wb);
foreach ($dump_rows as $i => $row) {
	$dump_rows[$i]['domain'] = $app->functions->htmlentities($row['domain']);
	$dump_rows[$i]['state_label'] = $app->functions->htmlentities($row['state_label']);
	$dump_rows[$i]['size_label'] = $app->functions->htmlentities($row['size_label']);
	$dump_rows[$i]['content_label'] = $app->functions->htmlentities($row['content_label']);
	$dump_rows[$i]['valid_label'] = $app->functions->htmlentities($row['valid_label']);
	$dump_rows[$i]['token'] = $app->functions->htmlentities($row['token']);
	$dump_rows[$i]['message'] = $app->functions->htmlentities($row['message']);
	$dump_rows[$i]['created'] = $app->functions->htmlentities(
		isset($dumps[$i]['created_at']) ? substr((string) $dumps[$i]['created_at'], 0, 16) : '');
	$dump_rows[$i]['has_message'] = $row['message'] !== '' ? 1 : 0;
}
$app->tpl->setLoop('dumps', $dump_rows);
$app->tpl->setVar('has_dumps', count($dump_rows) > 0 ? 1 : 0);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_dump_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
