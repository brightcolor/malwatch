<?php

/**
 * The quarantine: everything the extension has taken out of a website,
 * across every site on this server, with restore, download and permanent
 * delete.
 *
 * A quarantine entry belongs to whichever server holds its store on disk,
 * not to one website's domain_id - the same reason malwatch_job.server_id,
 * not parent_domain_id, is what the cron on that machine reads. Selecting
 * entries from several websites at once is expected here, unlike the
 * per-website actions on malwatch_site_show.php.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Included rather than fetched through $app->load_language_file() - see
// malwatch_site_show.php and status.php for why: that method keeps the
// result in its own private property, so $wb would stay unset here. Loaded
// before the actions, not after, because the messages below read from $wb.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_quarantine.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_quarantine.lng';
}
include $lng_file;

$message = '';
$error = '';

// --- Actions -----------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	// A row button names exactly one entry and wins over whatever else is
	// checked; the checkboxes only speak when no single entry was named -
	// otherwise a stray checked box from an earlier click would ride along
	// with a row action that is supposed to touch just that one row.
	$single = isset($_POST['entry_id']) ? trim((string) $_POST['entry_id']) : '';
	if ($single !== '') {
		$ids = array($single);
	} else {
		$ids = array();
		if (isset($_POST['ids']) && is_array($_POST['ids'])) {
			foreach ($_POST['ids'] as $id) {
				$id = (string) $id;
				if ($id !== '') {
					$ids[] = $id;
				}
			}
		}
	}

	if ($action === 'restore' || $action === 'download' || $action === 'delete') {
		if (count($ids) === 0) {
			$error = $wb['err_no_selection_txt'];
		} else {
			$job_action = $action === 'download' ? 'export' : $action;
			$result = malwatch_queue_quarantine_action($app, $ids, $job_action);
			if (is_int($result)) {
				if ($action === 'restore') {
					$message = $result === 1 ? $wb['msg_restore_one_txt']
						: sprintf($wb['msg_restore_many_txt'], number_format($result, 0, ',', '.'));
				} elseif ($action === 'delete') {
					$message = $result === 1 ? $wb['msg_delete_one_txt']
						: sprintf($wb['msg_delete_many_txt'], number_format($result, 0, ',', '.'));
				} else {
					$message = $result === 1 ? $wb['msg_download_one_txt'] : $wb['msg_download_many_txt'];
				}
			} else {
				$error = $result;
			}
		}
	}
}

// --- Page ----------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_quarantine_list.htm');
$app->tpl->setVar($wb);

$totals = $app->db->queryOneRecord('SELECT COUNT(*) AS n, COALESCE(SUM(archive_bytes),0) AS b FROM malwatch_quarantine');
$total_count = is_array($totals) ? $app->functions->intval($totals['n']) : 0;
$total_bytes = is_array($totals) ? (float) $totals['b'] : 0.0;

$app->tpl->setVar('has_entries', $total_count > 0 ? 1 : 0);
if ($total_count === 0) {
	$app->tpl->setVar('lede', $wb['lede_none_txt']);
} elseif ($total_count === 1) {
	$app->tpl->setVar('lede', $wb['lede_one_txt']);
} else {
	$app->tpl->setVar('lede', sprintf($wb['lede_many_txt'], number_format($total_count, 0, ',', '.')));
}

// {n} is left in place for the client-side counter (see the template's
// script); the two %s never change while the page sits on screen, so they
// are filled in once, here, instead of being re-sent from the server on
// every checkbox click.
$selected_template = sprintf($wb['toolbar_selected_txt'],
	number_format($total_count, 0, ',', '.'), malwatch_bytes($total_bytes));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_line', $app->functions->htmlentities(str_replace('{n}', '0', $selected_template)));

$app->tpl->setVar('footnote_zip_body',
	sprintf($wb['footnote_zip_body_txt'], '<span class="mw-mono">infected</span>'));
$app->tpl->setVar('footnote_where_body',
	sprintf($wb['footnote_where_body_txt'], '<span class="mw-mono">/var/lib/malwatch/quarantine/</span>'));

// Entries whose export is already under way: a pending or running job of
// kind 'quarantine' with action 'export' names them in its options. Read
// once here rather than per row - the job table has at most a handful of
// open rows, and a query per table row would not.
$exporting = array();
$pending_jobs = $app->db->queryAllRecords(
	"SELECT options FROM malwatch_job WHERE job_kind = 'quarantine' AND job_status IN ('pending','running')");
if (is_array($pending_jobs)) {
	foreach ($pending_jobs as $pending_job) {
		$options = json_decode((string) $pending_job['options'], true);
		if (!is_array($options) || !isset($options['action']) || $options['action'] !== 'export') {
			continue;
		}
		foreach ((array) (isset($options['ids']) ? $options['ids'] : array()) as $exporting_id) {
			$exporting[(string) $exporting_id] = true;
		}
	}
}

$rows = $app->db->queryAllRecords('SELECT * FROM malwatch_quarantine ORDER BY quarantine_id DESC LIMIT 500');

$entry_rows = array();
if (is_array($rows)) {
	foreach ($rows as $row) {
		$entry_id = (string) $row['entry_id'];

		// Directories carry a trailing slash in the display regardless of how
		// the stored rel_path happens to be written, so the kind label above
		// it is never the only thing telling the two apart.
		$path = rtrim((string) $row['rel_path'], '/');
		if ($row['entry_kind'] === 'dir') {
			$path .= '/';
		}

		$stamp = strtotime((string) $row['created_at']);
		$moved_when = ($stamp !== false && $stamp > 0) ? malwatch_when($stamp) : '–';

		$domain_id = $app->functions->intval($row['parent_domain_id']);

		// The same 24 hour window malwatch_quarantine_download.php enforces:
		// the cron sweeps the spool file and the token together, but only
		// once an hour, so a token can sit here past its cutoff for a little
		// while. Treating it as ready that whole time would offer a link
		// that 404s the moment it is actually clicked.
		$export_ready_at = (string) $row['export_ready_at'];
		$ready_stamp = $export_ready_at !== '' ? strtotime($export_ready_at) : false;
		$export_token = (string) $row['export_token'];
		$dl_ready = $export_token !== '' && $ready_stamp !== false && $ready_stamp > (time() - 86400);
		$dl_preparing = !$dl_ready && isset($exporting[$entry_id]);

		$entry_rows[] = array(
			'entry_id' => $app->functions->htmlentities($entry_id),
			'kind_label' => $app->functions->htmlentities(
				$row['entry_kind'] === 'dir' ? $wb['kind_dir_txt'] : $wb['kind_file_txt']),
			'path' => $app->functions->htmlentities($path),
			'domain' => $app->functions->htmlentities((string) $row['domain']),
			'domain_id' => $domain_id,
			'has_domain_link' => $domain_id > 0 ? 1 : 0,
			'reason' => $app->functions->htmlentities((string) $row['reason']),
			'moved_when' => $app->functions->htmlentities($moved_when),
			'origin_label' => $app->functions->htmlentities(malwatch_origin_label($wb, $row['origin'])),
			'size_label' => $app->functions->htmlentities(malwatch_bytes($row['bytes'])),
			'dl_ready' => $dl_ready ? 1 : 0,
			'dl_preparing' => $dl_preparing ? 1 : 0,
			'dl_normal' => (!$dl_ready && !$dl_preparing) ? 1 : 0,
			'dl_token' => $app->functions->htmlentities($export_token),
			'dl_ready_label' => $app->functions->htmlentities(sprintf($wb['dl_ready_txt'], malwatch_bytes($row['export_bytes']))),
		);
	}
}
$app->tpl->setLoop('entries', $entry_rows);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_quarantine_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
