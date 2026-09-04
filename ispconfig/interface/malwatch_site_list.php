<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

$message = '';
$error = '';

// --- Actions ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	if ($action === 'scan_one') {
		$domain_id = $app->functions->intval($_POST['domain_id']);
		$result = malwatch_queue_scan($app, $domain_id);
		if ($result === true) {
			$message = 'Die Prüfung wurde eingeplant und startet innerhalb einer Minute.';
		} else {
			$error = $result;
		}
	} elseif ($action === 'scan_all') {
		$queued = 0;
		$skipped = 0;
		$webs = $app->db->queryAllRecords(
			"SELECT domain_id FROM web_domain WHERE active = 'y' AND type IN ('vhost','vhostsubdomain','vhostalias')");
		if (is_array($webs)) {
			foreach ($webs as $web) {
				if (malwatch_queue_scan($app, $app->functions->intval($web['domain_id'])) === true) {
					$queued++;
				} else {
					$skipped++;
				}
			}
		}
		$message = $queued . ' Prüfung(en) eingeplant.';
		if ($skipped > 0) {
			$message .= ' ' . $skipped . ' Website(s) übersprungen, dort läuft bereits eine Prüfung.';
		}
	}
}

// --- Data ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_site_list.htm');

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch.lng';
}
include $lng_file;
$app->tpl->setVar($wb);

$config = malwatch_get_config($app);
$app->tpl->setVar('binary_missing', $config['binary_ready'] ? 0 : 1);
$app->tpl->setVar('binary_path', $app->functions->htmlentities($config['binary_path']));

$rows = $app->db->queryAllRecords(
	"SELECT w.domain_id, w.domain, w.active, w.document_root, "
	. 's.site_id, s.schedule, s.last_run, s.next_run, s.open_findings, s.worst_severity, s.last_state, '
	. 's.notify_admin, s.notify_client, s.disable_site, '
	. "(SELECT COUNT(*) FROM malwatch_job j WHERE j.parent_domain_id = w.domain_id AND j.job_status IN ('pending','running')) AS busy "
	. 'FROM web_domain w LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id '
	. "WHERE w.type IN ('vhost','vhostsubdomain','vhostalias') "
	. 'ORDER BY w.domain ASC');

$records = array();
$summary = array('clean' => 0, 'findings' => 0, 'outdated' => 0, 'unknown' => 0, 'error' => 0);

if (is_array($rows)) {
	foreach ($rows as $row) {
		$state = $row['last_state'] === null || $row['last_state'] === '' ? 'unknown' : $row['last_state'];
		if (!isset($summary[$state])) {
			$summary[$state] = 0;
		}
		$summary[$state]++;

		$records[] = array(
			'domain_id' => $app->functions->intval($row['domain_id']),
			'domain' => $app->functions->htmlentities($row['domain']),
			'site_active' => $row['active'] === 'y' ? 1 : 0,
			'configured' => $row['site_id'] === null ? 0 : 1,
			'schedule' => $app->functions->htmlentities(malwatch_schedule_label($wb, $row['schedule'])),
			'last_run' => $app->functions->htmlentities(malwatch_datetime($row['last_run'])),
			'next_run' => $app->functions->htmlentities(malwatch_datetime($row['next_run'])),
			'open_findings' => $app->functions->intval($row['open_findings']),
			'worst_severity' => $app->functions->htmlentities((string) $row['worst_severity']),
			'worst_label' => $app->functions->htmlentities(malwatch_severity_label($wb, $row['worst_severity'])),
			'state' => $app->functions->htmlentities($state),
			'state_label' => $app->functions->htmlentities(malwatch_state_label($wb, $state)),
			'state_class' => malwatch_state_class($state),
			'busy' => $app->functions->intval($row['busy']) > 0 ? 1 : 0,
			'actions' => $app->functions->htmlentities(malwatch_action_summary($wb, $row)),
		);
	}
}

$app->tpl->setLoop('records', $records);
$app->tpl->setVar('has_records', count($records) > 0);
$app->tpl->setVar('count_total', count($records));
$app->tpl->setVar('count_findings', $summary['findings']);
$app->tpl->setVar('count_clean', $summary['clean']);
$app->tpl->setVar('count_outdated', $summary['outdated']);
$app->tpl->setVar('count_unknown', $summary['unknown']);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_site_list');
$app->tpl->setVar('csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
