<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
if ($domain_id < 1) {
	die('Ungültige Website.');
}

$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
if (!is_array($web)) {
	die('Die Website wurde nicht gefunden.');
}

$message = '';
$error = '';

// --- Actions ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	if ($action === 'scan') {
		$result = malwatch_queue_scan($app, $domain_id);
		if ($result === true) {
			$message = 'Die Prüfung wurde eingeplant und startet innerhalb einer Minute.';
		} else {
			$error = $result;
		}
	} elseif ($action === 'ignore' || $action === 'reopen') {
		$finding_id = $app->functions->intval($_POST['finding_id']);
		$state = $action === 'ignore' ? 'ignored' : 'open';
		$app->db->query('UPDATE malwatch_finding SET finding_state = ? WHERE finding_id = ? AND parent_domain_id = ?',
			$state, $finding_id, $domain_id);
		$message = $action === 'ignore' ? 'Der Fund wurde freigegeben.' : 'Der Fund wurde wieder geöffnet.';
	} elseif ($action === 'enable_site') {
		if ($web['active'] === 'n') {
			// Re-enabling goes through the datalog, so the web server config
			// is rewritten exactly as it is when an operator flips the switch
			// on the website form.
			$app->db->datalogUpdate('web_domain', array('active' => 'y'), 'domain_id', $domain_id);
			$message = 'Die Website wurde wieder eingeschaltet.';
			$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
		}
	}
}

// --- Page ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_site_show.htm');

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch.lng';
}
include $lng_file;
$app->tpl->setVar($wb);

$site = $app->db->queryOneRecord('SELECT * FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
$last_scan = $app->db->queryOneRecord(
	'SELECT * FROM malwatch_scan WHERE parent_domain_id = ? ORDER BY scan_id DESC LIMIT 1', $domain_id);
$job = $app->db->queryOneRecord(
	"SELECT * FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running') "
	. 'ORDER BY job_id DESC LIMIT 1', $domain_id);

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities($web['domain']));
$app->tpl->setVar('scan_path', $app->functions->htmlentities(malwatch_scan_path($web)));
$app->tpl->setVar('site_active', $web['active'] === 'y' ? 1 : 0);
$app->tpl->setVar('configured', is_array($site) ? 1 : 0);
$app->tpl->setVar('busy', is_array($job) ? 1 : 0);
$app->tpl->setVar('busy_status', is_array($job) ? $app->functions->htmlentities($job['job_status']) : '');

if (is_array($last_scan)) {
	$app->tpl->setVar('has_scan', 1);
	$app->tpl->setVar('last_run', $app->functions->htmlentities(malwatch_datetime($last_scan['finished_at'])));
	$app->tpl->setVar('duration', $app->functions->htmlentities(malwatch_duration($last_scan['duration_seconds'])));
	$app->tpl->setVar('files_scanned', $app->functions->intval($last_scan['files_scanned']));
	$app->tpl->setVar('engines', $app->functions->htmlentities($last_scan['engines']));
	$app->tpl->setVar('scan_notes', nl2br($app->functions->htmlentities((string) $last_scan['notes'])));
	$app->tpl->setVar('state_label',
		$app->functions->htmlentities(malwatch_state_label($wb, $last_scan['scan_state'])));
	$app->tpl->setVar('state_class', malwatch_state_class($last_scan['scan_state']));
} else {
	$app->tpl->setVar('has_scan', 0);
}

// --- Findings --------------------------------------------------------------
$findings = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_finding WHERE parent_domain_id = ? '
	. "AND finding_state IN ('open','ignored') "
	. 'ORDER BY FIELD(finding_state, ?, ?), FIELD(severity, ?, ?, ?, ?) DESC, file_path ASC LIMIT 500',
	$domain_id, 'open', 'ignored', 'low', 'medium', 'high', 'critical');

$finding_rows = array();
if (is_array($findings)) {
	foreach ($findings as $row) {
		$finding_rows[] = array(
			'finding_id' => $app->functions->intval($row['finding_id']),
			'file_path' => $app->functions->htmlentities($row['file_path']),
			'line_number' => $app->functions->intval($row['line_number']),
			'has_line' => $app->functions->intval($row['line_number']) > 0 ? 1 : 0,
			'rule_id' => $app->functions->htmlentities($row['rule_id']),
			'severity' => $app->functions->htmlentities($row['severity']),
			'severity_label' => $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity'])),
			'severity_class' => malwatch_severity_class($row['severity']),
			'engine' => $app->functions->htmlentities($row['engine']),
			'excerpt' => $app->functions->htmlentities($row['excerpt']),
			'first_seen' => $app->functions->htmlentities(malwatch_datetime($row['first_seen'])),
			'is_ignored' => $row['finding_state'] === 'ignored' ? 1 : 0,
		);
	}
}
$app->tpl->setLoop('findings', $finding_rows);
$app->tpl->setVar('has_findings', count($finding_rows) > 0);

// --- Software --------------------------------------------------------------
$software = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_software WHERE parent_domain_id = ? ORDER BY outdated DESC, product ASC, slug ASC LIMIT 300',
	$domain_id);

$software_rows = array();
if (is_array($software)) {
	foreach ($software as $row) {
		$name = $row['product'];
		if ((string) $row['slug'] !== '') {
			$name .= ' / ' . $row['slug'];
		}
		$software_rows[] = array(
			'name' => $app->functions->htmlentities($name),
			'kind' => $app->functions->htmlentities($row['software_kind']),
			'install_path' => $app->functions->htmlentities($row['install_path']),
			'installed_version' => $app->functions->htmlentities($row['installed_version']),
			'latest_version' => $app->functions->htmlentities($row['latest_version']),
			'is_outdated' => $row['outdated'] === 'y' ? 1 : 0,
			'is_unknown' => $row['version_unknown'] === 'y' ? 1 : 0,
		);
	}
}
$app->tpl->setLoop('software', $software_rows);
$app->tpl->setVar('has_software', count($software_rows) > 0);

// --- History ---------------------------------------------------------------
$scans = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_scan WHERE parent_domain_id = ? ORDER BY scan_id DESC LIMIT 15', $domain_id);

$scan_rows = array();
if (is_array($scans)) {
	foreach ($scans as $row) {
		$scan_rows[] = array(
			'finished_at' => $app->functions->htmlentities(malwatch_datetime($row['finished_at'])),
			'duration' => $app->functions->htmlentities(malwatch_duration($row['duration_seconds'])),
			'files_scanned' => $app->functions->intval($row['files_scanned']),
			'count_critical' => $app->functions->intval($row['count_critical']),
			'count_high' => $app->functions->intval($row['count_high']),
			'count_medium' => $app->functions->intval($row['count_medium']),
			'count_low' => $app->functions->intval($row['count_low']),
			'count_outdated' => $app->functions->intval($row['count_outdated']),
			'new_findings' => $app->functions->intval($row['new_findings']),
			'state_label' => $app->functions->htmlentities(malwatch_state_label($wb, $row['scan_state'])),
			'state_class' => malwatch_state_class($row['scan_state']),
		);
	}
}
$app->tpl->setLoop('scans', $scan_rows);
$app->tpl->setVar('has_scans', count($scan_rows) > 0);

// --- Action log ------------------------------------------------------------
$actions = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_action_log WHERE parent_domain_id = ? ORDER BY action_id DESC LIMIT 15', $domain_id);

$action_rows = array();
if (is_array($actions)) {
	foreach ($actions as $row) {
		$action_rows[] = array(
			'created_at' => $app->functions->htmlentities(malwatch_datetime($row['created_at'])),
			'action_type' => $app->functions->htmlentities($row['action_type']),
			'action_label' => $app->functions->htmlentities(
				isset($wb['action_' . $row['action_type'] . '_txt']) ? $wb['action_' . $row['action_type'] . '_txt'] : $row['action_type']),
			'recipient' => $app->functions->htmlentities($row['recipient']),
			'trigger_severity' => $app->functions->htmlentities($row['trigger_severity']),
			'trigger_findings' => $app->functions->intval($row['trigger_findings']),
			'detail' => $app->functions->htmlentities($row['detail']),
		);
	}
}
$app->tpl->setLoop('actionlog', $action_rows);
$app->tpl->setVar('has_actionlog', count($action_rows) > 0);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_site_show');
$app->tpl->setVar('csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
