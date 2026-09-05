<?php

/**
 * Serves the progress of one job as JSON.
 *
 * No template: the panel's form.tpl.htm would append its own markup and the
 * caller would not get valid JSON back.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

$job_id = $app->functions->intval(isset($_GET['job_id']) ? $_GET['job_id'] : 0);
$domain_id = $app->functions->intval(isset($_GET['domain_id']) ? $_GET['domain_id'] : 0);

// Without a job the caller asks about a website, and gets the job that is
// currently running there - which is what a page has after a reload.
if ($job_id < 1 && $domain_id > 0) {
	$row = $app->db->queryOneRecord(
		"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running') "
		. 'ORDER BY job_id DESC LIMIT 1', $domain_id);
	if (is_array($row)) {
		$job_id = $app->functions->intval($row['job_id']);
	}
}

if ($job_id < 1) {
	echo json_encode(array('state' => 'none'));
	exit;
}

$job = $app->db->queryOneRecord(
	'SELECT job_id, job_kind, job_status, parent_domain_id, exit_code FROM malwatch_job WHERE job_id = ?',
	$job_id);
if (!is_array($job)) {
	echo json_encode(array('state' => 'none'));
	exit;
}

$out = array(
	'state' => (string) $job['job_status'],
	'kind' => (string) $job['job_kind'],
	'job_id' => $app->functions->intval($job['job_id']),
	'domain_id' => $app->functions->intval($job['parent_domain_id']),
);

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/runs/job-' . $out['job_id'] . '.progress';
$raw = @file_get_contents($file);
if ($raw !== false) {
	$doc = json_decode($raw, true);
	if (is_array($doc)) {
		$out['progress'] = $doc;
	}
}

echo json_encode($out);
