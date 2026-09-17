<?php

/**
 * The WAF jobs for the Abwehr pages as JSON: every queued or running one, and
 * from the id in since= on the finished ones as well, so a page can show how
 * its jobs ended. No template: the caller reads JSON only.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_waf_panel.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$since = $app->functions->intval(isset($_GET['since']) ? $_GET['since'] : 0);
$jobs = array();
$running = 0;
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND (job_status IN ('pending','running') OR (? > 0 AND job_id >= ?)) ORDER BY job_id", $since, $since)) as $row) {
	$job = waf_panel_job($wb, $row);
	$running += $job['running'] ? 1 : 0;
	$jobs[] = $job;
}
echo json_encode(array('jobs' => $jobs, 'running' => $running));
