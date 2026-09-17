<?php

/**
 * Abwehr: every exception with its state, filtered by state and website.
 * "Entfernen" queues a job like the page of a website; the malwatch cron
 * takes the exception out of the rule files, and the page follows the job.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

// After a button the filters come back as hidden fields of the form.
$filters = waf_panel_exception_filters(array_merge($_GET, $_POST));

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_exception_list.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_exception_remove_txt', 'confirm_exception_remove_txt')));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

// Running jobs are followed like on the overview.
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	$first_job = $first_job === 0 ? $job['job_id'] : $first_job;
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);

$all_rows = waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_exception ORDER BY exception_id DESC'));
$list = waf_panel_exception_list($all_rows, $filters);
$link = 'security/malwatch_waf_exception_list.php';

$state_links = array();
foreach (array('', 'active', 'pending', 'error', 'removing') as $state) {
	$query = waf_panel_exception_query($filters, array('state' => $state));
	$state_links[] = array(
		'label' => $app->functions->htmlentities(sprintf($wb['exc_count_txt'],
			$state === '' ? $wb['filter_all_txt'] : waf_panel_exception_state_label($wb, $state),
			number_format($list['counts'][$state], 0, ',', '.'))),
		'href' => $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')),
		'current' => $state === $filters['state'] ? 1 : 0,
	);
}
$app->tpl->setLoop('state_links', $state_links);

$site_links = array(array('value' => '', 'label' => $wb['filter_all_txt']));
if ($list['has_global']) {
	$site_links[] = array('value' => 'all', 'label' => $wb['exc_filter_global_txt']);
}
foreach ($list['sites'] as $choice) {
	$site_links[] = $choice;
}
$sites = array();
foreach ($site_links as $choice) {
	$query = waf_panel_exception_query($filters, array('site' => $choice['value']));
	$sites[] = array(
		'label' => $app->functions->htmlentities($choice['label']),
		'href' => $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')),
		'current' => $choice['value'] === $filters['site'] ? 1 : 0,
	);
}
$app->tpl->setLoop('site_links', $sites);
$app->tpl->setVar('has_site_links', count($sites) > 1 ? 1 : 0);

$rows = array();
foreach ($list['rows'] as $row) {
	$exception = waf_panel_exception_row($wb, $row);
	$rows[] = array(
		'exception_id' => $exception['exception_id'],
		'exc_rule' => $app->functions->htmlentities($exception['rule_id']),
		'exc_rule_title' => $app->functions->htmlentities(waf_panel_rule_title($wb, $exception['rule_id'], '')),
		'exc_site' => $app->functions->htmlentities($exception['site']),
		'exc_site_href' => strpos((string) $row['scope'], 'site') === 0
			? $app->functions->htmlentities('security/malwatch_waf_show.php?id=' . $exception['site_id']) : '',
		'exc_scope' => $app->functions->htmlentities($exception['scope_label']),
		'exc_target' => $app->functions->htmlentities($exception['target']),
		'exc_note' => $app->functions->htmlentities($exception['note']),
		'exc_state' => $app->functions->htmlentities($exception['state_label']),
		'exc_failed' => $exception['state'] === 'error' ? 1 : 0,
		'exc_error' => $app->functions->htmlentities($exception['error']),
		'exc_created' => $app->functions->htmlentities($exception['created_by'] . ', ' . malwatch_datetime($exception['created_at'])),
		'can_remove' => $exception['can_remove'] ? 1 : 0,
	);
}
$app->tpl->setLoop('rows', $rows);
$app->tpl->setVar('has_rows', count($rows) > 0 ? 1 : 0);
$app->tpl->setVar('has_any', count($all_rows) > 0 ? 1 : 0);

$query = waf_panel_exception_query($filters, array());
$app->tpl->setVar('self_href', $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')));
$app->tpl->setVar('filter_state', $app->functions->htmlentities($filters['state']));
$app->tpl->setVar('filter_site', $app->functions->htmlentities($filters['site']));

$csrf = $app->auth->csrf_token_get('malwatch_waf_exception_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
