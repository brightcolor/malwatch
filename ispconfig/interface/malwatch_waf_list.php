<?php

/**
 * Abwehr: the WAF of every website at a glance.
 *
 * States, the hits of the chosen period with a small curve per day, the rule
 * each website sees most, the emergency stop and the response body switch.
 * The buttons queue jobs; the malwatch cron carries them out (malwatch_waf),
 * and the page follows them through malwatch_waf_jobs.php.
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

$language = $app->functions->check_language($_SESSION['s']['language']);
$lng_file = 'lib/lang/' . $language . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;
$catalog = waf_panel_rule_catalog(waf_panel_rule_catalog_file('lib/lang', $language));

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

$settings = waf_panel_settings($app);
$clock = waf_panel_clock($app);
// After a button the filters come back as hidden fields of the form.
$filters = waf_panel_filters(array_merge($_GET, $_POST), $settings['waf_stats_days']);

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_list.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_emergency_on_txt', 'btn_emergency_off_txt',
	'confirm_emergency_on_txt', 'confirm_emergency_off_txt', 'response_title_txt', 'hint_select_txt',
	'btn_bulk_detect_txt', 'btn_bulk_enforce_txt', 'btn_bulk_off_txt',
	'confirm_bulk_detect_txt', 'confirm_bulk_enforce_txt', 'confirm_bulk_off_txt')));

$sites = waf_panel_rows($app->db->queryAllRecords(
	'SELECT w.domain_id, w.domain, s.waf_state, s.waf_state_since, s.waf_pending_state FROM web_domain w '
	. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.type = 'vhost' AND w.active = 'y' ORDER BY w.domain"));
$day_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT parent_domain_id, day, hits, would_block FROM malwatch_waf_site_day '
	. 'WHERE day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $filters['days'] - 1));
$rule_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT parent_domain_id, rule_id, MAX(rule_msg) AS rule_msg, SUM(hits) AS hits FROM malwatch_waf_day '
	. 'WHERE day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY parent_domain_id, rule_id', $filters['days'] - 1));
$wordpress = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT DISTINCT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND software_kind = 'core'")) as $row) {
	$wordpress[] = (int) $row['parent_domain_id'];
}

// Queued and running jobs: their websites show "wird umgesetzt", and the
// script follows them from the first one on.
$pending = array();
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	$pending = array_merge($pending, $job['sites']);
	if ($first_job === 0) {
		$first_job = $job['job_id'];
	}
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);

$recent_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('done','error') ORDER BY job_id DESC LIMIT 3")) as $row) {
	$job = waf_panel_job($wb, $row);
	$recent_rows[] = array(
		'job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']
			. ($job['log'] !== '' ? ' – ' . $job['log'] : '')),
		'job_failed' => $job['status'] === 'error' ? 1 : 0,
	);
}
$app->tpl->setLoop('recent', $recent_rows);
$app->tpl->setVar('has_recent', count($recent_rows) > 0 ? 1 : 0);

$overview = waf_panel_overview($sites, $pending, $day_rows, $rule_rows, $wordpress, $clock['today'], $filters['days'], $filters);
$app->tpl->setVar('lede', $app->functions->htmlentities(waf_panel_lede($wb, $overview['counts'], $filters['days'])));

$rows = array();
foreach ($overview['rows'] as $row) {
	$rows[] = array(
		'domain_id' => $row['domain_id'],
		'domain' => $app->functions->htmlentities($row['domain']),
		'state_class' => $row['state'],
		'state_label' => $app->functions->htmlentities(waf_panel_state_label($wb, $row['state'])),
		'is_pending' => $row['pending'] ? 1 : 0,
		'since_label' => $row['since'] !== '' && $row['state'] !== 'off'
			? $app->functions->htmlentities(sprintf($wb['since_txt'], malwatch_datetime($row['since']))) : '',
		'hits' => number_format($row['hits'], 0, ',', '.'),
		'would_block' => number_format($row['would_block'], 0, ',', '.'),
		'has_block' => $row['would_block'] > 0 ? 1 : 0,
		'spark' => $filters['days'] > 1 ? waf_panel_sparkline($row['values'], 64, 18) : '',
		'top_rule' => $row['top_rule'] === '' ? ''
			: $app->functions->htmlentities(waf_panel_rule_title($wb, $row['top_rule'], $row['top_rule_msg'], $catalog)),
		'top_rule_id' => $app->functions->htmlentities($row['top_rule']),
		'is_wordpress' => $row['wordpress'] ? 1 : 0,
	);
}
$app->tpl->setLoop('rows', $rows);
$app->tpl->setVar('has_rows', count($rows) > 0 ? 1 : 0);
$app->tpl->setVar('selected_template', $app->functions->htmlentities(
	sprintf($wb['selected_template_txt'], number_format(count($rows), 0, ',', '.'))));
$app->tpl->setVar('selected_none', $app->functions->htmlentities($wb['selected_none_txt']));

$link = 'security/malwatch_waf_list.php?';
$periods = array();
foreach (waf_periods($settings['waf_stats_days']) as $days) {
	$periods[] = array(
		'label' => $app->functions->htmlentities($days === 1 ? $wb['period_today_txt'] : sprintf($wb['period_days_txt'], $days)),
		'href' => $app->functions->htmlentities($link . waf_panel_query($filters, array('days' => $days))),
		'current' => $days === $filters['days'] ? 1 : 0,
	);
}
$app->tpl->setLoop('periods', $periods);
$state_links = array();
foreach (array('', 'off', 'detect', 'enforce') as $state) {
	$state_links[] = array(
		'label' => $app->functions->htmlentities($state === '' ? $wb['filter_all_txt'] : waf_panel_state_label($wb, $state)),
		'href' => $app->functions->htmlentities($link . waf_panel_query($filters, array('state' => $state))),
		'current' => $state === $filters['state'] ? 1 : 0,
	);
}
$app->tpl->setLoop('state_links', $state_links);
$app->tpl->setVar('wp_href', $app->functions->htmlentities($link . waf_panel_query($filters, array('wordpress' => !$filters['wordpress']))));
$app->tpl->setVar('hits_href', $app->functions->htmlentities($link . waf_panel_query($filters, array('hits' => !$filters['hits']))));
$app->tpl->setVar('self_href', $app->functions->htmlentities($link . waf_panel_query($filters, array())));
$app->tpl->setVar('days', $filters['days']);
$app->tpl->setVar('filter_state', $app->functions->htmlentities($filters['state']));
$app->tpl->setVar('filter_wp', $filters['wordpress'] ? 1 : 0);
$app->tpl->setVar('filter_hits', $filters['hits'] ? 1 : 0);

$app->tpl->setVar('emergency', $settings['waf_emergency'] === 'y' ? 1 : 0);
$app->tpl->setVar('emergency_line', $app->functions->htmlentities(
	sprintf($wb['emergency_since_txt'], malwatch_datetime($settings['waf_emergency_since']))));
$lean = $settings['waf_response_body'] === 'lean';
$app->tpl->setVar('response_button', $app->functions->htmlentities($lean ? $wb['response_lean_btn_txt'] : $wb['response_full_btn_txt']));
$app->tpl->setVar('response_ok', $app->functions->htmlentities($lean ? $wb['response_to_full_txt'] : $wb['response_to_lean_txt']));
$app->tpl->setVar('response_confirm', $app->functions->htmlentities($lean ? $wb['confirm_full_txt'] : $wb['confirm_lean_txt']));
$app->tpl->setVar('response_target', $lean ? 'full' : 'lean');

$exceptions = $app->db->queryOneRecord(
	"SELECT COUNT(*) AS n, COALESCE(SUM(exception_state = 'error'), 0) AS errors FROM malwatch_waf_exception");
$exception_count = is_array($exceptions) ? (int) $exceptions['n'] : 0;
$exception_errors = is_array($exceptions) ? (int) $exceptions['errors'] : 0;
$app->tpl->setVar('exceptions_link', $app->functions->htmlentities($exception_errors > 0
	? sprintf($wb['exceptions_errors_txt'], $exception_count, $exception_errors)
	: sprintf($wb['exceptions_link_txt'], $exception_count)));

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_waf_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
