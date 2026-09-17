<?php
/**
 * Checks the pure helpers of the Abwehr pages against the German texts.
 *
 *   php ispconfig/tests/waf_panel_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';

$wb = array();
include __DIR__ . '/../interface/lang/en_malwatch_waf.lng';
$en = $wb;
$wb = array();
include __DIR__ . '/../interface/lang/de_malwatch_waf.lng';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

expect_same('same keys in both languages', array(
	array_values(array_diff(array_keys($wb), array_keys($en))),
	array_values(array_diff(array_keys($en), array_keys($wb))),
), array(array(), array()));

// --- B1: labels --------------------------------------------------------------

expect_same('state label', waf_panel_state_label($wb, 'detect'), 'mitschreiben');
expect_same('unknown state label', waf_panel_state_label($wb, 'foo'), 'foo');
expect_same('scope label', waf_panel_scope_label($wb, 'site_param'), 'nur dieser Parameter');
expect_same('exception state label', waf_panel_exception_state_label($wb, 'removing'), 'wird entfernt');
expect_same('reason label', waf_panel_reason_label($wb, 'too_early'), 'Die Website schreibt noch nicht lange genug mit.');
expect_same('job label', waf_panel_job_label($wb, 'emergency'), 'Notaus');
expect_same('status label', waf_panel_status_label($wb, 'running'), 'läuft');
expect_same('rule title from its group', waf_panel_rule_title($wb, '942100', 'SQL Injection Attack Detected via libinjection'), 'SQL-Einschleusung');
expect_same('rule title from the message', waf_panel_rule_title($wb, '10010', 'own rule'), 'own rule');
expect_same('rule title from the number', waf_panel_rule_title($wb, '999999', ''), 'Regel 999999');
expect_same('fallback text', waf_panel_text($wb, 'no_such_key_txt', 'x'), 'x');

// --- B2: views ---------------------------------------------------------------

$rows = array(
	array('day' => '2026-09-14', 'hits' => '3', 'would_block' => '1'),
	array('day' => '2026-09-16', 'hits' => '5', 'would_block' => '0'),
	array('day' => '2026-09-16', 'hits' => '2', 'would_block' => '2'),
	array('day' => '2026-09-01', 'hits' => '9', 'would_block' => '9'),
);
expect_same('series', waf_panel_day_series($rows, '2026-09-16', 3), array(
	array('day' => '2026-09-14', 'hits' => 3, 'would_block' => 1),
	array('day' => '2026-09-15', 'hits' => 0, 'would_block' => 0),
	array('day' => '2026-09-16', 'hits' => 7, 'would_block' => 2),
));
expect_same('series of one day', waf_panel_day_series($rows, '2026-09-16', 1), array(array('day' => '2026-09-16', 'hits' => 7, 'would_block' => 2)));
$month_end = waf_panel_day_series(array(), '2026-10-02', 7);
expect_same('series over a month end', array(count($month_end), $month_end[0]['day']), array(7, '2026-09-26'));
expect_same('series with a bad date', waf_panel_day_series($rows, 'gestern', 3), array());

expect_same('sparkline', waf_panel_sparkline(array(0, 2, 1), 60, 16), '0.0,15.5 30.0,0.5 60.0,8.0');
expect_same('sparkline of zeros', waf_panel_sparkline(array(0, 0), 60, 16), '0.0,15.5 60.0,15.5');
expect_same('sparkline of one value', waf_panel_sparkline(array(4), 60, 16), '60.0,0.5');
expect_same('sparkline of nothing', waf_panel_sparkline(array(), 60, 16), '');

$sites = array(
	array('domain_id' => '11', 'domain' => 'beispiel.test', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-10 08:00:00', 'waf_pending_state' => ''),
	array('domain_id' => '12', 'domain' => 'zweite.test', 'waf_state' => 'enforce', 'waf_state_since' => '2026-09-01 08:00:00', 'waf_pending_state' => ''),
	array('domain_id' => '13', 'domain' => 'dritte.test', 'waf_state' => null, 'waf_state_since' => null, 'waf_pending_state' => null),
	array('domain_id' => '14', 'domain' => 'vierte.test', 'waf_state' => 'off', 'waf_state_since' => null, 'waf_pending_state' => 'detect'),
);
$day_rows = array(
	array('parent_domain_id' => '11', 'day' => '2026-09-16', 'hits' => '10', 'would_block' => '3'),
	array('parent_domain_id' => '11', 'day' => '2026-09-15', 'hits' => '4', 'would_block' => '0'),
	array('parent_domain_id' => '12', 'day' => '2026-09-16', 'hits' => '4', 'would_block' => '4'),
);
$rule_rows = array(
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'hits' => '9'),
	array('parent_domain_id' => '11', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'hits' => '12'),
	array('parent_domain_id' => '12', 'rule_id' => '930130', 'rule_msg' => 'Restricted File Access Attempt', 'hits' => '4'),
);
$no_filter = array('state' => '', 'wordpress' => false, 'hits' => false);
$view = waf_panel_overview($sites, array(13), $day_rows, $rule_rows, array(11, 13), '2026-09-16', 7, $no_filter);
expect_same('overview counts', $view['counts'], array('off' => 2, 'detect' => 1, 'enforce' => 1, 'pending' => 2,
	'hits' => 18, 'would_block' => 7, 'sites_with_hits' => 2));
expect_same('overview order', array_column($view['rows'], 'domain'), array('beispiel.test', 'zweite.test', 'dritte.test', 'vierte.test'));
$first = $view['rows'][0];
expect_same('overview row', array($first['domain_id'], $first['state'], $first['since'], $first['pending'], $first['wordpress'],
	$first['hits'], $first['would_block'], $first['top_rule'], $first['top_rule_hits']),
	array(11, 'detect', '2026-09-10 08:00:00', false, true, 14, 3, '941100', 12));
expect_same('overview curve', $first['values'], array(0, 0, 0, 0, 0, 4, 10));
expect_same('overview without a site row', array($view['rows'][2]['state'], $view['rows'][2]['since'], $view['rows'][2]['pending']), array('off', '', true));
expect_same('overview pending from the site row', $view['rows'][3]['pending'], true);
$only = waf_panel_overview($sites, array(), $day_rows, $rule_rows, array(11, 13), '2026-09-16', 1,
	array('state' => 'off', 'wordpress' => true, 'hits' => false));
expect_same('overview filtered', array_column($only['rows'], 'domain'), array('dritte.test'));
expect_same('overview counts cover every website', $only['counts']['hits'], 14);
$with_hits = waf_panel_overview($sites, array(), $day_rows, $rule_rows, array(), '2026-09-16', 7,
	array('state' => '', 'wordpress' => false, 'hits' => true));
expect_same('overview with hits only', array_column($with_hits['rows'], 'domain'), array('beispiel.test', 'zweite.test'));

expect_same('lede of the spec', waf_panel_lede($wb, array('detect' => 2, 'enforce' => 0, 'hits' => 14, 'would_block' => 3), 1),
	'2 Websites schreiben mit, keine blockiert. Heute 14 Treffer, 3 davon wären abgewiesen worden.');
expect_same('lede of a week', waf_panel_lede($wb, array('detect' => 1, 'enforce' => 1, 'hits' => 1200, 'would_block' => 0), 7),
	'Eine Website schreibt mit, eine blockiert. In 7 Tagen 1.200 Treffer.');
expect_same('lede without detecting websites', waf_panel_lede($wb, array('detect' => 0, 'enforce' => 3, 'hits' => 0, 'would_block' => 0), 30),
	'Keine Website schreibt mit, 3 blockieren. In 30 Tagen 0 Treffer.');

$filters = waf_panel_filters(array('days' => '30', 'state' => 'enforce', 'wp' => '1'), 90);
expect_same('filters', $filters, array('days' => 30, 'state' => 'enforce', 'wordpress' => true, 'hits' => false));
expect_same('filters with odd values', waf_panel_filters(array('days' => '5', 'state' => 'scharf'), 90),
	array('days' => 7, 'state' => '', 'wordpress' => false, 'hits' => false));
expect_same('query', waf_panel_query($filters, array('hits' => true)), 'days=30&state=enforce&wp=1&hits=1');
expect_same('query without filters', waf_panel_query($filters, array('state' => '', 'wordpress' => false)), 'days=30');

$rule_day_rows = array(
	array('day' => '2026-09-15', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '2', 'would_block_hits' => '1'),
	array('day' => '2026-09-16', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/wp-admin/admin-ajax.php', 'hits' => '5', 'would_block_hits' => '0'),
	array('day' => '2026-09-16', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '1', 'would_block_hits' => '1'),
	array('day' => '2026-09-14', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'path' => '/seite', 'hits' => '3', 'would_block_hits' => '3'),
	array('day' => '2026-09-16', 'rule_id' => '10010', 'rule_msg' => '', 'path' => '/x', 'hits' => '1', 'would_block_hits' => '0'),
);
$rules = waf_panel_rules($wb, $rule_day_rows);
expect_same('rules order', array_column($rules, 'rule_id'), array('942100', '941100', '10010'));
expect_same('rule sums', array($rules[0]['hits'], $rules[0]['would_block'], $rules[0]['last_day'], $rules[0]['title'],
	$rules[0]['msg'], $rules[0]['can_except'], $rules[0]['path_count']),
	array(8, 2, '2026-09-16', 'SQL-Einschleusung', 'SQL Injection Attack Detected via libinjection', true, 2));
expect_same('rule paths', $rules[0]['paths'], array(array('path' => '/wp-admin/admin-ajax.php', 'hits' => 5), array('path' => '/suche', 'hits' => 3)));
expect_same('own rule', array($rules[2]['can_except'], $rules[2]['title']), array(false, 'Regel 10010'));

expect_same('paths', waf_panel_paths($rule_day_rows), array(
	array('path' => '/wp-admin/admin-ajax.php', 'hits' => 5, 'rules' => array('942100')),
	array('path' => '/seite', 'hits' => 3, 'rules' => array('941100')),
	array('path' => '/suche', 'hits' => 3, 'rules' => array('942100')),
	array('path' => '/x', 'hits' => 1, 'rules' => array('10010')),
));

$hit_row = array('hit_id' => '5', 'seen_at' => '2026-09-16 21:09:19', 'client_ip' => '198.51.100.7', 'method' => 'POST',
	'uri' => '/wp-json/batch/v1', 'path' => '/wp-json/batch/v1', 'status' => '207', 'anomaly_score' => '5',
	'would_block' => 'y', 'logged_in' => 'n',
	'rules' => '[{"id":"949110","msg":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":"","param":""},'
		. '{"id":"942190","msg":"Detects MSSQL code execution and information gathering attempts","data":"Matched Data: x","param":"json.requests.0.path"}]',
	'request_headers' => '{"Host":"beispiel.test","Cookie":"a=[entfernt]"}', 'request_body' => '{"a":1}',
	'response_file' => '', 'response_bytes' => '0');
$hit = waf_panel_hit($wb, $hit_row);
expect_same('hit basics', array($hit['hit_id'], $hit['status'], $hit['score'], $hit['would_block'], $hit['logged_in'],
	$hit['has_body'], $hit['has_response']), array(5, 207, 5, true, false, true, false));
expect_same('hit rule titles', array_column($hit['rules'], 'title'), array('Punktgrenze überschritten', 'SQL-Einschleusung'));
expect_same('hit prefill skips the score', $hit['prefill'], array('rule_id' => '942190', 'path' => '/wp-json/batch/v1', 'param' => 'json.requests.0.path'));
expect_same('hit headers', $hit['headers'], array(array('name' => 'Host', 'value' => 'beispiel.test'), array('name' => 'Cookie', 'value' => 'a=[entfernt]')));
$broken = waf_panel_hit($wb, array_merge($hit_row, array('rules' => 'kaputt', 'request_headers' => '', 'request_body' => null, 'response_file' => 'x.html.gz')));
expect_same('hit with broken JSON', array($broken['rules'], $broken['headers'], $broken['has_body'], $broken['has_response'], $broken['prefill']['rule_id']),
	array(array(), array(), false, true, ''));

$settings = waf_settings(array());
$site = array('waf_state' => 'detect', 'waf_state_since' => '2026-09-10 08:00:00');
$totals = array('would_block' => '12', 'would_block_logged_in' => '3');
$enforce_rules = array(
	array('rule_id' => '941100', 'rule_msg' => 'XSS', 'would_block_hits' => '2'),
	array('rule_id' => '942100', 'rule_msg' => 'SQLi', 'would_block_hits' => '9'),
	array('rule_id' => '930130', 'rule_msg' => 'Files', 'would_block_hits' => '0'),
);
$enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-16 12:00:00');
expect_same('enforce too early', array($enforce['allowed'], $enforce['reason'], $enforce['free_from']), array(false, 'too_early', '2026-09-17 08:00:00'));
expect_same('enforce figures', array($enforce['would_block'], $enforce['logged_in'], $enforce['days']), array(12, 3, 7));
expect_same('enforce rules', array_column($enforce['rules'], 'rule_id'), array('942100', '941100'));
$enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-17 08:00:00');
expect_same('enforce free', array($enforce['allowed'], $enforce['reason']), array(true, ''));
$enforce = waf_panel_enforce($wb, array('waf_state' => 'enforce', 'waf_state_since' => '2026-09-01 08:00:00'), null, array(), $settings, '2026-09-17 08:00:00');
expect_same('enforce already on', array($enforce['allowed'], $enforce['reason'], $enforce['free_from'], $enforce['would_block']), array(false, '', '', 0));
$enforce = waf_panel_enforce($wb, null, null, array(), $settings, '2026-09-17 08:00:00');
expect_same('enforce from nothing', array($enforce['state'], $enforce['reason']), array('off', 'not_detect'));

list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'site_path', 'exc_rule' => ' 942100 ',
	'exc_path' => '/wp-admin/admin-ajax.php', 'exc_param' => 'x', 'exc_note' => "Formular\nKontakt"), 11);
expect_same('input site_path', array($row, $wrong), array(array('scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100',
	'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'note' => 'Formular Kontakt'), ''));
list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'all', 'exc_rule' => '941160', 'exc_path' => '/x'), 11);
expect_same('input all drops website and path', array($row['parent_domain_id'], $row['path'], $wrong), array(0, '', ''));
list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'site_param', 'exc_rule' => '942100', 'exc_param' => 'a"b'), 11);
expect_same('input with a bad parameter', $wrong, 'param');
list($row, $wrong) = waf_panel_exception_input(array(), 11);
expect_same('input without a scope', $wrong, 'scope');

expect_same('preview text', waf_panel_preview_text($wb, array('covered' => 18, 'total' => 21), 7),
	'Diese Ausnahme hätte 18 von 21 Treffern der letzten 7 Tage verhindert.');
expect_same('preview without hits', waf_panel_preview_text($wb, array('covered' => 0, 'total' => 0), 7),
	'In den letzten 7 Tagen gab es keinen Treffer dieser Regel.');

$job = waf_panel_job($wb, array('job_id' => '9', 'job_status' => 'running',
	'options' => '{"action":"set_state","state":"detect","domain_ids":[11,"12"]}', 'job_log' => ''));
expect_same('job view', $job, array('job_id' => 9, 'status' => 'running', 'status_label' => 'läuft',
	'label' => 'Zustand ändern: mitschreiben', 'log' => '', 'sites' => array(11, 12), 'running' => true));
$job = waf_panel_job($wb, array('job_id' => '10', 'job_status' => 'error', 'options' => 'kaputt', 'job_log' => "Zeile eins\nZeile zwei"));
expect_same('job view of a broken row', array($job['label'], $job['log'], $job['running']), array('', 'Zeile eins', false));

$exception = waf_panel_exception_row($wb, array('exception_id' => '3', 'scope' => 'site_param', 'parent_domain_id' => '11',
	'domain' => 'beispiel.test', 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q', 'note' => 'Suche',
	'exception_state' => 'active', 'error_reason' => '', 'created_by' => 'admin', 'created_at' => '2026-09-16 10:00:00'));
expect_same('exception row', array($exception['exception_id'], $exception['scope_label'], $exception['site'], $exception['site_id'],
	$exception['target'], $exception['state_label'], $exception['can_remove']),
	array(3, 'nur dieser Parameter', 'beispiel.test', 11, '/suche · Parameter q', 'aktiv', true));
$exception = waf_panel_exception_row($wb, array('exception_id' => '4', 'scope' => 'all', 'parent_domain_id' => '0',
	'domain' => '', 'rule_id' => '941160', 'path' => '', 'param' => '', 'note' => '',
	'exception_state' => 'pending', 'error_reason' => '', 'created_by' => 'admin', 'created_at' => '2026-09-16 10:00:00'));
expect_same('exception row for every website', array($exception['site'], $exception['target'], $exception['can_remove']),
	array('alle Websites', '', false));

// --- B5: day label -----------------------------------------------------------

expect_same('day label', waf_panel_day_label('2026-09-16'), '16.09.2026');
expect_same('day label of something else', waf_panel_day_label('gestern'), 'gestern');

// --- B6: exception list ------------------------------------------------------

function exception_ids($list)
{
	$ids = array();
	foreach ($list['rows'] as $row) {
		$ids[] = (int) $row['exception_id'];
	}
	return $ids;
}

expect_same('exception filters', waf_panel_exception_filters(array('state' => 'error', 'site' => '12')),
	array('state' => 'error', 'site' => '12'));
expect_same('exception filters for every website', waf_panel_exception_filters(array('site' => 'all')),
	array('state' => '', 'site' => 'all'));
expect_same('exception filters refuse other values',
	waf_panel_exception_filters(array('state' => 'deleted', 'site' => '12 OR 1=1')), array('state' => '', 'site' => ''));
expect_same('exception filters refuse website 0', waf_panel_exception_filters(array('site' => '0')),
	array('state' => '', 'site' => ''));

$exception_rows = array(
	array('exception_id' => '1', 'scope' => 'site', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'exception_state' => 'active'),
	array('exception_id' => '2', 'scope' => 'all_path', 'parent_domain_id' => '0', 'domain' => '', 'exception_state' => 'error'),
	array('exception_id' => '3', 'scope' => 'site_path', 'parent_domain_id' => '11', 'domain' => 'Beispiel.test', 'exception_state' => 'error'),
	array('exception_id' => '4', 'scope' => 'site_param', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'exception_state' => 'pending'),
);
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array()));
expect_same('exception list unfiltered', exception_ids($list), array(1, 2, 3, 4));
expect_same('exception list websites by name', $list['sites'],
	array(array('value' => '11', 'label' => 'Beispiel.test'), array('value' => '12', 'label' => 'zweite.test')));
expect_same('exception list knows global rows', $list['has_global'], true);
expect_same('exception list counts', $list['counts'],
	array('' => 4, 'pending' => 1, 'active' => 1, 'error' => 2, 'removing' => 0));
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => '12')));
expect_same('one website with the global rows', exception_ids($list), array(1, 2, 4));
expect_same('counts follow the website', $list['counts'],
	array('' => 3, 'pending' => 1, 'active' => 1, 'error' => 1, 'removing' => 0));
expect_same('websites stay complete under a filter', count($list['sites']), 2);
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => 'all', 'state' => 'error')));
expect_same('global rows with an error', exception_ids($list), array(2));
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => '11', 'state' => 'error')));
expect_same('one website with an error', exception_ids($list), array(2, 3));
$list = waf_panel_exception_list(array_slice($exception_rows, 0, 1), waf_panel_exception_filters(array()));
expect_same('no global rows', $list['has_global'], false);

expect_same('exception query', waf_panel_exception_query(array('state' => 'error', 'site' => '12'), array('site' => '')),
	'state=error');
expect_same('exception query for every website',
	waf_panel_exception_query(array('state' => '', 'site' => ''), array('site' => 'all')), 'site=all');
expect_same('exception query with both', waf_panel_exception_query(array('state' => 'active', 'site' => '11'), array()),
	'state=active&site=11');

// --- B7: settings form -------------------------------------------------------

function waf_config_form()
{
	$form = array();
	$file = __DIR__ . '/../interface/form/malwatch_waf_config.tform.php';
	if (is_file($file)) {
		include $file;
	}
	return $form + array('name' => '', 'db_table' => '', 'db_table_idx' => '', 'title' => '', 'tabs' => array());
}

function waf_config_words($lang)
{
	$wb = array();
	$file = __DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_config.lng';
	if (is_file($file)) {
		include $file;
	}
	return $wb;
}

$config_form = waf_config_form();
expect_same('settings form row', array($config_form['name'], $config_form['db_table'], $config_form['db_table_idx']),
	array('malwatch_waf_config', 'malwatch_config', 'config_id'));
$config_tab = isset($config_form['tabs']['waf']) ? $config_form['tabs']['waf'] : array('title' => '', 'fields' => array());
expect_same('settings form edits the numbers only', array_keys($config_tab['fields']), array_keys(waf_settings_limits()));
$config_words = array('de' => waf_config_words('de'), 'en' => waf_config_words('en'));
expect_same('settings words in both languages', array(
	array_values(array_diff(array_keys($config_words['de']), array_keys($config_words['en']))),
	array_values(array_diff(array_keys($config_words['en']), array_keys($config_words['de']))),
), array(array(), array()));
$config_defaults = waf_settings_defaults();
foreach (waf_settings_limits() as $key => $limit) {
	$field = isset($config_tab['fields'][$key]) ? $config_tab['fields'][$key] : array();
	$validator = isset($field['validators'][0]) ? $field['validators'][0] : array();
	expect_same("settings form type of $key", array(
		isset($field['datatype']) ? $field['datatype'] : '',
		isset($validator['type']) ? $validator['type'] : '',
	), array('INTEGER', 'RANGE'));
	expect_same("settings form range of $key", isset($validator['range']) ? $validator['range'] : '', $limit[0] . ':' . $limit[1]);
	expect_same("settings form default of $key", isset($field['default']) ? $field['default'] : '', (string) $config_defaults[$key]);
	expect_same("settings form message of $key",
		isset($validator['errmsg']) && isset($config_words['de'][$validator['errmsg']]), true);
	expect_same("settings form label of $key", isset($config_words['de'][$key . '_txt']), true);
}
expect_same('settings form title and tab', array(
	isset($config_words['de'][$config_form['title']]),
	isset($config_words['de'][$config_tab['title']]),
), array(true, true));

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel: alle Prüfungen bestanden\n";
