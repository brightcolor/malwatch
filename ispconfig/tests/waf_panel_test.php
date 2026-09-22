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
$en_words = $wb;
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
$config_numbers = array();
foreach ($config_tab['fields'] as $key => $field) {
	if (isset($field['validators'][0]['type']) && $field['validators'][0]['type'] === 'RANGE') {
		$config_numbers[] = $key;
	}
}
expect_same('settings form edits the numbers only', $config_numbers, array_keys(waf_settings_limits()));
expect_same('settings form knows every choice', array_keys(waf_origin_choices()),
	array_values(array_intersect(array_keys($config_tab['fields']), array_keys(waf_origin_choices()))));
foreach (waf_origin_choices() as $key => $values) {
	expect_same("settings form choices of $key",
		isset($config_tab['fields'][$key]['value']) ? array_keys($config_tab['fields'][$key]['value']) : array(), $values);
}
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

// --- A7: rule cards, address filter, catalog in the helpers ----------------------

expect_same('ranked', waf_panel_ranked(array('b' => 2, 'a' => 2, 'c' => 5)), array(
	array('key' => 'c', 'count' => 5), array('key' => 'a', 'count' => 2), array('key' => 'b', 'count' => 2),
));
expect_same('ranked turns numeric keys into strings', waf_panel_ranked(array('17' => 1)), array(array('key' => '17', 'count' => 1)));

$card_catalog = array('rules' => array('920440' => array('title' => 'Verbotene Dateiendung', 'trigger' => 'Dateiendung „%s“')),
	'groups' => array());
$card_rows = array(
	array('client_ip' => '192.0.2.7', 'logged_in' => 'n', 'rules' => '[{"id":"930130","msg":"Restricted File Access Attempt",'
		. '"data":"Matched Data: .env found within REQUEST_FILENAME: /.env","param":""},'
		. '{"id":"920440","msg":"URL file extension is restricted by policy","data":".bak","param":""}]'),
	array('client_ip' => '192.0.2.7', 'logged_in' => 'n', 'rules' => '[{"id":"930130","msg":"x",'
		. '"data":"Matched Data: .env found within REQUEST_FILENAME: /x/.env","param":""}]'),
	array('client_ip' => '198.51.100.3', 'logged_in' => 'y', 'rules' => '[{"id":"930130","msg":"x",'
		. '"data":"Matched Data: .git/config found within REQUEST_FILENAME: /.git/config","param":""}]'),
	array('client_ip' => '', 'logged_in' => 'n', 'rules' => 'kaputt'),
);
$card = waf_panel_rule_hits($wb, $card_catalog, $card_rows);
expect_same('card rules', array_map('strval', array_keys($card)), array('930130', '920440'));
expect_same('card figures', array($card['930130']['hits'], $card['930130']['logged_in']), array(3, 1));
expect_same('card addresses', $card['930130']['addresses'], array(
	array('key' => '192.0.2.7', 'count' => 2), array('key' => '198.51.100.3', 'count' => 1),
));
expect_same('card triggers', $card['930130']['triggers'], array(
	array('key' => 'Dateiname der Anfrage enthält „.env“', 'count' => 2),
	array('key' => 'Dateiname der Anfrage enthält „.git/config“', 'count' => 1),
));
expect_same('card trigger with the catalog pattern', $card['920440']['triggers'],
	array(array('key' => 'Dateiendung „.bak“', 'count' => 1)));
expect_same('card without rows', waf_panel_rule_hits($wb, $card_catalog, array()), array());

expect_same('ip filter v4', waf_panel_ip_filter(array('ip' => ' 192.0.2.7 ')), '192.0.2.7');
expect_same('ip filter v6', waf_panel_ip_filter(array('ip' => '2001:db8::1')), '2001:db8::1');
expect_same('ip filter rejects text', waf_panel_ip_filter(array('ip' => '192.0.2.7<script>')), '');
expect_same('ip filter without value', waf_panel_ip_filter(array()), '');
expect_same('ip filter rejects arrays', waf_panel_ip_filter(array('ip' => array('192.0.2.7'))), '');
expect_same('ip notice for text', waf_panel_ip_filter_rejected(array('ip' => ' kein-ip ')), 'kein-ip');
expect_same('ip notice for an address', waf_panel_ip_filter_rejected(array('ip' => '192.0.2.7')), '');
expect_same('ip notice without value', waf_panel_ip_filter_rejected(array('ip' => '  ')), '');
expect_same('ip notice for arrays', waf_panel_ip_filter_rejected(array('ip' => array('x'))), '');
expect_same('ip notice cuts long input', strlen(waf_panel_ip_filter_rejected(array('ip' => str_repeat('x', 300)))), 64);

$catalog_rules = waf_panel_rules($wb, $rule_day_rows,
	array('rules' => array('942100' => array('title' => 'SQL-Einschleusung (libinjection)')), 'groups' => array()));
expect_same('rules with catalog titles', array_column($catalog_rules, 'title'),
	array('SQL-Einschleusung (libinjection)', 'Skript-Einschleusung (XSS)', 'Regel 10010'));
$catalog_enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-16 12:00:00',
	array('rules' => array('941100' => array('title' => 'XSS (libinjection)')), 'groups' => array()));
expect_same('enforce with catalog titles', array_column($catalog_enforce['rules'], 'title'),
	array('SQL-Einschleusung', 'XSS (libinjection)'));

$catalog_hit = waf_panel_hit($wb, $hit_row,
	array('rules' => array('942190' => array('title' => 'Ausspähen der Datenbank', 'class' => 'attack')), 'groups' => array()));
expect_same('hit rule with catalog', array($catalog_hit['rules'][1]['title'], $catalog_hit['rules'][1]['class'],
	$catalog_hit['rules'][1]['class_label'], $catalog_hit['rules'][1]['trigger'], $catalog_hit['rules'][1]['note']),
	array('Ausspähen der Datenbank', 'attack', 'Angriffsversuch', 'Gefunden: „x“', ''));
expect_same('hit score rule without trigger', array($catalog_hit['rules'][0]['title'], $catalog_hit['rules'][0]['trigger'],
	$catalog_hit['rules'][0]['class'], $catalog_hit['rules'][0]['class_label'], $catalog_hit['rules'][0]['class_text']),
	array('Punktgrenze überschritten', '', '', '', ''));

// --- A3: rule catalog ----------------------------------------------------------

expect_same('rule classes', waf_panel_rule_classes(),
	array('scanner', 'attack', 'false_positive_prone', 'protocol', 'scoring', 'response'));

$catalog = array(
	'rules' => array('930130' => array('title' => 'Zugriff auf geschützte Datei', 'what' => 'Liest .env.', 'class' => 'scanner',
		'note' => 'Hinweis.', 'trigger' => '')),
	'groups' => array(
		'942' => array('what' => 'SQL-Bausteine.', 'class' => 'false_positive_prone'),
		'941' => array('what' => 'Skripte.', 'class' => 'kaputt'),
	),
);
$info = waf_panel_rule_info($wb, $catalog, '930130', 'Restricted File Access Attempt');
expect_same('rule info from the catalog',
	array($info['rule_id'], $info['title'], $info['what'], $info['class'], $info['class_label'], $info['note'], $info['crs']),
	array('930130', 'Zugriff auf geschützte Datei', 'Liest .env.', 'scanner', 'Scanner', 'Hinweis.', 'Restricted File Access Attempt'));
expect_same('rule info class text', $info['class_text'],
	'Typisch für automatische Scanner. Antwortet die Website mit 404 oder 403, wurde nichts geliefert.');
$info = waf_panel_rule_info($wb, $catalog, '942999', 'Some SQL rule');
expect_same('rule info from the group', array($info['title'], $info['what'], $info['class'], $info['class_label'], $info['trigger']),
	array('SQL-Einschleusung', 'SQL-Bausteine.', 'false_positive_prone', 'Fehlalarm möglich', ''));
$info = waf_panel_rule_info($wb, $catalog, '941999', 'XSS rule');
expect_same('rule info with a wrong class', array($info['class'], $info['class_label'], $info['class_text']), array('', '', ''));
$info = waf_panel_rule_info($wb, array(), '10010', 'own rule');
expect_same('rule info without a catalog', array($info['title'], $info['what'], $info['class']), array('own rule', '', ''));
expect_same('rule title from the catalog', waf_panel_rule_title($wb, '930130', 'x', $catalog), 'Zugriff auf geschützte Datei');
expect_same('group titles 910 912 922', array(
	waf_panel_rule_title($wb, '910999', ''), waf_panel_rule_title($wb, '912999', ''), waf_panel_rule_title($wb, '922999', ''),
), array('Bekannte Angreiferadresse', 'Überlastungsangriff', 'Mehrteiliges Formular'));

$rules_file = tempnam(sys_get_temp_dir(), 'mwrules');
file_put_contents($rules_file, "<?php\n\$wb['rule_930130_title'] = 'T';\n\$wb['rule_930130_class'] = 'scanner';\n"
	. "\$wb['group_942_what'] = 'W';\n\$wb['other_txt'] = 'x';\n\$wb['rule_12_title'] = 'kurz';\n");
$read = waf_panel_rule_catalog($rules_file);
expect_same('rule catalog from a file', array($read['rules']['930130'], $read['groups']['942'], count($read['rules'])),
	array(array('title' => 'T', 'class' => 'scanner'), array('what' => 'W'), 1));
unlink($rules_file);
expect_same('rule catalog of a missing file', waf_panel_rule_catalog(__DIR__ . '/no-such-file.lng'),
	array('rules' => array(), 'groups' => array()));

$rules_dir = sys_get_temp_dir() . '/mwrules' . getmypid();
@mkdir($rules_dir);
touch($rules_dir . '/en_malwatch_waf_rules.lng');
touch($rules_dir . '/de_malwatch_waf_rules.lng');
expect_same('rule catalog file of a language', waf_panel_rule_catalog_file($rules_dir, 'de'), $rules_dir . '/de_malwatch_waf_rules.lng');
expect_same('rule catalog file falls back to English', waf_panel_rule_catalog_file($rules_dir, 'fr'), $rules_dir . '/en_malwatch_waf_rules.lng');
expect_same('rule catalog file with a strange language', waf_panel_rule_catalog_file($rules_dir . '/', '../x'), $rules_dir . '/en_malwatch_waf_rules.lng');
unlink($rules_dir . '/en_malwatch_waf_rules.lng');
unlink($rules_dir . '/de_malwatch_waf_rules.lng');
rmdir($rules_dir);

// --- A2: triggers --------------------------------------------------------------

expect_same('trigger parts matched', waf_panel_trigger_parts('Matched Data: <script> found within ARGS:q: <script>alert(1)</script>'),
	array('form' => 'matched', 'piece' => '<script>', 'target' => 'ARGS:q', 'value' => '<script>alert(1)</script>'));
expect_same('trigger parts with a colon in the value', waf_panel_trigger_parts('Matched Data: $((41*271)) found within ARGS:0: {then: $1:__proto__:then}'),
	array('form' => 'matched', 'piece' => '$((41*271))', 'target' => 'ARGS:0', 'value' => '{then: $1:__proto__:then}'));
expect_same('trigger parts without value', waf_panel_trigger_parts('Matched Data: zip://x found within ARGS:file'),
	array('form' => 'matched', 'piece' => 'zip://x', 'target' => 'ARGS:file', 'value' => ''));
expect_same('trigger parts of a form part', waf_panel_trigger_parts('Matched Data: utf-7 found within Content-Type multipart form'),
	array('form' => 'matched', 'piece' => 'utf-7', 'target' => 'Content-Type multipart form', 'value' => ''));
expect_same('trigger parts assignment', waf_panel_trigger_parts('ARGS_NAMES:aaaa=aaaa'),
	array('form' => 'assign', 'piece' => '', 'target' => 'ARGS_NAMES:aaaa', 'value' => 'aaaa'));
expect_same('trigger parts header', waf_panel_trigger_parts('Restricted header detected: /accept-charset/'),
	array('form' => 'header', 'piece' => '', 'target' => '', 'value' => 'accept-charset'));
expect_same('trigger parts plain', waf_panel_trigger_parts('.bak'),
	array('form' => 'plain', 'piece' => '', 'target' => '', 'value' => '.bak'));
expect_same('trigger parts plain with prefix', waf_panel_trigger_parts('Matched Data: utf-7'),
	array('form' => 'plain', 'piece' => '', 'target' => '', 'value' => 'utf-7'));
expect_same('trigger parts empty', waf_panel_trigger_parts('  '),
	array('form' => 'none', 'piece' => '', 'target' => '', 'value' => ''));

expect_same('target parameter', waf_panel_target_label($wb, 'ARGS:q'), 'Parameter „q“');
expect_same('target post parameter', waf_panel_target_label($wb, 'ARGS_POST:json.content'), 'Parameter „json.content“');
expect_same('target parameter names', waf_panel_target_label($wb, 'ARGS_NAMES:aaaa'), 'Name eines Parameters');
expect_same('target file name', waf_panel_target_label($wb, 'REQUEST_FILENAME'), 'Dateiname der Anfrage');
expect_same('target base name', waf_panel_target_label($wb, 'REQUEST_BASENAME'), 'Dateiname der Anfrage');
expect_same('target address', waf_panel_target_label($wb, 'REQUEST_URI_RAW'), 'Adresse der Anfrage');
expect_same('target request line', waf_panel_target_label($wb, 'REQUEST_LINE'), 'Anfragezeile');
expect_same('target query', waf_panel_target_label($wb, 'QUERY_STRING'), 'Parameterteil der Adresse');
expect_same('target header', waf_panel_target_label($wb, 'REQUEST_HEADERS:User-Agent'), 'Kopfzeile „User-Agent“');
expect_same('target header names', waf_panel_target_label($wb, 'REQUEST_HEADERS_NAMES:x-foo'), 'Name einer Kopfzeile');
expect_same('target cookie', waf_panel_target_label($wb, 'REQUEST_COOKIES:sid'), 'Cookie „sid“');
expect_same('target cookie names', waf_panel_target_label($wb, 'REQUEST_COOKIES_NAMES:sid'), 'Name eines Cookies');
expect_same('target body', waf_panel_target_label($wb, 'REQUEST_BODY'), 'Anfrageinhalt');
expect_same('target xml', waf_panel_target_label($wb, 'XML:/*'), 'XML-Inhalt');
expect_same('target files', waf_panel_target_label($wb, 'FILES:upload'), 'Name einer hochgeladenen Datei');
expect_same('target files names', waf_panel_target_label($wb, 'FILES_NAMES'), 'Name einer hochgeladenen Datei');
expect_same('target method', waf_panel_target_label($wb, 'REQUEST_METHOD'), 'Methode');
expect_same('target protocol', waf_panel_target_label($wb, 'REQUEST_PROTOCOL'), 'Protokoll');
expect_same('target unknown', waf_panel_target_label($wb, 'TX:extension'), 'TX:extension');
expect_same('target parameter without a name', waf_panel_target_label($wb, 'ARGS'), 'ARGS');

expect_same('trigger text contains', waf_panel_trigger_text($wb, 'Matched Data: .env found within REQUEST_FILENAME: /.env', ''),
	'Dateiname der Anfrage enthält „.env“');
expect_same('trigger text with a fixed piece', waf_panel_trigger_text($wb, 'Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>', ''),
	'Parameter „q“: <script>alert(1)</script>');
expect_same('trigger text assignment', waf_panel_trigger_text($wb, 'REQUEST_HEADERS:Content-Length=abc', ''),
	'Kopfzeile „Content-Length“: abc');
expect_same('trigger text header', waf_panel_trigger_text($wb, 'Restricted header detected: /proxy/', ''), 'Kopfzeile „proxy“');
expect_same('trigger text with pattern', waf_panel_trigger_text($wb, '.bak', 'Dateiendung „%s“'), 'Dateiendung „.bak“');
expect_same('trigger text without pattern', waf_panel_trigger_text($wb, '.bak', ''), 'Gefunden: „.bak“');
expect_same('trigger text with a broken pattern', waf_panel_trigger_text($wb, 'x', 'Wert %d und %s'), 'Gefunden: „x“');
expect_same('trigger text empty', waf_panel_trigger_text($wb, '', 'Dateiendung „%s“'), '');
expect_same('trigger text keeps percent signs', waf_panel_trigger_text($wb, 'Matched Data: %s%n found within ARGS:x: %s%n', ''),
	'Parameter „x“ enthält „%s%n“');
expect_same('trigger text cuts the piece',
	strlen(waf_panel_trigger_text($wb, 'Matched Data: ' . str_repeat('a', 200) . ' found within ARGS:x', '')),
	strlen('Parameter „x“ enthält „“') + 120);

// --- A1: how many hits the rule cards read -------------------------------------

$card = waf_settings(array());
expect_same('card hits default', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 5000);
$card = waf_settings(array('waf_card_hits' => '99'));
expect_same('card hits floor', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 100);
$card = waf_settings(array('waf_card_hits' => '250000'));
expect_same('card hits ceiling', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 100000);

// A range message names the limits of its field and what to do next.
foreach (waf_settings_limits() as $key => $limit) {
	$errmsg = isset($config_tab['fields'][$key]['validators'][0]['errmsg']) ? $config_tab['fields'][$key]['validators'][0]['errmsg'] : '';
	$de = isset($config_words['de'][$errmsg]) ? $config_words['de'][$errmsg] : '';
	$en = isset($config_words['en'][$errmsg]) ? $config_words['en'][$errmsg] : '';
	expect_same("range message of $key", array(
		strpos($de, $limit[0] . ' bis ' . $limit[1]) !== false, strpos($de, 'erneut speichern') !== false,
		strpos($en, $limit[0] . ' to ' . $limit[1]) !== false, strpos($en, 'save again') !== false,
	), array(true, true, true, true));
}

// --- B3: the key on the settings page -----------------------------------------

expect_same('mask of a key', waf_panel_key_mask('ABCD1234WXYZ'), '••••WXYZ');
expect_same('mask of a short key', waf_panel_key_mask('AB'), '••••AB');
expect_same('mask without a key', waf_panel_key_mask(''), '');
expect_same('mask of something that is no text', waf_panel_key_mask(null), '');

// --- B4: the state of the sources ---------------------------------------------

$origin_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'off',
	'waf_origin_tor_hours' => 1, 'waf_origin_list_hours' => 24, 'waf_origin_db_hours' => 24);
$origin_rows = array(
	'dbip_country' => array('source' => 'dbip_country', 'version' => '2026-09', 'entries' => '512345',
		'fetched_at' => '2026-09-17 06:00:00', 'checked_at' => '2026-09-17 06:00:00', 'error' => '', 'error_at' => null),
	'dbip_asn' => array('source' => 'dbip_asn', 'version' => '2026-09', 'entries' => '410000',
		'fetched_at' => '2026-09-17 06:00:10', 'checked_at' => '2026-09-17 06:00:10',
		'error' => 'Die Quelle dbip_asn liefert nur 12 Bereiche.', 'error_at' => '2026-09-17 18:00:00'),
);
expect_same('a time of the database', waf_panel_time_label('2026-09-17 06:00:00'), '17.09.2026 06:00');
expect_same('a time that is none', waf_panel_time_label('0000-00-00 00:00:00'), '');
$origin_view = waf_panel_origin_rows($wb, $origin_settings, $origin_rows, '2026-09-17 20:00:00');
expect_same('a row for every chosen source', array_column($origin_view, 'source'),
	array('dbip_country', 'dbip_asn', 'tor'));
expect_same('the source in words', $origin_view[0]['label'], 'DB-IP Lite: Land');
expect_same('the state of a loaded source', $origin_view[0]['state'],
	'Stand 2026-09, 512.345 Bereiche, geladen am 17.09.2026 06:00');
expect_same('a source with an error', array($origin_view[1]['failed'], $origin_view[1]['state']),
	array(1, 'Die Quelle dbip_asn liefert nur 12 Bereiche. Es gilt der Stand von 17.09.2026 06:00.'));
expect_same('a source that never loaded', array($origin_view[2]['failed'], $origin_view[2]['state']),
	array(0, 'Noch nicht geladen. Der Cron holt die Liste beim nächsten stündlichen Durchgang.'));
expect_same('the line of the overview', waf_panel_origin_line($wb, $origin_settings, $origin_rows),
	'Herkunft: DB-IP Lite: Land 512.345 Bereiche, DB-IP Lite: Netz 410.000 Bereiche, Tor noch nicht geladen.');
expect_same('the line with everything off', waf_panel_origin_line($wb, array(), array()),
	'Herkunft der Adressen ist aus.');

// proxycheck.io steht neben den Bereichsdateien: eine Zeile mit dem Kontingent.
$external_settings = array('waf_origin_geo' => 'dbip', 'waf_origin_tor' => 'off', 'waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_daily' => 500);
$external_rows = array(
	'dbip_country' => $origin_rows['dbip_country'],
	'dbip_asn' => array('source' => 'dbip_asn', 'version' => '2026-09', 'entries' => '410000',
		'fetched_at' => '2026-09-17 06:00:10', 'checked_at' => '2026-09-17 06:00:10', 'error' => '', 'error_at' => null),
	'proxycheck' => array('source' => 'proxycheck', 'version' => '', 'entries' => '128',
		'fetched_at' => '2026-09-18 08:00:00', 'checked_at' => '2026-09-18 08:00:00', 'error' => '', 'error_at' => null,
		'day' => '2026-09-18', 'queries' => '240'),
);
$external_view = waf_panel_origin_rows($wb, $external_settings, $external_rows, '2026-09-18 09:00:00');
expect_same('the external source gets its own row', array_column($external_view, 'source'),
	array('dbip_country', 'dbip_asn', 'proxycheck'));
expect_same('the external source in words', $external_view[2]['label'], 'proxycheck.io');
expect_same('queries of the day and checked addresses', $external_view[2]['state'],
	'heute 240 von 500 Abfragen, 128 Adressen geprüft');
expect_same('a new day starts at zero',
	waf_panel_origin_rows($wb, $external_settings, $external_rows, '2026-09-19 09:00:00')[2]['state'],
	'heute 0 von 500 Abfragen, 128 Adressen geprüft');
expect_same('every row says what it counts', array_column($external_view, 'kind'),
	array('ranges', 'ranges', 'addresses'));
$failed_rows = array('proxycheck' => array('source' => 'proxycheck', 'version' => '', 'entries' => '12',
	'fetched_at' => '2026-09-18 08:00:00', 'checked_at' => '2026-09-18 08:30:00',
	'error' => 'proxycheck.io hat die Anfrage abgelehnt.', 'error_at' => '2026-09-18 08:30:00',
	'day' => '2026-09-18', 'queries' => '12'));
$failed_settings = array('waf_origin_net' => 'proxycheck', 'waf_origin_proxycheck_daily' => 500);
$failed_view = waf_panel_origin_rows($wb, $failed_settings, $failed_rows, '2026-09-18 09:00:00');
expect_same('an error stands before the numbers', array($failed_view[0]['failed'], $failed_view[0]['state']),
	array(1, 'proxycheck.io hat die Anfrage abgelehnt. heute 12 von 500 Abfragen, 12 Adressen geprüft'));
expect_same('the overview counts addresses, not ranges',
	waf_panel_origin_line($wb, $failed_settings, $failed_rows), 'Herkunft: proxycheck.io 12 Adressen geprüft.');

// Ein Schlüssel im Formular: leer behält, verdeckt behält, der Haken löscht.
expect_same('an empty field keeps the stored key', waf_panel_key_keep('', 'ab-12cd', false), 'ab-12cd');
expect_same('the masked value keeps the stored key',
	waf_panel_key_keep(waf_panel_key_mask('ab-12cd'), 'ab-12cd', false), 'ab-12cd');
expect_same('a new key replaces the stored one', waf_panel_key_keep(' neu-4711 ', 'ab-12cd', false), 'neu-4711');
expect_same('the checkbox removes the key', waf_panel_key_keep('neu-4711', 'ab-12cd', true), '');
expect_same('nothing stored, nothing posted', waf_panel_key_keep('', '', false), '');

// Was die Seite vor dem Speichern vermisst.
expect_same('nothing is missing',
	waf_panel_origin_missing(array('waf_origin_geo' => 'dbip', 'waf_origin_net' => 'x4b')), array());
expect_same('MaxMind without an account', waf_panel_origin_missing(array('waf_origin_geo' => 'maxmind',
	'waf_origin_maxmind_account' => '', 'waf_origin_maxmind_key' => 'abc')), array('waf_origin_maxmind_missing_error'));
expect_same('proxycheck without a key', waf_panel_origin_missing(array('waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_key' => '')), array('waf_origin_proxycheck_missing_error'));
expect_same('proxycheck with a key', waf_panel_origin_missing(array('waf_origin_net' => 'proxycheck',
	'waf_origin_proxycheck_key' => 'ab-12cd')), array());
expect_same('both are missing',
	waf_panel_origin_missing(array('waf_origin_geo' => 'maxmind', 'waf_origin_net' => 'proxycheck')),
	array('waf_origin_maxmind_missing_error', 'waf_origin_proxycheck_missing_error'));

// --- B7: the origin at an address ---------------------------------------------

$origin_row = array('country' => 'de', 'asn' => '3320', 'as_org' => 'Deutsche Telekom AG', 'is_tor' => 'n',
	'is_vpn' => 'y', 'is_hosting' => 'y', 'is_proxy' => 'n', 'vpn_operator' => 'Beispiel VPN', 'external_state' => 'done');
$origin = waf_panel_origin($wb, $origin_row, 'de');
expect_same('country and provider of an address', array($origin['country'], $origin['provider'], $origin['known']),
	array('DE', 'AS3320 Deutsche Telekom AG', true));
expect_same('the marks of an address', $origin['chips'], array('VPN Beispiel VPN', 'Rechenzentrum'));
$long = waf_panel_origin($wb, array('country' => '', 'asn' => '64500', 'as_org' => str_repeat('Name ', 20),
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'pending'), 'de');
expect_same('a long provider is cut', array(strlen($long['provider']), strlen($long['provider_full']) > 40),
	array(40, true));
expect_same('an address that is being checked', $long['state'], 'wird geprüft');
expect_same('an address the limit stopped', waf_panel_origin($wb, array('country' => '', 'asn' => 0, 'as_org' => '',
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'limit'), 'de')['state'], 'nicht geprüft, Tageslimit');
expect_same('an address without a row', array(waf_panel_origin($wb, null, 'de')['known'],
	waf_panel_origin($wb, null, 'de')['chips']), array(false, array()));
expect_same('the country in words', waf_origin_country_name('FR', 'de') !== 'FR', class_exists('Locale'));
expect_same('a country code that is none', waf_origin_country_name('kein-land', 'de'), '');
expect_same('a code the library does not know stays a code', waf_origin_country_name('QQ', 'de'), 'QQ');
expect_same('the word for a reason names the country and its code', waf_origin_country_word('fr'),
	class_exists('Locale') ? waf_origin_country_name('FR', 'de') . ' (FR)' : 'FR');
expect_same('an unknown code stays a code in a reason', waf_origin_country_word('QQ'), 'QQ');
expect_same('no code, no word', waf_origin_country_word(''), '');
expect_same('the attribution of DB-IP', waf_panel_origin_credit($wb, array('waf_origin_geo' => 'dbip')),
	array('text' => 'IP-Daten: DB-IP', 'url' => 'https://db-ip.com'));
expect_same('the attribution of MaxMind',
	waf_panel_origin_credit($wb, array('waf_origin_geo' => 'maxmind'))['url'], 'https://www.maxmind.com');
expect_same('no attribution while the source is off', waf_panel_origin_credit($wb, array()),
	array('text' => '', 'url' => ''));

// --- Die Seite Sperren --------------------------------------------------------

expect_same('a permanent block', waf_panel_ban_until($wb, array('state' => 'active', 'until' => null),
	'2026-09-18 10:00:00'), 'dauerhaft');
expect_same('a block that runs', waf_panel_ban_until($wb, array('state' => 'active', 'until' => '2026-09-18 10:47:00'),
	'2026-09-18 10:00:00'), 'noch 47 Minuten');
expect_same('a block that runs for hours', waf_panel_ban_until($wb,
	array('state' => 'active', 'until' => '2026-09-19 10:00:00'), '2026-09-18 10:00:00'), 'noch 24 Stunden');
expect_same('an expired block', waf_panel_ban_until($wb, array('state' => 'expired', 'until' => '2026-09-18 09:00:00'),
	'2026-09-18 10:00:00'), 'abgelaufen');
expect_same('a proposal has no end', waf_panel_ban_until($wb, array('state' => 'proposed', 'until' => null),
	'2026-09-18 10:00:00'), '');

$ban_rows = array(
	array('ip' => '192.0.2.50', 'state' => 'active', 'rule' => '930130', 'score' => '60', 'hits' => '12',
		'reason' => '60 Punkte aus 12 Treffern in 10 Minuten auf beispiel.test, meist Regel 930130.',
		'level' => '1', 'source' => 'auto', 'created_at' => '2026-09-18 09:50:00',
		'blocked_at' => '2026-09-18 09:50:00', 'until' => '2026-09-18 10:50:00', 'lifted_at' => null,
		'lifted_by' => '', 'denied' => '318', 'denied_at' => '2026-09-18 09:59:00'),
	array('ip' => '198.51.100.50', 'state' => 'proposed', 'rule' => '', 'score' => '55', 'hits' => '11',
		'reason' => '55 Punkte aus 11 Treffern in 10 Minuten auf zweite.test.',
		'level' => '1', 'source' => 'auto', 'created_at' => '2026-09-18 09:55:00', 'blocked_at' => null,
		'until' => null, 'lifted_at' => null, 'lifted_by' => '', 'denied' => '0', 'denied_at' => null),
);
$ban_origins = array('192.0.2.50' => array('country' => 'de', 'asn' => '3320', 'as_org' => 'Deutsche Telekom AG',
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'y', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'none'));
$ban_view = waf_panel_ban_rows($wb, $ban_rows, $ban_origins, '2026-09-18 10:00:00', 'de');
expect_same('a row per block', array_column($ban_view, 'ip'), array('192.0.2.50', '198.51.100.50'));
expect_same('the state in words', array($ban_view[0]['state_label'], $ban_view[1]['state_label']),
	array('gesperrt', 'Vorschlag'));
expect_same('the end in words', $ban_view[0]['until_label'], 'noch 50 Minuten');
expect_same('the turned away requests', $ban_view[0]['denied'], '318');
expect_same('the origin travels with the address',
	array($ban_view[0]['origin']['country'], $ban_view[0]['origin']['provider']),
	array('DE', 'AS3320 Deutsche Telekom AG'));
expect_same('where it came from', array($ban_view[0]['source_label'], $ban_view[0]['rule']),
	array('automatisch', '930130'));
expect_same('an address without origin stays empty', $ban_view[1]['origin']['known'], false);

// --- Mehr Zeilen, als die Seite zeigt ------------------------------------------

expect_same('a list starts with one step', waf_panel_ban_rows_wanted(array(), 'proposed', 25, 1000), 25);
expect_same('a list shows what the page asks for',
	waf_panel_ban_rows_wanted(array('rows_proposed' => '50'), 'proposed', 25, 1000), 50);
expect_same('each list has its own number',
	waf_panel_ban_rows_wanted(array('rows_proposed' => '50'), 'active', 25, 1000), 25);
expect_same('never fewer than one step',
	waf_panel_ban_rows_wanted(array('rows_past' => '3'), 'past', 25, 1000), 25);
expect_same('never more than the limit',
	waf_panel_ban_rows_wanted(array('rows_past' => '99999999999'), 'past', 25, 1000), 1000);
expect_same('what is no number counts as nothing', array(
	waf_panel_ban_rows_wanted(array('rows_f2b' => '-5'), 'f2b', 25, 1000),
	waf_panel_ban_rows_wanted(array('rows_f2b' => '5e3'), 'f2b', 25, 1000),
	waf_panel_ban_rows_wanted(array('rows_f2b' => array('50')), 'f2b', 25, 1000),
), array(25, 25, 25));
expect_same('a step above the limit shrinks to it', waf_panel_ban_rows_wanted(array(), 'past', 300, 200), 200);

expect_same('when everything is shown there is no button', waf_panel_ban_more($wb, 7, 7, 25, 1000), null);
expect_same('the button loads one step and names the rest', waf_panel_ban_more($wb, 25, 156, 25, 1000),
	array('next' => 50, 'label' => 'Weitere 25 laden (131 übrig)', 'note' => ''));
expect_same('the last rows are loaded by name', waf_panel_ban_more($wb, 150, 156, 25, 1000),
	array('next' => 156, 'label' => 'Die übrigen 6 laden', 'note' => ''));
expect_same('the limit shortens the last step', waf_panel_ban_more($wb, 190, 1530, 25, 200),
	array('next' => 200, 'label' => 'Weitere 10 laden (1.340 übrig)', 'note' => ''));
$more = waf_panel_ban_more($wb, 200, 1530, 25, 200);
expect_same('at the limit a note names both numbers and the setting', array($more['next'], $more['label'],
	strpos($more['note'], '200 von 1.530') !== false, strpos($more['note'], 'Abwehr > Einstellungen') !== false),
	array(0, '', true, true));
expect_same('the English button reads the same way', waf_panel_ban_more($en_words, 25, 156, 25, 1000)['label'],
	'Load 25 more (131 left)');

expect_same('the origin count names what is chosen', array(
	waf_panel_ban_origin_count($wb, true, 3),
	waf_panel_ban_origin_count($wb, true, 0),
	waf_panel_ban_origin_count($wb, false, 2),
	waf_panel_ban_origin_count($wb, false, 0),
), array('3 gewählt', 'nichts gewählt', 'aus, 2 gewählt', 'aus'));

// --- Die Auswahl der Herkunft -------------------------------------------------

$rows = array(
	array('value' => 'FR', 'label' => 'FR', 'hits' => 2272, 'addresses' => 2),
	array('value' => 'BE', 'label' => 'BE', 'hits' => 1006, 'addresses' => 2),
	array('value' => '', 'label' => '', 'hits' => 9, 'addresses' => 1),
);
$view = waf_panel_ban_origin_rows($rows, array('FR', 'CN'));
expect_same('the busiest come first and the empty row stays out',
	array_map(function ($one) { return $one['value']; }, $view), array('FR', 'BE', 'CN'));
expect_same('what is on the list is ticked',
	array($view[0]['chosen'], $view[1]['chosen'], $view[2]['chosen']), array(1, 0, 1));
expect_same('the numbers are written out', array($view[0]['hits'], $view[0]['addresses']), array('2.272', '2'));
expect_same('a chosen value without hits stays visible',
	array($view[2]['value'], $view[2]['hits']), array('CN', '0'));
expect_same('without a kind the label stays as it came', array($view[0]['label'], $view[0]['code']), array('FR', ''));
$named = waf_panel_ban_origin_rows($rows, array('FR', 'CN'), 25, 'country', 'de');
expect_same('countries are written out, with their code beside', array(
	$named[0]['label'], $named[0]['code'], $named[2]['label'], $named[2]['code'],
), class_exists('Locale')
	? array(waf_origin_country_name('FR', 'de'), 'FR', waf_origin_country_name('CN', 'de'), 'CN')
	: array('FR', '', 'CN', ''));
$named = waf_panel_ban_origin_rows(array(
	array('value' => '15169', 'label' => 'Google LLC', 'hits' => 5, 'addresses' => 1),
	array('value' => '64500', 'label' => '', 'hits' => 2, 'addresses' => 1),
), array('64501'), 25, 'asn');
expect_same('a provider shows its number beside its name', array(
	$named[0]['label'], $named[0]['code'], $named[1]['label'], $named[1]['code'], $named[2]['label'], $named[2]['code'],
), array('Google LLC', 'AS15169', 'AS64500', '', 'AS64501', ''));
$long = array();
for ($i = 0; $i < 40; $i++) {
	$long[] = array('value' => 'L' . $i, 'label' => 'L' . $i, 'hits' => 40 - $i, 'addresses' => 1);
}
expect_same('the list stays short', count(waf_panel_ban_origin_rows($long, array())), 25);

// --- Die Adresse der veröffentlichten Liste ----------------------------------

$key = str_repeat('a1b2', 8);
$view = waf_panel_ban_url($wb, array('waf_ban_token' => $key), 'cp.beispiel.test', 3);
expect_same('the page shows the address and how many stand in the list',
	array($view['url'], $view['has_url']),
	array('https://cp.beispiel.test/security/malwatch_waf_ban_url.php?list=' . $key, 1));
expect_same('the number is written out', strpos($view['count'], '3') !== false, true);
$none = waf_panel_ban_url($wb, array('waf_ban_token' => ''), 'cp.beispiel.test', 0);
expect_same('without a key there is no address yet', array($none['url'], $none['has_url']), array('', 0));
expect_same('and the hint says where it comes from', $none['hint'] !== '' && $none['hint'] !== $view['hint'], true);
$odd = waf_panel_ban_url($wb, array('waf_ban_token' => $key), 'cp.beispiel.test/x', 3);
expect_same('with a key but an unusable name the page says so, not that the key is missing',
	array($odd['url'], $odd['has_url'], $odd['hint'] !== $none['hint'],
		strpos($odd['hint'], 'cp.beispiel.test/x') !== false), array('', 0, true, true));

// --- fail2ban auf der Seite „Sperren" ------------------------------------------

$now = '2026-09-22 02:00:00';
$f2b = waf_panel_f2b_rows($wb, array(
	array('server_id' => '1', 'jail' => 'recidive', 'ip' => '91.92.243.20', 'banned_at' => '2026-09-15 21:20:27',
		'until' => '2026-09-23 20:01:51'),
	array('server_id' => '1', 'jail' => 'sshd', 'ip' => '198.51.100.9', 'banned_at' => '2026-09-22 01:55:00',
		'until' => '2026-09-22 02:05:00'),
	array('server_id' => '1', 'jail' => 'recidive', 'ip' => '198.51.100.10', 'banned_at' => '2026-09-20 00:00:00',
		'until' => null),
), $now);
expect_same('each ban with jail, reason, beginning and end', array(
	array($f2b[0]['ip'], $f2b[0]['jail'], $f2b[0]['reason'], $f2b[0]['since']),
	strpos($f2b[1]['until_label'], '5') !== false,
	$f2b[2]['until_label'] !== '' && $f2b[2]['until_label'] !== $f2b[0]['until_label'],
), array(
	array('91.92.243.20', 'recidive', 'Wiederholungstäter, alle Dienste gesperrt (recidive)', '15.09.2026 21:20'),
	true,
	true,
));

expect_same('the state line for every case', array(
	waf_panel_f2b_state($wb, array()) !== '',
	strpos(waf_panel_f2b_state($wb, array(array('state' => 'ok', 'error' => '', 'read_at' => '2026-09-22 01:59:01'))),
		'01:59') !== false,
	strpos(waf_panel_f2b_state($wb, array(array('state' => 'error', 'error' => 'Failed to access socket path',
		'read_at' => '2026-09-22 01:59:01'))), 'Failed to access socket path') !== false,
	waf_panel_f2b_state($wb, array(array('state' => 'off', 'error' => '', 'read_at' => null)))
		!== waf_panel_f2b_state($wb, array(array('state' => 'missing', 'error' => '', 'read_at' => null))),
), array(true, true, true, true));

$options = waf_panel_mode_options($wb, 'jail_only', 'ban_mode_global_txt');
expect_same('the choice of a jail offers the global mode first and marks the current one', array(
	array_map(function ($one) { return $one['mode_value']; }, $options),
	array_map(function ($one) { return $one['mode_selected']; }, $options),
), array(array('', 'web_jail', 'web_forever_jail', 'jail_only'), array(0, 0, 0, 1)));
$rule_options = waf_panel_mode_options($wb, '', 'ban_mode_web_only_txt', waf_f2b_rule_modes());
expect_same('a rule offers only what the automatic can do', array(
	array_map(function ($one) { return $one['mode_value']; }, $rule_options),
	$rule_options[0]['mode_selected'],
), array(array('', 'web_jail', 'web_forever_jail'), 1));

$jail_rows = waf_panel_f2b_jails($wb, array(array('jails' => 'sshd,recidive')), array('recidive' => 'jail_only'));
expect_same('every known jail with its setting', array(
	array_map(function ($one) { return $one['jail']; }, $jail_rows),
	$jail_rows[0]['options'][3]['mode_selected'],
), array(array('recidive', 'sshd'), 1));

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel: alle Prüfungen bestanden\n";
