<?php

/**
 * Abwehr for one website: the state with its switch and the preview for
 * enforce, the history, the rules with their addresses and explanations,
 * the paths and stored requests of the period, the exceptions and the form
 * that adds one.
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

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
// The address filter of the stored requests; after a button it comes back as
// a hidden field of the form.
$ip_filter = waf_panel_ip_filter(array_merge($_GET, $_POST));
$ip_rejected = waf_panel_ip_filter_rejected(array_merge($_GET, $_POST));
$ip_query = $ip_filter !== '' ? '&ip=' . rawurlencode($ip_filter) : '';

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_show.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('state_head_txt', 'btn_set_off_txt', 'btn_set_detect_txt',
	'btn_set_enforce_txt', 'confirm_set_off_txt', 'confirm_set_detect_txt', 'confirm_set_enforce_txt',
	'btn_exception_remove_txt', 'confirm_exception_remove_txt', 'btn_exception_add_txt',
	'confirm_exception_add_txt', 'preview_wait_txt')));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));
$csrf = $app->auth->csrf_token_get('malwatch_waf_show');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$site = $domain_id > 0 ? $app->db->queryOneRecord(
	'SELECT w.domain_id, w.domain, s.waf_state, s.waf_state_since, s.waf_pending_state, s.waf_ban_score, '
	. 's.waf_ban_trigger FROM web_domain w '
	. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.domain_id = ? AND w.type = 'vhost'", $domain_id) : null;
$app->tpl->setVar('has_site', is_array($site) ? 1 : 0);
if (!is_array($site)) {
	$app->tpl_defaults();
	$app->tpl->pparse();
	exit;
}

$settings = waf_panel_settings($app);
$clock = waf_panel_clock($app);
$filters = waf_panel_filters(array_merge($_GET, $_POST), $settings['waf_stats_days']);
$days = $filters['days'];
$state = waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities($site['domain']));
$app->tpl->setVar('days', $days);
$app->tpl->setVar('ip_value', $app->functions->htmlentities($ip_filter));
$app->tpl->setVar('state_class', $state);
$app->tpl->setVar('state_label', $app->functions->htmlentities(waf_panel_state_label($wb, $state)));
$app->tpl->setVar('state_line', $app->functions->htmlentities(sprintf($wb['state_current_txt'], waf_panel_state_label($wb, $state))
	. ($state !== 'off' && (string) $site['waf_state_since'] !== '' ? ', ' . sprintf($wb['since_txt'], malwatch_datetime($site['waf_state_since'])) : '')));


// Die Schwelle dieser Website für Sperren: 0 heißt „wie der Server".
$ban_settings = waf_settings($app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
$ban_score = is_array($site) && isset($site['waf_ban_score']) ? (int) $site['waf_ban_score'] : 0;
$ban_trigger = is_array($site) && isset($site['waf_ban_trigger'])
	&& (string) $site['waf_ban_trigger'] === 'n' ? 'n' : 'y';
$app->tpl->setVar('ban_score_value', $ban_score > 0 ? $ban_score : '');
$app->tpl->setVar('ban_site_line', $app->functions->htmlentities($ban_trigger === 'n'
	? $wb['ban_site_never_txt']
	: ($ban_score > 0 ? sprintf($wb['ban_site_own_txt'] . ': %s', number_format($ban_score, 0, ',', '.'))
		: sprintf($wb['ban_site_server_txt'], number_format((int) $ban_settings['waf_ban_score'], 0, ',', '.')))));
$app->tpl->setVar('ban_is_never', $ban_trigger === 'n' ? 1 : 0);$app->tpl->setVar('is_off', $state === 'off' ? 1 : 0);
$app->tpl->setVar('is_detect', $state === 'detect' ? 1 : 0);
$app->tpl->setVar('is_enforce', $state === 'enforce' ? 1 : 0);

// Jobs that change this website, or every website, are followed like on the overview.
$pending = false;
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	if (in_array($domain_id, $job['sites'], true)) {
		$pending = true;
	}
	$first_job = $first_job === 0 ? $job['job_id'] : $first_job;
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setVar('is_pending', $pending || (string) $site['waf_pending_state'] !== '' ? 1 : 0);
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);
$app->tpl->setVar('self_href', $app->functions->htmlentities('security/malwatch_waf_show.php?id=' . $domain_id . '&days=' . $days . $ip_query));

// The preview for enforce.
$totals = $app->db->queryOneRecord(
	'SELECT COALESCE(SUM(would_block), 0) AS would_block, COALESCE(SUM(would_block_logged_in), 0) AS would_block_logged_in '
	. 'FROM malwatch_waf_site_day WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)',
	$domain_id, $settings['waf_preview_days'] - 1);
$block_rules = waf_panel_rows($app->db->queryAllRecords(
	'SELECT rule_id, MAX(rule_msg) AS rule_msg, SUM(would_block_hits) AS would_block_hits FROM malwatch_waf_day '
	. 'WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY rule_id',
	$domain_id, $settings['waf_preview_days'] - 1));
$enforce = waf_panel_enforce($wb, $site, $totals, $block_rules, $settings, $clock['now'], $catalog);
$app->tpl->setVar('enforce_allowed', $enforce['allowed'] ? 1 : 0);
$hint = $enforce['reason'] !== '' ? waf_panel_reason_label($wb, $enforce['reason']) : '';
if ($enforce['reason'] === 'too_early' && $enforce['free_from'] !== '') {
	$hint .= ' ' . sprintf($wb['free_from_txt'], malwatch_datetime($enforce['free_from']));
}
$app->tpl->setVar('enforce_hint', $app->functions->htmlentities($hint));
$app->tpl->setVar('preview_line', $app->functions->htmlentities($enforce['would_block'] > 0
	? sprintf($wb['preview_block_txt'], $enforce['days'], number_format($enforce['would_block'], 0, ',', '.'),
		number_format($enforce['logged_in'], 0, ',', '.'))
	: sprintf($wb['preview_block_none_txt'], $enforce['days'])));
$block_rows = array();
foreach (array_slice($enforce['rules'], 0, 8) as $rule) {
	$block_rows[] = array('rule_line' => $app->functions->htmlentities($rule['title'] . ' (' . $rule['rule_id'] . '): '
		. number_format($rule['hits'], 0, ',', '.')));
}
$app->tpl->setLoop('block_rules', $block_rows);
$app->tpl->setVar('has_block_rules', count($block_rows) > 0 ? 1 : 0);

// Period links and history.
$link = 'security/malwatch_waf_show.php?id=' . $domain_id . '&days=';
$periods = array();
foreach (waf_periods($settings['waf_stats_days']) as $period) {
	$periods[] = array(
		'label' => $app->functions->htmlentities($period === 1 ? $wb['period_today_txt'] : sprintf($wb['period_days_txt'], $period)),
		'href' => $app->functions->htmlentities($link . $period . $ip_query),
		'current' => $period === $days ? 1 : 0,
	);
}
$app->tpl->setLoop('periods', $periods);

$series = waf_panel_day_series(waf_panel_rows($app->db->queryAllRecords(
	'SELECT day, hits, would_block FROM malwatch_waf_site_day WHERE parent_domain_id = ? '
	. 'AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $domain_id, $days - 1)), $clock['today'], $days);
$max = 1;
foreach ($series as $day) {
	$max = max($max, $day['hits']);
}
$bars = array();
foreach ($series as $day) {
	$bars[] = array(
		'hit_pct' => (int) round($day['hits'] * 100 / $max),
		'block_pct' => $day['hits'] > 0 ? (int) round($day['would_block'] * 100 / $day['hits']) : 0,
		'bar_title' => $app->functions->htmlentities(sprintf($wb['history_bar_txt'], waf_panel_day_label($day['day']),
			number_format($day['hits'], 0, ',', '.'), number_format($day['would_block'], 0, ',', '.'))),
	);
}
$app->tpl->setLoop('bars', $bars);
$app->tpl->setVar('chart_max', number_format($max, 0, ',', '.'));
$app->tpl->setVar('chart_first', count($series) > 0 ? $app->functions->htmlentities(waf_panel_day_label($series[0]['day'])) : '');
$app->tpl->setVar('chart_last', count($series) > 1
	? $app->functions->htmlentities(waf_panel_day_label($series[count($series) - 1]['day'])) : '');

// Rules and paths of the period. The latest stored requests, up to
// waf_card_hits of them, give each rule its addresses and triggers.
$day_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT day, rule_id, rule_msg, path, hits, would_block_hits FROM malwatch_waf_day WHERE parent_domain_id = ? '
	. 'AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $domain_id, $days - 1));
$card_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT client_ip, logged_in, rules FROM malwatch_waf_hit WHERE parent_domain_id = ? '
	. 'ORDER BY seen_at DESC, hit_id DESC LIMIT ?', $domain_id, (int) $settings['waf_card_hits']));
$card_hits = waf_panel_rule_hits($wb, $catalog, $card_rows);
// The origin of every address the cards show; the stored requests add theirs below.
$card_ips = array();
foreach ($card_hits as $rule) {
	foreach (array_slice($rule['addresses'], 0, 5) as $address) {
		$card_ips[] = $address['key'];
	}
}
$origin_rows = waf_panel_origin_lookup($app, $card_ips);
$origin_credit = waf_panel_origin_credit($wb, $settings);
$app->tpl->setVar('origin_credit', $app->functions->htmlentities($origin_credit['text']));
$app->tpl->setVar('origin_credit_href', $app->functions->htmlentities($origin_credit['url']));
$app->tpl->setVar('origin_off', count(waf_origin_chosen($settings)) === 0 ? 1 : 0);
$app->tpl->setVar('rule_addresses_head', $app->functions->htmlentities(count($card_rows) >= $settings['waf_card_hits']
	? sprintf($wb['addresses_capped_txt'], number_format($settings['waf_card_hits'], 0, ',', '.'))
	: sprintf($wb['addresses_head_txt'], $settings['waf_detail_days'])));
$no_card = array('hits' => 0, 'logged_in' => 0, 'addresses' => array(), 'triggers' => array());
// Rules whose automatic blocks also go to fail2ban; the cards show the choice.
$rule_modes = array();
foreach (waf_panel_rows($app->db->queryAllRecords('SELECT rule_id, everywhere_mode FROM malwatch_waf_ban_rule')) as $row) {
	$rule_modes[(string) $row['rule_id']] = (string) $row['everywhere_mode'];
}
$rule_rows = array();
foreach (waf_panel_rules($wb, $day_rows, $catalog) as $rule) {
	$info = waf_panel_rule_info($wb, $catalog, $rule['rule_id'], $rule['msg']);
	$seen = isset($card_hits[$rule['rule_id']]) ? $card_hits[$rule['rule_id']] : $no_card;
	$paths = array();
	foreach ($rule['paths'] as $path) {
		$paths[] = array('path' => $app->functions->htmlentities($path['path']), 'path_hits' => number_format($path['hits'], 0, ',', '.'));
	}
	$addresses = array();
	foreach (array_slice($seen['addresses'], 0, 5) as $address) {
		$origin = waf_panel_origin($wb, isset($origin_rows[$address['key']]) ? $origin_rows[$address['key']] : null, $language);
		$chips = array();
		foreach ($origin['chips'] as $chip) {
			$chips[] = array('chip' => $app->functions->htmlentities($chip));
		}
		$addresses[] = array(
			'address' => $app->functions->htmlentities($address['key']),
			'address_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($address['count'], 0, ',', '.'))),
			'address_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($address['key'])),
			'address_country' => $app->functions->htmlentities($origin['country']),
			'address_country_name' => $app->functions->htmlentities($origin['country_name']),
			'address_provider' => $app->functions->htmlentities($origin['provider']),
			'address_provider_full' => $app->functions->htmlentities($origin['provider_full']),
			'address_chips' => $chips,
			'address_has_chips' => count($chips) > 0 ? 1 : 0,
		);
	}
	$triggers = array();
	foreach (array_slice($seen['triggers'], 0, 3) as $trigger) {
		$triggers[] = array(
			'trigger' => $app->functions->htmlentities($trigger['key']),
			'trigger_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($trigger['count'], 0, ',', '.'))),
		);
	}
	$modes = array();
	foreach (waf_panel_mode_options($wb, isset($rule_modes[$rule['rule_id']]) ? $rule_modes[$rule['rule_id']] : '',
		'ban_mode_web_only_txt', waf_f2b_rule_modes()) as $option) {
		$modes[] = array(
			'mode_value' => $app->functions->htmlentities($option['mode_value']),
			'mode_label' => $app->functions->htmlentities($option['mode_label']),
			'mode_selected' => $option['mode_selected'],
		);
	}
	$rule_rows[] = array(
		'rule_modes' => $modes,
		'rule_id' => $app->functions->htmlentities($rule['rule_id']),
		'rule_title' => $app->functions->htmlentities($info['title']),
		'rule_line' => $app->functions->htmlentities(sprintf($wb['rule_hits_txt'], number_format($rule['hits'], 0, ',', '.'),
			number_format($rule['would_block'], 0, ',', '.'))),
		'rule_last' => $app->functions->htmlentities(sprintf($wb['rule_last_txt'], waf_panel_day_label($rule['last_day']))),
		'rule_paths' => $paths,
		'more_paths' => $rule['path_count'] > count($paths)
			? $app->functions->htmlentities(sprintf($wb['rule_more_paths_txt'], $rule['path_count'] - count($paths))) : '',
		'can_except' => $rule['can_except'] ? 1 : 0,
		'first_path' => $app->functions->htmlentities(count($rule['paths']) === 1 ? $rule['paths'][0]['path'] : ''),
		'rule_addresses' => $addresses,
		'has_addresses' => count($addresses) > 0 ? 1 : 0,
		'more_addresses' => count($seen['addresses']) > 5
			? $app->functions->htmlentities(sprintf($wb['addresses_more_txt'], count($seen['addresses']) - 5)) : '',
		'rule_what' => $app->functions->htmlentities($info['what']),
		'rule_triggers' => $triggers,
		'has_triggers' => count($triggers) > 0 ? 1 : 0,
		'rule_class' => $app->functions->htmlentities($info['class_label']),
		'rule_class_key' => $app->functions->htmlentities($info['class']),
		'rule_class_text' => $app->functions->htmlentities($info['class_text']),
		'rule_note' => $app->functions->htmlentities($info['note']),
		'rule_logged_in' => $seen['logged_in'] > 0
			? $app->functions->htmlentities(sprintf($wb['logged_in_share_txt'], number_format($seen['logged_in'], 0, ',', '.'),
				number_format($seen['hits'], 0, ',', '.'))) : '',
		'rule_crs' => $info['crs'] !== '' ? $app->functions->htmlentities(sprintf($wb['crs_label_txt'], $info['crs'])) : '',
	);
}
$app->tpl->setLoop('rules', $rule_rows);
$app->tpl->setVar('has_rules', count($rule_rows) > 0 ? 1 : 0);

$path_rows = array();
foreach (array_slice(waf_panel_paths($day_rows), 0, 50) as $path) {
	$path_rows[] = array(
		'path' => $app->functions->htmlentities($path['path']),
		'path_hits' => number_format($path['hits'], 0, ',', '.'),
		'path_rules' => $app->functions->htmlentities(implode(', ', $path['rules'])),
	);
}
$app->tpl->setLoop('paths', $path_rows);
$app->tpl->setVar('has_paths', count($path_rows) > 0 ? 1 : 0);

// Stored requests, all of the website or those of one address.
if ($ip_filter !== '') {
	$stored = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_waf_hit WHERE parent_domain_id = ? AND client_ip = ?',
		$domain_id, $ip_filter);
	$stored_rows = $app->db->queryAllRecords('SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = ? AND client_ip = ? '
		. 'ORDER BY seen_at DESC, hit_id DESC LIMIT 100', $domain_id, $ip_filter);
} else {
	$stored = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_waf_hit WHERE parent_domain_id = ?', $domain_id);
	$stored_rows = $app->db->queryAllRecords('SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = ? '
		. 'ORDER BY seen_at DESC, hit_id DESC LIMIT 100', $domain_id);
}
$app->tpl->setVar('ip_filter', $ip_filter !== '' ? 1 : 0);
$hit_ips = array();
foreach (waf_panel_rows($stored_rows) as $row) {
	$hit_ips[] = (string) $row['client_ip'];
}
$origin_rows = array_merge($origin_rows, waf_panel_origin_lookup($app, $hit_ips));
$app->tpl->setVar('ip_jump', $ip_filter !== '' || $ip_rejected !== '' ? 1 : 0);
$app->tpl->setVar('ip_rejected', $app->functions->htmlentities($ip_rejected !== ''
	? sprintf($wb['ip_filter_invalid_txt'], $ip_rejected) : ''));
$app->tpl->setVar('ip_filter_line', $app->functions->htmlentities(sprintf($wb['ip_filter_txt'], $ip_filter)));
$app->tpl->setVar('ip_filter_clear_href', $app->functions->htmlentities($link . $days));
$app->tpl->setVar('hits_none_line', $app->functions->htmlentities($ip_filter !== '' ? $wb['ip_filter_none_txt'] : $wb['hits_none_txt']));
$hit_rows = array();
foreach (waf_panel_rows($stored_rows) as $row) {
	$hit = waf_panel_hit($wb, $row, $catalog);
	$rules = array();
	foreach ($hit['rules'] as $rule) {
		$rules[] = array(
			'hit_rule' => $app->functions->htmlentities($rule['title'] . ' (' . $rule['rule_id'] . ')'),
			'hit_rule_class' => $app->functions->htmlentities($rule['class_label']),
			'hit_rule_class_key' => $app->functions->htmlentities($rule['class']),
			'hit_rule_trigger' => $app->functions->htmlentities($rule['trigger']),
			'hit_rule_class_text' => $app->functions->htmlentities($rule['class_text']),
			'hit_rule_note' => $app->functions->htmlentities($rule['note']),
			'hit_rule_data' => $app->functions->htmlentities(trim($rule['msg'] . ' ' . $rule['data'])),
		);
	}
	$headers = array();
	foreach ($hit['headers'] as $header) {
		$headers[] = array('header_name' => $app->functions->htmlentities($header['name']),
			'header_value' => $app->functions->htmlentities($header['value']));
	}
	$ids = array();
	foreach ($hit['rules'] as $rule) {
		$ids[] = $rule['rule_id'];
	}
	$hit_origin = waf_panel_origin($wb, isset($origin_rows[$hit['client_ip']]) ? $origin_rows[$hit['client_ip']] : null, $language);
	$hit_chips = array();
	foreach ($hit_origin['chips'] as $chip) {
		$hit_chips[] = array('chip' => $app->functions->htmlentities($chip));
	}
	$hit_rows[] = array(
		'hit_id' => $hit['hit_id'],
		'hit_time' => $app->functions->htmlentities(malwatch_datetime($hit['seen_at'])),
		'hit_ip' => $app->functions->htmlentities($hit['client_ip']),
		'hit_country' => $app->functions->htmlentities($hit_origin['country']),
		'hit_country_name' => $app->functions->htmlentities($hit_origin['country_name']),
		'hit_provider' => $app->functions->htmlentities($hit_origin['provider']),
		'hit_provider_full' => $app->functions->htmlentities($hit_origin['provider_full']),
		'hit_origin_state' => $app->functions->htmlentities($hit_origin['state']),
		'hit_chips' => $hit_chips,
		'hit_has_chips' => count($hit_chips) > 0 ? 1 : 0,
		'hit_has_ip' => $hit['client_ip'] !== '' ? 1 : 0,
		'hit_ip_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($hit['client_ip'])),
		'hit_request' => $app->functions->htmlentities($hit['method'] . ' ' . $hit['uri']),
		'hit_ids' => $app->functions->htmlentities(implode(', ', $ids)),
		'hit_score' => $app->functions->htmlentities(sprintf($wb['hit_score_txt'], $hit['score'])),
		'hit_status' => $app->functions->htmlentities(sprintf($wb['hit_status_txt'], $hit['status'])),
		'hit_block' => $hit['would_block'] ? 1 : 0,
		'hit_logged_in' => $hit['logged_in'] ? 1 : 0,
		'hit_rules' => $rules,
		'hit_headers' => $headers,
		'has_body' => $hit['has_body'] ? 1 : 0,
		'hit_body' => $app->functions->htmlentities($hit['body']),
		'has_response' => $hit['has_response'] ? 1 : 0,
		'response_size' => $app->functions->htmlentities(sprintf($wb['response_size_txt'], malwatch_bytes($hit['response_bytes']))),
		'can_except' => $hit['prefill']['rule_id'] !== '' ? 1 : 0,
		'prefill_rule' => $app->functions->htmlentities($hit['prefill']['rule_id']),
		'prefill_path' => $app->functions->htmlentities($hit['prefill']['path']),
		'prefill_param' => $app->functions->htmlentities($hit['prefill']['param']),
	);
}
$app->tpl->setLoop('hits', $hit_rows);
$app->tpl->setVar('has_hits', count($hit_rows) > 0 ? 1 : 0);
$app->tpl->setVar('hits_limit', $app->functions->htmlentities(sprintf($wb['hits_limit_txt'], count($hit_rows),
	number_format(is_array($stored) ? (int) $stored['n'] : 0, 0, ',', '.'), $settings['waf_detail_days'])));

// Exceptions of this website and those for every website.
$exception_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT * FROM malwatch_waf_exception WHERE parent_domain_id = ? OR scope IN ('all','all_path') ORDER BY exception_id",
	$domain_id)) as $row) {
	$exception = waf_panel_exception_row($wb, $row);
	$exception_rows[] = array(
		'exception_id' => $exception['exception_id'],
		'exc_rule' => $app->functions->htmlentities($exception['rule_id']),
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
$app->tpl->setLoop('exceptions', $exception_rows);
$app->tpl->setVar('has_exceptions', count($exception_rows) > 0 ? 1 : 0);

$scopes = array();
foreach (waf_exception_scopes() as $scope) {
	$scopes[] = array('scope' => $scope, 'scope_label' => $app->functions->htmlentities(waf_panel_scope_label($wb, $scope)),
		'checked' => $scope === 'site_path' ? 1 : 0);
}
$app->tpl->setLoop('scopes', $scopes);

$app->tpl_defaults();
$app->tpl->pparse();
