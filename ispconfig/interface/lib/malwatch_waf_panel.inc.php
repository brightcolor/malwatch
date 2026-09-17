<?php

/**
 * Helpers for the pages "Abwehr" (the WAF part) in the Security module.
 *
 * The first part is pure and tested in tests/waf_panel_test.php; the
 * database part at the end serves the pages. The shared rules live in
 * malwatch_waf_lib.inc.php, which sits in the same directory here and after
 * the installation.
 */

require_once __DIR__ . '/malwatch_waf_lib.inc.php';

/** A language line, or $fallback when the file lacks it. */
function waf_panel_text($wb, $key, $fallback)
{
	return isset($wb[$key]) ? (string) $wb[$key] : (string) $fallback;
}

function waf_panel_state_label($wb, $state)
{
	return waf_panel_text($wb, 'state_' . $state . '_txt', $state);
}

function waf_panel_scope_label($wb, $scope)
{
	return waf_panel_text($wb, 'scope_' . $scope . '_txt', $scope);
}

function waf_panel_exception_state_label($wb, $state)
{
	return waf_panel_text($wb, 'exc_state_' . $state . '_txt', $state);
}

/** The words for a code of waf_enforce_block_reason() or waf_exception_check(). */
function waf_panel_reason_label($wb, $reason)
{
	return waf_panel_text($wb, 'reason_' . $reason . '_txt', $reason);
}

function waf_panel_job_label($wb, $action)
{
	return waf_panel_text($wb, 'job_' . $action . '_txt', $action);
}

function waf_panel_status_label($wb, $status)
{
	return waf_panel_text($wb, 'job_status_' . $status . '_txt', $status);
}

/**
 * The heading of a rule: its title in the catalog, else its CRS group in
 * words, else the CRS message, else its number.
 */
function waf_panel_rule_title($wb, $rule_id, $message, $catalog = array())
{
	$rule_id = (string) $rule_id;
	if (isset($catalog['rules'][$rule_id]['title']) && (string) $catalog['rules'][$rule_id]['title'] !== '') {
		return (string) $catalog['rules'][$rule_id]['title'];
	}
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($wb['group_' . $m[1] . '_txt'])) {
		return (string) $wb['group_' . $m[1] . '_txt'];
	}
	if (trim((string) $message) !== '') {
		return (string) $message;
	}
	return sprintf(waf_panel_text($wb, 'rule_fallback_txt', '%s'), $rule_id);
}

/** The classes a rule of the catalog may carry. */
function waf_panel_rule_classes()
{
	return array('scanner', 'attack', 'false_positive_prone', 'protocol', 'scoring', 'response');
}

/** The catalog file for $language in $dir; the English one when that language has none. */
function waf_panel_rule_catalog_file($dir, $language)
{
	$dir = rtrim((string) $dir, '/');
	$language = preg_match('/^[a-z]{2}$/', (string) $language) ? (string) $language : 'en';
	$file = $dir . '/' . $language . '_malwatch_waf_rules.lng';
	return is_file($file) ? $file : $dir . '/en_malwatch_waf_rules.lng';
}

/**
 * The rule catalog in a language file: rules keyed by id with title, what,
 * class, note and trigger as far as the file has them, groups keyed by their
 * three digits with what and class. Other lines of the file are left out.
 */
function waf_panel_rule_catalog($file)
{
	$wb = array();
	if (is_file((string) $file)) {
		include (string) $file;
	}
	$catalog = array('rules' => array(), 'groups' => array());
	foreach ($wb as $key => $value) {
		if (preg_match('/^rule_(\d{3,7})_(title|what|class|note|trigger)$/', (string) $key, $m)) {
			$catalog['rules'][$m[1]][$m[2]] = (string) $value;
		} elseif (preg_match('/^group_(\d{3})_(what|class)$/', (string) $key, $m)) {
			$catalog['groups'][$m[1]][$m[2]] = (string) $value;
		}
	}
	return $catalog;
}

/**
 * What the pages say about one rule: its catalog entry, else the texts of its
 * CRS group. crs is the English message of the rule set.
 */
function waf_panel_rule_info($wb, $catalog, $rule_id, $message)
{
	$rule_id = (string) $rule_id;
	$entry = isset($catalog['rules'][$rule_id]) ? $catalog['rules'][$rule_id] : array();
	$group = array();
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($catalog['groups'][$m[1]])) {
		$group = $catalog['groups'][$m[1]];
	}
	$class = isset($entry['class']) ? (string) $entry['class'] : (isset($group['class']) ? (string) $group['class'] : '');
	if (!in_array($class, waf_panel_rule_classes(), true)) {
		$class = '';
	}
	return array(
		'rule_id' => $rule_id,
		'title' => waf_panel_rule_title($wb, $rule_id, $message, $catalog),
		'what' => isset($entry['what']) ? (string) $entry['what'] : (isset($group['what']) ? (string) $group['what'] : ''),
		'class' => $class,
		'class_label' => $class === '' ? '' : waf_panel_text($wb, 'class_' . $class . '_txt', $class),
		'class_text' => $class === '' ? '' : waf_panel_text($wb, 'class_' . $class . '_text_txt', ''),
		'note' => isset($entry['note']) ? (string) $entry['note'] : '',
		'trigger' => isset($entry['trigger']) ? (string) $entry['trigger'] : '',
		'crs' => trim((string) $message),
	);
}

/**
 * The parts of a rule's data in an audit entry. CRS writes most rules as
 * "Matched Data: <piece> found within <target>: <value>"; some write
 * "<target>=<value>", 920450 writes "Restricted header detected: /<name>/",
 * and the rest only a value. form is matched, assign, header, plain or none.
 */
function waf_panel_trigger_parts($data)
{
	$data = trim((string) $data);
	$parts = array('form' => 'none', 'piece' => '', 'target' => '', 'value' => '');
	if ($data === '') {
		return $parts;
	}
	if (preg_match('/^Matched Data: (.*?) found within (.+?)(?:: (.*))?$/s', $data, $m)) {
		$parts['form'] = 'matched';
		$parts['piece'] = $m[1];
		$parts['target'] = $m[2];
		$parts['value'] = isset($m[3]) ? $m[3] : '';
		return $parts;
	}
	if (preg_match('/^([A-Z_]+(?::[^=]*)?)=(.*)$/s', $data, $m)) {
		$parts['form'] = 'assign';
		$parts['target'] = $m[1];
		$parts['value'] = $m[2];
		return $parts;
	}
	if (preg_match('#^Restricted header detected: /?(.*?)/?$#s', $data, $m)) {
		$parts['form'] = 'header';
		$parts['value'] = $m[1];
		return $parts;
	}
	$parts['form'] = 'plain';
	$parts['value'] = preg_replace('/^Matched Data: /', '', $data);
	return $parts;
}

/** A variable of ModSecurity in words; one the page does not know stays as it is. */
function waf_panel_target_label($wb, $target)
{
	$target = (string) $target;
	$pos = strpos($target, ':');
	$base = $pos === false ? $target : substr($target, 0, $pos);
	$name = $pos === false ? '' : substr($target, $pos + 1);
	$named = array(
		'ARGS' => 'target_param_txt', 'ARGS_GET' => 'target_param_txt', 'ARGS_POST' => 'target_param_txt',
		'REQUEST_HEADERS' => 'target_header_txt', 'REQUEST_COOKIES' => 'target_cookie_txt',
	);
	$plain = array(
		'ARGS_NAMES' => 'target_param_names_txt', 'ARGS_GET_NAMES' => 'target_param_names_txt',
		'ARGS_POST_NAMES' => 'target_param_names_txt',
		'REQUEST_FILENAME' => 'target_filename_txt', 'REQUEST_BASENAME' => 'target_filename_txt',
		'REQUEST_URI' => 'target_uri_txt', 'REQUEST_URI_RAW' => 'target_uri_txt',
		'REQUEST_LINE' => 'target_request_line_txt', 'QUERY_STRING' => 'target_query_txt',
		'REQUEST_HEADERS_NAMES' => 'target_header_names_txt', 'REQUEST_COOKIES_NAMES' => 'target_cookie_names_txt',
		'REQUEST_BODY' => 'target_body_txt', 'XML' => 'target_xml_txt',
		'FILES' => 'target_files_txt', 'FILES_NAMES' => 'target_files_txt',
		'REQUEST_METHOD' => 'target_method_txt', 'REQUEST_PROTOCOL' => 'target_protocol_txt',
	);
	if (isset($named[$base]) && $name !== '') {
		return sprintf(waf_panel_text($wb, $named[$base], '%s'), $name);
	}
	if (isset($plain[$base])) {
		return waf_panel_text($wb, $plain[$base], $target);
	}
	return $target;
}

/**
 * The trigger of one rule in a hit as a sentence, '' when the data names
 * none. $pattern comes from the catalog (rule_<id>_trigger) and words data
 * that carries a value only; it must hold exactly one %s.
 */
function waf_panel_trigger_text($wb, $data, $pattern)
{
	$parts = waf_panel_trigger_parts($data);
	$piece = waf_cut($parts['piece'], 120);
	$value = waf_cut($parts['value'], 120);
	// Pieces CRS writes as fixed words say nothing; the value does.
	if (in_array($piece, array('XSS data', 'Suspicious payload', 'Suspicious JS global variable'), true)) {
		$piece = '';
	}
	if ($parts['form'] === 'matched' || $parts['form'] === 'assign') {
		$target = waf_panel_target_label($wb, $parts['target']);
		if ($piece !== '') {
			return sprintf(waf_panel_text($wb, 'trigger_contains_txt', '%1$s: %2$s'), $target, $piece);
		}
		return $value !== '' ? sprintf(waf_panel_text($wb, 'trigger_value_txt', '%1$s: %2$s'), $target, $value) : $target;
	}
	if ($parts['form'] === 'header') {
		return sprintf(waf_panel_text($wb, 'target_header_txt', '%s'), $value);
	}
	if ($parts['form'] === 'plain') {
		$pattern = (string) $pattern;
		if (!preg_match('/^[^%]*%s[^%]*$/', $pattern)) {
			$pattern = waf_panel_text($wb, 'trigger_found_txt', '%s');
		}
		return sprintf($pattern, $value);
	}
	return '';
}

// --- Views -------------------------------------------------------------------

/**
 * One entry per day of the period ending with $today, the rows (day, hits,
 * would_block) summed per day. $today is CURDATE() of the database.
 */
function waf_panel_day_series($rows, $today, $days)
{
	$sums = array();
	foreach ($rows as $row) {
		$day = (string) $row['day'];
		if (!isset($sums[$day])) {
			$sums[$day] = array(0, 0);
		}
		$sums[$day][0] += (int) $row['hits'];
		$sums[$day][1] += isset($row['would_block']) ? (int) $row['would_block'] : 0;
	}
	$date = DateTime::createFromFormat('!Y-m-d', (string) $today, new DateTimeZone('UTC'));
	if ($date === false || $date->format('Y-m-d') !== (string) $today) {
		return array();
	}
	$days = max(1, (int) $days);
	$date->modify('-' . ($days - 1) . ' days');
	$series = array();
	for ($i = 0; $i < $days; $i++) {
		$day = $date->format('Y-m-d');
		$series[] = array('day' => $day,
			'hits' => isset($sums[$day]) ? $sums[$day][0] : 0,
			'would_block' => isset($sums[$day]) ? $sums[$day][1] : 0);
		$date->modify('+1 day');
	}
	return $series;
}

/** The points of an SVG polyline for $values in a $width by $height box; the highest value reaches the top. */
function waf_panel_sparkline($values, $width, $height)
{
	$values = array_values($values);
	$count = count($values);
	if ($count === 0) {
		return '';
	}
	$max = max(1, max($values));
	$points = array();
	foreach ($values as $i => $value) {
		$x = $count === 1 ? $width : $i * $width / ($count - 1);
		$y = $height - ((int) $value / $max) * ($height - 1) - 0.5;
		$points[] = number_format($x, 1, '.', '') . ',' . number_format($y, 1, '.', '');
	}
	return implode(' ', $points);
}

/**
 * The rows and heading figures of the overview. $sites: web_domain joined
 * with malwatch_site; $pending: ids a queued or running job is changing;
 * $day_rows and $rule_rows: the period's figures. The counts cover every
 * website, the rows only those the filters let through.
 */
function waf_panel_overview($sites, $pending, $day_rows, $rule_rows, $wordpress, $today, $days, $filters)
{
	$by_site = array();
	foreach ($day_rows as $row) {
		$by_site[(int) $row['parent_domain_id']][] = $row;
	}
	$top = array();
	foreach ($rule_rows as $row) {
		$site = (int) $row['parent_domain_id'];
		if (!isset($top[$site]) || (int) $row['hits'] > $top[$site]['hits']) {
			$top[$site] = array('rule_id' => (string) $row['rule_id'], 'rule_msg' => (string) $row['rule_msg'], 'hits' => (int) $row['hits']);
		}
	}
	$counts = array('off' => 0, 'detect' => 0, 'enforce' => 0, 'pending' => 0, 'hits' => 0, 'would_block' => 0, 'sites_with_hits' => 0);
	$rows = array();
	foreach ($sites as $site) {
		$id = (int) $site['domain_id'];
		$state = waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';
		$hits = 0;
		$block = 0;
		$values = array();
		foreach (waf_panel_day_series(isset($by_site[$id]) ? $by_site[$id] : array(), $today, $days) as $day) {
			$hits += $day['hits'];
			$block += $day['would_block'];
			$values[] = $day['hits'];
		}
		$is_pending = in_array($id, $pending, true) || (string) $site['waf_pending_state'] !== '';
		$counts[$state]++;
		$counts['pending'] += $is_pending ? 1 : 0;
		$counts['hits'] += $hits;
		$counts['would_block'] += $block;
		$counts['sites_with_hits'] += $hits > 0 ? 1 : 0;
		if (($filters['state'] !== '' && $filters['state'] !== $state)
			|| ($filters['wordpress'] && !in_array($id, $wordpress, true))
			|| ($filters['hits'] && $hits === 0)) {
			continue;
		}
		$rows[] = array(
			'domain_id' => $id,
			'domain' => (string) $site['domain'],
			'state' => $state,
			'since' => (string) $site['waf_state_since'],
			'pending' => $is_pending,
			'wordpress' => in_array($id, $wordpress, true),
			'hits' => $hits,
			'would_block' => $block,
			'values' => $values,
			'top_rule' => isset($top[$id]) ? $top[$id]['rule_id'] : '',
			'top_rule_msg' => isset($top[$id]) ? $top[$id]['rule_msg'] : '',
			'top_rule_hits' => isset($top[$id]) ? $top[$id]['hits'] : 0,
		);
	}
	usort($rows, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['domain'], $b['domain']);
	});
	return array('rows' => $rows, 'counts' => $counts);
}

/** The sentence above the overview. */
function waf_panel_lede($wb, $counts, $days)
{
	$detect = (int) $counts['detect'];
	$enforce = (int) $counts['enforce'];
	if ($detect === 0) {
		$first = waf_panel_text($wb, 'lede_detect_none_txt', '');
	} elseif ($detect === 1) {
		$first = waf_panel_text($wb, 'lede_detect_one_txt', '');
	} else {
		$first = sprintf(waf_panel_text($wb, 'lede_detect_many_txt', '%s'), number_format($detect, 0, ',', '.'));
	}
	if ($enforce === 0) {
		$second = waf_panel_text($wb, 'lede_enforce_none_txt', '');
	} elseif ($enforce === 1) {
		$second = waf_panel_text($wb, 'lede_enforce_one_txt', '');
	} else {
		$second = sprintf(waf_panel_text($wb, 'lede_enforce_many_txt', '%s'), number_format($enforce, 0, ',', '.'));
	}
	$hits = number_format((int) $counts['hits'], 0, ',', '.');
	$third = (int) $days === 1
		? sprintf(waf_panel_text($wb, 'lede_today_txt', '%s'), $hits)
		: sprintf(waf_panel_text($wb, 'lede_period_txt', '%s %s'), (int) $days, $hits);
	if ((int) $counts['would_block'] > 0) {
		$third .= sprintf(waf_panel_text($wb, 'lede_would_block_txt', '%s'), number_format((int) $counts['would_block'], 0, ',', '.'));
	}
	return $first . ', ' . $second . '. ' . $third . '.';
}

/** Period and filters of the overview from its query string. */
function waf_panel_filters($get, $stats_days)
{
	$state = isset($get['state']) ? (string) $get['state'] : '';
	return array(
		'days' => waf_period(isset($get['days']) ? $get['days'] : 7, $stats_days),
		'state' => waf_state_valid($state) ? $state : '',
		'wordpress' => !empty($get['wp']),
		'hits' => !empty($get['hits']),
	);
}

/** The overview's query string with some filters changed. */
function waf_panel_query($filters, $changes)
{
	$merged = array_merge($filters, $changes);
	$parts = array('days=' . (int) $merged['days']);
	if ($merged['state'] !== '') {
		$parts[] = 'state=' . rawurlencode($merged['state']);
	}
	if ($merged['wordpress']) {
		$parts[] = 'wp=1';
	}
	if ($merged['hits']) {
		$parts[] = 'hits=1';
	}
	return implode('&', $parts);
}

/**
 * The rules of one website over the period, the most hits first. $rows come
 * from malwatch_waf_day (day, rule_id, rule_msg, path, hits, would_block_hits).
 */
function waf_panel_rules($wb, $rows, $catalog = array())
{
	$rules = array();
	foreach ($rows as $row) {
		$id = (string) $row['rule_id'];
		if (!isset($rules[$id])) {
			$rules[$id] = array('rule_id' => $id, 'msg' => '', 'hits' => 0, 'would_block' => 0, 'paths' => array(), 'last_day' => '');
		}
		$rules[$id]['hits'] += (int) $row['hits'];
		$rules[$id]['would_block'] += (int) $row['would_block_hits'];
		if ($rules[$id]['msg'] === '' && (string) $row['rule_msg'] !== '') {
			$rules[$id]['msg'] = (string) $row['rule_msg'];
		}
		if (strcmp((string) $row['day'], $rules[$id]['last_day']) > 0) {
			$rules[$id]['last_day'] = (string) $row['day'];
		}
		$path = (string) $row['path'];
		$rules[$id]['paths'][$path] = (isset($rules[$id]['paths'][$path]) ? $rules[$id]['paths'][$path] : 0) + (int) $row['hits'];
	}
	$list = array();
	foreach ($rules as $id => $rule) {
		$paths = $rule['paths'];
		uksort($paths, function ($a, $b) use ($paths) {
			return $paths[$a] !== $paths[$b] ? $paths[$b] - $paths[$a] : strcmp((string) $a, (string) $b);
		});
		$top = array();
		foreach (array_slice($paths, 0, 3, true) as $path => $hits) {
			$top[] = array('path' => (string) $path, 'hits' => $hits);
		}
		$rule['rule_id'] = (string) $id;
		$rule['paths'] = $top;
		$rule['path_count'] = count($paths);
		$rule['title'] = waf_panel_rule_title($wb, $id, $rule['msg'], $catalog);
		$rule['can_except'] = waf_exception_check(array('scope' => 'site', 'parent_domain_id' => 1, 'rule_id' => (string) $id)) === '';
		$list[] = $rule;
	}
	usort($list, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['rule_id'], $b['rule_id']);
	});
	return $list;
}

/** The paths of one website over the period, the most hits first, with their rules. */
function waf_panel_paths($rows)
{
	$paths = array();
	foreach ($rows as $row) {
		$path = (string) $row['path'];
		if (!isset($paths[$path])) {
			$paths[$path] = array('path' => $path, 'hits' => 0, 'rules' => array());
		}
		$paths[$path]['hits'] += (int) $row['hits'];
		$rule = (string) $row['rule_id'];
		$paths[$path]['rules'][$rule] = (isset($paths[$path]['rules'][$rule]) ? $paths[$path]['rules'][$rule] : 0) + (int) $row['hits'];
	}
	$list = array();
	foreach ($paths as $entry) {
		arsort($entry['rules']);
		$entry['rules'] = array_map('strval', array_keys($entry['rules']));
		$list[] = $entry;
	}
	usort($list, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['path'], $b['path']);
	});
	return $list;
}

/**
 * array(key => count) as a list of array('key' => ..., 'count' => ...), the
 * highest count first, equal counts by key.
 */
function waf_panel_ranked($counts)
{
	$list = array();
	foreach ($counts as $key => $count) {
		$list[] = array('key' => (string) $key, 'count' => (int) $count);
	}
	usort($list, function ($a, $b) {
		return $a['count'] !== $b['count'] ? $b['count'] - $a['count'] : strcmp($a['key'], $b['key']);
	});
	return $list;
}

/**
 * Addresses and triggers per rule from stored hits of one website. $rows come
 * from malwatch_waf_hit (client_ip, logged_in, rules). Each rule gets hits,
 * logged_in, and its addresses and triggers as waf_panel_ranked() lists.
 */
function waf_panel_rule_hits($wb, $catalog, $rows)
{
	$rules = array();
	foreach ($rows as $row) {
		$list = json_decode((string) $row['rules'], true);
		if (!is_array($list)) {
			continue;
		}
		$ip = (string) $row['client_ip'];
		$logged_in = (string) $row['logged_in'] === 'y';
		foreach ($list as $rule) {
			$id = isset($rule['id']) ? (string) $rule['id'] : '';
			if ($id === '') {
				continue;
			}
			if (!isset($rules[$id])) {
				$rules[$id] = array('hits' => 0, 'logged_in' => 0, 'addresses' => array(), 'triggers' => array());
			}
			$rules[$id]['hits']++;
			if ($logged_in) {
				$rules[$id]['logged_in']++;
			}
			if ($ip !== '') {
				$rules[$id]['addresses'][$ip] = (isset($rules[$id]['addresses'][$ip]) ? $rules[$id]['addresses'][$ip] : 0) + 1;
			}
			$pattern = isset($catalog['rules'][$id]['trigger']) ? (string) $catalog['rules'][$id]['trigger'] : '';
			$text = waf_panel_trigger_text($wb, isset($rule['data']) ? $rule['data'] : '', $pattern);
			if ($text !== '') {
				$rules[$id]['triggers'][$text] = (isset($rules[$id]['triggers'][$text]) ? $rules[$id]['triggers'][$text] : 0) + 1;
			}
		}
	}
	foreach ($rules as $id => $rule) {
		$rules[$id]['addresses'] = waf_panel_ranked($rule['addresses']);
		$rules[$id]['triggers'] = waf_panel_ranked($rule['triggers']);
	}
	return $rules;
}

/** The address filter of the website page: a valid IP address, else ''. */
function waf_panel_ip_filter($get)
{
	$ip = isset($get['ip']) && is_string($get['ip']) ? trim($get['ip']) : '';
	return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
}

/** A stored key as the page shows it: four dots and its last four characters. */
function waf_panel_key_mask($key)
{
	$key = is_string($key) ? trim($key) : '';
	return $key === '' ? '' : '••••' . substr($key, -4);
}

/**
 * The address filter as typed when it is no valid IP address, cut to 64
 * bytes for the notice on the page; '' when the filter is empty or valid.
 */
function waf_panel_ip_filter_rejected($get)
{
	$ip = isset($get['ip']) && is_string($get['ip']) ? trim($get['ip']) : '';
	return $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) === false ? waf_cut($ip, 64) : '';
}

/**
 * One stored hit for the detail page. Each rule carries its title, the
 * trigger in words and its class from $catalog. prefill is what the
 * exception form starts with: the first rule an exception may name, its
 * parameter, the path.
 */
function waf_panel_hit($wb, $row, $catalog = array())
{
	$rules = json_decode((string) $row['rules'], true);
	$headers = json_decode((string) $row['request_headers'], true);
	$list = array();
	$prefill = array('rule_id' => '', 'path' => (string) $row['path'], 'param' => '');
	foreach (is_array($rules) ? $rules : array() as $rule) {
		$id = isset($rule['id']) ? (string) $rule['id'] : '';
		$msg = isset($rule['msg']) ? (string) $rule['msg'] : '';
		$param = isset($rule['param']) ? (string) $rule['param'] : '';
		$data = isset($rule['data']) ? (string) $rule['data'] : '';
		$info = waf_panel_rule_info($wb, $catalog, $id, $msg);
		$list[] = array('rule_id' => $id, 'title' => $info['title'], 'msg' => $msg, 'data' => $data, 'param' => $param,
			'trigger' => waf_panel_trigger_text($wb, $data, $info['trigger']),
			'class' => $info['class'], 'class_label' => $info['class_label'], 'class_text' => $info['class_text'],
			'note' => $info['note']);
		if ($prefill['rule_id'] === ''
			&& waf_exception_check(array('scope' => 'site', 'parent_domain_id' => 1, 'rule_id' => $id)) === '') {
			$prefill['rule_id'] = $id;
			$prefill['param'] = $param;
		}
	}
	$header_list = array();
	foreach (is_array($headers) ? $headers : array() as $name => $value) {
		$header_list[] = array('name' => (string) $name, 'value' => is_scalar($value) ? (string) $value : '');
	}
	$body = $row['request_body'] === null ? '' : (string) $row['request_body'];
	return array(
		'hit_id' => (int) $row['hit_id'],
		'seen_at' => (string) $row['seen_at'],
		'client_ip' => (string) $row['client_ip'],
		'method' => (string) $row['method'],
		'uri' => (string) $row['uri'],
		'status' => (int) $row['status'],
		'score' => (int) $row['anomaly_score'],
		'would_block' => (string) $row['would_block'] === 'y',
		'logged_in' => (string) $row['logged_in'] === 'y',
		'rules' => $list,
		'headers' => $header_list,
		'body' => $body,
		'has_body' => $body !== '',
		'has_response' => (string) $row['response_file'] !== '',
		'response_bytes' => (int) $row['response_bytes'],
		'prefill' => $prefill,
	);
}

/**
 * What enforce would have meant over the preview period, and whether its
 * button is free. $totals sums malwatch_waf_site_day (would_block,
 * would_block_logged_in); $rule_rows sums malwatch_waf_day per rule
 * (rule_id, rule_msg, would_block_hits) over the same days.
 */
function waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now, $catalog = array())
{
	$state = is_array($site) && waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';
	$since = is_array($site) ? $site['waf_state_since'] : null;
	$reason = waf_enforce_block_reason($state, $since, $now, $settings['waf_min_detect_days'], $settings['waf_emergency']);
	$rules = array();
	foreach ($rule_rows as $row) {
		if ((int) $row['would_block_hits'] > 0) {
			$rules[] = array('rule_id' => (string) $row['rule_id'],
				'title' => waf_panel_rule_title($wb, $row['rule_id'], $row['rule_msg'], $catalog),
				'hits' => (int) $row['would_block_hits']);
		}
	}
	usort($rules, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['rule_id'], $b['rule_id']);
	});
	return array(
		'state' => $state,
		'allowed' => $reason === '' && $state !== 'enforce',
		'reason' => $reason,
		'free_from' => $state === 'detect' ? waf_enforce_free_from($since, $settings['waf_min_detect_days']) : '',
		'would_block' => is_array($totals) ? (int) $totals['would_block'] : 0,
		'logged_in' => is_array($totals) ? (int) $totals['would_block_logged_in'] : 0,
		'rules' => $rules,
		'days' => (int) $settings['waf_preview_days'],
	);
}

/**
 * The exception the form describes, ready to store: path and parameter only
 * where the scope uses them, the website only for per-site scopes, the note
 * without control characters. Returns array(row, wrong field or '').
 */
function waf_panel_exception_input($post, $site_id)
{
	$scope = isset($post['exc_scope']) ? (string) $post['exc_scope'] : '';
	$with_path = in_array($scope, array('site_path', 'site_param', 'all_path'), true);
	$note = isset($post['exc_note']) ? (string) $post['exc_note'] : '';
	$row = array(
		'scope' => $scope,
		'parent_domain_id' => strpos($scope, 'site') === 0 ? (int) $site_id : 0,
		'rule_id' => isset($post['exc_rule']) ? trim((string) $post['exc_rule']) : '',
		'path' => $with_path && isset($post['exc_path']) ? trim((string) $post['exc_path']) : '',
		'param' => $scope === 'site_param' && isset($post['exc_param']) ? trim((string) $post['exc_param']) : '',
		'note' => waf_cut(trim(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $note)), 255),
	);
	return array($row, waf_exception_check($row));
}

function waf_panel_preview_text($wb, $preview, $days)
{
	if ((int) $preview['total'] === 0) {
		return sprintf(waf_panel_text($wb, 'preview_none_txt', '%s'), (int) $days);
	}
	return sprintf(waf_panel_text($wb, 'preview_txt', '%s %s %s'),
		number_format((int) $preview['covered'], 0, ',', '.'), number_format((int) $preview['total'], 0, ',', '.'), (int) $days);
}

/** One WAF job for the pages: what it does, how it stands, the first line of its log. */
function waf_panel_job($wb, $row)
{
	$options = json_decode((string) $row['options'], true);
	$options = is_array($options) ? $options : array();
	$action = isset($options['action']) ? (string) $options['action'] : '';
	$label = $action === '' ? '' : waf_panel_job_label($wb, $action);
	if ($action === 'set_state' && isset($options['state'])) {
		$label .= ': ' . waf_panel_state_label($wb, (string) $options['state']);
	}
	$log = preg_split('/\R/', trim((string) $row['job_log']));
	return array(
		'job_id' => (int) $row['job_id'],
		'status' => (string) $row['job_status'],
		'status_label' => waf_panel_status_label($wb, (string) $row['job_status']),
		'label' => $label,
		'log' => (string) $log[0],
		'sites' => isset($options['domain_ids']) && is_array($options['domain_ids']) ? array_map('intval', $options['domain_ids']) : array(),
		'running' => in_array((string) $row['job_status'], array('pending', 'running'), true),
	);
}

/** One exception for the lists. Only active rows and rows in error may be removed. */
function waf_panel_exception_row($wb, $row)
{
	$scope = (string) $row['scope'];
	$target = array();
	if ((string) $row['path'] !== '') {
		$target[] = (string) $row['path'];
	}
	if ((string) $row['param'] !== '') {
		$target[] = sprintf(waf_panel_text($wb, 'param_label_txt', '%s'), (string) $row['param']);
	}
	$state = (string) $row['exception_state'];
	return array(
		'exception_id' => (int) $row['exception_id'],
		'rule_id' => (string) $row['rule_id'],
		'scope_label' => waf_panel_scope_label($wb, $scope),
		'site' => strpos($scope, 'site') === 0 ? (string) $row['domain'] : waf_panel_text($wb, 'all_sites_txt', ''),
		'site_id' => (int) $row['parent_domain_id'],
		'target' => implode(' · ', $target),
		'note' => (string) $row['note'],
		'state' => $state,
		'state_label' => waf_panel_exception_state_label($wb, $state),
		'error' => (string) $row['error_reason'],
		'created_by' => (string) $row['created_by'],
		'created_at' => (string) $row['created_at'],
		'can_remove' => in_array($state, array('active', 'error'), true),
	);
}

// --- Database ----------------------------------------------------------------

function waf_panel_rows($result)
{
	return is_array($result) ? $result : array();
}

/** The WAF settings as the pages use them. */
function waf_panel_settings($app)
{
	return waf_settings($app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
}

/** NOW() and CURDATE() of the database, the clock every WAF date is written on. */
function waf_panel_clock($app)
{
	$row = $app->db->queryOneRecord('SELECT NOW() AS now_at, CURDATE() AS today');
	if (!is_array($row)) {
		return array('now' => date('Y-m-d H:i:s'), 'today' => date('Y-m-d'));
	}
	return array('now' => (string) $row['now_at'], 'today' => (string) $row['today']);
}

/** The web servers a job for every website goes to. */
function waf_panel_web_servers($app)
{
	$ids = array();
	foreach (waf_panel_rows($app->db->queryAllRecords(
		'SELECT server_id FROM server WHERE web_server = 1 AND active = 1 ORDER BY server_id')) as $row) {
		$ids[] = (int) $row['server_id'];
	}
	return $ids;
}

/** Queues a WAF job through the datalog, like every other job of the panel, and returns its id. */
function waf_panel_queue($app, $server_id, $action, $fields)
{
	$user = isset($_SESSION['s']['user']['username']) ? (string) $_SESSION['s']['user']['username'] : '';
	$clock = waf_panel_clock($app);
	return (int) $app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $app->functions->intval($_SESSION['s']['user']['userid']),
		'sys_groupid' => $app->functions->intval($_SESSION['s']['user']['default_group']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => (int) $server_id,
		'parent_domain_id' => 0,
		'domain' => '',
		'scan_path' => '',
		'job_source' => 'manual',
		'job_kind' => 'waf',
		'job_status' => 'pending',
		'options' => waf_json(array_merge($fields, array('action' => (string) $action, 'user' => $user))),
		'created_at' => $clock['now'],
	), 'job_id');
}

/**
 * Carries out a button of the Abwehr pages; the page has checked the token.
 * Returns array(message, error), both plain text.
 */
function waf_panel_handle_post($app, $wb, $post)
{
	$action = isset($post['waf_action']) ? (string) $post['waf_action'] : '';
	if ($action === '') {
		return array('', '');
	}

	if ($action === 'state') {
		$state = isset($post['waf_target']) ? (string) $post['waf_target'] : '';
		if (!waf_state_valid($state)) {
			return array('', $wb['err_state_txt']);
		}
		$ids = array();
		if (isset($post['waf_site']) && (int) $post['waf_site'] > 0) {
			$ids[] = (int) $post['waf_site'];
		}
		if (isset($post['waf_pick']) && is_array($post['waf_pick'])) {
			foreach ($post['waf_pick'] as $id) {
				$ids[] = (int) $id;
			}
		}
		$ids = array_values(array_unique(array_filter($ids)));
		if (count($ids) === 0) {
			return array('', $wb['err_no_site_txt']);
		}
		$settings = waf_panel_settings($app);
		$clock = waf_panel_clock($app);
		$by_server = array();
		$skipped = 0;
		foreach ($ids as $id) {
			$row = $app->db->queryOneRecord(
				'SELECT w.domain_id, w.server_id, s.waf_state, s.waf_state_since FROM web_domain w '
				. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.domain_id = ? AND w.type = 'vhost'", $id);
			if (!is_array($row) || ($state === 'enforce' && waf_enforce_block_reason((string) $row['waf_state'],
				$row['waf_state_since'], $clock['now'], $settings['waf_min_detect_days'], $settings['waf_emergency']) !== '')) {
				$skipped++;
				continue;
			}
			$by_server[(int) $row['server_id']][] = $id;
		}
		$queued = 0;
		foreach ($by_server as $server_id => $site_ids) {
			waf_panel_queue($app, $server_id, 'set_state', array('domain_ids' => $site_ids, 'state' => $state));
			$queued += count($site_ids);
		}
		if ($queued === 0) {
			return array('', $wb['err_nothing_to_switch_txt']);
		}
		$message = sprintf($wb['msg_state_queued_txt'], waf_panel_state_label($wb, $state), number_format($queued, 0, ',', '.'));
		if ($skipped > 0) {
			$message .= ' ' . sprintf($wb['msg_state_skipped_txt'], number_format($skipped, 0, ',', '.'));
		}
		return array($message, '');
	}

	if ($action === 'emergency_on' || $action === 'emergency_off') {
		foreach (waf_panel_web_servers($app) as $server_id) {
			waf_panel_queue($app, $server_id, 'emergency', array('on' => $action === 'emergency_on', 'hard' => false));
		}
		return array($action === 'emergency_on' ? $wb['msg_emergency_on_txt'] : $wb['msg_emergency_off_txt'], '');
	}

	if ($action === 'response_body') {
		$mode = isset($post['waf_mode']) ? (string) $post['waf_mode'] : '';
		if (!waf_response_body_valid($mode)) {
			return array('', $wb['err_mode_txt']);
		}
		foreach (waf_panel_web_servers($app) as $server_id) {
			waf_panel_queue($app, $server_id, 'response_body', array('mode' => $mode));
		}
		return array($mode === 'lean' ? $wb['msg_lean_txt'] : $wb['msg_full_txt'], '');
	}

	if ($action === 'exception_add') {
		list($row, $wrong) = waf_panel_exception_input($post, isset($post['exc_site']) ? (int) $post['exc_site'] : 0);
		if ($wrong !== '') {
			return array('', waf_panel_reason_label($wb, $wrong));
		}
		$web = null;
		if ($row['parent_domain_id'] > 0) {
			$web = $app->db->queryOneRecord(
				"SELECT domain_id, domain, server_id FROM web_domain WHERE domain_id = ? AND type = 'vhost'", $row['parent_domain_id']);
			if (!is_array($web)) {
				return array('', $wb['err_no_site_txt']);
			}
		}
		$user = isset($_SESSION['s']['user']['username']) ? (string) $_SESSION['s']['user']['username'] : '';
		$clock = waf_panel_clock($app);
		foreach (is_array($web) ? array((int) $web['server_id']) : waf_panel_web_servers($app) as $server_id) {
			$app->db->query(
				'INSERT INTO malwatch_waf_exception (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, scope, parent_domain_id, domain, rule_id, path, param, note, exception_state, created_by, created_at) '
				. "VALUES (?, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
				$app->functions->intval($_SESSION['s']['user']['userid']),
				$app->functions->intval($_SESSION['s']['user']['default_group']),
				$server_id, $row['scope'], $row['parent_domain_id'], is_array($web) ? (string) $web['domain'] : '',
				$row['rule_id'], $row['path'], $row['param'], $row['note'], waf_cut($user, 64), $clock['now']);
			waf_panel_queue($app, $server_id, 'exception_add', array('exception_id' => (int) $app->db->insertID()));
		}
		return array($wb['msg_exception_added_txt'], '');
	}

	if ($action === 'exception_remove') {
		$exception_id = isset($post['waf_exception']) ? (int) $post['waf_exception'] : 0;
		$row = $app->db->queryOneRecord(
			'SELECT exception_id, server_id, exception_state FROM malwatch_waf_exception WHERE exception_id = ?', $exception_id);
		if (!is_array($row) || !in_array((string) $row['exception_state'], array('active', 'error'), true)) {
			return array('', $wb['err_exception_txt']);
		}
		$app->db->query("UPDATE malwatch_waf_exception SET exception_state = 'removing' WHERE exception_id = ?", $exception_id);
		waf_panel_queue($app, (int) $row['server_id'], 'exception_remove', array('exception_id' => $exception_id));
		return array($wb['msg_exception_removing_txt'], '');
	}

	return array('', $wb['err_unknown_action_txt']);
}

/**
 * The preview of the exception a form describes. Day figures cover
 * waf_preview_days; a parameter needs single hits and reaches back no further
 * than they are kept.
 */
function waf_panel_preview($app, $wb, $get)
{
	$site_id = isset($get['id']) ? (int) $get['id'] : 0;
	list($row, $wrong) = waf_panel_exception_input($get, $site_id);
	if ($wrong !== '') {
		return array('valid' => false, 'preview' => array('covered' => 0, 'total' => 0), 'text' => waf_panel_reason_label($wb, $wrong));
	}
	$settings = waf_panel_settings($app);
	$days = $settings['waf_preview_days'];
	$items = array();
	if ($row['scope'] === 'site_param') {
		$days = min($days, $settings['waf_detail_days']);
		foreach (waf_panel_rows($app->db->queryAllRecords(
			'SELECT parent_domain_id, path, rules FROM malwatch_waf_hit WHERE parent_domain_id = ? '
			. 'AND seen_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', $site_id, $days)) as $hit) {
			$rules = json_decode((string) $hit['rules'], true);
			foreach (is_array($rules) ? $rules : array() as $rule) {
				if (isset($rule['id']) && (string) $rule['id'] === $row['rule_id']) {
					$items[] = array('parent_domain_id' => (int) $hit['parent_domain_id'], 'rule_id' => $row['rule_id'],
						'path' => (string) $hit['path'], 'hits' => 1,
						'params' => isset($rule['param']) && $rule['param'] !== '' ? array((string) $rule['param']) : array());
				}
			}
		}
	} else {
		$items = waf_panel_rows($app->db->queryAllRecords(
			'SELECT parent_domain_id, rule_id, path, SUM(hits) AS hits FROM malwatch_waf_day '
			. 'WHERE rule_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY parent_domain_id, rule_id, path',
			$row['rule_id'], $days - 1));
	}
	$preview = waf_exception_preview($items, $row);
	return array('valid' => true, 'preview' => $preview, 'text' => waf_panel_preview_text($wb, $preview, $days));
}

/** A day of the database ('Y-m-d') as 'd.m.Y', without any clock involved. */
function waf_panel_day_label($day)
{
	return preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', (string) $day, $m) ? $m[3] . '.' . $m[2] . '.' . $m[1] : (string) $day;
}

/**
 * The filters of the exception list. 'site' is the id of a website, 'all'
 * for the exceptions of every website, or '' for no filter; anything else
 * counts as no filter.
 */
function waf_panel_exception_filters($get)
{
	$state = isset($get['state']) ? (string) $get['state'] : '';
	$site = isset($get['site']) ? (string) $get['site'] : '';
	if ($site !== 'all' && preg_match('/^[1-9][0-9]{0,9}$/', $site) !== 1) {
		$site = '';
	}
	return array(
		'state' => in_array($state, array('pending', 'active', 'error', 'removing'), true) ? $state : '',
		'site' => $site,
	);
}

/**
 * The exception list for $filters. A website shows its own exceptions and
 * those for every website, because both apply to it. 'sites' names every
 * website with an exception of its own, sorted by name, whatever the filter;
 * 'counts' counts the states within the chosen website. $rows come from
 * malwatch_waf_exception.
 */
function waf_panel_exception_list($rows, $filters)
{
	$sites = array();
	$has_global = false;
	$counts = array('' => 0, 'pending' => 0, 'active' => 0, 'error' => 0, 'removing' => 0);
	$list = array();
	foreach ($rows as $row) {
		$global = strpos((string) $row['scope'], 'all') === 0;
		$site_id = (int) $row['parent_domain_id'];
		if ($global) {
			$has_global = true;
		} else {
			$sites[$site_id] = (string) $row['domain'];
		}
		if ($filters['site'] === 'all' && !$global) {
			continue;
		}
		if ($filters['site'] !== '' && $filters['site'] !== 'all' && !$global && $site_id !== (int) $filters['site']) {
			continue;
		}
		$state = (string) $row['exception_state'];
		$counts['']++;
		if (isset($counts[$state])) {
			$counts[$state]++;
		}
		if ($filters['state'] === '' || $state === $filters['state']) {
			$list[] = $row;
		}
	}
	asort($sites, SORT_NATURAL | SORT_FLAG_CASE);
	$choices = array();
	foreach ($sites as $id => $domain) {
		$choices[] = array('value' => (string) $id, 'label' => $domain);
	}
	return array('rows' => $list, 'sites' => $choices, 'has_global' => $has_global, 'counts' => $counts);
}

/** The exception list's query string with some filters changed. */
function waf_panel_exception_query($filters, $changes)
{
	$merged = array_merge($filters, $changes);
	$parts = array();
	if ($merged['state'] !== '') {
		$parts[] = 'state=' . rawurlencode($merged['state']);
	}
	if ($merged['site'] !== '') {
		$parts[] = 'site=' . rawurlencode($merged['site']);
	}
	return implode('&', $parts);
}
