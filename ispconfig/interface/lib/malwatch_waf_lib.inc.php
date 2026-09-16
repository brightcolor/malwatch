<?php

/**
 * Pure functions for the WAF part of malwatch ("Abwehr" in the panel).
 *
 * Shared by the panel pages, the server class malwatch_waf, the tools under
 * waf/ and the tests. Text and arrays in, text and arrays out. The only file
 * access sits in waf_read_lines() and the file helpers at the end, which take
 * their paths and commands from the caller.
 *
 * Runs on PHP 7.0: no ??, no typed properties, no arrow functions.
 */

if (!defined('WAF_MARK_BEGIN')) {
	define('WAF_MARK_BEGIN', '# WAF-BEGIN');
	define('WAF_MARK_END', '# WAF-END');
	// Written by the first tool (waf-schalter) and still recognised.
	define('WAF_MARK_BEGIN_OLD', '# WAF-Anfang');
	define('WAF_MARK_END_OLD', '# WAF-Ende');
	// Shown in the panel in place of a removed header value.
	define('WAF_REMOVED', '[entfernt]');
	define('WAF_RULE_LEAN', 10199);
	define('WAF_RULE_EXCEPTION_BASE', 10200);
}

function waf_states()
{
	return array('off', 'detect', 'enforce');
}

function waf_state_valid($state)
{
	return in_array($state, waf_states(), true);
}

/** Maps the names of the first tool onto the current ones; '' for anything else. */
function waf_state_normalize($state)
{
	$old = array('aus' => 'off', 'mitschreiben' => 'detect', 'scharf' => 'enforce');
	$state = (string) $state;
	if (isset($old[$state])) {
		return $old[$state];
	}
	return waf_state_valid($state) ? $state : '';
}

/** The managed block for the field "nginx directives"; '' for off. */
function waf_block_text($state)
{
	if ($state === 'off' || !waf_state_valid($state)) {
		return '';
	}
	$lines = array(WAF_MARK_BEGIN . ' (' . $state . ') - managed by waf-switch', 'modsecurity on;');
	if ($state === 'enforce') {
		$lines[] = "modsecurity_rules 'SecRuleEngine On';";
	}
	$lines[] = WAF_MARK_END;
	return implode("\n", $lines) . "\n";
}

/**
 * Removes the managed block, new or old marker, with its own line break.
 * Everything around it stays byte for byte, the break of the line before
 * included.
 */
function waf_block_remove($text)
{
	$pattern = '/(?:' . preg_quote(WAF_MARK_BEGIN, '/') . '.*?' . preg_quote(WAF_MARK_END, '/')
		. '|' . preg_quote(WAF_MARK_BEGIN_OLD, '/') . '.*?' . preg_quote(WAF_MARK_END_OLD, '/')
		. ')[^\r\n]*(?:\R)?/s';
	return preg_replace($pattern, '', (string) $text);
}

function waf_block_set($text, $state)
{
	$rest = waf_block_remove($text);
	$block = waf_block_text($state);
	if ($block === '') {
		return $rest;
	}
	if (trim($rest) === '') {
		return $block;
	}
	// A text without a closing line break gets one; anything else stays as it is.
	if (!preg_match('/\R$/', $rest)) {
		$rest .= "\n";
	}
	return $rest . $block;
}

/** The state the managed block names; 'off' without a block or with an unknown name. */
function waf_block_state($text)
{
	$text = (string) $text;
	foreach (array(WAF_MARK_BEGIN, WAF_MARK_BEGIN_OLD) as $mark) {
		if (preg_match('/' . preg_quote($mark, '/') . '\s*\(([a-z]+)\)/', $text, $m)) {
			$state = waf_state_normalize($m[1]);
			return $state === '' ? 'off' : $state;
		}
	}
	return 'off';
}

function waf_block_is_old($text)
{
	return strpos((string) $text, WAF_MARK_BEGIN_OLD) !== false;
}

/**
 * The state a generated vhost file shows. ISPConfig drops comment lines when
 * it copies the directives into the vhost, so only the directives count.
 */
function waf_vhost_state($vhost)
{
	$on = false;
	$enforce = false;
	foreach (preg_split('/\R/', (string) $vhost) as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if (preg_match('/^modsecurity\s+on\s*;/i', $line)) {
			$on = true;
		}
		if (preg_match('/^modsecurity_rules\s+.*SecRuleEngine\s+On/i', $line)) {
			$enforce = true;
		}
	}
	if ($on && $enforce) {
		return 'enforce';
	}
	return $on ? 'detect' : 'off';
}

/**
 * The vhost text without any modsecurity directive, for the hard emergency
 * stop: with the module gone, nginx rejects every file that still names one.
 * Returns array(text, number of removed lines).
 */
function waf_vhost_strip($vhost)
{
	$kept = array();
	$removed = 0;
	foreach (preg_split('/(?<=\n)/', (string) $vhost, -1, PREG_SPLIT_NO_EMPTY) as $line) {
		if (preg_match('/^\s*modsecurity(?:_[a-z_]+)?\s/i', $line)) {
			$removed++;
			continue;
		}
		$kept[] = $line;
	}
	return array(implode('', $kept), $removed);
}

function waf_response_body_valid($mode)
{
	return in_array($mode, array('full', 'lean'), true);
}

/**
 * Content of response-body.conf. 110 CRS rules set ctl:auditLogParts=+E and so
 * write the whole response into the entry; "lean" takes it back out in phase 5,
 * after every CRS rule ran. Anything but 'lean' writes 'full'.
 */
function waf_response_body_text($mode)
{
	$lean = $mode === 'lean';
	$lines = array(
		'# Response body in the audit log: ' . ($lean ? 'lean' : 'full'),
		'# Managed by malwatch (page Abwehr, waf-switch response-body). Do not edit.',
		'#',
		'# full: CRS rules may write the whole response into the entry. 110 rules set',
		'#       ctl:auditLogParts=+E; a hit then weighs about 125 KB instead of about 4 KB.',
		'# lean: a phase 5 rule takes the response back out after every CRS rule ran.',
		'#       Matches, headers and the request body stay complete.',
	);
	if ($lean) {
		$lines[] = 'SecAction "id:' . WAF_RULE_LEAN . ',phase:5,pass,nolog,ctl:auditLogParts=-E"';
	}
	return implode("\n", $lines) . "\n";
}

/** The mode a response-body.conf (or the old antwortrumpf.conf) carries. Comments do not count. */
function waf_response_body_mode($text)
{
	foreach (preg_split('/\R/', (string) $text) as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if (strpos($line, 'ctl:auditLogParts=-E') !== false) {
			return 'lean';
		}
	}
	return 'full';
}

/** Content of state.conf, the emergency switch; included after every other file. */
function waf_state_file_text($emergency)
{
	$text = "# Emergency switch. Empty in normal operation; the emergency stop writes\n"
		. "# SecRuleEngine Off below. Managed by malwatch, do not edit.\n";
	return $emergency ? $text . "SecRuleEngine Off\n" : $text;
}

function waf_state_file_is_emergency($text)
{
	foreach (preg_split('/\R/', (string) $text) as $line) {
		if (preg_match('/^\s*SecRuleEngine\s+Off\b/i', $line)) {
			return true;
		}
	}
	return false;
}

/** At most $bytes bytes of $text, cut on a UTF-8 character boundary. */
function waf_cut($text, $bytes)
{
	$text = (string) $text;
	if (strlen($text) <= $bytes) {
		return $text;
	}
	if (function_exists('mb_strcut')) {
		return mb_strcut($text, 0, $bytes, 'UTF-8');
	}
	return preg_replace('/[\x80-\xFF]+$/', '', substr($text, 0, $bytes));
}

/** JSON for the database; '[]' when the value cannot be encoded. */
function waf_json($value)
{
	$json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	return $json === false ? '[]' : $json;
}

// --- Audit log ---------------------------------------------------------------

/**
 * Replaces bytes that are no valid UTF-8 with U+FFFD, so json_decode and
 * MySQL accept the text. A question mark would read as the start of a query.
 */
function waf_utf8_clean($text)
{
	$text = (string) $text;
	if (preg_match('//u', $text) === 1) {
		return $text;
	}
	if (function_exists('mb_convert_encoding')) {
		$previous = mb_substitute_character();
		mb_substitute_character(0xFFFD);
		$text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
		mb_substitute_character($previous);
		return $text;
	}
	return preg_replace('/[\x80-\xFF]/', "\xEF\xBF\xBD", $text);
}

/** 'Wed Sep 16 21:09:19 2026' (ctime, local time of the web server) as 'Y-m-d H:i:s'; '' otherwise. */
function waf_audit_time($stamp)
{
	$months = array('Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4, 'May' => 5, 'Jun' => 6,
		'Jul' => 7, 'Aug' => 8, 'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12);
	if (!preg_match('/^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/', trim((string) $stamp), $m)) {
		return '';
	}
	if (!isset($months[$m[1]]) || !checkdate($months[$m[1]], (int) $m[2], (int) $m[6])
		|| (int) $m[3] > 23 || (int) $m[4] > 59 || (int) $m[5] > 60) {
		return '';
	}
	return sprintf('%04d-%02d-%02d %02d:%02d:%02d', (int) $m[6], $months[$m[1]], (int) $m[2],
		(int) $m[3], (int) $m[4], min(59, (int) $m[5]));
}

/** A request header by name, whatever its case; '' when missing. */
function waf_audit_header($headers, $name)
{
	if (!is_array($headers)) {
		return '';
	}
	foreach ($headers as $key => $value) {
		if (strcasecmp((string) $key, $name) === 0) {
			return is_array($value) ? implode(', ', $value) : (string) $value;
		}
	}
	return '';
}

/** A host name the way the host map knows it: lower case, no port, no closing dot; '' if unusable. */
function waf_host_normalize($host)
{
	$host = strtolower(trim((string) $host));
	$host = rtrim(preg_replace('/:\d+$/', '', $host), '.');
	if ($host === '' || strlen($host) > 253
		|| !preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/', $host)) {
		return '';
	}
	return $host;
}

/** The cookie names of a Cookie header, in order, without their values. */
function waf_cookie_names($header)
{
	$names = array();
	foreach (explode(';', (string) $header) as $pair) {
		$pos = strpos($pair, '=');
		$name = trim($pos === false ? $pair : substr($pair, 0, $pos));
		if ($name !== '') {
			$names[] = $name;
		}
	}
	return $names;
}

/**
 * The request headers as they are stored: the values of Cookie,
 * Authorization and Proxy-Authorization are replaced, the cookie names stay.
 * Names are cut at 128 bytes, values at 1000.
 */
function waf_headers_sanitize($headers)
{
	$clean = array();
	if (!is_array($headers)) {
		return $clean;
	}
	foreach ($headers as $name => $value) {
		$name = waf_cut((string) $name, 128);
		$value = is_array($value) ? implode(', ', $value) : (string) $value;
		$lower = strtolower($name);
		if ($lower === 'cookie') {
			$parts = array();
			foreach (waf_cookie_names($value) as $cookie) {
				$parts[] = $cookie . '=' . WAF_REMOVED;
			}
			$value = implode('; ', $parts);
		} elseif ($lower === 'authorization' || $lower === 'proxy-authorization') {
			$value = WAF_REMOVED;
		}
		$clean[$name] = waf_cut($value, 1000);
	}
	return $clean;
}

/** CRS rules that only add up and report: 949 and 959 act on the score, 980 correlates. */
function waf_is_scoring_rule($rule_id)
{
	return preg_match('/^(?:949|959|980)\d{3}$/', (string) $rule_id) === 1;
}

/** The ARGS name a CRS match names ("... found within ARGS:filter: ..."); '' otherwise. */
function waf_audit_param($data)
{
	if (preg_match('/found within ARGS:([A-Za-z0-9_.\[\]-]{1,128})(?::|\s|$)/', (string) $data, $m)) {
		return $m[1];
	}
	return '';
}

/**
 * One line of the JSON audit log as a hit, or null for a line that is no
 * usable entry. tests/waf_audit_sample.log shows the shape ModSecurity 3.0.12
 * writes.
 */
function waf_audit_parse_line($line)
{
	$line = trim((string) $line);
	if ($line === '' || $line[0] !== '{') {
		return null;
	}
	$doc = json_decode(waf_utf8_clean($line), true);
	if (!is_array($doc) || !isset($doc['transaction']) || !is_array($doc['transaction'])) {
		return null;
	}
	$t = $doc['transaction'];
	$seen_at = waf_audit_time(isset($t['time_stamp']) ? $t['time_stamp'] : '');
	$messages = isset($t['messages']) && is_array($t['messages']) ? $t['messages'] : array();
	if ($seen_at === '' || count($messages) === 0) {
		return null;
	}

	$rules = array();
	$seen = array();
	$score = 0;
	$would_block = false;
	foreach ($messages as $message) {
		$details = is_array($message) && isset($message['details']) && is_array($message['details'])
			? $message['details'] : array();
		$rule_id = isset($details['ruleId']) ? (string) $details['ruleId'] : '';
		if (!preg_match('/^[0-9]{1,9}$/', $rule_id)) {
			continue;
		}
		$text = isset($message['message']) ? (string) $message['message'] : '';
		if ($rule_id === '949110') {
			$would_block = true;
			if (preg_match('/Total Score:\s*(\d+)/', $text, $m)) {
				$score = max($score, (int) $m[1]);
			}
		}
		if (isset($seen[$rule_id]) || count($rules) >= 50) {
			continue;
		}
		$seen[$rule_id] = true;
		$data = isset($details['data']) ? (string) $details['data'] : '';
		$rules[] = array(
			'id' => $rule_id,
			'msg' => waf_cut($text, 255),
			'data' => waf_cut($data, 300),
			'param' => waf_audit_param($data),
		);
	}
	if (count($rules) === 0) {
		return null;
	}

	$request = isset($t['request']) && is_array($t['request']) ? $t['request'] : array();
	$response = isset($t['response']) && is_array($t['response']) ? $t['response'] : array();
	$headers = isset($request['headers']) && is_array($request['headers']) ? $request['headers'] : array();
	$uri = isset($request['uri']) ? (string) $request['uri'] : '';
	$query = strpos($uri, '?');
	$path = $query === false ? $uri : substr($uri, 0, $query);

	$logged_in = false;
	foreach (waf_cookie_names(waf_audit_header($headers, 'Cookie')) as $name) {
		if (strpos($name, 'wordpress_logged_in_') === 0) {
			$logged_in = true;
		}
	}
	$client_ip = isset($t['client_ip']) ? (string) $t['client_ip'] : '';
	$unique_id = isset($t['unique_id']) ? (string) $t['unique_id'] : '';
	if (!preg_match('/^[A-Za-z0-9.@_-]{1,64}$/', $unique_id)) {
		// Without an id of its own the line names itself, so a second read of
		// the same line still finds its row.
		$unique_id = 'sha1-' . sha1($line);
	}
	$method = isset($request['method']) ? strtoupper((string) $request['method']) : '';

	return array(
		'unique_id' => $unique_id,
		'seen_at' => $seen_at,
		'client_ip' => filter_var($client_ip, FILTER_VALIDATE_IP) !== false ? $client_ip : '',
		'host' => waf_host_normalize(waf_audit_header($headers, 'Host')),
		'method' => substr(preg_replace('/[^A-Z]/', '', $method), 0, 10),
		'uri' => waf_cut(waf_utf8_clean($uri), 2048),
		'path' => waf_cut(waf_utf8_clean($path), 1024),
		'status' => isset($response['http_code']) ? (int) $response['http_code'] : 0,
		'rules' => $rules,
		'anomaly_score' => $score,
		'would_block' => $would_block,
		'logged_in' => $logged_in,
		'headers' => waf_headers_sanitize($headers),
		'body' => isset($request['body']) ? waf_cut((string) $request['body'], 1048576) : null,
		'response_body' => isset($response['body']) ? (string) $response['body'] : null,
	);
}

/** Hits per host and rule for waf-report, the most first. Scoring rules are left out. */
function waf_audit_summarize($lines)
{
	$groups = array();
	foreach ($lines as $line) {
		$hit = waf_audit_parse_line($line);
		if ($hit === null) {
			continue;
		}
		foreach ($hit['rules'] as $rule) {
			if (waf_is_scoring_rule($rule['id'])) {
				continue;
			}
			$key = $hit['host'] . '|' . $rule['id'];
			if (!isset($groups[$key])) {
				$groups[$key] = array('host' => $hit['host'], 'rule_id' => $rule['id'],
					'message' => $rule['msg'], 'hits' => 0, 'example' => $hit['path']);
			}
			$groups[$key]['hits']++;
		}
	}
	$report = array_values($groups);
	usort($report, function ($a, $b) {
		if ($a['hits'] === $b['hits']) {
			return strcmp($a['host'] . '|' . $a['rule_id'], $b['host'] . '|' . $b['rule_id']);
		}
		return $b['hits'] - $a['hits'];
	});
	return $report;
}

/** Where reading starts: 0 for another file (inode) or one that shrank (copytruncate). */
function waf_reader_start($stored_inode, $stored_offset, $inode, $size)
{
	$stored_offset = max(0, (int) $stored_offset);
	if ((int) $stored_inode !== (int) $inode || (int) $size < $stored_offset) {
		return 0;
	}
	return $stored_offset;
}

/**
 * Up to $max_lines complete lines from $offset on. A last line without its
 * line break stays for the next run. Returns array('lines', 'offset', 'more')
 * or null when the file cannot be opened.
 */
function waf_read_lines($file, $offset, $max_lines)
{
	$handle = @fopen($file, 'rb');
	if ($handle === false) {
		return null;
	}
	$offset = (int) $offset;
	$lines = array();
	$more = false;
	if (fseek($handle, $offset) === 0) {
		while (true) {
			$line = fgets($handle);
			if ($line === false || substr($line, -1) !== "\n") {
				break;
			}
			if (count($lines) >= $max_lines) {
				$more = true;
				break;
			}
			$offset += strlen($line);
			$lines[] = rtrim($line, "\r\n");
		}
	}
	fclose($handle);
	return array('lines' => $lines, 'offset' => $offset, 'more' => $more);
}

// --- Websites and their names ------------------------------------------------

/**
 * Which website a host name belongs to. A vhost always answers to www. as
 * well; alias and subdomain rows belong to their parent; subdomain '*' makes
 * a wildcard. Websites come first, so an alias never takes another website's
 * name. Inactive rows are left out.
 */
function waf_host_map($rows)
{
	$map = array('exact' => array(), 'wildcard' => array());
	$groups = array(0 => array(), 1 => array());
	foreach ($rows as $row) {
		if ((string) $row['active'] === 'y') {
			$groups[(string) $row['type'] === 'vhost' ? 0 : 1][] = $row;
		}
	}
	$children = array('alias', 'subdomain', 'vhostalias', 'vhostsubdomain');
	foreach ($groups as $group) {
		foreach ($group as $row) {
			$type = (string) $row['type'];
			if ($type === 'vhost') {
				$site = (int) $row['domain_id'];
			} elseif (in_array($type, $children, true)) {
				$site = (int) $row['parent_domain_id'];
			} else {
				continue;
			}
			$domain = waf_host_normalize($row['domain']);
			if ($site < 1 || $domain === '') {
				continue;
			}
			$sub = isset($row['subdomain']) ? (string) $row['subdomain'] : 'none';
			$names = array($domain);
			if ($type === 'vhost' || $sub === 'www') {
				$names[] = 'www.' . $domain;
			}
			foreach ($names as $name) {
				if (!isset($map['exact'][$name])) {
					$map['exact'][$name] = $site;
				}
			}
			if ($sub === '*' && !isset($map['wildcard'][$domain])) {
				$map['wildcard'][$domain] = $site;
			}
		}
	}
	return $map;
}

/** The website of a host, 0 when none: the exact name first, then the closest wildcard. */
function waf_host_lookup($map, $host)
{
	$host = waf_host_normalize($host);
	if ($host === '') {
		return 0;
	}
	if (isset($map['exact'][$host])) {
		return (int) $map['exact'][$host];
	}
	$labels = explode('.', $host);
	for ($i = 1; $i < count($labels) - 1; $i++) {
		$parent = implode('.', array_slice($labels, $i));
		if (isset($map['wildcard'][$parent])) {
			return (int) $map['wildcard'][$parent];
		}
	}
	return 0;
}

/** The names of one website, sorted. */
function waf_hosts_of($map, $site_id)
{
	$exact = array_keys($map['exact'], (int) $site_id, true);
	$wildcard = array_keys($map['wildcard'], (int) $site_id, true);
	sort($exact);
	sort($wildcard);
	return array('exact' => $exact, 'wildcard' => $wildcard);
}

/**
 * The pattern for REQUEST_HEADERS:Host in a rule file; the rule lowercases
 * the header first. Only names that pass waf_host_normalize() get in, so the
 * dot is the one character to escape. '' when no name is left.
 */
function waf_host_pattern($hosts)
{
	$parts = array();
	foreach ($hosts['exact'] as $host) {
		if (waf_host_normalize($host) === $host) {
			$parts[] = str_replace('.', '\.', $host);
		}
	}
	foreach ($hosts['wildcard'] as $domain) {
		if (waf_host_normalize($domain) === $domain) {
			$parts[] = '(?:[a-z0-9-]+\.)+' . str_replace('.', '\.', $domain);
		}
	}
	if (count($parts) === 0) {
		return '';
	}
	return '^(?:' . implode('|', $parts) . ')(?::\d+)?$';
}

// --- Exceptions --------------------------------------------------------------

function waf_exception_scopes()
{
	return array('site', 'site_path', 'site_param', 'all', 'all_path');
}

/**
 * Checks one exception before the panel stores it and again before a job
 * turns it into a rule. Returns '' or the field that is wrong.
 */
function waf_exception_check($row)
{
	$scope = isset($row['scope']) ? (string) $row['scope'] : '';
	$site = isset($row['parent_domain_id']) ? (int) $row['parent_domain_id'] : 0;
	$rule = isset($row['rule_id']) ? (string) $row['rule_id'] : '';
	$path = isset($row['path']) ? (string) $row['path'] : '';
	$param = isset($row['param']) ? (string) $row['param'] : '';

	if (!in_array($scope, waf_exception_scopes(), true)) {
		return 'scope';
	}
	if ((strpos($scope, 'site') === 0) !== ($site > 0)) {
		return 'site';
	}
	// The own rules (10000-10999) keep passwords out of the log and the
	// server's own requests out of the check; the scoring rules only add up.
	if (!preg_match('/^[0-9]{3,7}$/', $rule) || waf_is_scoring_rule($rule)
		|| ((int) $rule >= 10000 && (int) $rule <= 10999)) {
		return 'rule_id';
	}
	$path_needed = $scope === 'site_path' || $scope === 'all_path';
	if ($path === '' ? $path_needed : (!($path_needed || $scope === 'site_param')
		|| !preg_match('#^/[A-Za-z0-9._~/%+-]{0,1023}$#', $path))) {
		return 'path';
	}
	if (($scope === 'site_param') !== ($param !== '')
		|| ($param !== '' && !preg_match('/^[A-Za-z0-9_.\[\]-]{1,128}$/', $param))) {
		return 'param';
	}
	return '';
}

function waf_exception_rule_id($exception_id)
{
	return WAF_RULE_EXCEPTION_BASE + (int) $exception_id;
}

/**
 * The two rule files the panel owns: exclusions-panel-before.conf (included
 * before the CRS rules, runtime ctl actions) and exclusions-panel-after.conf
 * (after them, SecRuleRemoveById for every website). Only pending and active
 * rows count, in the order of their ids. A row that fails the check, or whose
 * website has no name in $hosts, stays out and is listed in 'skipped'. The
 * note of an exception never reaches a file.
 */
function waf_exception_rules($rows, $hosts)
{
	$header = "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n";
	$before = $header . "# Included before the CRS rules: runtime exclusions (ctl).\n";
	$after = $header . "# Included after the CRS rules: exclusions for every website.\n";
	$skipped = array();

	usort($rows, function ($a, $b) {
		return (int) $a['exception_id'] - (int) $b['exception_id'];
	});
	foreach ($rows as $row) {
		$state = isset($row['exception_state']) ? (string) $row['exception_state'] : '';
		if ($state !== 'pending' && $state !== 'active') {
			continue;
		}
		$id = (int) $row['exception_id'];
		// CRS owns the ids from 900000 on.
		$reason = ($id < 1 || waf_exception_rule_id($id) >= 900000) ? 'exception_id' : waf_exception_check($row);
		if ($reason !== '') {
			$skipped[$id] = $reason;
			continue;
		}
		$scope = (string) $row['scope'];
		$rule = (string) $row['rule_id'];
		$path = (string) $row['path'];
		$rid = waf_exception_rule_id($id);
		$title = "\n# exception " . $id . ' (' . $scope . ")\n";

		if ($scope === 'all') {
			$after .= $title . 'SecRuleRemoveById ' . $rule . "\n";
			continue;
		}
		if ($scope === 'all_path') {
			$before .= $title . 'SecRule REQUEST_FILENAME "@beginsWith ' . $path . '" "id:' . $rid
				. ',phase:1,pass,nolog,t:none,ctl:ruleRemoveById=' . $rule . "\"\n";
			continue;
		}

		$site = (int) $row['parent_domain_id'];
		$pattern = isset($hosts[$site]) ? waf_host_pattern($hosts[$site]) : '';
		if ($pattern === '') {
			$skipped[$id] = 'site';
			continue;
		}
		$ctl = $scope === 'site_param'
			? 'ctl:ruleRemoveTargetById=' . $rule . ';ARGS:' . (string) $row['param']
			: 'ctl:ruleRemoveById=' . $rule;
		$host_rule = 'SecRule REQUEST_HEADERS:Host "@rx ' . $pattern . '" "id:' . $rid
			. ',phase:1,pass,nolog,t:none,t:lowercase,';
		if ($path === '') {
			$before .= $title . $host_rule . $ctl . "\"\n";
		} else {
			$before .= $title . $host_rule . "chain\"\n"
				. '    SecRule REQUEST_FILENAME "@beginsWith ' . $path . '" "t:none,' . $ctl . "\"\n";
		}
	}
	return array('before' => $before, 'after' => $after, 'skipped' => $skipped);
}

/**
 * How many hits an exception would have prevented. total counts the hits of
 * the rule on the exception's websites (all websites for all and all_path);
 * covered the part the exception matches. Rows of the day table carry no
 * params, so site_param needs rows built from single hits.
 */
function waf_exception_preview($items, $exception)
{
	$scope = (string) $exception['scope'];
	$site = (int) $exception['parent_domain_id'];
	$rule = (string) $exception['rule_id'];
	$path = isset($exception['path']) ? (string) $exception['path'] : '';
	$param = isset($exception['param']) ? (string) $exception['param'] : '';
	$per_site = strpos($scope, 'site') === 0;
	$covered = 0;
	$total = 0;
	foreach ($items as $item) {
		if ((string) $item['rule_id'] !== $rule || ($per_site && (int) $item['parent_domain_id'] !== $site)) {
			continue;
		}
		$hits = (int) $item['hits'];
		$total += $hits;
		if ($path !== '' && strpos((string) $item['path'], $path) !== 0) {
			continue;
		}
		if ($scope === 'site_param') {
			$params = isset($item['params']) && is_array($item['params']) ? $item['params'] : array();
			if (!in_array($param, $params, true)) {
				continue;
			}
		}
		$covered += $hits;
	}
	return array('covered' => $covered, 'total' => $total);
}
