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

require_once __DIR__ . '/malwatch_waf_f2b.inc.php';

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

/**
 * The managed block for the field "nginx directives"; '' for off. $ban_log is
 * the second access log (waf_blocked_log) or '' for none.
 */
function waf_block_text($state, $ban_log = '')
{
	if ($state === 'off' || !waf_state_valid($state)) {
		return '';
	}
	$lines = array(WAF_MARK_BEGIN . ' (' . $state . ') - managed by waf-switch', 'modsecurity on;');
	if (is_string($ban_log) && $ban_log !== '') {
		// The second log carries the answers 403 of the deny list; its format and
		// its condition stand in the include of the block list. Without that
		// file nginx refuses the unknown format, so the caller decides.
		$lines[] = 'access_log ' . $ban_log . ' mw_block if=$mw_denied;';
	}
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

function waf_block_set($text, $state, $ban_log = '')
{
	$rest = waf_block_remove($text);
	$block = waf_block_text($state, $ban_log);
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
 * writes. $login_cookies are the beginnings of cookie names that mark a
 * logged-in session (waf_login_cookies), $rules_max how many rule messages a
 * hit keeps (waf_hit_rules_max); null takes the default.
 */
function waf_audit_parse_line($line, $login_cookies = null, $rules_max = null)
{
	if ($rules_max === null) {
		$defaults = waf_settings_defaults();
		$rules_max = (int) $defaults['waf_hit_rules_max'];
	}
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
		if (isset($seen[$rule_id]) || count($rules) >= $rules_max) {
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

	// A request comes from a logged-in session when one of its cookies begins
	// like an entry of waf_login_cookies.
	if ($login_cookies === null) {
		$defaults = waf_settings_defaults();
		$login_cookies = waf_list_parse($defaults['waf_login_cookies']);
	}
	$logged_in = false;
	foreach (waf_cookie_names(waf_audit_header($headers, 'Cookie')) as $name) {
		foreach ($login_cookies as $prefix) {
			if ((string) $prefix !== '' && strpos($name, (string) $prefix) === 0) {
				$logged_in = true;
			}
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

// --- Settings ----------------------------------------------------------------

/** The WAF settings in malwatch_config with their defaults. */
/**
 * The values each choice of the origin settings accepts. Anything else falls
 * back to the default, so a row from an older schema or a hand-edited value
 * never turns a source on.
 */
function waf_origin_choices()
{
	return array(
		'waf_origin_geo' => array('off', 'dbip', 'maxmind'),
		'waf_origin_tor' => array('off', 'torproject'),
		'waf_origin_net' => array('off', 'x4b', 'proxycheck'),
	);
}

function waf_settings_defaults()
{
	return array(
		'waf_detail_days' => 7,
		'waf_stats_days' => 90,
		'waf_log_keep_days' => 7,
		'waf_preview_days' => 7,
		'waf_min_detect_days' => 7,
		'waf_response_body' => 'full',
		'waf_ingest_max_lines' => 5000,
		'waf_job_deadline_minutes' => 5,
		'waf_tick_wait_seconds' => 30,
		'waf_audit_log' => '/var/log/waf/audit.log',
		'waf_conf_dir' => '/etc/nginx/waf',
		'waf_emergency' => 'n',
		'waf_emergency_since' => null,
		'waf_card_hits' => 5000,
		'waf_origin_geo' => 'off',
		'waf_origin_maxmind_account' => '',
		'waf_origin_maxmind_key' => '',
		'waf_origin_tor' => 'off',
		'waf_origin_net' => 'off',
		'waf_origin_proxycheck_key' => '',
		'waf_origin_proxycheck_daily' => 500,
		'waf_ban_mode' => 'off',
		'waf_ban_score' => 50,
		'waf_ban_window_minutes' => 10,
		'waf_ban_logged_in_percent' => 10,
		'waf_ban_hours_first' => 1,
		'waf_ban_hours_second' => 24,
		'waf_ban_hours_third' => 168,
		'waf_ban_max' => 5000,
		'waf_ban_keep_days' => 30,
		'waf_ban_proposal_days' => 7,
		'waf_ban_page_step' => 25,
		'waf_ban_page_rows' => 1000,
		'waf_ban_page_timeout' => 30,
		'waf_f2b' => 'on',
		'waf_everywhere_mode' => 'web_jail',
		'waf_everywhere_jail' => 'recidive',
		'waf_ban_bots' => 'on',
		'waf_ban_token' => '',
		'waf_ban_origin' => 'off',
		'waf_ban_origin_score' => 20,
		'waf_ban_origin_factor' => 200,
		'waf_ban_origin_now' => 'off',
		'waf_ban_origin_hosting' => 'off',
		'waf_ban_origin_vpn' => 'off',
		'waf_ban_origin_tor' => 'off',
		'waf_ban_origin_countries' => '',
		'waf_ban_origin_asn' => '',
		'waf_origin_tor_hours' => 1,
		'waf_origin_list_hours' => 24,
		'waf_origin_db_hours' => 24,
		'waf_ban_logged_in_paths' => '/wp-admin/,/wp-json/',
		'waf_ban_full_paths' => 'wp-login.php,xmlrpc.php',
		'waf_login_cookies' => 'wordpress_logged_in_',
		'waf_own_networks' => '127.0.0.0/8,::1/128,10.50.0.0/24',
		'waf_ban_origin_rows' => 25,
		'waf_poll_seconds' => 5,
		'waf_tick_fresh_seconds' => 180,
		'waf_lock_retry_ms' => 250,
		'waf_ban_rule_hits' => 200,
		'waf_periods' => '1,7,30,90',
		'waf_period_default' => 7,
		// From 0.34.0 the technical values: the sources of the origin (addresses,
		// smallest plausible number of entries, largest download in MB), downloads,
		// proxycheck.io, cleanup, reading and the command line.
		'waf_src_dbip_country_urls' => 'https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz',
		'waf_src_dbip_country_min' => 100000,
		'waf_src_dbip_country_mb' => 80,
		'waf_src_dbip_asn_urls' => 'https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz',
		'waf_src_dbip_asn_min' => 100000,
		'waf_src_dbip_asn_mb' => 80,
		'waf_src_maxmind_country_urls' => 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip',
		'waf_src_maxmind_country_min' => 100000,
		'waf_src_maxmind_country_mb' => 80,
		'waf_src_maxmind_asn_urls' => 'https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip',
		'waf_src_maxmind_asn_min' => 100000,
		'waf_src_maxmind_asn_mb' => 80,
		'waf_src_tor_urls' => 'https://check.torproject.org/torbulkexitlist',
		'waf_src_tor_min' => 100,
		'waf_src_tor_mb' => 20,
		'waf_src_x4b_vpn_urls' => 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt,https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt',
		'waf_src_x4b_vpn_min' => 1000,
		'waf_src_x4b_vpn_mb' => 20,
		'waf_src_x4b_datacenter_urls' => 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt,https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt',
		'waf_src_x4b_datacenter_min' => 1000,
		'waf_src_x4b_datacenter_mb' => 20,
		'waf_src_searchbots_urls' => 'https://developers.google.com/static/search/apis/ipranges/googlebot.json,https://www.bing.com/toolbox/bingbot.json',
		'waf_src_searchbots_min' => 10,
		'waf_src_searchbots_mb' => 8,
		'waf_origin_bad_percent' => 1,
		'waf_origin_keep_percent' => 50,
		'waf_fetch_connect_seconds' => 10,
		'waf_fetch_timeout_seconds' => 120,
		'waf_fetch_redirects' => 3,
		'waf_proxycheck_url' => 'https://proxycheck.io/v3/',
		'waf_proxycheck_batch' => 100,
		'waf_proxycheck_answer_mb' => 2,
		'waf_proxycheck_connect_seconds' => 5,
		'waf_proxycheck_timeout_seconds' => 10,
		'waf_proxycheck_retry_minutes' => 60,
		'waf_proxycheck_tries' => 3,
		'waf_origin_lookup_batch' => 500,
		'waf_cleanup_batch' => 1000,
		'waf_cleanup_rounds' => 50,
		'waf_response_grace_minutes' => 60,
		'waf_blocked_lines' => 20000,
		'waf_hit_rules_max' => 50,
		'waf_show_paths' => 50,
		'waf_preview_delay_ms' => 300,
		'waf_cli_jobs' => 20,
		'waf_cli_wait_margin_minutes' => 2,
		// From 0.35.0 the places and names on the server (see waf_path_settings(),
		// waf/install.sh lays them out), the limits of ModSecurity and the minutes
		// of the guard and of the hourly pass.
		'waf_rules_include' => '/etc/nginx/conf.d/waf.conf',
		'waf_blocked_include' => '/etc/nginx/conf.d/waf-blocked.conf',
		'waf_nginx_service' => 'nginx',
		'waf_modsec_base' => '/etc/nginx/modsecurity.conf',
		'waf_crs_setup' => '/etc/modsecurity/crs/crs-setup.conf',
		'waf_crs_rules' => '/usr/share/modsecurity-crs/rules/*.conf',
		'waf_rules_check' => '/usr/lib/*/libexec/modsec-rules-check',
		'waf_cache_dir' => '/var/cache/waf',
		'waf_blocked_log' => '/var/log/waf/blocked.log',
		'waf_guard_log' => '/var/log/waf/guard.log',
		'waf_backup_dir' => '/var/backups/waf-switch',
		'waf_logrotate_file' => '/etc/logrotate.d/waf',
		'waf_tools_dir' => '/usr/local/sbin',
		'waf_cron_file' => '/etc/cron.d/malwatch-waf',
		'waf_hc_run' => '/usr/local/sbin/hc-run',
		'waf_hc_tick_name' => 'waf-tick',
		'waf_hc_guard_name' => 'waf-guard',
		'waf_hc_watch_name' => 'malwatch-wache',
		'waf_bin_dirs' => '/usr/local/sbin,/usr/local/bin,/usr/sbin,/usr/bin,/sbin,/bin',
		'waf_body_limit_kb' => 12800,
		'waf_body_nofiles_limit_kb' => 128,
		'waf_body_limit_action' => 'ProcessPartial',
		'waf_guard_minute' => 5,
		'waf_hourly_minute' => 7,
		// From 0.36.0: the watch over the scanner (waf-switch watch).
		'waf_watch_minutes' => 5,
		'waf_watch_stale_minutes' => 15,
		'waf_watch_pending_minutes' => 180,
		'waf_watch_overdue_hours' => 12,
		'waf_watch_remind_hours' => 24,
		'waf_watch_crash_pause' => 10,
	);
}

/** What ModSecurity does with a request body beyond waf_body_limit_kb: check its beginning, or refuse it. */
function waf_body_limit_actions()
{
	return array('ProcessPartial', 'Reject');
}

/** The three states of the automatic blocking. */
function waf_ban_modes()
{
	return array('off', 'propose', 'block');
}

/** The range each number is held to: array(min, max). */
function waf_settings_limits()
{
	return array(
		'waf_detail_days' => array(1, 3650),
		'waf_stats_days' => array(1, 3650),
		'waf_log_keep_days' => array(1, 365),
		'waf_preview_days' => array(1, 365),
		'waf_min_detect_days' => array(0, 365),
		'waf_ingest_max_lines' => array(100, 100000),
		'waf_job_deadline_minutes' => array(2, 120),
		'waf_tick_wait_seconds' => array(0, 50),
		'waf_card_hits' => array(100, 100000),
		'waf_origin_proxycheck_daily' => array(1, 100000),
		'waf_ban_score' => array(5, 10000),
		'waf_ban_window_minutes' => array(1, 1440),
		'waf_ban_logged_in_percent' => array(0, 100),
		'waf_ban_hours_first' => array(1, 8760),
		'waf_ban_hours_second' => array(1, 8760),
		'waf_ban_hours_third' => array(1, 8760),
		'waf_ban_max' => array(100, 100000),
		'waf_ban_keep_days' => array(1, 365),
		'waf_ban_proposal_days' => array(1, 365),
		'waf_ban_page_step' => array(5, 500),
		'waf_ban_page_rows' => array(20, 5000),
		'waf_ban_page_timeout' => array(5, 300),
		'waf_ban_origin_score' => array(0, 10000),
		'waf_ban_origin_factor' => array(100, 1000),
		'waf_origin_tor_hours' => array(1, 168),
		'waf_origin_list_hours' => array(1, 720),
		'waf_origin_db_hours' => array(1, 720),
		'waf_ban_origin_rows' => array(5, 200),
		'waf_poll_seconds' => array(2, 60),
		'waf_tick_fresh_seconds' => array(120, 3600),
		'waf_lock_retry_ms' => array(50, 5000),
		'waf_ban_rule_hits' => array(50, 5000),
		'waf_period_default' => array(1, 3650),
		'waf_src_dbip_country_min' => array(1, 10000000),
		'waf_src_dbip_country_mb' => array(1, 1024),
		'waf_src_dbip_asn_min' => array(1, 10000000),
		'waf_src_dbip_asn_mb' => array(1, 1024),
		'waf_src_maxmind_country_min' => array(1, 10000000),
		'waf_src_maxmind_country_mb' => array(1, 1024),
		'waf_src_maxmind_asn_min' => array(1, 10000000),
		'waf_src_maxmind_asn_mb' => array(1, 1024),
		'waf_src_tor_min' => array(1, 10000000),
		'waf_src_tor_mb' => array(1, 1024),
		'waf_src_x4b_vpn_min' => array(1, 10000000),
		'waf_src_x4b_vpn_mb' => array(1, 1024),
		'waf_src_x4b_datacenter_min' => array(1, 10000000),
		'waf_src_x4b_datacenter_mb' => array(1, 1024),
		'waf_src_searchbots_min' => array(1, 10000000),
		'waf_src_searchbots_mb' => array(1, 1024),
		'waf_origin_bad_percent' => array(0, 50),
		'waf_origin_keep_percent' => array(0, 100),
		'waf_fetch_connect_seconds' => array(1, 120),
		'waf_fetch_timeout_seconds' => array(10, 3600),
		'waf_fetch_redirects' => array(0, 10),
		'waf_proxycheck_batch' => array(1, 1000),
		'waf_proxycheck_answer_mb' => array(1, 50),
		'waf_proxycheck_connect_seconds' => array(1, 60),
		'waf_proxycheck_timeout_seconds' => array(2, 300),
		'waf_proxycheck_retry_minutes' => array(5, 1440),
		'waf_proxycheck_tries' => array(1, 10),
		'waf_origin_lookup_batch' => array(1, 100000),
		'waf_cleanup_batch' => array(100, 100000),
		'waf_cleanup_rounds' => array(1, 1000),
		'waf_response_grace_minutes' => array(5, 10080),
		'waf_blocked_lines' => array(1, 1000000),
		'waf_hit_rules_max' => array(5, 500),
		'waf_show_paths' => array(10, 1000),
		'waf_preview_delay_ms' => array(50, 5000),
		'waf_cli_jobs' => array(5, 500),
		'waf_cli_wait_margin_minutes' => array(0, 60),
		'waf_guard_minute' => array(0, 59),
		'waf_hourly_minute' => array(0, 59),
		'waf_body_limit_kb' => array(1, 1048576),
		'waf_body_nofiles_limit_kb' => array(1, 1048576),
		'waf_watch_minutes' => array(1, 60),
		'waf_watch_stale_minutes' => array(5, 1440),
		'waf_watch_pending_minutes' => array(15, 10080),
		'waf_watch_overdue_hours' => array(1, 720),
		'waf_watch_remind_hours' => array(1, 720),
		'waf_watch_crash_pause' => array(1, 1440),
	);
}

if (!defined('WAF_LIST_MAX')) {
	/** The longest text a list of the settings holds: its column is varchar(1024). */
	define('WAF_LIST_MAX', 1024);
}
if (!defined('WAF_URL_LIST_MAX')) {
	/** The addresses of a source: their column is varchar(512), so the row of the settings keeps its room. */
	define('WAF_URL_LIST_MAX', 512);
}
if (!defined('WAF_ORIGIN_CHOICE_MAX')) {
	/** The chosen countries and providers: each column is varchar(255), so no more entries fit. */
	define('WAF_ORIGIN_CHOICE_MAX', 255);
}
if (!defined('WAF_URL_MAX')) {
	/** A single address of the settings: its column is varchar(255). */
	define('WAF_URL_MAX', 255);
}

/**
 * The settings that hold lists, and what each list holds: paths, cookie names,
 * networks, periods in days, addresses (urls) or a single address (url). They
 * are stored with commas and shown one entry per line.
 */
function waf_settings_lists()
{
	return array(
		'waf_ban_logged_in_paths' => 'paths',
		'waf_ban_full_paths' => 'paths',
		'waf_login_cookies' => 'cookies',
		'waf_own_networks' => 'networks',
		'waf_periods' => 'days',
		'waf_src_dbip_country_urls' => 'urls',
		'waf_src_dbip_asn_urls' => 'urls',
		'waf_src_maxmind_country_urls' => 'urls',
		'waf_src_maxmind_asn_urls' => 'urls',
		'waf_src_tor_urls' => 'urls',
		'waf_src_x4b_vpn_urls' => 'urls',
		'waf_src_x4b_datacenter_urls' => 'urls',
		'waf_src_searchbots_urls' => 'urls',
		'waf_proxycheck_url' => 'url',
	);
}

/** The entries of a stored or typed list: split at line breaks and commas, trimmed, without blanks and doubles. */
function waf_list_parse($text)
{
	$items = array();
	foreach (preg_split('/[\r\n,]+/', (string) $text) as $one) {
		$one = trim($one);
		if ($one !== '' && !in_array($one, $items, true)) {
			$items[] = $one;
		}
	}
	return $items;
}

/** A list as it is stored. */
function waf_list_join($items)
{
	return implode(',', $items);
}

/** A stored list for a text field, one entry per line. */
function waf_list_lines($text)
{
	return implode("\n", waf_list_parse($text));
}

/** The entries that are no path: whitespace or a comma inside. */
function waf_list_bad_paths($items)
{
	return array_values(array_filter($items, function ($one) {
		return !preg_match('/^[^\s,]+$/u', (string) $one);
	}));
}

/** The entries that are no beginning of a cookie name: letters, digits, dot, dash and underscore. */
function waf_list_bad_cookies($items)
{
	return array_values(array_filter($items, function ($one) {
		return !preg_match('/^[A-Za-z0-9_.-]+$/', (string) $one);
	}));
}

/** The entries that are no network: a range like 10.0.0.0/8 or 2001:db8::/32, or a single address. */
function waf_list_bad_networks($items)
{
	return array_values(array_filter($items, function ($one) {
		return waf_origin_cidr($one) === null;
	}));
}

/** The entries that are no period: whole days from 1 up to the longest keep of the day figures. */
function waf_list_bad_days($items)
{
	$limits = waf_settings_limits();
	$longest = $limits['waf_stats_days'][1];
	return array_values(array_filter($items, function ($one) use ($longest) {
		return !preg_match('/^[1-9][0-9]*$/', (string) $one) || (int) $one > $longest;
	}));
}

/** The entries that are no address to download from: https://, a host, no space. {month} may stand in it. */
function waf_list_bad_urls($items)
{
	return array_values(array_filter($items, function ($one) {
		return !preg_match('#^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:[/?][^\s]*)?$#', (string) $one);
	}));
}

/** How long a stored list of the kind may be: the length of its column. */
function waf_list_max($kind)
{
	if ($kind === 'urls') {
		return WAF_URL_LIST_MAX;
	}
	return $kind === 'url' ? WAF_URL_MAX : WAF_LIST_MAX;
}

/** true while the stored list fits into its column ($max, WAF_LIST_MAX without). */
function waf_list_fits($items, $max = null)
{
	return strlen(waf_list_join($items)) <= ($max === null ? WAF_LIST_MAX : (int) $max);
}

/** How the server downloads the lists of the sources (curl): connect, whole download, redirects. */
function waf_fetch_options($settings)
{
	return array(
		'connect' => (int) $settings['waf_fetch_connect_seconds'],
		'timeout' => (int) $settings['waf_fetch_timeout_seconds'],
		'redirects' => (int) $settings['waf_fetch_redirects'],
	);
}

/** How the server asks proxycheck.io: connect, whole answer, largest answer in bytes. */
function waf_proxycheck_options($settings)
{
	return array(
		'connect' => (int) $settings['waf_proxycheck_connect_seconds'],
		'timeout' => (int) $settings['waf_proxycheck_timeout_seconds'],
		'bytes' => (int) $settings['waf_proxycheck_answer_mb'] * 1024 * 1024,
	);
}

/** The address of proxycheck.io from the settings with the key as its last parameter. */
function waf_proxycheck_address($url, $key)
{
	$url = (string) $url;
	return $url . (strpos($url, '?') === false ? '?' : '&') . 'key=' . rawurlencode((string) $key);
}

// --- Places and names on the server -------------------------------------------

if (!defined('WAF_PATH_MAX')) {
	/** A place of the settings: its column is varchar(255). */
	define('WAF_PATH_MAX', 255);
}
if (!defined('WAF_NAME_MAX')) {
	/** A name of the settings: its column is varchar(64). */
	define('WAF_NAME_MAX', 64);
}

/**
 * The places and names of the Abwehr on the server, in the order the panel and
 * waf-switch paths show them. waf/install.sh lays them out and changes them;
 * the panel shows them only. The kind says what a value must be:
 *   file     an absolute path of a file
 *   dir      an absolute path of a directory
 *   pattern  an absolute path that may hold * (a glob)
 *   program  the path of a program, or empty: the runs then start directly
 *   dirs     directories, stored with commas
 *   name     a name for systemd or healthchecks
 */
function waf_path_settings()
{
	return array(
		'waf_conf_dir' => array('kind' => 'dir', 'group' => 'nginx'),
		'waf_rules_include' => array('kind' => 'file', 'group' => 'nginx'),
		'waf_blocked_include' => array('kind' => 'file', 'group' => 'nginx'),
		'waf_nginx_service' => array('kind' => 'name', 'group' => 'nginx'),
		'waf_modsec_base' => array('kind' => 'file', 'group' => 'modsec'),
		'waf_crs_setup' => array('kind' => 'file', 'group' => 'modsec'),
		'waf_crs_rules' => array('kind' => 'pattern', 'group' => 'modsec'),
		'waf_rules_check' => array('kind' => 'pattern', 'group' => 'modsec'),
		'waf_cache_dir' => array('kind' => 'dir', 'group' => 'modsec'),
		'waf_audit_log' => array('kind' => 'file', 'group' => 'logs'),
		'waf_blocked_log' => array('kind' => 'file', 'group' => 'logs'),
		'waf_guard_log' => array('kind' => 'file', 'group' => 'logs'),
		'waf_backup_dir' => array('kind' => 'dir', 'group' => 'logs'),
		'waf_logrotate_file' => array('kind' => 'file', 'group' => 'logs'),
		'waf_tools_dir' => array('kind' => 'dir', 'group' => 'tools'),
		'waf_cron_file' => array('kind' => 'file', 'group' => 'tools'),
		'waf_hc_run' => array('kind' => 'program', 'group' => 'tools'),
		'waf_hc_tick_name' => array('kind' => 'name', 'group' => 'tools'),
		'waf_hc_guard_name' => array('kind' => 'name', 'group' => 'tools'),
		'waf_hc_watch_name' => array('kind' => 'name', 'group' => 'tools'),
		'waf_bin_dirs' => array('kind' => 'dirs', 'group' => 'tools'),
	);
}

/** The variable of the environment that changes a place for waf/install.sh: MALWATCH_WAF_CONF_DIR for waf_conf_dir. */
function waf_path_env($key)
{
	return 'MALWATCH_' . strtoupper((string) $key);
}

/** Variables of the form MALWATCH_WAF_* that belong to the tools themselves. */
function waf_path_env_other()
{
	return array('MALWATCH_WAF_LIB');
}

/**
 * A place or name checked for its kind: array(value, problem). The value comes
 * back normalized: double slashes once, a directory without its closing slash,
 * directories joined with commas. The problem is '' or a word the command line
 * and the panel turn into a sentence: empty, relative, chars, dots, root,
 * trailing, long, name.
 */
function waf_path_check($kind, $value)
{
	$value = trim((string) $value);
	if ($kind === 'dirs') {
		$dirs = array();
		foreach (waf_list_parse($value) as $one) {
			$check = waf_path_check('dir', $one);
			if ($check[1] !== '') {
				return array($value, $check[1]);
			}
			if (!in_array($check[0], $dirs, true)) {
				$dirs[] = $check[0];
			}
		}
		if (count($dirs) === 0) {
			return array('', 'empty');
		}
		$joined = waf_list_join($dirs);
		return strlen($joined) > WAF_LIST_MAX ? array($value, 'long') : array($joined, '');
	}
	if ($kind === 'name') {
		if ($value === '') {
			return array('', 'empty');
		}
		return strlen($value) <= WAF_NAME_MAX && preg_match('/^[A-Za-z0-9][A-Za-z0-9@._-]*$/', $value)
			? array($value, '') : array($value, 'name');
	}
	if ($value === '') {
		return array('', $kind === 'program' ? '' : 'empty');
	}
	if ($value[0] !== '/') {
		return array($value, 'relative');
	}
	if (!preg_match($kind === 'pattern' ? '#^[A-Za-z0-9._/*-]+$#' : '#^[A-Za-z0-9._/-]+$#', $value)) {
		return array($value, 'chars');
	}
	$value = preg_replace('#/+#', '/', $value);
	if (preg_match('#(?:^|/)\.\.?(?:/|$)#', $value)) {
		return array($value, 'dots');
	}
	if ($kind === 'dir') {
		$value = rtrim($value, '/');
		if ($value === '') {
			return array('/', 'root');
		}
	} elseif (substr($value, -1) === '/') {
		return array($value, 'trailing');
	}
	return strlen($value) > WAF_PATH_MAX ? array($value, 'long') : array($value, '');
}

/**
 * Places that would share a file or a directory: each is a problem of the later
 * one in the catalog, array(problem, key, name, value, other). Two logs in one
 * file break both readers; two includes in one file load one of them twice.
 */
function waf_path_conflicts($values)
{
	$seen = array('file' => array(), 'dir' => array());
	$problems = array();
	foreach (waf_path_settings() as $key => $entry) {
		$class = in_array($entry['kind'], array('file', 'program'), true) ? 'file'
			: ($entry['kind'] === 'dir' ? 'dir' : '');
		$value = isset($values[$key]) ? (string) $values[$key] : '';
		if ($class === '' || $value === '') {
			continue;
		}
		if (isset($seen[$class][$value])) {
			$problems[] = array('problem' => 'same_' . $class, 'key' => $key, 'name' => waf_path_env($key),
				'value' => $value, 'other' => $seen[$class][$value]);
			continue;
		}
		$seen[$class][$value] = $key;
	}
	return $problems;
}

/**
 * The places with the changes waf/install.sh hands over through the environment
 * (see waf_path_env()). Returns values, the keys that changed and the
 * problems, each array(problem, key, name, value, other). A variable of that
 * form that names no place is a problem as well, so a typing error never goes
 * unnoticed: 'panel' when it names a setting of the panel, 'unknown' else. A
 * refused value keeps the stored one.
 */
function waf_path_overlay($settings, $env)
{
	$catalog = waf_path_settings();
	$defaults = waf_settings_defaults();
	$values = array();
	foreach ($catalog as $key => $entry) {
		$values[$key] = (string) $settings[$key];
	}
	$problems = array();
	foreach ($env as $name => $value) {
		$name = (string) $name;
		if (strpos($name, 'MALWATCH_WAF_') !== 0 || in_array($name, waf_path_env_other(), true)) {
			continue;
		}
		$key = strtolower(substr($name, strlen('MALWATCH_')));
		if (!isset($catalog[$key])) {
			$problems[] = array('problem' => array_key_exists($key, $defaults) ? 'panel' : 'unknown', 'key' => $key,
				'name' => $name, 'value' => (string) $value, 'other' => '');
			continue;
		}
		$check = waf_path_check($catalog[$key]['kind'], $value);
		if ($check[1] !== '') {
			$problems[] = array('problem' => $check[1], 'key' => $key, 'name' => $name, 'value' => (string) $value,
				'other' => '');
			continue;
		}
		$values[$key] = $check[0];
	}
	$problems = array_merge($problems, waf_path_conflicts($values));
	$changed = array();
	foreach ($values as $key => $value) {
		if ($value !== (string) $settings[$key]) {
			$changed[] = $key;
		}
	}
	return array('values' => $values, 'changed' => $changed, 'problems' => $problems);
}

/** One German sentence for a problem of waf_path_overlay(): what is wrong and what to do. waf-switch prints it. */
function waf_path_problem_text($problem)
{
	$catalog = waf_path_settings();
	$defaults = waf_settings_defaults();
	$key = (string) $problem['key'];
	$example = isset($defaults[$key]) ? (string) $defaults[$key] : '';
	$chars = 'A-Z, a-z, 0-9 und . _ / -' . (isset($catalog[$key]) && $catalog[$key]['kind'] === 'pattern' ? ' *' : '');
	$texts = array(
		'empty' => '%1$s ist leer. Bitte einen Wert angeben; die Vorgabe ist %3$s.',
		'relative' => '%1$s=%2$s ist kein absoluter Pfad. Bitte mit / beginnen, etwa %3$s.',
		'chars' => '%1$s=%2$s enthält Zeichen außerhalb von %4$s. Bitte einen Pfad aus diesen Zeichen wählen.',
		'dots' => '%1$s=%2$s enthält . oder .. als Ordner. Bitte den Pfad direkt angeben, etwa %3$s.',
		'root' => '%1$s=%2$s: Das Wurzelverzeichnis ist für die Abwehr zu allgemein. Bitte ein eigenes Verzeichnis angeben, etwa %3$s.',
		'trailing' => '%1$s=%2$s endet mit /. Eine Datei braucht einen Namen, etwa %3$s.',
		'long' => '%1$s=%2$s ist länger, als die Einstellung aufnimmt (Pfade bis ' . WAF_PATH_MAX
			. ' Zeichen, Verzeichnislisten bis ' . WAF_LIST_MAX . '). Bitte kürzer wählen.',
		'name' => '%1$s=%2$s ist kein gültiger Name. Erlaubt sind Buchstaben, Ziffern und . _ @ - bis ' . WAF_NAME_MAX
			. ' Zeichen, etwa %3$s.',
		'same_file' => '%1$s=%2$s: Diese Datei nutzt schon %5$s. Jede Datei der Abwehr braucht einen eigenen Pfad.',
		'same_dir' => '%1$s=%2$s: Dieses Verzeichnis nutzt schon %5$s. Bitte ein eigenes Verzeichnis angeben.',
		'panel' => '%1$s gehört zu den Einstellungen im Panel und ändert sich unter Abwehr > Einstellungen.',
		'unknown' => '%1$s ist keine Einstellung der Abwehr. waf-switch paths zeigt alle Variablen.',
	);
	$text = isset($texts[$problem['problem']]) ? $texts[$problem['problem']] : '%1$s=%2$s wird abgelehnt (%6$s).';
	return sprintf($text, $problem['name'], $problem['value'], $example, $chars,
		$problem['other'] !== '' ? waf_path_env($problem['other']) : '', $problem['problem']);
}

/** A value for the shell in single quotes; a quote inside becomes '\''. */
function waf_shell_quote($value)
{
	return "'" . str_replace("'", "'\\''", (string) $value) . "'";
}

/**
 * The places for waf/install.sh as lines of the shell: each place as NAME with
 * the wanted value and OLD_NAME with the stored one, then the program
 * directories as a PATH, the places that move, the lock file and the number
 * of websites whose field carries a block of the Abwehr.
 */
function waf_path_shell_text($stored, $overlay, $lock_file, $sites)
{
	$settings = array_merge($stored, $overlay['values']);
	$text = '';
	foreach (waf_path_settings() as $key => $entry) {
		$name = strtoupper($key);
		$text .= $name . '=' . waf_shell_quote($settings[$key]) . "\n"
			. 'OLD_' . $name . '=' . waf_shell_quote($stored[$key]) . "\n";
	}
	return $text
		. 'WAF_BIN_PATH=' . waf_shell_quote(implode(':', waf_list_parse($settings['waf_bin_dirs']))) . "\n"
		. 'WAF_CHANGED=' . waf_shell_quote(implode(' ', $overlay['changed'])) . "\n"
		. 'WAF_LOCK=' . waf_shell_quote($lock_file) . "\n"
		. 'WAF_SITES=' . (int) $sites . "\n";
}

/** The text of a file that follows the places, by the name waf-switch paths render takes; null for another name. */
function waf_path_render_text($file, $settings)
{
	switch ((string) $file) {
		case 'main.conf':
			return waf_main_conf_text($settings);
		case 'settings.conf':
			return waf_settings_conf_text($settings);
		case 'rules-include':
			return waf_rules_include_text($settings);
		case 'blocked-include':
			return waf_blocked_include_text($settings);
		case 'logrotate':
			return waf_logrotate_text($settings['waf_log_keep_days'], $settings['waf_audit_log'], $settings['waf_blocked_log']);
		case 'cron':
			return waf_cron_text($settings);
	}
	return null;
}

/**
 * The WAF settings from a malwatch_config row. A column an older schema lacks,
 * or an empty value, takes its default; numbers stay within their limits;
 * places and names pass waf_path_check() or take their default.
 */
function waf_settings($row)
{
	$row = is_array($row) ? $row : array();
	$defaults = waf_settings_defaults();
	$settings = array();
	$lists = waf_settings_lists();
	$places = waf_path_settings();
	foreach ($defaults as $key => $default) {
		$value = isset($row[$key]) ? $row[$key] : null;
		// An emptied list is a choice of the operator, and so is an empty hc-run;
		// a missing column takes the default.
		$empty_ok = isset($lists[$key]) || (isset($places[$key]) && $places[$key]['kind'] === 'program');
		$missing = $value === null || ($value === '' && !$empty_ok);
		$settings[$key] = $missing ? $default : $value;
	}
	foreach (waf_settings_limits() as $key => $limit) {
		$settings[$key] = max($limit[0], min($limit[1], (int) $settings[$key]));
	}
	if (!waf_response_body_valid($settings['waf_response_body'])) {
		$settings['waf_response_body'] = $defaults['waf_response_body'];
	}
	$settings['waf_emergency'] = $settings['waf_emergency'] === 'y' ? 'y' : 'n';
	foreach ($places as $key => $entry) {
		$check = waf_path_check($entry['kind'], $settings[$key]);
		$settings[$key] = $check[1] === '' ? $check[0] : $defaults[$key];
	}
	if (!in_array((string) $settings['waf_body_limit_action'], waf_body_limit_actions(), true)) {
		$settings['waf_body_limit_action'] = $defaults['waf_body_limit_action'];
	}
	foreach (waf_origin_choices() as $key => $values) {
		if (!in_array($settings[$key], $values, true)) {
			$settings[$key] = $defaults[$key];
		}
	}
	// The account is digits, the licence key letters, digits and underscores;
	// MaxMind hands out nothing else, and both go into a URL.
	$settings['waf_origin_maxmind_account'] = preg_match('/^\d{0,32}$/', (string) $settings['waf_origin_maxmind_account'])
		? (string) $settings['waf_origin_maxmind_account'] : '';
	$settings['waf_origin_maxmind_key'] = preg_match('/^[A-Za-z0-9_]{0,128}$/', (string) $settings['waf_origin_maxmind_key'])
		? (string) $settings['waf_origin_maxmind_key'] : '';
	// proxycheck.io hands out keys of letters, digits and hyphens; the key
	// travels in the address of the request.
	$settings['waf_origin_proxycheck_key'] = preg_match('/^[A-Za-z0-9-]{0,128}$/', (string) $settings['waf_origin_proxycheck_key'])
		? (string) $settings['waf_origin_proxycheck_key'] : '';
	if (!in_array($settings['waf_ban_mode'], waf_ban_modes(), true)) {
		$settings['waf_ban_mode'] = $defaults['waf_ban_mode'];
	}
	$settings['waf_ban_bots'] = $settings['waf_ban_bots'] === 'off' ? 'off' : 'on';
	$settings['waf_f2b'] = $settings['waf_f2b'] === 'off' ? 'off' : 'on';
	if (!in_array((string) $settings['waf_everywhere_mode'], waf_f2b_modes(), true)) {
		$settings['waf_everywhere_mode'] = $defaults['waf_everywhere_mode'];
	}
	if (!waf_f2b_jail_ok($settings['waf_everywhere_jail'])) {
		$settings['waf_everywhere_jail'] = $defaults['waf_everywhere_jail'];
	}
	return $settings;
}

// --- Decisions ---------------------------------------------------------------

/**
 * When a website that detects since $since may enforce. Both are wall-clock
 * times from the database; the arithmetic runs in UTC so a clock change never
 * moves the result. '' without a date.
 */
function waf_enforce_free_from($since, $min_days)
{
	$since = (string) $since;
	if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $since) || $since === '0000-00-00 00:00:00') {
		return '';
	}
	$date = DateTime::createFromFormat('Y-m-d H:i:s', $since, new DateTimeZone('UTC'));
	if ($date === false) {
		return '';
	}
	$date->modify('+' . max(0, (int) $min_days) . ' days');
	return $date->format('Y-m-d H:i:s');
}

/** Why a website may not be switched to enforce now; '' when it may. */
function waf_enforce_block_reason($state, $since, $now, $min_days, $emergency)
{
	if ($emergency === 'y') {
		return 'emergency';
	}
	if ($state === 'enforce') {
		return '';
	}
	if ($state !== 'detect') {
		return 'not_detect';
	}
	$free = waf_enforce_free_from($since, $min_days);
	if ($free === '' || strcmp((string) $now, $free) < 0) {
		return 'too_early';
	}
	return '';
}

/**
 * The periods the overview offers, in days, shortest first: the list
 * waf_periods within the time the day figures are kept (waf_stats_days).
 * Without one inside that time the overview offers the time itself.
 */
function waf_periods($settings)
{
	$keep = max(1, (int) $settings['waf_stats_days']);
	$periods = array();
	foreach (waf_list_parse($settings['waf_periods']) as $one) {
		$days = (int) $one;
		if ((string) $days === $one && $days >= 1 && $days <= $keep && !in_array($days, $periods, true)) {
			$periods[] = $days;
		}
	}
	sort($periods);
	return count($periods) > 0 ? $periods : array($keep);
}

/** The period asked for if the overview offers it, else waf_period_default, else the longest one offered. */
function waf_period($requested, $settings)
{
	$periods = waf_periods($settings);
	if (is_scalar($requested) && in_array((int) $requested, $periods, true)) {
		return (int) $requested;
	}
	$default = (int) $settings['waf_period_default'];
	return in_array($default, $periods, true) ? $default : $periods[count($periods) - 1];
}

/** Content of the logrotate file (waf_logrotate_file). copytruncate keeps the file ModSecurity holds open. */
function waf_logrotate_text($keep_days, $audit_log, $blocked_log)
{
	return "# Managed by malwatch (Abwehr > Einstellungen). Every change here is overwritten.\n"
		. $audit_log . " {\n"
		. "\tdaily\n"
		. "\trotate " . max(1, (int) $keep_days) . "\n"
		. "\tcompress\n"
		. "\tdelaycompress\n"
		. "\tmissingok\n"
		. "\tnotifempty\n"
		. "\tcopytruncate\n"
		. "}\n"
		. "\n"
		. $blocked_log . " {\n"
		. "\tdaily\n"
		. "\trotate " . max(1, (int) $keep_days) . "\n"
		. "\tcompress\n"
		. "\tdelaycompress\n"
		. "\tmissingok\n"
		. "\tnotifempty\n"
		. "\tcopytruncate\n"
		. "\tcreate 640 www-data adm\n"
		. "}\n";
}

/**
 * Content of main.conf in the rules directory: the base of ModSecurity, the
 * own settings, the CRS with the exclusions around its rules, the answer of
 * the page and the emergency switch last.
 */
function waf_main_conf_text($settings)
{
	$dir = $settings['waf_conf_dir'];
	$lines = array(
		$settings['waf_modsec_base'],
		$dir . '/settings.conf',
		$settings['waf_crs_setup'],
		$dir . '/crs-extra.conf',
		$dir . '/exclusions-before.conf',
		$dir . '/exclusions-panel-before.conf',
		$settings['waf_crs_rules'],
		$dir . '/exclusions-after.conf',
		$dir . '/exclusions-panel-after.conf',
		$dir . '/response-body.conf',
		$dir . '/state.conf',
	);
	return 'Include ' . implode("\nInclude ", $lines) . "\n";
}

/**
 * Content of settings.conf in the rules directory. The engine only detects
 * here; a website that enforces switches it on in its vhost. The audit log
 * holds the hits as JSON in the parts the evaluation reads. Without files a
 * body never gets more room than a body with files.
 */
function waf_settings_conf_text($settings)
{
	$all = (int) $settings['waf_body_limit_kb'] * 1024;
	$plain = min($all, (int) $settings['waf_body_nofiles_limit_kb'] * 1024);
	return "SecRuleEngine DetectionOnly\n"
		. "SecRequestBodyAccess On\n"
		. 'SecRequestBodyLimit ' . $all . "\n"
		. 'SecRequestBodyNoFilesLimit ' . $plain . "\n"
		. 'SecRequestBodyLimitAction ' . $settings['waf_body_limit_action'] . "\n"
		. "SecResponseBodyAccess Off\n"
		. "SecAuditEngine RelevantOnly\n"
		. 'SecAuditLogRelevantStatus "^$"' . "\n"
		. "SecAuditLogParts ABCFHZ\n"
		. "SecAuditLogType Serial\n"
		. 'SecAuditLog ' . $settings['waf_audit_log'] . "\n"
		. "SecAuditLogFormat JSON\n"
		. "SecAuditLogFileMode 0600\n"
		. "SecAuditLogDirMode 0750\n"
		. 'SecTmpDir ' . $settings['waf_cache_dir'] . "\n"
		. 'SecDataDir ' . $settings['waf_cache_dir'] . "\n"
		. "SecDebugLogLevel 0\n"
		. "SecStatusEngine Off\n";
}

/** Content of the include of the rules (waf_rules_include). */
function waf_rules_include_text($settings)
{
	return "# Loads the rules once for every server block; each website switches them on in its vhost.\n"
		. 'modsecurity_rules_file ' . $settings['waf_conf_dir'] . "/main.conf;\n";
}

/**
 * Content of the include of the block list (waf_blocked_include): the list
 * malwatch writes, and format and condition of the second access log.
 */
function waf_blocked_include_text($settings)
{
	return "# Managed by malwatch. Bindet die Sperrliste ein, die malwatch schreibt, und\n"
		. "# legt Format und Bedingung für das zweite Zugriffslog fest, aus dem der Cron\n"
		. "# die abgewehrten Versuche zählt. Diese Datei selbst wird nicht überschrieben.\n"
		. 'include ' . $settings['waf_conf_dir'] . "/blocked.conf;\n"
		. "\n"
		. "map \$status \$mw_denied {\n"
		. "\t403     1;\n"
		. "\tdefault 0;\n"
		. "}\n"
		. "\n"
		. "log_format mw_block '\$time_iso8601 \$remote_addr \$status \$host \"\$request\"';\n";
}

/**
 * Content of the cron file of the Abwehr (waf_cron_file): the minute clock and
 * the hourly guard, apart from the cron of ISPConfig. With hc-run each run
 * reports to healthchecks under its name; without it the runs start directly.
 */
function waf_cron_text($settings)
{
	$hc = (string) $settings['waf_hc_run'];
	$run = function ($name, $command) use ($hc) {
		return $hc === '' ? $command
			: 'if [ -x ' . $hc . ' ]; then ' . $hc . ' ' . $name . ' -- ' . $command . '; else ' . $command . '; fi';
	};
	$tools = $settings['waf_tools_dir'];
	$text = "# Managed by malwatch (waf/install.sh, Abwehr > Einstellungen). Every change here is overwritten.\n"
		. "# The minute clock of the Abwehr and its hourly guard, apart from the cron of\n"
		. "# ISPConfig: that one runs all its jobs one after another under one lock, and a\n"
		. "# long run - AWStats at night - held the Abwehr up for half an hour.\n"
		. "# The watch over the scanner checks the cron job of malwatch in ISPConfig from\n"
		. "# here, so it also notices when the cron of ISPConfig itself stands.\n";
	if ($hc !== '') {
		$text .= "# hc-run reports each run to healthchecks once its address stands in\n"
			. '# /etc/hc-run.d/' . $settings['waf_hc_tick_name'] . '.url, /etc/hc-run.d/'
			. $settings['waf_hc_guard_name'] . ".url and\n"
			. '# /etc/hc-run.d/' . $settings['waf_hc_watch_name'] . ".url.\n";
	}
	$every = (int) $settings['waf_watch_minutes'];
	return $text
		. "SHELL=/bin/sh\n"
		. 'PATH=' . implode(':', waf_list_parse($settings['waf_bin_dirs'])) . "\n"
		. '* * * * * root ' . $run($settings['waf_hc_tick_name'], $tools . '/waf-switch tick') . " > /dev/null 2>&1\n"
		. (int) $settings['waf_guard_minute'] . ' * * * * root '
		. $run($settings['waf_hc_guard_name'], $tools . '/waf-guard') . " > /dev/null 2>&1\n"
		. ($every <= 1 ? '*' : '*/' . $every) . ' * * * * root '
		. $run($settings['waf_hc_watch_name'], $tools . '/waf-switch watch') . " > /dev/null 2>&1\n";
}

if (!defined('WAF_WATCH_EXAMPLES')) {
	/** How many late websites a message of the watch names; the rest it counts. */
	define('WAF_WATCH_EXAMPLES', 3);
}

/** A point in time in the messages of the watch, in the clock of the server. */
function waf_watch_time($time)
{
	return date('d.m.Y H:i', (int) $time);
}

/** How long a scan schedule waits between two runs, as malwatch_helper::next_run() plans them; 0 for off. */
function waf_watch_schedule_seconds($schedule)
{
	switch ((string) $schedule) {
		case 'daily':
			return 86400;
		case 'weekly':
			return 7 * 86400;
		case 'monthly':
			return 30 * 86400;
	}
	return 0;
}

/**
 * What the watch over the scanner (waf-switch watch, from 0.36.0) makes of the
 * state it read. $facts:
 *
 *   now          Unix time
 *   cron         running, last_run, next_run of cronjob_malwatch in sys_cron
 *                (Unix times), or null without a row
 *   cron_alive   a cron.php of ISPConfig holds its lock right now
 *   crash        time, text, pause_until the guard of 560-malwatch left after a
 *                crash no catch reached, or null
 *   crash_new    the watch has not reported that crash yet; a crash counts
 *                as a problem while it is new or its pause lasts, so the
 *                all-clear waits for the first run after the pause
 *   pending      count and oldest (Unix time or null) of the waiting jobs
 *   sites        domain, schedule, last_run of the active websites
 *
 * Returns release (clear the running flag), the kinds and the problems in a
 * fixed order, and the lines waf-switch prints: the problems, or one line that
 * says all is well.
 */
function waf_watch_assess(array $facts, array $settings)
{
	$now = (int) $facts['now'];
	$stale = (int) $settings['waf_watch_stale_minutes'] * 60;
	$kinds = array();
	$problems = array();
	$release = false;

	$cron = isset($facts['cron']) && is_array($facts['cron']) ? $facts['cron'] : null;
	$last = null;
	if ($cron === null) {
		$kinds[] = 'no_row';
		$problems[] = 'ISPConfig kennt den Cron-Job von malwatch nicht, sys_cron hat keine Zeile dafür. '
			. 'Bitte das Paket von malwatch erneut einspielen.';
	} else {
		$last = $cron['last_run'] === null ? null : (int) $cron['last_run'];
		$next = $cron['next_run'] === null ? null : (int) $cron['next_run'];
		if (!empty($cron['running']) && $last !== null && $now - $last >= $stale) {
			if (empty($facts['cron_alive'])) {
				$release = true;
				$kinds[] = 'stale';
				$problems[] = 'Der Cron-Job von malwatch galt seit ' . waf_watch_time($last) . ' als laufend, obwohl der '
					. 'Cron von ISPConfig nicht mehr lief. Die Wache hat die Sperre gelöst, damit der Job wieder startet.';
			} else {
				$kinds[] = 'busy';
				$problems[] = 'Der Cron-Job von malwatch läuft seit ' . waf_watch_time($last) . '. Die Wache wartet, '
					. 'solange der Cron von ISPConfig noch arbeitet.';
			}
		} elseif (empty($cron['running']) && $last !== null && $now - $last >= $stale && ($next === null || $next <= $now)) {
			$kinds[] = 'silent';
			$problems[] = 'Der Cron-Job von malwatch lief zuletzt ' . waf_watch_time($last) . '. Bitte prüfen, ob der Cron '
				. 'von ISPConfig (cron.sh in der crontab von root) läuft.';
		}
	}

	$crash = isset($facts['crash']) && is_array($facts['crash']) ? $facts['crash'] : null;
	if ($crash !== null && (!empty($facts['crash_new']) || (int) $crash['pause_until'] > $now)) {
		$kinds[] = 'crash';
		$text = 'Der Cron-Job von malwatch ist ' . waf_watch_time((int) $crash['time']) . ' abgestürzt: '
			. rtrim((string) $crash['text'], '. ') . '.';
		if (!empty($crash['pause_until']) && (int) $crash['pause_until'] > $now) {
			$text .= ' Er pausiert bis ' . waf_watch_time((int) $crash['pause_until']) . ' und startet dann neu.';
		}
		$problems[] = $text;
	}

	$pending = isset($facts['pending']) && is_array($facts['pending']) ? $facts['pending'] : array();
	$count = isset($pending['count']) ? (int) $pending['count'] : 0;
	$oldest = isset($pending['oldest']) && $pending['oldest'] !== null ? (int) $pending['oldest'] : null;
	if ($oldest !== null && $now - $oldest >= (int) $settings['waf_watch_pending_minutes'] * 60) {
		$kinds[] = 'pending';
		$problems[] = ($count === 1 ? '1 Auftrag wartet seit ' : $count . ' Aufträge warten, der älteste seit ')
			. waf_watch_time($oldest) . '. Bitte unter Security > Scanner nachsehen, ob ein Lauf hängt.';
	}

	$grace = (int) $settings['waf_watch_overdue_hours'] * 3600;
	$late = array();
	foreach (isset($facts['sites']) && is_array($facts['sites']) ? $facts['sites'] : array() as $site) {
		$interval = waf_watch_schedule_seconds($site['schedule']);
		if ($interval === 0 || $site['last_run'] === null) {
			continue;
		}
		if ($now - (int) $site['last_run'] >= $interval + $grace) {
			$late[] = $site;
		}
	}
	if (count($late) > 0) {
		$kinds[] = 'overdue';
		$shown = array();
		foreach (array_slice($late, 0, WAF_WATCH_EXAMPLES) as $site) {
			$shown[] = $site['domain'] . ' (zuletzt ' . waf_watch_time((int) $site['last_run']) . ')';
		}
		$problems[] = (count($late) === 1 ? '1 Website wurde' : count($late) . ' Websites wurden')
			. ' länger nicht geprüft als geplant: ' . implode(', ', $shown)
			. (count($late) > count($shown) ? ' und weitere' : '') . '.';
	}

	if (count($problems) > 0) {
		$lines = $problems;
	} else {
		$lines = array('Alles in Ordnung: Der Cron-Job lief zuletzt ' . ($last === null ? 'noch nie' : waf_watch_time($last))
			. ', ' . ($count === 1 ? '1 Auftrag wartet' : $count . ' Aufträge warten') . '.');
	}
	return array('release' => $release, 'kinds' => $kinds, 'problems' => $problems, 'lines' => $lines);
}

/**
 * Whether the watch writes a mail now: 'problem' for a kind it has not
 * mailed yet or when waf_watch_remind_hours passed since the last mail,
 * 'clear' when the problems it mailed are gone, '' otherwise. $state holds
 * the kinds of the last run and mailed_at.
 */
function waf_watch_mail_due(array $state, array $kinds, $now, array $settings)
{
	$before = isset($state['kinds']) && is_array($state['kinds']) ? $state['kinds'] : array();
	if (count($kinds) === 0) {
		return count($before) > 0 ? 'clear' : '';
	}
	if (count(array_diff($kinds, $before)) > 0) {
		return 'problem';
	}
	$mailed = isset($state['mailed_at']) ? (int) $state['mailed_at'] : 0;
	return (int) $now - $mailed >= (int) $settings['waf_watch_remind_hours'] * 3600 ? 'problem' : '';
}

/** Subject and body of the mail about the problems the watch found since $since. */
function waf_watch_mail_text(array $problems, $host, $since)
{
	$count = count($problems);
	return array(
		'subject' => 'malwatch auf ' . $host . ': ' . ($count === 1 ? '1 Problem' : $count . ' Probleme') . ' mit dem Scanner',
		'body' => 'Die Wache von malwatch meldet seit ' . waf_watch_time($since) . ":\n\n- " . implode("\n- ", $problems)
			. "\n\nDie Wache prüft weiter und schreibt wieder, sobald alles in Ordnung ist. Ihre Einstellungen stehen unter "
			. "Abwehr > Einstellungen > Takt und Hintergrund.\n",
	);
}

/** Subject and body of the mail that the problems since $since are gone. */
function waf_watch_clear_text($host, $since)
{
	return array(
		'subject' => 'malwatch auf ' . $host . ': Scanner wieder in Ordnung',
		'body' => 'Die Probleme, die die Wache seit ' . waf_watch_time($since) . " gemeldet hat, bestehen nicht mehr.\n",
	);
}

/**
 * What a job does with one website when it starts. $web is the web_domain
 * row (domain_id, domain, type, server_id, nginx_directives) or null, $site
 * the malwatch_site row or null, $vhost_state what the vhost file shows now.
 * $mode 'keep' rewrites the marker and keeps the state the field names.
 * action: skip (reason says why), confirm (field and vhost already match),
 * wait (field matches, vhost not yet), write (store text in the field).
 */
function waf_site_plan($web, $site, $target, $mode, $server_id, $vhost_state, $now, $settings)
{
	$result = array('action' => 'skip', 'reason' => '', 'text' => '', 'target' => (string) $target);
	if (!is_array($web) || (string) $web['type'] !== 'vhost') {
		$result['reason'] = 'not_found';
		return $result;
	}
	if ((int) $web['server_id'] !== (int) $server_id) {
		$result['reason'] = 'other_server';
		return $result;
	}
	$old = (string) $web['nginx_directives'];
	if ($mode === 'keep') {
		$result['target'] = waf_block_state($old);
	}
	if (!waf_state_valid($result['target'])) {
		$result['reason'] = 'state';
		return $result;
	}
	if ($mode !== 'keep' && $result['target'] === 'enforce') {
		$state = is_array($site) ? (string) $site['waf_state'] : 'off';
		$since = is_array($site) ? $site['waf_state_since'] : null;
		$reason = waf_enforce_block_reason($state, $since, $now, $settings['waf_min_detect_days'], $settings['waf_emergency']);
		if ($reason !== '') {
			$result['reason'] = $reason;
			return $result;
		}
	}
	// The second access log only belongs into the vhost when nginx knows its
	// format; the caller hands over its path in waf_ban_log, or ''.
	$new = waf_block_set($old, $result['target'], isset($settings['waf_ban_log']) ? (string) $settings['waf_ban_log'] : '');
	if ($new !== $old) {
		$result['action'] = 'write';
		$result['text'] = $new;
		return $result;
	}
	$result['action'] = $vhost_state === $result['target'] ? 'confirm' : 'wait';
	$result['text'] = $old;
	return $result;
}

/**
 * Where a waiting website stands in a later pass. $rejected: ISPConfig left
 * a fresh .err next to the vhost; $overdue: the job ran past its deadline.
 */
function waf_site_progress($entry, $vhost_state, $rejected, $overdue)
{
	if ($rejected) {
		return 'failed:rejected';
	}
	if ($vhost_state === $entry['target']) {
		return 'confirmed';
	}
	return $overdue ? 'failed:deadline' : 'waiting';
}

/** A failed website gets its old field back only while the field still holds what the job wrote. */
function waf_rollback_allowed($current_text, $written_hash)
{
	return hash_equals((string) $written_hash, sha1((string) $current_text));
}

// --- Files -------------------------------------------------------------------

/** The .conf files of a directory, sorted; an empty list when there is none. */
function waf_conf_files($dir)
{
	$files = glob(rtrim($dir, '/') . '/*.conf');
	if (!is_array($files)) {
		return array();
	}
	sort($files);
	return $files;
}

/** Writes through a temporary file and rename, mode 0644. */
function waf_write_atomic($file, $text)
{
	$tmp = $file . '.new';
	if (@file_put_contents($tmp, $text) === false) {
		return false;
	}
	@chmod($tmp, 0644);
	if (!@rename($tmp, $file)) {
		@unlink($tmp);
		return false;
	}
	return true;
}

/** Removes a directory tree. Links are removed, never followed. */
function waf_remove_dir($dir)
{
	if (is_link($dir)) {
		@unlink($dir);
		return;
	}
	if (!is_dir($dir)) {
		return;
	}
	$items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::CHILD_FIRST);
	foreach ($items as $item) {
		if ($item->isLink() || !$item->isDir()) {
			@unlink($item->getPathname());
		} else {
			@rmdir($item->getPathname());
		}
	}
	@rmdir($dir);
}

/** Copies every .conf of $dir into $target, which is emptied first. */
function waf_snapshot($dir, $target)
{
	waf_remove_dir($target);
	@mkdir($target, 0700, true);
	foreach (waf_conf_files($dir) as $file) {
		copy($file, rtrim($target, '/') . '/' . basename($file));
	}
}

/** Puts back every file of the snapshot that differs; returns their names. */
function waf_restore_snapshot($snapshot, $dir)
{
	$restored = array();
	foreach (waf_conf_files($snapshot) as $file) {
		$name = basename($file);
		$target = rtrim($dir, '/') . '/' . $name;
		$text = (string) file_get_contents($file);
		if (!is_file($target) || (string) file_get_contents($target) !== $text) {
			waf_write_atomic($target, $text);
			$restored[] = $name;
		}
	}
	return $restored;
}

function waf_apply_result($ok, $reason, $detail)
{
	return array('ok' => $ok, 'reason' => $reason, 'detail' => waf_cut(trim((string) $detail), 2000));
}

function waf_restore_previous($dir, $staging, $names)
{
	foreach ($names as $name) {
		$saved = $staging . '/previous/' . $name;
		if (is_file($saved)) {
			waf_write_atomic($dir . '/' . $name, (string) file_get_contents($saved));
		}
	}
}

/**
 * Replaces managed files in the WAF directory so that nginx never loads a
 * broken set: copy the directory to staging, write the changes there, check a
 * main.conf that includes the copy, swap the files by rename, nginx -t,
 * reload, is-active. A failed check changes nothing; a failed test or reload
 * puts the previous files back and never reloads. After success the directory
 * is copied to last_good. Only files that exist are replaced (waf/install.sh
 * creates all of them), main.conf never. On failure the staging directory
 * stays for inspection; the hourly cleanup removes it.
 */
function waf_apply_files($paths, $changes, $run)
{
	$dir = rtrim($paths['conf_dir'], '/');
	$staging = rtrim($paths['staging'], '/');
	foreach ($changes as $name => $text) {
		if ($name === 'main.conf' || !preg_match('/^[a-z0-9][a-z0-9.-]*\.conf$/', (string) $name)) {
			return waf_apply_result(false, 'bad_name', $name);
		}
		if (!is_file($dir . '/' . $name)) {
			return waf_apply_result(false, 'missing_file', $dir . '/' . $name);
		}
	}
	if (!is_file($dir . '/main.conf')) {
		return waf_apply_result(false, 'missing_file', $dir . '/main.conf');
	}
	foreach ($changes as $name => $text) {
		if ((string) file_get_contents($dir . '/' . $name) === (string) $text) {
			unset($changes[$name]);
		}
	}
	if (count($changes) === 0) {
		return waf_apply_result(true, 'unchanged', '');
	}

	waf_remove_dir($staging);
	if (!@mkdir($staging . '/previous', 0700, true)) {
		return waf_apply_result(false, 'staging', $staging);
	}
	foreach (waf_conf_files($dir) as $file) {
		copy($file, $staging . '/' . basename($file));
	}
	foreach ($changes as $name => $text) {
		file_put_contents($staging . '/' . $name, $text);
	}
	$main = str_replace('Include ' . $dir . '/', 'Include ' . $staging . '/', (string) file_get_contents($dir . '/main.conf'));
	file_put_contents($staging . '/main.check.conf', $main);

	$check = call_user_func($run, 'rules_check', $staging . '/main.check.conf');
	if ($check[0] !== 0) {
		return waf_apply_result(false, 'rules_check', $check[1]);
	}

	$names = array_keys($changes);
	foreach ($names as $name) {
		copy($dir . '/' . $name, $staging . '/previous/' . $name);
	}
	foreach ($changes as $name => $text) {
		waf_write_atomic($dir . '/' . $name, $text);
	}

	$test = call_user_func($run, 'nginx_test', '');
	if ($test[0] !== 0) {
		waf_restore_previous($dir, $staging, $names);
		return waf_apply_result(false, 'nginx_test', $test[1]);
	}
	$reload = call_user_func($run, 'nginx_reload', '');
	if ($reload[0] !== 0) {
		waf_restore_previous($dir, $staging, $names);
		return waf_apply_result(false, 'nginx_reload', $reload[1]);
	}
	$active = call_user_func($run, 'nginx_active', '');
	if ($active[0] !== 0) {
		// nginx went away after a reload that passed its test. The previous
		// files go back and nginx gets one start; waf-guard reports the rest.
		waf_restore_previous($dir, $staging, $names);
		call_user_func($run, 'nginx_start', '');
		return waf_apply_result(false, 'nginx_inactive', $active[1]);
	}

	waf_snapshot($dir, $paths['last_good']);
	waf_remove_dir($staging);
	return waf_apply_result(true, '', '');
}
