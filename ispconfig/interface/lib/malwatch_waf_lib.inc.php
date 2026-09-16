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
