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

/** The heading of a rule: its CRS group in words, else the CRS message, else its number. */
function waf_panel_rule_title($wb, $rule_id, $message)
{
	$rule_id = (string) $rule_id;
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($wb['group_' . $m[1] . '_txt'])) {
		return (string) $wb['group_' . $m[1] . '_txt'];
	}
	if (trim((string) $message) !== '') {
		return (string) $message;
	}
	return sprintf(waf_panel_text($wb, 'rule_fallback_txt', '%s'), $rule_id);
}
