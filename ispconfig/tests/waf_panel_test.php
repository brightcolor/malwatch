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

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel: alle Prüfungen bestanden\n";
