<?php
/**
 * Checks the pure functions of the WAF part ("Abwehr").
 *
 *   php ispconfig/tests/waf_lib_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_lib.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

// --- A1: states, block, vhost, response body, state file ---------------------

$block_detect = "# WAF-BEGIN (detect) - managed by waf-switch\nmodsecurity on;\n# WAF-END\n";
$block_enforce = "# WAF-BEGIN (enforce) - managed by waf-switch\nmodsecurity on;\nmodsecurity_rules 'SecRuleEngine On';\n# WAF-END\n";
$block_old = "# WAF-Anfang (mitschreiben) \xE2\x80\x93 verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n";

expect_same('states', waf_states(), array('off', 'detect', 'enforce'));
expect_same('valid detect', waf_state_valid('detect'), true);
expect_same('invalid old name', waf_state_valid('scharf'), false);
expect_same('normalize old', waf_state_normalize('mitschreiben'), 'detect');
expect_same('normalize scharf', waf_state_normalize('scharf'), 'enforce');
expect_same('normalize aus', waf_state_normalize('aus'), 'off');
expect_same('normalize new', waf_state_normalize('enforce'), 'enforce');
expect_same('normalize junk', waf_state_normalize('an'), '');

expect_same('empty field, detect', waf_block_set('', 'detect'), $block_detect);
expect_same('empty field, enforce', waf_block_set('', 'enforce'), $block_enforce);
expect_same('empty field, off', waf_block_set('', 'off'), '');
expect_same('unknown state writes nothing', waf_block_set('', 'an'), '');
expect_same('null field', waf_block_set(null, 'detect'), $block_detect);

$own = "location = /xmlrpc.php {\n    deny all;\n}\n";
$set = waf_block_set($own, 'detect');
expect_same('own directives stay', substr($set, 0, strlen($own)), $own);
expect_same('block at the end', substr($set, -strlen($block_detect)), $block_detect);
expect_same('round trip', waf_block_set($set, 'off'), $own);
$enforced = waf_block_set($set, 'enforce');
expect_same('one begin', substr_count($enforced, '# WAF-BEGIN'), 1);
expect_same('one end', substr_count($enforced, '# WAF-END'), 1);
expect_same('round trip after change', waf_block_set($enforced, 'off'), $own);

$crlf = "location / {\r\n    try_files \$uri =404;\r\n}\r\n";
expect_same('CRLF stays', waf_block_set(waf_block_set($crlf, 'detect'), 'off'), $crlf);
expect_same('line break added', waf_block_set('client_max_body_size 64M;', 'detect'), "client_max_body_size 64M;\n" . $block_detect);

// The block of the first tool is replaced, not doubled.
$old_field = $own . $block_old;
expect_same('old marker is old', waf_block_is_old($old_field), true);
expect_same('new marker is not old', waf_block_is_old($set), false);
expect_same('old state read', waf_block_state($old_field), 'detect');
expect_same('old block replaced', waf_block_set($old_field, 'detect'), $set);
expect_same('old block removed', waf_block_remove($old_field), $own);
expect_same('state detect', waf_block_state($set), 'detect');
expect_same('state enforce', waf_block_state($enforced), 'enforce');
expect_same('state without block', waf_block_state($own), 'off');
expect_same('state with odd marker', waf_block_state("# WAF-BEGIN (maybe)\nmodsecurity on;\n# WAF-END\n"), 'off');

// ISPConfig drops comment lines when it writes the vhost; only directives count.
expect_same('vhost off', waf_vhost_state("server {\n    listen 80;\n}\n"), 'off');
expect_same('vhost detect', waf_vhost_state("server {\n    modsecurity on;\n}\n"), 'detect');
expect_same('vhost enforce', waf_vhost_state("server {\n    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n}\n"), 'enforce');
expect_same('vhost commented', waf_vhost_state("server {\n    # modsecurity on;\n}\n"), 'off');
expect_same('vhost switched off', waf_vhost_state("server {\n    modsecurity off;\n}\n"), 'off');
expect_same('vhost empty', waf_vhost_state(''), 'off');

$vhost = "server {\n    listen 80;\n    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n    root /var/www;\n}\n";
$stripped = waf_vhost_strip($vhost);
expect_same('strip removes both lines', $stripped, array("server {\n    listen 80;\n    root /var/www;\n}\n", 2));
expect_same('strip leaves a clean file', waf_vhost_strip("server {\n}\n"), array("server {\n}\n", 0));
expect_same('stripped vhost is off', waf_vhost_state($stripped[0]), 'off');

$full = waf_response_body_text('full');
$lean = waf_response_body_text('lean');
expect_same('full without rule', strpos($full, 'ctl:auditLogParts=-E'), false);
expect_same('lean rule', strpos($lean, 'SecAction "id:10199,phase:5,pass,nolog,ctl:auditLogParts=-E"') !== false, true);
expect_same('mode full', waf_response_body_mode($full), 'full');
expect_same('mode lean', waf_response_body_mode($lean), 'lean');
expect_same('mode of empty file', waf_response_body_mode(''), 'full');
expect_same('mode ignores comments', waf_response_body_mode("# ctl:auditLogParts=-E\n"), 'full');
expect_same('valid lean', waf_response_body_valid('lean'), true);
expect_same('invalid old name', waf_response_body_valid('schlank'), false);
expect_same('unknown mode writes full', waf_response_body_text('schlank'), $full);

expect_same('state file normal', waf_state_file_is_emergency(waf_state_file_text(false)), false);
expect_same('state file emergency', waf_state_file_is_emergency(waf_state_file_text(true)), true);
expect_same('state file emergency line', substr(waf_state_file_text(true), -18), "SecRuleEngine Off\n");
expect_same('old state file', waf_state_file_is_emergency("# Notaus-Schalter\nSecRuleEngine Off\n"), true);

expect_same('cut keeps short text', waf_cut('abc', 5), 'abc');
expect_same('cut on a character boundary', waf_cut("a\xC3\xA4b", 2), 'a');
expect_same('json of a list', waf_json(array('a' => '/x', 'b' => "\xC3\xA4")), "{\"a\":\"/x\",\"b\":\"\xC3\xA4\"}");
expect_same('json of broken text', waf_json(array("\xFF")), '[]');

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_lib: alle Prüfungen bestanden\n";
