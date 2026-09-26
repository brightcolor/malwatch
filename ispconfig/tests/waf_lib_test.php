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

// --- A2: audit lines ---------------------------------------------------------

$sample = file(__DIR__ . '/waf_audit_sample.log', FILE_IGNORE_NEW_LINES);
expect_same('sample has eight lines', count($sample), 8);

$hit = waf_audit_parse_line($sample[0]);
expect_same('1 unique id', $hit['unique_id'], '1758049759112233445');
expect_same('1 time', $hit['seen_at'], '2026-09-16 21:09:19');
expect_same('1 client', $hit['client_ip'], '198.51.100.7');
expect_same('1 host', $hit['host'], 'beispiel.test');
expect_same('1 method', $hit['method'], 'POST');
expect_same('1 uri', $hit['uri'], '/wp-json/batch/v1');
expect_same('1 path', $hit['path'], '/wp-json/batch/v1');
expect_same('1 status', $hit['status'], 207);
expect_same('1 rule ids', array($hit['rules'][0]['id'], $hit['rules'][1]['id']), array('942190', '949110'));
expect_same('1 rule message', $hit['rules'][0]['msg'], 'Detects MSSQL code execution and information gathering attempts');
expect_same('1 parameter', $hit['rules'][0]['param'], 'json.requests.0.path');
expect_same('1 no parameter on the score', $hit['rules'][1]['param'], '');
expect_same('1 score', $hit['anomaly_score'], 5);
expect_same('1 would block', $hit['would_block'], true);
expect_same('1 logged in', $hit['logged_in'], true);
expect_same('1 cookie values removed', $hit['headers']['Cookie'], 'wordpress_logged_in_0a1b2c=[entfernt]; wp-settings-1=[entfernt]');
expect_same('1 authorization removed', $hit['headers']['Authorization'], '[entfernt]');
expect_same('1 other headers stay', $hit['headers']['Content-Type'], 'application/json');
expect_same('1 body', $hit['body'], '{"requests":[{"path":"/wp/v2/posts?filter=exec master..xp_cmdshell"}]}');
expect_same('1 no response body', $hit['response_body'], null);
expect_same('1 no secret left', strpos(waf_json($hit), 'geheim'), false);

$hit = waf_audit_parse_line($sample[1]);
expect_same('2 padded day', $hit['seen_at'], '2026-09-06 09:05:00');
expect_same('2 host with port and capitals', $hit['host'], 'www.beispiel.test');
expect_same('2 path without query', $hit['path'], '/suche');
expect_same('2 uri with query', $hit['uri'], '/suche?q=1%27+OR+%271%27%3D%271');
expect_same('2 parameter q', $hit['rules'][0]['param'], 'q');
expect_same('2 would not block', $hit['would_block'], false);
expect_same('2 score zero', $hit['anomaly_score'], 0);
expect_same('2 not logged in', $hit['logged_in'], false);
expect_same('2 no body', $hit['body'], null);
expect_same('2 response body', $hit['response_body'], '<html><body>Treffer</body></html>');

$hit = waf_audit_parse_line($sample[2]);
expect_same('3 id from the line', substr($hit['unique_id'], 0, 5) . strlen($hit['unique_id']), 'sha1-45');
expect_same('3 same id twice', waf_audit_parse_line($sample[2])['unique_id'], $hit['unique_id']);
expect_same('3 lower-case host header', $hit['host'], 'zweite.test');
expect_same('3 each rule once', count($hit['rules']), 3);
expect_same('3 first match names the parameter', $hit['rules'][0]['param'], 'x');
expect_same('3 score', $hit['anomaly_score'], 10);
expect_same('3 status', $hit['status'], 404);

expect_same('4 broken line', waf_audit_parse_line($sample[3]), null);
expect_same('5 no messages', waf_audit_parse_line($sample[4]), null);
expect_same('7 no time', waf_audit_parse_line($sample[6]), null);
expect_same('empty line', waf_audit_parse_line(''), null);

$bad = str_replace('/seite?x=%3Csvg%3E', "/seite\xFF?x=1", $sample[7]);
$hit = waf_audit_parse_line($bad);
expect_same('invalid UTF-8 still read', is_array($hit), true);
expect_same('invalid UTF-8 replaced in the path', $hit['path'], "/seite\xEF\xBF\xBD");
expect_same('invalid UTF-8 keeps the query apart', $hit['uri'], "/seite\xEF\xBF\xBD?x=1");
expect_same('invalid UTF-8 encodes', waf_json($hit) !== '[]', true);

expect_same('utf8 clean keeps valid', waf_utf8_clean("gr\xC3\xBC\xC3\x9F"), "gr\xC3\xBC\xC3\x9F");
expect_same('utf8 clean replaces', waf_utf8_clean("a\xFFb"), "a\xEF\xBF\xBDb");

expect_same('time', waf_audit_time('Wed Sep 16 21:09:19 2026'), '2026-09-16 21:09:19');
expect_same('time impossible date', waf_audit_time('Mon Feb 30 10:00:00 2026'), '');
expect_same('time words', waf_audit_time('gestern'), '');

expect_same('header lookup', waf_audit_header(array('host' => 'a.test'), 'Host'), 'a.test');
expect_same('header missing', waf_audit_header(array(), 'Host'), '');

expect_same('host dot', waf_host_normalize('beispiel.test.'), 'beispiel.test');
expect_same('host ipv6', waf_host_normalize('[::1]:80'), '');
expect_same('host space', waf_host_normalize('bad host'), '');
expect_same('host underscore', waf_host_normalize('a_b.test'), '');
expect_same('host empty', waf_host_normalize(''), '');

expect_same('cookie names', waf_cookie_names('a=1; b=2;c'), array('a', 'b', 'c'));
expect_same('no cookies', waf_cookie_names(''), array());

expect_same('score 949', waf_is_scoring_rule('949110'), true);
expect_same('score 959', waf_is_scoring_rule('959100'), true);
expect_same('score 980', waf_is_scoring_rule('980130'), true);
expect_same('detection rule', waf_is_scoring_rule('942100'), false);
expect_same('own rule', waf_is_scoring_rule('10001'), false);

expect_same('param of ARGS', waf_audit_param('Matched Data: x found within ARGS:q: y'), 'q');
expect_same('param of ARGS_NAMES', waf_audit_param('found within ARGS_NAMES:x: x'), '');
expect_same('param of a file name', waf_audit_param('found within REQUEST_FILENAME: /.env'), '');

$report = waf_audit_summarize($sample);
expect_same('report groups', count($report), 4);
expect_same('report first', array($report[0]['host'], $report[0]['rule_id'], $report[0]['hits']), array('zweite.test', '941100', 2));
expect_same('report example', $report[0]['example'], '/seite');
expect_same('report second by name', array($report[1]['host'], $report[1]['rule_id']), array('beispiel.test', '942190'));
expect_same('report leaves the score out', in_array('949110', array_column($report, 'rule_id'), true), false);

expect_same('reader new inode', waf_reader_start(0, 0, 5, 100), 0);
expect_same('reader goes on', waf_reader_start(5, 50, 5, 100), 50);
expect_same('reader after copytruncate', waf_reader_start(5, 50, 5, 40), 0);
expect_same('reader after rotation', waf_reader_start(5, 50, 6, 100), 0);

$log = tempnam(sys_get_temp_dir(), 'waf');
file_put_contents($log, "a\nb\nc");
expect_same('read complete lines', waf_read_lines($log, 0, 10), array('lines' => array('a', 'b'), 'offset' => 4, 'more' => false));
expect_same('read one line', waf_read_lines($log, 0, 1), array('lines' => array('a'), 'offset' => 2, 'more' => true));
file_put_contents($log, "\n", FILE_APPEND);
expect_same('read the finished line', waf_read_lines($log, 4, 10), array('lines' => array('c'), 'offset' => 6, 'more' => false));
expect_same('read past the end', waf_read_lines($log, 6, 10), array('lines' => array(), 'offset' => 6, 'more' => false));
unlink($log);
expect_same('read a missing file', waf_read_lines($log, 0, 10), null);

// --- A3: host map and exceptions ---------------------------------------------

$rows = array(
	array('domain_id' => 11, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'beispiel.test', 'subdomain' => 'www', 'active' => 'y'),
	array('domain_id' => 12, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'zweite.test', 'subdomain' => '*', 'active' => 'y'),
	array('domain_id' => 13, 'parent_domain_id' => 0, 'type' => 'vhost', 'domain' => 'aus.test', 'subdomain' => 'none', 'active' => 'n'),
	array('domain_id' => 21, 'parent_domain_id' => 11, 'type' => 'alias', 'domain' => 'Alias-Beispiel.test', 'subdomain' => 'www', 'active' => 'y'),
	array('domain_id' => 22, 'parent_domain_id' => 11, 'type' => 'vhostsubdomain', 'domain' => 'shop.beispiel.test', 'subdomain' => 'none', 'active' => 'y'),
	// An alias that claims the name of another website does not win.
	array('domain_id' => 23, 'parent_domain_id' => 11, 'type' => 'alias', 'domain' => 'zweite.test', 'subdomain' => 'none', 'active' => 'y'),
	array('domain_id' => 24, 'parent_domain_id' => 0, 'type' => 'alias', 'domain' => 'waise.test', 'subdomain' => 'none', 'active' => 'y'),
);
$map = waf_host_map($rows);
expect_same('lookup vhost', waf_host_lookup($map, 'beispiel.test'), 11);
expect_same('lookup www', waf_host_lookup($map, 'WWW.beispiel.test:443'), 11);
expect_same('lookup alias', waf_host_lookup($map, 'alias-beispiel.test'), 11);
expect_same('lookup alias www', waf_host_lookup($map, 'www.alias-beispiel.test'), 11);
expect_same('lookup subdomain website', waf_host_lookup($map, 'shop.beispiel.test'), 11);
expect_same('vhost wins over alias', waf_host_lookup($map, 'zweite.test'), 12);
expect_same('wildcard', waf_host_lookup($map, 'a.b.zweite.test'), 12);
expect_same('inactive website', waf_host_lookup($map, 'aus.test'), 0);
expect_same('alias without parent', waf_host_lookup($map, 'waise.test'), 0);
expect_same('unknown host', waf_host_lookup($map, 'fremd.test'), 0);
expect_same('no wildcard for a plain vhost', waf_host_lookup($map, 'x.beispiel.test'), 0);
expect_same('empty host', waf_host_lookup($map, ''), 0);

$hosts11 = waf_hosts_of($map, 11);
expect_same('hosts of a website', $hosts11, array(
	'exact' => array('alias-beispiel.test', 'beispiel.test', 'shop.beispiel.test', 'www.alias-beispiel.test', 'www.beispiel.test'),
	'wildcard' => array(),
));
$hosts12 = waf_hosts_of($map, 12);
expect_same('hosts with wildcard', $hosts12, array('exact' => array('www.zweite.test', 'zweite.test'), 'wildcard' => array('zweite.test')));
$pattern12 = '^(?:www\.zweite\.test|zweite\.test|(?:[a-z0-9-]+\.)+zweite\.test)(?::\d+)?$';
expect_same('pattern', waf_host_pattern($hosts12), $pattern12);
expect_same('pattern without names', waf_host_pattern(array('exact' => array(), 'wildcard' => array())), '');
expect_same('pattern skips odd names', waf_host_pattern(array('exact' => array('a"b.test'), 'wildcard' => array())), '');
expect_same('pattern matches', preg_match('/' . $pattern12 . '/', 'shop.zweite.test:8080'), 1);
expect_same('pattern rejects', preg_match('/' . $pattern12 . '/', 'zweite.test.fremd.test'), 0);

$ok = array('scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '');
$site_row = array('scope' => 'site', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => '');
$param_row = array('scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => 'filter');
expect_same('valid site_path', waf_exception_check($ok), '');
expect_same('valid site', waf_exception_check($site_row), '');
expect_same('valid site_param', waf_exception_check($param_row), '');
expect_same('valid all', waf_exception_check(array('scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '')), '');
expect_same('unknown scope', waf_exception_check(array_merge($ok, array('scope' => 'server'))), 'scope');
expect_same('site scope without website', waf_exception_check(array_merge($ok, array('parent_domain_id' => 0))), 'site');
expect_same('all scope with website', waf_exception_check(array('scope' => 'all_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/x', 'param' => '')), 'site');
expect_same('rule id with quote', waf_exception_check(array_merge($ok, array('rule_id' => '942100"'))), 'rule_id');
expect_same('rule id too short', waf_exception_check(array_merge($ok, array('rule_id' => '12'))), 'rule_id');
expect_same('own rule', waf_exception_check(array_merge($ok, array('rule_id' => '10010'))), 'rule_id');
expect_same('scoring rule', waf_exception_check(array_merge($ok, array('rule_id' => '949110'))), 'rule_id');
expect_same('path with quote', waf_exception_check(array_merge($ok, array('path' => '/a"b'))), 'path');
expect_same('path with line break', waf_exception_check(array_merge($ok, array('path' => "/a\nSecRuleEngine Off"))), 'path');
expect_same('path with space', waf_exception_check(array_merge($ok, array('path' => '/a b'))), 'path');
expect_same('path without slash', waf_exception_check(array_merge($ok, array('path' => 'wp-admin'))), 'path');
expect_same('path missing', waf_exception_check(array_merge($ok, array('path' => ''))), 'path');
expect_same('path not allowed for site', waf_exception_check(array_merge($site_row, array('path' => '/x'))), 'path');
expect_same('param missing', waf_exception_check(array_merge($param_row, array('param' => ''))), 'param');
expect_same('param with control character', waf_exception_check(array_merge($param_row, array('param' => "a\x00b"))), 'param');
expect_same('param with comma', waf_exception_check(array_merge($param_row, array('param' => 'a,ctl:ruleEngine=Off'))), 'param');
expect_same('param not allowed', waf_exception_check(array_merge($ok, array('param' => 'x'))), 'param');
expect_same('rule id of an exception', waf_exception_rule_id(3), 10203);

$exceptions = array(
	array('exception_id' => 4, 'scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '/xmlrpc.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 1, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 2, 'scope' => 'site_path', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'exception_state' => 'pending'),
	array('exception_id' => 3, 'scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => 'filter', 'exception_state' => 'active'),
	array('exception_id' => 5, 'scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 6, 'scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q', 'exception_state' => 'active'),
	array('exception_id' => 7, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'removing'),
	array('exception_id' => 8, 'scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '10010', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 9, 'scope' => 'site', 'parent_domain_id' => 99, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
);
$rules = waf_exception_rules($exceptions, array(12 => $hosts12));
$host_rule = 'SecRule REQUEST_HEADERS:Host "@rx ' . $pattern12 . '" ';
$expected_before = "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n"
	. "# Included before the CRS rules: runtime exclusions (ctl).\n"
	. "\n# exception 1 (site)\n"
	. $host_rule . "\"id:10201,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveById=942100\"\n"
	. "\n# exception 2 (site_path)\n"
	. $host_rule . "\"id:10202,phase:1,pass,nolog,t:none,t:lowercase,chain\"\n"
	. "    SecRule REQUEST_FILENAME \"@beginsWith /wp-admin/admin-ajax.php\" \"t:none,ctl:ruleRemoveById=942100\"\n"
	. "\n# exception 3 (site_param)\n"
	. $host_rule . "\"id:10203,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveTargetById=942100;ARGS:filter\"\n"
	. "\n# exception 4 (all_path)\n"
	. "SecRule REQUEST_FILENAME \"@beginsWith /xmlrpc.php\" \"id:10204,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=941100\"\n"
	. "\n# exception 6 (site_param)\n"
	. $host_rule . "\"id:10206,phase:1,pass,nolog,t:none,t:lowercase,chain\"\n"
	. "    SecRule REQUEST_FILENAME \"@beginsWith /suche\" \"t:none,ctl:ruleRemoveTargetById=942100;ARGS:q\"\n";
expect_same('rules before', $rules['before'], $expected_before);
expect_same('rules after', $rules['after'], "# Managed by malwatch (page Abwehr). Every change here is overwritten.\n"
	. "# Included after the CRS rules: exclusions for every website.\n"
	. "\n# exception 5 (all)\nSecRuleRemoveById 941160\n");
expect_same('rules skipped', $rules['skipped'], array(8 => 'rule_id', 9 => 'site'));
expect_same('rules are stable', waf_exception_rules(array_reverse($exceptions), array(12 => $hosts12)), $rules);
$empty = waf_exception_rules(array(), array());
expect_same('empty files keep their header', array(substr_count($empty['before'], "\n"), substr_count($empty['after'], "\n"), $empty['skipped']), array(2, 2, array()));
$bad_id = waf_exception_rules(array(array_merge($exceptions[1], array('exception_id' => 0))), array(12 => $hosts12));
expect_same('bad exception id', $bad_id['skipped'], array(0 => 'exception_id'));

$items = array(
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 18),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/kontakt', 'hits' => 3),
	array('parent_domain_id' => 12, 'rule_id' => '941100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 5),
	array('parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => 7),
);
expect_same('preview site_path', waf_exception_preview($items, array('scope' => 'site_path', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/wp-admin/', 'param' => '')), array('covered' => 18, 'total' => 21));
expect_same('preview site', waf_exception_preview($items, array('scope' => 'site', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => '')), array('covered' => 21, 'total' => 21));
expect_same('preview all_path', waf_exception_preview($items, array('scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '')), array('covered' => 25, 'total' => 28));
expect_same('preview all', waf_exception_preview($items, array('scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '', 'param' => '')), array('covered' => 5, 'total' => 5));
$hit_items = array(
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'hits' => 1, 'params' => array('q')),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'hits' => 1, 'params' => array('s')),
	array('parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/liste', 'hits' => 1, 'params' => array('q')),
);
expect_same('preview site_param', waf_exception_preview($hit_items, array('scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '', 'param' => 'q')), array('covered' => 2, 'total' => 3));
expect_same('preview site_param with path', waf_exception_preview($hit_items, array('scope' => 'site_param', 'parent_domain_id' => 12, 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q')), array('covered' => 1, 'total' => 3));

// --- A4: settings, decisions, files ------------------------------------------

$defaults = waf_settings(null);
expect_same('default detail days', $defaults['waf_detail_days'], 7);
expect_same('default stats days', $defaults['waf_stats_days'], 90);
expect_same('default response body', $defaults['waf_response_body'], 'full');
expect_same('default conf dir', $defaults['waf_conf_dir'], '/etc/nginx/waf');
expect_same('default emergency', array($defaults['waf_emergency'], $defaults['waf_emergency_since']), array('n', null));
expect_same('keys', array_keys($defaults), array_keys(waf_settings_defaults()));
$custom = waf_settings(array('waf_detail_days' => '30', 'waf_stats_days' => '0', 'waf_ingest_max_lines' => '999999',
	'waf_response_body' => 'lean', 'waf_emergency' => 'y', 'waf_emergency_since' => '2026-09-16 21:00:00',
	'waf_conf_dir' => '/etc/nginx/waf/', 'waf_audit_log' => '/var/log/../etc/passwd', 'waf_job_deadline_minutes' => ''));
expect_same('custom days', $custom['waf_detail_days'], 30);
expect_same('days held to the minimum', $custom['waf_stats_days'], 1);
expect_same('lines held to the maximum', $custom['waf_ingest_max_lines'], 100000);
expect_same('empty value takes the default', $custom['waf_job_deadline_minutes'], 5);
expect_same('lean kept', $custom['waf_response_body'], 'lean');
expect_same('emergency kept', array($custom['waf_emergency'], $custom['waf_emergency_since']), array('y', '2026-09-16 21:00:00'));
expect_same('closing slash dropped', $custom['waf_conf_dir'], '/etc/nginx/waf');
expect_same('path with dots refused', $custom['waf_audit_log'], '/var/log/waf/audit.log');
$odd = waf_settings(array('waf_response_body' => 'schlank', 'waf_conf_dir' => '//'));
expect_same('odd mode refused', $odd['waf_response_body'], 'full');
expect_same('root dir refused', $odd['waf_conf_dir'], '/etc/nginx/waf');

expect_same('free from', waf_enforce_free_from('2026-09-16 13:20:15', 7), '2026-09-23 13:20:15');
expect_same('free from over the clock change', waf_enforce_free_from('2026-10-20 12:00:00', 7), '2026-10-27 12:00:00');
expect_same('free from without date', waf_enforce_free_from(null, 7), '');
expect_same('free from zero date', waf_enforce_free_from('0000-00-00 00:00:00', 7), '');
expect_same('enforce allowed', waf_enforce_block_reason('detect', '2026-09-16 13:20:15', '2026-09-23 13:20:15', 7, 'n'), '');
expect_same('enforce too early', waf_enforce_block_reason('detect', '2026-09-16 13:20:15', '2026-09-23 13:20:14', 7, 'n'), 'too_early');
expect_same('enforce from off', waf_enforce_block_reason('off', '', '2026-09-23 13:20:15', 7, 'n'), 'not_detect');
expect_same('enforce during emergency', waf_enforce_block_reason('detect', '2026-09-01 00:00:00', '2026-09-23 13:20:15', 7, 'y'), 'emergency');
expect_same('enforce again', waf_enforce_block_reason('enforce', '2026-09-01 00:00:00', '2026-09-23 13:20:15', 7, 'n'), '');
expect_same('enforce without waiting time', waf_enforce_block_reason('detect', '2026-09-23 13:20:15', '2026-09-23 13:20:15', 0, 'n'), '');
expect_same('detect without date', waf_enforce_block_reason('detect', null, '2026-09-23 13:20:15', 7, 'n'), 'too_early');

// The periods of the overview come from waf_periods and waf_period_default,
// within the time the day figures are kept (waf_stats_days).
$plain_periods = waf_settings(array());
$with_keep = function ($settings, $days) { return array_merge($settings, array('waf_stats_days' => $days)); };
expect_same('periods', waf_periods($plain_periods), array(1, 7, 30, 90));
expect_same('periods of a short keep', waf_periods($with_keep($plain_periods, 10)), array(1, 7));
expect_same('periods of one day', waf_periods($with_keep($plain_periods, 1)), array(1));
expect_same('period chosen', waf_period('30', $plain_periods), 30);
expect_same('period unknown', waf_period('14', $plain_periods), 7);
expect_same('period beyond the keep', waf_period(90, $with_keep($plain_periods, 10)), 7);
expect_same('period of one day', waf_period(7, $with_keep($plain_periods, 1)), 1);
$own_periods = array_merge($plain_periods, array('waf_periods' => "14\n3, 60,3", 'waf_period_default' => 14));
expect_same('own periods, sorted and without doubles', waf_periods($own_periods), array(3, 14, 60));
expect_same('own periods beyond the keep', waf_periods($with_keep($own_periods, 30)), array(3, 14));
expect_same('no own period within the keep offers the keep',
	waf_periods(array_merge($with_keep($own_periods, 30), array('waf_periods' => '120'))), array(30));
expect_same('an emptied list of periods offers the keep', waf_periods(array_merge($own_periods, array('waf_periods' => ''))), array(90));
expect_same('own default period', waf_period('', $own_periods), 14);
expect_same('own period chosen', waf_period('3', $own_periods), 3);
expect_same('a default period missing in the list falls back to the longest',
	waf_period('', array_merge($own_periods, array('waf_period_default' => 7))), 60);

$rotate = waf_logrotate_text(14, '/var/log/waf/audit.log');
expect_same('logrotate path', strpos($rotate, "\n/var/log/waf/audit.log {\n") !== false, true);
expect_same('logrotate keep', strpos($rotate, "\trotate 14\n") !== false, true);
expect_same('logrotate copytruncate', strpos($rotate, "\tcopytruncate\n") !== false, true);
expect_same('logrotate minimum', strpos(waf_logrotate_text(0, '/x'), "\trotate 1\n") !== false, true);

$web = array('domain_id' => 11, 'domain' => 'beispiel.test', 'type' => 'vhost', 'server_id' => 1, 'nginx_directives' => $own);
$web_detect = array_merge($web, array('nginx_directives' => $set));
$site_detect = array('waf_state' => 'detect', 'waf_state_since' => '2026-09-01 10:00:00');
$now = '2026-09-16 12:00:00';
$plan = waf_site_plan($web, null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan writes', array($plan['action'], $plan['text'], $plan['target']), array('write', $set, 'detect'));
$plan = waf_site_plan(null, null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan missing website', array($plan['action'], $plan['reason']), array('skip', 'not_found'));
$plan = waf_site_plan(array_merge($web, array('type' => 'alias')), null, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan alias', $plan['reason'], 'not_found');
$plan = waf_site_plan($web, null, 'detect', 'set', 2, 'off', $now, $defaults);
expect_same('plan other server', $plan['reason'], 'other_server');
$plan = waf_site_plan($web, null, 'an', 'set', 1, 'off', $now, $defaults);
expect_same('plan unknown state', $plan['reason'], 'state');
$plan = waf_site_plan($web, null, 'enforce', 'set', 1, 'off', $now, $defaults);
expect_same('plan enforce from off', $plan['reason'], 'not_detect');
$plan = waf_site_plan($web_detect, $site_detect, 'enforce', 'set', 1, 'detect', $now, $defaults);
expect_same('plan enforce after waiting', array($plan['action'], $plan['text']), array('write', $enforced));
$plan = waf_site_plan($web_detect, $site_detect, 'enforce', 'set', 1, 'detect', $now, $custom);
expect_same('plan enforce during emergency', $plan['reason'], 'emergency');
$plan = waf_site_plan($web_detect, $site_detect, 'detect', 'set', 1, 'detect', $now, $defaults);
expect_same('plan confirms a match', $plan['action'], 'confirm');
$plan = waf_site_plan($web_detect, $site_detect, 'detect', 'set', 1, 'off', $now, $defaults);
expect_same('plan waits for ISPConfig', $plan['action'], 'wait');
$plan = waf_site_plan(array_merge($web, array('nginx_directives' => $old_field)), null, '', 'keep', 1, 'detect', $now, $defaults);
expect_same('plan rewrites the old marker', array($plan['action'], $plan['target'], $plan['text']), array('write', 'detect', $set));
$plan = waf_site_plan($web_detect, null, '', 'keep', 1, 'detect', $now, $defaults);
expect_same('plan keeps a new marker', array($plan['action'], $plan['target']), array('confirm', 'detect'));
$plan = waf_site_plan($web, null, '', 'keep', 1, 'off', $now, $defaults);
expect_same('plan keep without block', array($plan['action'], $plan['target']), array('confirm', 'off'));
$plan = waf_site_plan(array_merge($web, array('nginx_directives' => $enforced)), null, '', 'keep', 1, 'enforce', $now, $custom);
expect_same('plan keep does not ask for enforce', $plan['action'], 'confirm');

$entry = array('target' => 'detect');
expect_same('progress confirmed', waf_site_progress($entry, 'detect', false, false), 'confirmed');
expect_same('progress waiting', waf_site_progress($entry, 'off', false, false), 'waiting');
expect_same('progress overdue', waf_site_progress($entry, 'off', false, true), 'failed:deadline');
expect_same('progress rejected', waf_site_progress($entry, 'detect', true, false), 'failed:rejected');
expect_same('rollback allowed', waf_rollback_allowed($set, sha1($set)), true);
expect_same('rollback refused', waf_rollback_allowed($set . "# edited\n", sha1($set)), false);
expect_same('rollback without hash', waf_rollback_allowed('', ''), false);

$tmp = sys_get_temp_dir() . '/waf_test_' . getmypid();
waf_remove_dir($tmp);
mkdir($tmp . '/conf', 0777, true);
file_put_contents($tmp . '/conf/main.conf', 'Include ' . $tmp . "/conf/state.conf\nInclude " . $tmp . "/conf/response-body.conf\n");
file_put_contents($tmp . '/conf/state.conf', waf_state_file_text(false));
file_put_contents($tmp . '/conf/response-body.conf', waf_response_body_text('full'));
file_put_contents($tmp . '/conf/notes.txt', 'no rule file');
expect_same('conf files', array_map('basename', waf_conf_files($tmp . '/conf')), array('main.conf', 'response-body.conf', 'state.conf'));
$paths = array('conf_dir' => $tmp . '/conf', 'staging' => $tmp . '/staging/7', 'last_good' => $tmp . '/last-good');

// Stands in for the real commands and records every call.
$calls = array();
$answers = array();
$run = function ($name, $argument) use (&$calls, &$answers) {
	$calls[] = $name;
	if ($name === 'rules_check') {
		// The check must read the staged copy, never the live file.
		$calls[] = strpos((string) file_get_contents($argument), '/staging/7/state.conf') !== false ? 'staged' : 'live';
	}
	return isset($answers[$name]) ? $answers[$name] : array(0, '');
};

$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(true)), $run);
expect_same('apply ok', $result, array('ok' => true, 'reason' => '', 'detail' => ''));
expect_same('apply order', $calls, array('rules_check', 'staged', 'nginx_test', 'nginx_reload', 'nginx_active'));
expect_same('apply wrote', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('apply snapshot', file_get_contents($tmp . '/last-good/state.conf'), waf_state_file_text(true));
expect_same('apply cleaned up', is_dir($tmp . '/staging/7'), false);

$calls = array();
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(true)), $run);
expect_same('apply without change', array($result['ok'], $result['reason'], $calls), array(true, 'unchanged', array()));

$calls = array();
$answers = array('rules_check' => array(1, 'Rules error. File: state.conf. Line: 3.'));
$result = waf_apply_files($paths, array('state.conf' => "SecRuleEngine Broken\n"), $run);
expect_same('rules check refuses', $result, array('ok' => false, 'reason' => 'rules_check', 'detail' => 'Rules error. File: state.conf. Line: 3.'));
expect_same('nothing touched after the check', $calls, array('rules_check', 'staged'));
expect_same('live file unchanged', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);

$calls = array();
$answers = array('nginx_test' => array(1, 'nginx: [emerg] test failed'));
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(false)), $run);
expect_same('nginx -t refuses', $result['reason'], 'nginx_test');
expect_same('no reload after a failed test', in_array('nginx_reload', $calls, true), false);
expect_same('old file back', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('snapshot unchanged', waf_state_file_is_emergency(file_get_contents($tmp . '/last-good/state.conf')), true);

$calls = array();
$answers = array('nginx_active' => array(3, 'inactive'));
$result = waf_apply_files($paths, array('state.conf' => waf_state_file_text(false)), $run);
expect_same('inactive after reload', array($result['reason'], $calls), array('nginx_inactive',
	array('rules_check', 'staged', 'nginx_test', 'nginx_reload', 'nginx_active', 'nginx_start')));
expect_same('old file back after inactive', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);

$answers = array();
$result = waf_apply_files($paths, array('exclusions-panel-before.conf' => "# x\n"), $run);
expect_same('missing file refused', $result['reason'], 'missing_file');
$result = waf_apply_files($paths, array('main.conf' => "# x\n"), $run);
expect_same('main.conf refused', $result['reason'], 'bad_name');
$result = waf_apply_files($paths, array('../main.conf' => "# x\n"), $run);
expect_same('path in the name refused', $result['reason'], 'bad_name');

file_put_contents($tmp . '/conf/state.conf', "broken\n");
expect_same('restore snapshot', waf_restore_snapshot($tmp . '/last-good', $tmp . '/conf'), array('state.conf'));
expect_same('restored content', waf_state_file_is_emergency(file_get_contents($tmp . '/conf/state.conf')), true);
expect_same('restore twice changes nothing', waf_restore_snapshot($tmp . '/last-good', $tmp . '/conf'), array());
expect_same('restore from nothing', waf_restore_snapshot($tmp . '/missing', $tmp . '/conf'), array());

waf_write_atomic($tmp . '/conf/new.conf', "x\n");
expect_same('atomic write', array(file_get_contents($tmp . '/conf/new.conf'), is_file($tmp . '/conf/new.conf.new')), array("x\n", false));
waf_remove_dir($tmp);
expect_same('tree removed', is_dir($tmp), false);

// --- A8: shipped files match what the functions write ------------------------

$shipped = __DIR__ . '/../../waf/conf';
$panel = waf_exception_rules(array(), array());
expect_same('shipped panel before', file_get_contents($shipped . '/exclusions-panel-before.conf'), $panel['before']);
expect_same('shipped panel after', file_get_contents($shipped . '/exclusions-panel-after.conf'), $panel['after']);
expect_same('shipped response body', file_get_contents($shipped . '/response-body.conf'), waf_response_body_text('full'));
expect_same('shipped state', file_get_contents($shipped . '/state.conf'), waf_state_file_text(false));
expect_same('shipped logrotate', file_get_contents($shipped . '/logrotate-waf'), waf_logrotate_text(7, '/var/log/waf/audit.log'));
$main = file_get_contents($shipped . '/main.conf');
foreach (array('settings', 'crs-extra', 'exclusions-before', 'exclusions-panel-before', 'exclusions-after',
	'exclusions-panel-after', 'response-body', 'state') as $name) {
	expect_same('main includes ' . $name, strpos($main, "Include /etc/nginx/waf/$name.conf\n") !== false, true);
}
$crs = strpos($main, 'Include /usr/share/modsecurity-crs/rules/*.conf');
expect_same('runtime exclusions before the CRS rules', strpos($main, 'exclusions-panel-before.conf') < $crs, true);
expect_same('configure-time exclusions after the CRS rules', strpos($main, 'exclusions-panel-after.conf') > $crs, true);
expect_same('state comes last', substr(rtrim($main), -strlen('state.conf')), 'state.conf');

// --- B3: settings of the origin -----------------------------------------------

$origin = waf_settings(array());
expect_same('origin off by default', array($origin['waf_origin_geo'], $origin['waf_origin_tor'], $origin['waf_origin_net']),
	array('off', 'off', 'off'));
expect_same('hours by default', array($origin['waf_origin_tor_hours'], $origin['waf_origin_list_hours'],
	$origin['waf_origin_db_hours']), array(1, 24, 24));
$origin = waf_settings(array('waf_origin_geo' => 'maxmind', 'waf_origin_tor' => 'torproject', 'waf_origin_net' => 'x4b',
	'waf_origin_maxmind_account' => '123456', 'waf_origin_maxmind_key' => 'AbC_123', 'waf_origin_tor_hours' => '0',
	'waf_origin_list_hours' => '1000', 'waf_origin_db_hours' => '48'));
expect_same('origin as chosen', array($origin['waf_origin_geo'], $origin['waf_origin_tor'], $origin['waf_origin_net']),
	array('maxmind', 'torproject', 'x4b'));
expect_same('hours inside their limits', array($origin['waf_origin_tor_hours'], $origin['waf_origin_list_hours'],
	$origin['waf_origin_db_hours']), array(1, 720, 48));
expect_same('account and key kept', array($origin['waf_origin_maxmind_account'], $origin['waf_origin_maxmind_key']),
	array('123456', 'AbC_123'));
$origin = waf_settings(array('waf_origin_geo' => 'irgendwas', 'waf_origin_tor' => 'ja', 'waf_origin_net' => 'vielleicht',
	'waf_origin_maxmind_account' => 'abc', 'waf_origin_maxmind_key' => 'schlüssel mit leerzeichen'));
expect_same('unknown choices fall back to off', array($origin['waf_origin_geo'], $origin['waf_origin_tor'],
	$origin['waf_origin_net']), array('off', 'off', 'off'));
expect_same('account and key that fit no pattern', array($origin['waf_origin_maxmind_account'],
	$origin['waf_origin_maxmind_key']), array('', ''));
expect_same('the choices of every field', waf_origin_choices(), array(
	'waf_origin_geo' => array('off', 'dbip', 'maxmind'),
	'waf_origin_tor' => array('off', 'torproject'),
	'waf_origin_net' => array('off', 'x4b', 'proxycheck'),
));

// proxycheck.io steht neben den X4BNet-Listen zur Wahl und bringt zwei eigene Werte mit.
$picked = waf_settings(array('waf_origin_net' => 'proxycheck', 'waf_origin_proxycheck_key' => 'ab-12cd',
	'waf_origin_proxycheck_daily' => '2000'));
expect_same('the external source is kept', array($picked['waf_origin_net'], $picked['waf_origin_proxycheck_key'],
	$picked['waf_origin_proxycheck_daily']), array('proxycheck', 'ab-12cd', 2000));
expect_same('a key with a space is dropped',
	waf_settings(array('waf_origin_proxycheck_key' => 'ab 12'))['waf_origin_proxycheck_key'], '');
expect_same('the daily limit stays in its range',
	waf_settings(array('waf_origin_proxycheck_daily' => '999999'))['waf_origin_proxycheck_daily'], 100000);
expect_same('without a row the limit is the default',
	waf_settings(array())['waf_origin_proxycheck_daily'], 500);

// Das zweite Zugriffslog steht nur im vhost, wenn nginx das Format kennt.
expect_same('without the include of malwatch no second log',
	strpos(waf_block_text('detect'), 'blocked.log'), false);
expect_same('with it the line is there',
	strpos(waf_block_text('detect', true), 'access_log /var/log/waf/blocked.log mw_block if=$mw_denied;') !== false, true);
expect_same('a website that is off keeps its vhost clean', waf_block_text('off', true), '');

// --- Sperren ------------------------------------------------------------------

expect_same('the three modes', waf_ban_modes(), array('off', 'propose', 'block'));
$ban = waf_settings(array());
expect_same('blocking is off by default', $ban['waf_ban_mode'], 'off');
expect_same('the defaults of the numbers', array($ban['waf_ban_score'], $ban['waf_ban_window_minutes'],
	$ban['waf_ban_hours_first'], $ban['waf_ban_hours_second'], $ban['waf_ban_hours_third'],
	$ban['waf_ban_max'], $ban['waf_ban_keep_days']), array(50, 10, 1, 24, 168, 5000, 30));
expect_same('search engines are spared by default', $ban['waf_ban_bots'], 'on');
$ban = waf_settings(array('waf_ban_mode' => 'propose', 'waf_ban_score' => '80',
	'waf_ban_window_minutes' => '5', 'waf_ban_max' => '99', 'waf_ban_keep_days' => '400',
	'waf_ban_bots' => 'off'));
expect_same('a chosen mode is kept', $ban['waf_ban_mode'], 'propose');
expect_same('numbers inside their limits', array($ban['waf_ban_score'], $ban['waf_ban_window_minutes'],
	$ban['waf_ban_max'], $ban['waf_ban_keep_days']), array(80, 5, 100, 365));
expect_same('search engines can be switched off', $ban['waf_ban_bots'], 'off');
expect_same('an unknown mode falls back', waf_settings(array('waf_ban_mode' => 'vielleicht'))['waf_ban_mode'], 'off');
expect_same('logged-in requests count at a tenth by default',
	waf_settings(array())['waf_ban_logged_in_percent'], 10);
expect_same('the share of logged-in requests stays between 0 and 100', array(
	waf_settings(array('waf_ban_logged_in_percent' => '250'))['waf_ban_logged_in_percent'],
	waf_settings(array('waf_ban_logged_in_percent' => '0'))['waf_ban_logged_in_percent'],
), array(100, 0));

// --- Lists and numbers of 0.32.0 -------------------------------------------------

expect_same('a list reads lines and commas, drops blanks and doubles',
	waf_list_parse(" /wp-admin/\r\n/wp-json/, /wp-admin/\n\n"), array('/wp-admin/', '/wp-json/'));
expect_same('an empty list', waf_list_parse(''), array());
expect_same('a list is stored with commas', waf_list_join(array('/wp-admin/', '/wp-json/')), '/wp-admin/,/wp-json/');
expect_same('and shown one entry per line', waf_list_lines(' /wp-admin/, /wp-json/'), "/wp-admin/\n/wp-json/");
expect_same('paths without spaces or commas', waf_list_bad_paths(array(
	'/wp-admin/', 'wp-login.php', '/mit leerzeichen/', "/tab\there/")), array('/mit leerzeichen/', "/tab\there/"));
expect_same('cookie names from letters, digits, dot, dash and underscore',
	waf_list_bad_cookies(array('wordpress_logged_in_', 'joomla_user_state', 'kaputt;cookie')), array('kaputt;cookie'));
expect_same('networks as ranges or single addresses', waf_list_bad_networks(array(
	'127.0.0.0/8', '::1/128', '10.50.0.1', '10.50.0.0/33', 'kein-netz')), array('10.50.0.0/33', 'kein-netz'));
expect_same('a list fits into its column', array(
	waf_list_fits(array(str_repeat('a', 1024))), waf_list_fits(array(str_repeat('a', 1020), 'bcdef'))), array(true, false));
expect_same('periods as whole days within the longest keep', waf_list_bad_days(array(
	'1', '7', '0', 'x', '3650', '3651', '2.5', ' 30')), array('0', 'x', '3651', '2.5', ' 30'));
expect_same('the lists of the settings and what they hold', waf_settings_lists(), array(
	'waf_ban_logged_in_paths' => 'paths', 'waf_ban_full_paths' => 'paths', 'waf_login_cookies' => 'cookies',
	'waf_own_networks' => 'networks', 'waf_periods' => 'days'));

$fresh = waf_settings(array());
expect_same('the lists and numbers of 0.32.0 with their defaults', array(
	$fresh['waf_ban_logged_in_paths'], $fresh['waf_ban_full_paths'], $fresh['waf_login_cookies'],
	$fresh['waf_own_networks'], $fresh['waf_ban_origin_rows'], $fresh['waf_poll_seconds'],
	$fresh['waf_tick_fresh_seconds'], $fresh['waf_lock_retry_ms'], $fresh['waf_ban_rule_hits'],
	$fresh['waf_periods'], $fresh['waf_period_default'],
), array('/wp-admin/,/wp-json/', 'wp-login.php,xmlrpc.php', 'wordpress_logged_in_', '127.0.0.0/8,::1/128,10.50.0.0/24',
	25, 5, 180, 250, 200, '1,7,30,90', 7));
expect_same('an emptied list stays empty', array(
	waf_settings(array('waf_ban_logged_in_paths' => ''))['waf_ban_logged_in_paths'],
	waf_settings(array('waf_own_networks' => ''))['waf_own_networks'],
), array('', ''));
expect_same('the new numbers stay in their bounds', array(
	waf_settings(array('waf_ban_origin_rows' => '1'))['waf_ban_origin_rows'],
	waf_settings(array('waf_poll_seconds' => '999'))['waf_poll_seconds'],
	waf_settings(array('waf_tick_fresh_seconds' => '60'))['waf_tick_fresh_seconds'],
	waf_settings(array('waf_lock_retry_ms' => '1'))['waf_lock_retry_ms'],
), array(5, 60, 120, 50));
expect_same('the login cookie comes from the settings', array(
	waf_audit_parse_line($sample[0], array('joomla_user_'))['logged_in'],
	waf_audit_parse_line($sample[0], array('joomla_user_', 'wordpress_logged_in_'))['logged_in'],
	waf_audit_parse_line($sample[0], array())['logged_in'],
), array(false, true, false));

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_lib: alle Prüfungen bestanden\n";
