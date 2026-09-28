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

$rotate = waf_logrotate_text(14, '/var/log/waf/audit.log', '/var/log/waf/blocked.log');
expect_same('logrotate path', strpos($rotate, "\n/var/log/waf/audit.log {\n") !== false, true);
expect_same('logrotate keep', strpos($rotate, "\trotate 14\n") !== false, true);
expect_same('logrotate copytruncate', strpos($rotate, "\tcopytruncate\n") !== false, true);
expect_same('logrotate minimum', strpos(waf_logrotate_text(0, '/x', '/y'), "\trotate 1\n") !== false, true);

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
// From 0.35.0 the files with a place in them come from the settings; the
// fixtures hold them as they stand on the server with the defaults.
$main = waf_main_conf_text(waf_settings(array()));
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
	strpos(waf_block_text('detect', '/var/log/waf/blocked.log'), 'access_log /var/log/waf/blocked.log mw_block if=$mw_denied;') !== false, true);
expect_same('a website that is off keeps its vhost clean', waf_block_text('off', '/var/log/waf/blocked.log'), '');

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
	'waf_own_networks' => 'networks', 'waf_periods' => 'days',
	'waf_src_dbip_country_urls' => 'urls', 'waf_src_dbip_asn_urls' => 'urls', 'waf_src_maxmind_country_urls' => 'urls',
	'waf_src_maxmind_asn_urls' => 'urls', 'waf_src_tor_urls' => 'urls', 'waf_src_x4b_vpn_urls' => 'urls',
	'waf_src_x4b_datacenter_urls' => 'urls', 'waf_src_searchbots_urls' => 'urls', 'waf_proxycheck_url' => 'url'));

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

// --- The technical values of 0.34.0 ------------------------------------------------

$tech = waf_settings(array());
expect_same('the technical values with their defaults', array(
	$tech['waf_src_dbip_country_urls'], $tech['waf_src_dbip_country_min'], $tech['waf_src_dbip_country_mb'],
	$tech['waf_src_tor_min'], $tech['waf_src_tor_mb'], $tech['waf_src_x4b_vpn_min'], $tech['waf_src_searchbots_min'],
	$tech['waf_src_searchbots_mb'], $tech['waf_origin_bad_percent'], $tech['waf_origin_keep_percent'],
	$tech['waf_fetch_connect_seconds'], $tech['waf_fetch_timeout_seconds'], $tech['waf_fetch_redirects'],
	$tech['waf_proxycheck_url'], $tech['waf_proxycheck_batch'], $tech['waf_proxycheck_answer_mb'],
	$tech['waf_proxycheck_connect_seconds'], $tech['waf_proxycheck_timeout_seconds'],
	$tech['waf_proxycheck_retry_minutes'], $tech['waf_proxycheck_tries'], $tech['waf_origin_lookup_batch'],
	$tech['waf_cleanup_batch'], $tech['waf_cleanup_rounds'], $tech['waf_response_grace_minutes'],
	$tech['waf_blocked_lines'], $tech['waf_hit_rules_max'], $tech['waf_show_paths'], $tech['waf_preview_delay_ms'],
	$tech['waf_cli_jobs'], $tech['waf_cli_wait_margin_minutes'],
), array('https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz', 100000, 80, 100, 20, 1000, 10, 8, 1, 50,
	10, 120, 3, 'https://proxycheck.io/v3/', 100, 2, 5, 10, 60, 3, 500, 1000, 50, 60, 20000, 50, 50, 300, 20, 2));
expect_same('two addresses each for X4BNet and the search engines', array(
	count(waf_list_parse($tech['waf_src_x4b_vpn_urls'])), count(waf_list_parse($tech['waf_src_x4b_datacenter_urls'])),
	count(waf_list_parse($tech['waf_src_searchbots_urls']))), array(2, 2, 2));
expect_same('the technical numbers stay in their bounds', array(
	waf_settings(array('waf_fetch_redirects' => '99'))['waf_fetch_redirects'],
	waf_settings(array('waf_cleanup_batch' => '5'))['waf_cleanup_batch'],
	waf_settings(array('waf_src_tor_mb' => '0'))['waf_src_tor_mb'],
), array(10, 100, 1));
expect_same('addresses start with https:// and hold no space', waf_list_bad_urls(array(
	'https://a.example/x.csv.gz', 'https://a.example/lite-{month}.csv.gz', 'https://a.example:8443/list?x=1',
	'http://a.example/x', 'ftp://a.example/x', 'https://a b', 'https://', 'a.example')),
	array('http://a.example/x', 'ftp://a.example/x', 'https://a b', 'https://', 'a.example'));
expect_same('each list fits its column', array(waf_list_max('urls'), waf_list_max('url'), waf_list_max('paths')),
	array(512, 255, 1024));
expect_same('a list of addresses longer than its column', array(
	waf_list_fits(array(str_repeat('a', 512)), waf_list_max('urls')),
	waf_list_fits(array(str_repeat('a', 513)), waf_list_max('urls'))), array(true, false));
expect_same('the addresses and the single address of the settings', array(waf_settings_lists()['waf_src_tor_urls'],
	waf_settings_lists()['waf_proxycheck_url']), array('urls', 'url'));
expect_same('download options from the settings', waf_fetch_options(array_merge($tech,
	array('waf_fetch_connect_seconds' => 7, 'waf_fetch_timeout_seconds' => 90, 'waf_fetch_redirects' => 0))),
	array('connect' => 7, 'timeout' => 90, 'redirects' => 0));
expect_same('request options of proxycheck.io from the settings', waf_proxycheck_options(array_merge($tech,
	array('waf_proxycheck_connect_seconds' => 3, 'waf_proxycheck_timeout_seconds' => 20, 'waf_proxycheck_answer_mb' => 4))),
	array('connect' => 3, 'timeout' => 20, 'bytes' => 4194304));
expect_same('the address of proxycheck.io carries the key', array(
	waf_proxycheck_address('https://proxycheck.io/v3/', 'k-1'),
	waf_proxycheck_address('https://p.example/api?format=json', 'k 1')),
	array('https://proxycheck.io/v3/?key=k-1', 'https://p.example/api?format=json&key=k%201'));
expect_same('rule messages per hit follow the setting', array(count(waf_audit_parse_line($sample[2])['rules']),
	count(waf_audit_parse_line($sample[2], null, 2)['rules'])), array(3, 2));

// --- 0.35.0: places and names on the server -----------------------------------

// With the defaults every file comes out byte for byte as it stands on the
// server, so an update changes nothing on disk. The cron file gained the
// hourly guard in 0.35.0 and the watch over the scanner in 0.36.0.
$fixtures = __DIR__ . '/fixtures/waf';
$places = waf_settings(array());
expect_same('main.conf from the settings', waf_main_conf_text($places), file_get_contents($fixtures . '/main.conf'));
expect_same('settings.conf from the settings', waf_settings_conf_text($places), file_get_contents($fixtures . '/settings.conf'));
expect_same('include of the rules from the settings', waf_rules_include_text($places), file_get_contents($fixtures . '/waf.conf'));
expect_same('include of the block list from the settings', waf_blocked_include_text($places),
	file_get_contents($fixtures . '/waf-blocked.conf'));
expect_same('logrotate from the settings', waf_logrotate_text(7, $places['waf_audit_log'], $places['waf_blocked_log']),
	file_get_contents($fixtures . '/logrotate-waf'));
expect_same('cron file from the settings', waf_cron_text($places), file_get_contents($fixtures . '/cron-malwatch-waf'));
expect_same('the vhost block keeps its text', waf_block_text('detect', $places['waf_blocked_log']),
	"# WAF-BEGIN (detect) - managed by waf-switch\nmodsecurity on;\n"
	. 'access_log /var/log/waf/blocked.log mw_block if=$mw_denied;' . "\n# WAF-END\n");

// Other places reach every file.
$moved = array_merge($places, array(
	'waf_conf_dir' => '/opt/waf/rules', 'waf_modsec_base' => '/opt/modsec/base.conf',
	'waf_crs_setup' => '/opt/crs/setup.conf', 'waf_crs_rules' => '/opt/crs/rules/*.conf',
	'waf_audit_log' => '/srv/log/audit.json', 'waf_cache_dir' => '/srv/cache/waf',
	'waf_body_limit_kb' => 2048, 'waf_body_nofiles_limit_kb' => 64, 'waf_body_limit_action' => 'Reject',
	'waf_blocked_log' => '/srv/log/denied.log', 'waf_tools_dir' => '/opt/waf/bin', 'waf_hc_run' => '',
	'waf_guard_minute' => 17, 'waf_bin_dirs' => '/opt/bin,/usr/bin',
	'waf_hc_tick_name' => 'tick-a', 'waf_hc_guard_name' => 'guard-a',
));
$moved_main = waf_main_conf_text($moved);
expect_same('main.conf includes the base, the setup and the rules of the settings', array(
	strpos($moved_main, "Include /opt/modsec/base.conf\n") === 0,
	strpos($moved_main, "Include /opt/crs/setup.conf\n") !== false,
	strpos($moved_main, "Include /opt/crs/rules/*.conf\n") !== false,
	strpos($moved_main, "Include /opt/waf/rules/state.conf\n") !== false,
	strpos($moved_main, '/etc/'), strpos($moved_main, '/usr/')), array(true, true, true, true, false, false));
$moved_modsec = waf_settings_conf_text($moved);
expect_same('settings.conf carries the limits and places of the settings', array(
	strpos($moved_modsec, "SecRequestBodyLimit 2097152\n") !== false,
	strpos($moved_modsec, "SecRequestBodyNoFilesLimit 65536\n") !== false,
	strpos($moved_modsec, "SecRequestBodyLimitAction Reject\n") !== false,
	strpos($moved_modsec, "SecAuditLog /srv/log/audit.json\n") !== false,
	substr_count($moved_modsec, " /srv/cache/waf\n")), array(true, true, true, true, 2));
expect_same('settings.conf never allows more without files than in all', strpos(waf_settings_conf_text(
	array_merge($places, array('waf_body_limit_kb' => 100, 'waf_body_nofiles_limit_kb' => 500))),
	"SecRequestBodyNoFilesLimit 102400\n") !== false, true);
expect_same('the includes point at the rules directory of the settings', array(
	waf_rules_include_text($moved), strpos(waf_blocked_include_text($moved), "include /opt/waf/rules/blocked.conf;\n") !== false),
	array("# Loads the rules once for every server block; each website switches them on in its vhost.\n"
	. "modsecurity_rules_file /opt/waf/rules/main.conf;\n", true));
$moved_rotate = waf_logrotate_text(3, '/srv/log/audit.json', '/srv/log/denied.log');
expect_same('logrotate rotates the logs of the settings', array(strpos($moved_rotate, "/srv/log/audit.json {\n") !== false,
	strpos($moved_rotate, "\n/srv/log/denied.log {\n") !== false, strpos($moved_rotate, '/var/')), array(true, true, false));
$moved_cron = waf_cron_text($moved);
expect_same('without hc-run the runs start directly', array(
	strpos($moved_cron, "\n* * * * * root /opt/waf/bin/waf-switch tick > /dev/null 2>&1\n") !== false,
	strpos($moved_cron, "\n17 * * * * root /opt/waf/bin/waf-guard > /dev/null 2>&1\n") !== false,
	strpos($moved_cron, "\nPATH=/opt/bin:/usr/bin\n") !== false,
	strpos($moved_cron, 'hc-run')), array(true, true, true, false));
$moved_cron = waf_cron_text(array_merge($moved, array('waf_hc_run' => '/opt/hc/hc-run')));
expect_same('with hc-run each run reports under its name', array(
	strpos($moved_cron, 'then /opt/hc/hc-run tick-a -- /opt/waf/bin/waf-switch tick; else /opt/waf/bin/waf-switch tick; fi') !== false,
	strpos($moved_cron, 'then /opt/hc/hc-run guard-a -- /opt/waf/bin/waf-guard; else /opt/waf/bin/waf-guard; fi') !== false,
	strpos($moved_cron, '/etc/hc-run.d/tick-a.url') !== false), array(true, true, true));
expect_same('the vhost block writes into the log of the settings',
	strpos(waf_block_text('enforce', '/srv/log/denied.log'), 'access_log /srv/log/denied.log mw_block if=$mw_denied;' . "\n") !== false, true);
expect_same('without a log no line', strpos(waf_block_text('detect', ''), 'access_log'), false);

// The catalog of the places, their checks and their defaults.
$catalog = waf_path_settings();
expect_same('every place has its default', array_values(array_diff(array_keys($catalog), array_keys(waf_settings_defaults()))), array());
expect_same('the groups of the places', array_values(array_unique(array_map(function ($one) {
	return $one['group'];
}, $catalog))), array('nginx', 'modsec', 'logs', 'tools'));
expect_same('the defaults are the places of today', array($places['waf_rules_include'], $places['waf_blocked_include'],
	$places['waf_modsec_base'], $places['waf_crs_setup'], $places['waf_crs_rules'], $places['waf_rules_check'],
	$places['waf_cache_dir'], $places['waf_blocked_log'], $places['waf_guard_log'], $places['waf_backup_dir'],
	$places['waf_logrotate_file'], $places['waf_cron_file'], $places['waf_tools_dir'], $places['waf_hc_run'],
	$places['waf_nginx_service'], $places['waf_hc_tick_name'], $places['waf_hc_guard_name'], $places['waf_bin_dirs']),
	array('/etc/nginx/conf.d/waf.conf', '/etc/nginx/conf.d/waf-blocked.conf', '/etc/nginx/modsecurity.conf',
	'/etc/modsecurity/crs/crs-setup.conf', '/usr/share/modsecurity-crs/rules/*.conf', '/usr/lib/*/libexec/modsec-rules-check',
	'/var/cache/waf', '/var/log/waf/blocked.log', '/var/log/waf/guard.log', '/var/backups/waf-switch',
	'/etc/logrotate.d/waf', '/etc/cron.d/malwatch-waf', '/usr/local/sbin', '/usr/local/sbin/hc-run', 'nginx',
	'waf-tick', 'waf-guard', '/usr/local/sbin,/usr/local/bin,/usr/sbin,/usr/bin,/sbin,/bin'));
expect_same('the variable of a place', waf_path_env('waf_conf_dir'), 'MALWATCH_WAF_CONF_DIR');

expect_same('a directory loses its closing slash', waf_path_check('dir', '/opt/waf/'), array('/opt/waf', ''));
expect_same('double slashes count once', waf_path_check('file', '/var//log/waf/a.log'), array('/var/log/waf/a.log', ''));
expect_same('a relative path is refused', waf_path_check('file', 'var/log/a.log')[1], 'relative');
expect_same('spaces and umlauts are refused', array(waf_path_check('file', '/var/log/a b.log')[1],
	waf_path_check('dir', "/var/l\xC3\xB6g")[1]), array('chars', 'chars'));
expect_same('dots as a folder are refused', array(waf_path_check('file', '/var/log/../a.log')[1],
	waf_path_check('dir', '/var/./log')[1], waf_path_check('file', '/var/log/waf/audit.log.1')[1]), array('dots', 'dots', ''));
expect_same('the root is no directory of its own', array(waf_path_check('dir', '/')[1], waf_path_check('dir', '//')[1]),
	array('root', 'root'));
expect_same('a file needs a name', waf_path_check('file', '/var/log/')[1], 'trailing');
expect_same('only a pattern may hold a star', array(waf_path_check('pattern', '/usr/share/crs/*.conf')[1],
	waf_path_check('file', '/usr/share/crs/*.conf')[1]), array('', 'chars'));
expect_same('a path fits its column', array(waf_path_check('file', '/' . str_repeat('a', 254))[1],
	waf_path_check('file', '/' . str_repeat('a', 255))[1]), array('', 'long'));
expect_same('an empty place is refused, an empty hc-run allowed', array(waf_path_check('file', '')[1],
	waf_path_check('program', '')), array('empty', array('', '')));
expect_same('names for systemd and healthchecks', array(waf_path_check('name', 'nginx')[1],
	waf_path_check('name', 'waf-tick.2')[1], waf_path_check('name', 'nginx; reboot')[1], waf_path_check('name', '')[1],
	waf_path_check('name', str_repeat('a', 65))[1]), array('', '', 'name', 'empty', 'name'));
expect_same('directories of programs', array(waf_path_check('dirs', "/opt/bin/\n/usr/bin, /opt/bin"),
	waf_path_check('dirs', '/opt/bin,bin')[1], waf_path_check('dirs', ' , ')[1]),
	array(array('/opt/bin,/usr/bin', ''), 'relative', 'empty'));

$stored = waf_settings(array('waf_blocked_log' => 'blocked.log', 'waf_cron_file' => '/etc/cron.d/malwatch-waf/',
	'waf_hc_run' => '', 'waf_nginx_service' => 'nginx.service', 'waf_bin_dirs' => '', 'waf_crs_rules' => '/opt/crs/*.conf'));
expect_same('stored places are checked like typed ones', array($stored['waf_blocked_log'], $stored['waf_cron_file'],
	$stored['waf_hc_run'], $stored['waf_nginx_service'], $stored['waf_bin_dirs'], $stored['waf_crs_rules']),
	array('/var/log/waf/blocked.log', '/etc/cron.d/malwatch-waf', '', 'nginx.service',
	'/usr/local/sbin,/usr/local/bin,/usr/sbin,/usr/bin,/sbin,/bin', '/opt/crs/*.conf'));

// The limits of ModSecurity and the minutes of the clock stand in the panel.
$clock = waf_settings(array());
expect_same('limits of ModSecurity and minutes of the clock by default', array($clock['waf_body_limit_kb'],
	$clock['waf_body_nofiles_limit_kb'], $clock['waf_body_limit_action'], $clock['waf_guard_minute'],
	$clock['waf_hourly_minute']), array(12800, 128, 'ProcessPartial', 5, 7));
$clock = waf_settings(array('waf_body_limit_kb' => '0', 'waf_body_nofiles_limit_kb' => '2000000',
	'waf_body_limit_action' => 'Drop', 'waf_guard_minute' => '60', 'waf_hourly_minute' => '-1'));
expect_same('limits and minutes stay in their ranges', array($clock['waf_body_limit_kb'],
	$clock['waf_body_nofiles_limit_kb'], $clock['waf_body_limit_action'], $clock['waf_guard_minute'],
	$clock['waf_hourly_minute']), array(1, 1048576, 'ProcessPartial', 59, 0));
expect_same('both answers to a large request', waf_body_limit_actions(), array('ProcessPartial', 'Reject'));

// waf/install.sh hands changes over through the environment.
$overlay = waf_path_overlay($places, array('MALWATCH_WAF_CONF_DIR' => '/opt/waf/', 'PATH' => '/usr/bin',
	'MALWATCH_WAF_LIB' => '/tmp/lib.php'));
expect_same('the environment moves a place', array($overlay['values']['waf_conf_dir'], $overlay['changed'],
	$overlay['problems']), array('/opt/waf', array('waf_conf_dir'), array()));
$overlay = waf_path_overlay($places, array('MALWATCH_WAF_CONFDIR' => '/opt/waf', 'MALWATCH_WAF_GUARD_MINUTE' => '9',
	'MALWATCH_WAF_AUDIT_LOG' => 'audit.log'));
expect_same('a typing error, a setting of the panel and a bad path are named', array_map(function ($one) {
	return array($one['problem'], $one['name']);
}, $overlay['problems']), array(array('unknown', 'MALWATCH_WAF_CONFDIR'), array('panel', 'MALWATCH_WAF_GUARD_MINUTE'),
	array('relative', 'MALWATCH_WAF_AUDIT_LOG')));
expect_same('a bad value keeps the stored one', array($overlay['values']['waf_audit_log'], $overlay['changed']),
	array('/var/log/waf/audit.log', array()));
$overlay = waf_path_overlay($places, array('MALWATCH_WAF_BLOCKED_LOG' => '/var/log/waf/audit.log',
	'MALWATCH_WAF_BACKUP_DIR' => '/var/cache/waf/'));
expect_same('two places in one file or one directory are refused', array_map(function ($one) {
	return array($one['problem'], $one['key'], $one['other']);
}, $overlay['problems']), array(array('same_file', 'waf_blocked_log', 'waf_audit_log'),
	array('same_dir', 'waf_backup_dir', 'waf_cache_dir')));
expect_same('the stored places pass their own check', waf_path_overlay($places, array())['problems'], array());

// What waf-switch paths hands to waf/install.sh.
$shell = waf_path_shell_text($places, waf_path_overlay($places, array('MALWATCH_WAF_CONF_DIR' => '/opt/waf')),
	'/var/lib/malwatch/waf/lock', 3);
expect_same('the shell lines of a moved place', array(
	strpos($shell, "WAF_CONF_DIR='/opt/waf'\nOLD_WAF_CONF_DIR='/etc/nginx/waf'\n") === 0,
	strpos($shell, "WAF_HC_RUN='/usr/local/sbin/hc-run'\n") !== false,
	strpos($shell, "WAF_BIN_PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n") !== false,
	strpos($shell, "WAF_CHANGED='waf_conf_dir'\nWAF_LOCK='/var/lib/malwatch/waf/lock'\nWAF_SITES=3\n") !== false,
	substr_count($shell, "\n")), array(true, true, true, true, 2 * count(waf_path_settings()) + 4));
expect_same('a quote in a value stays inside the quotes', waf_shell_quote("/a'b"), "'/a'\\''b'");
expect_same('every file of the installer by its name', array(
	waf_path_render_text('main.conf', $places) === waf_main_conf_text($places),
	waf_path_render_text('settings.conf', $places) === waf_settings_conf_text($places),
	waf_path_render_text('rules-include', $places) === waf_rules_include_text($places),
	waf_path_render_text('blocked-include', $places) === waf_blocked_include_text($places),
	waf_path_render_text('logrotate', $places) === waf_logrotate_text(7, $places['waf_audit_log'], $places['waf_blocked_log']),
	waf_path_render_text('cron', $places) === waf_cron_text($places),
	waf_path_render_text('other', $places)), array(true, true, true, true, true, true, null));
expect_same('a problem names the variable, the value and the way out', array(
	waf_path_problem_text(array('problem' => 'relative', 'key' => 'waf_audit_log', 'name' => 'MALWATCH_WAF_AUDIT_LOG',
		'value' => 'a.log', 'other' => '')),
	strpos(waf_path_problem_text(array('problem' => 'same_file', 'key' => 'waf_blocked_log', 'name' => 'MALWATCH_WAF_BLOCKED_LOG',
		'value' => '/x', 'other' => 'waf_audit_log')), 'nutzt schon MALWATCH_WAF_AUDIT_LOG') !== false,
	strpos(waf_path_problem_text(array('problem' => 'chars', 'key' => 'waf_crs_rules', 'name' => 'MALWATCH_WAF_CRS_RULES',
		'value' => '/a b', 'other' => '')), '. _ / - *') !== false,
), array('MALWATCH_WAF_AUDIT_LOG=a.log ist kein absoluter Pfad. Bitte mit / beginnen, etwa /var/log/waf/audit.log.', true, true));
foreach (array('empty', 'relative', 'chars', 'dots', 'root', 'trailing', 'long', 'name', 'same_file', 'same_dir', 'panel',
	'unknown') as $code) {
	$text = waf_path_problem_text(array('problem' => $code, 'key' => 'waf_conf_dir', 'name' => 'MALWATCH_WAF_CONF_DIR',
		'value' => '/x', 'other' => 'waf_cache_dir'));
	expect_same("problem $code has a sentence", array(strpos($text, 'MALWATCH_WAF_CONF_DIR') === 0, strpos($text, '%'),
		substr($text, -1)), array(true, false, '.'));
}

// --- 0.36.0: the watch over the scanner ----------------------------------------

date_default_timezone_set('UTC');
$watch = waf_settings(array());
expect_same('the settings of the watch and their defaults', array($watch['waf_watch_minutes'],
	$watch['waf_watch_stale_minutes'], $watch['waf_watch_pending_minutes'], $watch['waf_watch_overdue_hours'],
	$watch['waf_watch_remind_hours'], $watch['waf_watch_crash_pause'], $watch['waf_hc_watch_name']),
	array(5, 15, 180, 12, 24, 10, 'malwatch-wache'));
expect_same('the name of the watch is a place', $catalog['waf_hc_watch_name'], array('kind' => 'name', 'group' => 'tools'));

// The cron file starts the watch every waf_watch_minutes, under its own name.
expect_same('the cron file runs the watch every five minutes', strpos(waf_cron_text($moved),
	"\n*/5 * * * * root /opt/waf/bin/waf-switch watch > /dev/null 2>&1\n") !== false, true);
expect_same('every minute is a plain star', strpos(waf_cron_text(array_merge($moved, array('waf_watch_minutes' => 1))),
	"\n* * * * * root /opt/waf/bin/waf-switch watch > /dev/null 2>&1\n") !== false, true);
$watch_cron = waf_cron_text(array_merge($moved, array('waf_hc_run' => '/opt/hc/hc-run', 'waf_hc_watch_name' => 'watch-a',
	'waf_watch_minutes' => 10)));
expect_same('with hc-run the watch reports under its name', array(
	strpos($watch_cron, "\n*/10 * * * * root if [ -x /opt/hc/hc-run ]; then /opt/hc/hc-run watch-a -- /opt/waf/bin/waf-switch watch; "
		. "else /opt/waf/bin/waf-switch watch; fi > /dev/null 2>&1\n") !== false,
	strpos($watch_cron, '/etc/hc-run.d/watch-a.url') !== false), array(true, true));

// What the watch makes of the state. A fixed clock; the facts of a healthy scanner.
$now = gmmktime(13, 53, 20, 9, 22, 2026);
$facts = array(
	'now' => $now,
	'cron' => array('running' => false, 'last_run' => $now - 60, 'next_run' => $now),
	'cron_alive' => false,
	'crash' => null,
	'crash_new' => false,
	'pending' => array('count' => 3, 'oldest' => $now - 600),
	'sites' => array(
		array('domain' => 'a.test', 'days' => 1, 'last_run' => $now - 3600),
		array('domain' => 'b.test', 'days' => 7, 'last_run' => $now - 3 * 86400),
	),
	'plans' => array(),
);
$healthy = waf_watch_assess($facts, $watch);
expect_same('a healthy scanner', array($healthy['release'], $healthy['kinds'], $healthy['problems'], $healthy['lines']),
	array(false, array(), array(), array('Alles in Ordnung: Der Cron-Job lief zuletzt 22.09.2026 13:52, 3 Aufträge warten.')));
expect_same('the watch notes when it first saw each interval', $healthy['plans'], array(
	'a.test' => array('days' => 1, 'since' => $now), 'b.test' => array('days' => 7, 'since' => $now)));

$stale_cron = array('running' => true, 'last_run' => $now - 20 * 60, 'next_run' => $now - 19 * 60);
$stale = waf_watch_assess(array_merge($facts, array('cron' => $stale_cron)), $watch);
expect_same('a job marked as running without the cron of ISPConfig gets freed', array($stale['release'], $stale['kinds'],
	$stale['problems']), array(true, array('stale'), array('Der Cron-Job von malwatch galt seit 22.09.2026 13:33 als laufend, '
	. 'obwohl der Cron von ISPConfig nicht mehr lief. Die Wache hat die Sperre gelöst, damit der Job wieder startet.')));
expect_same('within the limit the running job is left alone', waf_watch_assess(array_merge($facts, array('cron' =>
	array('running' => true, 'last_run' => $now - 5 * 60, 'next_run' => $now - 4 * 60))), $watch)['kinds'], array());
$busy = waf_watch_assess(array_merge($facts, array('cron' => $stale_cron, 'cron_alive' => true)), $watch);
expect_same('while the cron of ISPConfig still works the watch only reports', array($busy['release'], $busy['kinds']),
	array(false, array('busy')));
expect_same('another limit from the settings', waf_watch_assess(array_merge($facts, array('cron' => $stale_cron)),
	array_merge($watch, array('waf_watch_stale_minutes' => 30)))['kinds'], array());
$silent = waf_watch_assess(array_merge($facts, array('cron' => array('running' => false, 'last_run' => $now - 40 * 60,
	'next_run' => $now - 39 * 60))), $watch);
expect_same('a job that stopped running', array($silent['release'], $silent['kinds'], $silent['problems']), array(false,
	array('silent'), array('Der Cron-Job von malwatch lief zuletzt 22.09.2026 13:13. Bitte prüfen, ob der Cron von ISPConfig '
	. '(cron.sh in der crontab von root) läuft.')));
expect_same('a pause after a crash is no silence', waf_watch_assess(array_merge($facts, array('cron' => array('running' => false,
	'last_run' => $now - 40 * 60, 'next_run' => $now + 5 * 60))), $watch)['kinds'], array());
expect_same('without a row in sys_cron', waf_watch_assess(array_merge($facts, array('cron' => null)), $watch)['kinds'],
	array('no_row'));

$crash = array('time' => $now - 120, 'text' => 'malwatch_waf.inc.php:80: Allowed memory size of 134217728 bytes exhausted.',
	'pause_until' => $now + 480);
$crashed = waf_watch_assess(array_merge($facts, array('crash' => $crash, 'crash_new' => true)), $watch);
expect_same('a crash the watch has not reported yet', array($crashed['kinds'], $crashed['problems']), array(array('crash'),
	array('Der Cron-Job von malwatch ist 22.09.2026 13:51 abgestürzt: malwatch_waf.inc.php:80: Allowed memory size of '
	. '134217728 bytes exhausted. Er pausiert bis 22.09.2026 14:01 und startet dann neu.')));
expect_same('during its pause a reported crash stays a problem', waf_watch_assess(array_merge($facts,
	array('crash' => $crash)), $watch)['kinds'], array('crash'));
expect_same('after the pause a reported crash stays quiet', waf_watch_assess(array_merge($facts, array('crash' =>
	array_merge($crash, array('pause_until' => $now - 60)))), $watch)['kinds'], array());

$waiting = waf_watch_assess(array_merge($facts, array('pending' => array('count' => 59, 'oldest' => $now - 4 * 3600))), $watch);
expect_same('jobs waiting too long', array($waiting['kinds'], $waiting['problems']), array(array('pending'),
	array('59 Aufträge warten, der älteste seit 22.09.2026 09:53. Bitte unter Security > Scanner nachsehen, ob ein Lauf hängt.')));
expect_same('one job waiting', waf_watch_assess(array_merge($facts, array('pending' => array('count' => 1,
	'oldest' => $now - 4 * 3600))), $watch)['problems'], array('1 Auftrag wartet seit 22.09.2026 09:53. Bitte unter '
	. 'Security > Scanner nachsehen, ob ein Lauf hängt.'));
expect_same('another waiting limit from the settings', waf_watch_assess(array_merge($facts, array('pending' =>
	array('count' => 59, 'oldest' => $now - 4 * 3600))), array_merge($watch, array('waf_watch_pending_minutes' => 300)))['kinds'],
	array());

// A website is late once its last scan lies further back than its interval in
// days plus the grace. The watch counts from the last scan, or from the moment
// it first saw the interval of the website, whichever came later ($plans from
// its previous run).
$long_ago = $now - 100 * 86400;
$sites = array(
	array('domain' => 'a.test', 'days' => 1, 'last_run' => $now - 37 * 3600),
	array('domain' => 'b.test', 'days' => 7, 'last_run' => $now - 3 * 86400),
	array('domain' => 'c.test', 'days' => 30, 'last_run' => $now - 40 * 86400),
	array('domain' => 'd.test', 'days' => 1, 'last_run' => null),
	array('domain' => 'e.test', 'days' => 0, 'last_run' => $now - 400 * 86400),
);
$plans = array();
foreach ($sites as $site) {
	$plans[$site['domain']] = array('days' => $site['days'], 'since' => $long_ago);
}
$late = waf_watch_assess(array_merge($facts, array('sites' => $sites, 'plans' => $plans)), $watch);
expect_same('websites checked later than planned', array($late['kinds'], $late['problems']), array(array('overdue'),
	array('3 Websites wurden länger nicht geprüft als geplant: a.test (zuletzt 21.09.2026 00:53), c.test (zuletzt 13.08.2026 '
	. '13:53), d.test (noch nie geprüft).')));
expect_same('a website without an interval drops out of the plans', array_keys($late['plans']),
	array('a.test', 'b.test', 'c.test', 'd.test'));
expect_same('another grace from the settings', waf_watch_assess(array_merge($facts, array('sites' => array($sites[0]),
	'plans' => $plans)), array_merge($watch, array('waf_watch_overdue_hours' => 48)))['kinds'], array());

// Every 2 days: late after 2 days and 12 hours of grace, not before.
$two = array(
	array('domain' => 'f.test', 'days' => 2, 'last_run' => $now - 61 * 3600),
	array('domain' => 'g.test', 'days' => 2, 'last_run' => $now - 59 * 3600),
);
expect_same('every 2 days: late after 60 hours', waf_watch_assess(array_merge($facts, array('sites' => $two,
	'plans' => array('f.test' => array('days' => 2, 'since' => $long_ago), 'g.test' => array('days' => 2, 'since' => $long_ago)))),
	$watch)['problems'], array('1 Website wurde länger nicht geprüft als geplant: f.test (zuletzt 20.09.2026 00:53).'));

// A new or changed interval gets its full time from the moment the watch saw
// it: switching every website to 2 days with the first scans spread over the
// two days raises no alarm while their turn lies ahead.
$switched = array(array('domain' => 'h.test', 'days' => 2, 'last_run' => $now - 20 * 86400));
$first_look = waf_watch_assess(array_merge($facts, array('sites' => $switched, 'plans' => array())), $watch);
expect_same('an interval the watch has not seen yet', array($first_look['kinds'], $first_look['plans']),
	array(array(), array('h.test' => array('days' => 2, 'since' => $now))));
/** The facts of a healthy scanner at a later time. */
function watch_facts_at($facts, $time)
{
	return array_merge($facts, array('now' => $time, 'cron' => array('running' => false, 'last_run' => $time - 60,
		'next_run' => $time), 'pending' => array('count' => 0, 'oldest' => null)));
}
expect_same('59 hours after the switch it is not late yet', waf_watch_assess(array_merge(watch_facts_at($facts,
	$now + 59 * 3600), array('sites' => $switched, 'plans' => $first_look['plans'])), $watch)['kinds'], array());
expect_same('61 hours after the switch without a scan it is late', waf_watch_assess(array_merge(watch_facts_at($facts,
	$now + 61 * 3600), array('sites' => $switched, 'plans' => $first_look['plans'])), $watch)['kinds'], array('overdue'));
$changed = waf_watch_assess(array_merge($facts, array('sites' => array($sites[0]),
	'plans' => array('a.test' => array('days' => 7, 'since' => $long_ago)))), $watch);
expect_same('a changed interval starts anew', array($changed['kinds'], $changed['plans']),
	array(array(), array('a.test' => array('days' => 1, 'since' => $now))));
expect_same('an unchanged interval keeps its start', waf_watch_assess(array_merge($facts, array('sites' => array($sites[0]),
	'plans' => $plans)), $watch)['plans'], array('a.test' => array('days' => 1, 'since' => $long_ago)));
expect_same('a website never scanned is late once its plan is older than interval and grace', array(
	waf_watch_assess(array_merge($facts, array('sites' => array($sites[3]),
		'plans' => array('d.test' => array('days' => 1, 'since' => $now - 35 * 3600)))), $watch)['kinds'],
	waf_watch_assess(array_merge($facts, array('sites' => array($sites[3]),
		'plans' => array('d.test' => array('days' => 1, 'since' => $now - 37 * 3600)))), $watch)['kinds']),
	array(array(), array('overdue')));
expect_same('a zero date counts as never scanned', waf_watch_assess(array_merge($facts, array('sites' => array(
	array('domain' => 'z.test', 'days' => 1, 'last_run' => 0)), 'plans' => array('z.test' => array('days' => 1,
	'since' => $long_ago)))), $watch)['problems'], array('1 Website wurde länger nicht geprüft als geplant: z.test (noch nie '
	. 'geprüft).'));
expect_same('plans from a damaged state file count as unseen', waf_watch_assess(array_merge($facts, array(
	'sites' => array($sites[0]), 'plans' => array('a.test' => 'kaputt'))), $watch)['plans'],
	array('a.test' => array('days' => 1, 'since' => $now)));

$many = array();
$many_plans = array();
for ($i = 1; $i <= 5; $i++) {
	$many[] = array('domain' => 'w' . $i . '.test', 'days' => 1, 'last_run' => $now - 50 * 3600);
	$many_plans['w' . $i . '.test'] = array('days' => 1, 'since' => $long_ago);
}
expect_same('five late websites show three and the rest', waf_watch_assess(array_merge($facts, array('sites' => $many,
	'plans' => $many_plans)), $watch)['problems'], array('5 Websites wurden länger nicht geprüft als geplant: w1.test (zuletzt '
	. '20.09.2026 11:53), w2.test (zuletzt 20.09.2026 11:53), w3.test (zuletzt 20.09.2026 11:53) und weitere.'));
$all = waf_watch_assess(array_merge($facts, array('cron' => $stale_cron, 'crash' => $crash, 'crash_new' => true,
	'pending' => array('count' => 59, 'oldest' => $now - 4 * 3600), 'sites' => $sites, 'plans' => $plans)), $watch);
expect_same('the problems in a fixed order', array($all['kinds'], $all['lines'] === $all['problems']),
	array(array('stale', 'crash', 'pending', 'overdue'), true));

// The end of a scan as PHP wrote it, read back in the zone it was written in:
// ISPConfig writes in its own zone ($conf['timezone']), waf-switch runs in the
// zone of the server, and MySQL may run in a third.
$scan_end = gmmktime(8, 31, 19, 9, 28, 2026);
expect_same('a time written in UTC', waf_time_in_zone('2026-09-28 08:31:19', 'Etc/UTC'), $scan_end);
expect_same('the same moment written in Berlin summer time', waf_time_in_zone('2026-09-28 10:31:19', 'Europe/Berlin'),
	$scan_end);
expect_same('no time, an empty text and a zero date', array(waf_time_in_zone(null, 'Etc/UTC'), waf_time_in_zone('', 'Etc/UTC'),
	waf_time_in_zone('0000-00-00 00:00:00', 'Etc/UTC')), array(null, null, null));
expect_same('an unknown zone reads the text in the zone of PHP', waf_time_in_zone('2026-09-28 08:31:19', 'Mond/Basis'),
	$scan_end);
expect_same('a text that is no time', waf_time_in_zone('kein Datum', 'Etc/UTC'), null);

// When the watch writes a mail: a new kind of problem, a reminder, the all-clear.
expect_same('a new problem mails', waf_watch_mail_due(array(), array('stale'), $now, $watch), 'problem');
expect_same('the same problem waits for the reminder', waf_watch_mail_due(array('kinds' => array('stale'),
	'mailed_at' => $now - 3600), array('stale'), $now, $watch), '');
expect_same('the reminder after waf_watch_remind_hours', waf_watch_mail_due(array('kinds' => array('stale'),
	'mailed_at' => $now - 25 * 3600), array('stale'), $now, $watch), 'problem');
expect_same('another reminder time from the settings', waf_watch_mail_due(array('kinds' => array('stale'),
	'mailed_at' => $now - 25 * 3600), array('stale'), $now, array_merge($watch, array('waf_watch_remind_hours' => 48))), '');
expect_same('another kind of problem mails at once', waf_watch_mail_due(array('kinds' => array('stale'),
	'mailed_at' => $now - 3600), array('stale', 'pending'), $now, $watch), 'problem');
expect_same('the all-clear', waf_watch_mail_due(array('kinds' => array('stale'), 'mailed_at' => $now - 3600), array(), $now,
	$watch), 'clear');
expect_same('nothing to say', waf_watch_mail_due(array(), array(), $now, $watch), '');
$mail = waf_watch_mail_text(array('Erstes Problem.', 'Zweites Problem.'), 'web.test', $now - 600);
expect_same('the problem mail', array($mail['subject'], strpos($mail['body'], "seit 22.09.2026 13:43:\n\n- Erstes Problem.\n"
	. "- Zweites Problem.\n") !== false, strpos($mail['body'], 'Abwehr > Einstellungen > Takt und Hintergrund') !== false),
	array('malwatch auf web.test: 2 Probleme mit dem Scanner', true, true));
expect_same('one problem', waf_watch_mail_text(array('Ein Problem.'), 'web.test', $now)['subject'],
	'malwatch auf web.test: 1 Problem mit dem Scanner');
$clear = waf_watch_clear_text('web.test', $now - 3600);
expect_same('the all-clear mail', array($clear['subject'], strpos($clear['body'], 'seit 22.09.2026 12:53') !== false),
	array('malwatch auf web.test: Scanner wieder in Ordnung', true));

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_lib: alle Prüfungen bestanden\n";
