<?php
/**
 * Checks the WAF files of a stage with modsec-rules-check, as root on the
 * server, without touching /etc/nginx:
 *
 *   php waf_rules_probe.php <stage>
 *
 * <stage> holds ispconfig/ and waf/ of the repository. The probe copies
 * waf/conf next to it, points main.conf at the copy and checks the shipped
 * set, one exception of every scope, both response body modes, the
 * emergency switch, and a broken file that the check has to refuse.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[1])) {
	fwrite(STDERR, "usage: php waf_rules_probe.php <stage>\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');
require $stage . '/ispconfig/interface/lib/malwatch_waf_lib.inc.php';

$found = glob('/usr/lib/*/libexec/modsec-rules-check');
if (!is_array($found) || count($found) === 0) {
	fwrite(STDERR, "modsec-rules-check fehlt\n");
	exit(2);
}
$tool = $found[0];
$dir = $stage . '/rules-probe';

function shipped($stage, $dir, $name)
{
	return str_replace('/etc/nginx/waf/', $dir . '/', (string) file_get_contents($stage . '/waf/conf/' . $name));
}

waf_remove_dir($dir);
mkdir($dir, 0700, true);
foreach (waf_conf_files($stage . '/waf/conf') as $file) {
	file_put_contents($dir . '/' . basename($file), shipped($stage, $dir, basename($file)));
}

$hosts = array(11 => array('exact' => array('beispiel.test', 'www.beispiel.test'), 'wildcard' => array('beispiel.test')));
$rows = array(
	array('exception_id' => 1, 'scope' => 'site', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 2, 'scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 3, 'scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '942100', 'path' => '', 'param' => 'filter', 'exception_state' => 'active'),
	array('exception_id' => 4, 'scope' => 'site_param', 'parent_domain_id' => 11, 'rule_id' => '941100', 'path' => '/suche', 'param' => 'json.query[0]', 'exception_state' => 'active'),
	array('exception_id' => 5, 'scope' => 'all_path', 'parent_domain_id' => 0, 'rule_id' => '941100', 'path' => '/xmlrpc.php', 'param' => '', 'exception_state' => 'active'),
	array('exception_id' => 6, 'scope' => 'all', 'parent_domain_id' => 0, 'rule_id' => '941160', 'path' => '', 'param' => '', 'exception_state' => 'active'),
);
$rules = waf_exception_rules($rows, $hosts);
if (count($rules['skipped']) > 0) {
	fwrite(STDERR, "exceptions left out: " . json_encode($rules['skipped']) . "\n");
	exit(1);
}

// name => array(files to replace, expected exit code 0 or not)
$variants = array(
	'shipped' => array(array(), true),
	'exceptions' => array(array('exclusions-panel-before.conf' => $rules['before'], 'exclusions-panel-after.conf' => $rules['after']), true),
	'lean' => array(array('response-body.conf' => waf_response_body_text('lean')), true),
	'emergency' => array(array('state.conf' => waf_state_file_text(true)), true),
	'broken' => array(array('exclusions-panel-before.conf' => "SecRuleBroken 1\n"), false),
);
$failures = 0;
foreach ($variants as $name => $variant) {
	foreach ($variant[0] as $file => $text) {
		file_put_contents($dir . '/' . $file, $text);
	}
	$output = array();
	$code = 0;
	exec(escapeshellarg($tool) . ' ' . escapeshellarg($dir . '/main.conf') . ' 2>&1', $output, $code);
	$passed = $code === 0;
	printf("%-11s %-9s %s\n", $name, $passed ? 'bestanden' : 'abgelehnt', $passed === $variant[1] ? 'wie erwartet' : 'FALSCH');
	if ($passed !== $variant[1]) {
		$failures++;
		echo '  ', implode("\n  ", $output), "\n";
	}
	foreach ($variant[0] as $file => $text) {
		file_put_contents($dir . '/' . $file, shipped($stage, $dir, $file));
	}
}
waf_remove_dir($dir);
exit($failures > 0 ? 1 : 0);
