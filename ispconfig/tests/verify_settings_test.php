<?php
/**
 * Checks the settings of 0.41.0 that keep false alarms away: how the server
 * hands them to the scanner, how the panel checks and tidies them, and that
 * the automatic quarantine only moves findings of a high level.
 *
 *   php ispconfig/tests/verify_settings_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_actions.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$helper = new malwatch_helper();
$defaults = $helper->config_defaults();

// --- The switches with the defaults --------------------------------------------
$args = $helper->verify_arguments($defaults);
expect_same('defaults', $args, array(
	'--modified-exts=php,php3,php4,php5,php7,php8,phtml,phps,phar,inc,module,tpl,twig,js,mjs,cjs,html,htm,svg,htaccess,ini',
	'--script-hosts=google-analytics.com,www.google-analytics.com,ssl.google-analytics.com,ajax.googleapis.com,code.jquery.com',
	'--verify-hosts=codeload.github.com,api.github.com,github.com,gitlab.com,bitbucket.org',
	'--verify-max-downloads=50',
	'--verify-max-mb=50',
	'--verify-timeout=60',
	'--verify-retry-hours=24',
));

// --- Other values than the defaults ----------------------------------------------
$custom = array_merge($defaults, array(
	'modified_exts' => 'php, JS ,txt',
	'script_hosts' => '',
	'verify_hosts' => 'codeload.github.com',
	'verify_max_downloads' => '3',
	'verify_max_mb' => '10',
	'verify_timeout' => '20',
	'verify_retry_hours' => '0',
	'verify_composer' => 'n',
	'verify_originals' => 'n',
	'hashlookup' => 'y',
	'hashlookup_url' => 'https://hashlookup.example.org',
));
expect_same('other values', $helper->verify_arguments($custom), array(
	'--modified-exts=php,js,txt',
	'--script-hosts=',
	'--verify-hosts=codeload.github.com',
	'--verify-max-downloads=3',
	'--verify-max-mb=10',
	'--verify-timeout=20',
	'--verify-retry-hours=0',
	'--no-verify-composer',
	'--no-verify-originals',
	'--hashlookup-url=https://hashlookup.example.org',
));

// --- A stored value the page would refuse holds no scan up ------------------------
$broken = array_merge($defaults, array(
	'modified_exts' => 'php,p.hp',
	'script_hosts' => 'https://x.example',
	'verify_max_downloads' => '99999',
	'verify_timeout' => 'x',
	'hashlookup' => 'y',
	'hashlookup_url' => 'http://hashlookup.circl.lu',
));
$args = $helper->verify_arguments($broken);
expect_same('broken list gets the default', $args[0], '--modified-exts=' . $defaults['modified_exts']);
expect_same('broken hosts get the default', $args[1], '--script-hosts=' . $defaults['script_hosts']);
expect_same('number out of bounds gets the default', $args[3], '--verify-max-downloads=50');
expect_same('no number gets the default', $args[5], '--verify-timeout=60');
expect_same('an address without https asks nobody', in_array('--hashlookup-url=http://hashlookup.circl.lu', $args, true), false);
expect_same('an empty list of extensions gets the default', $helper->verify_arguments(array_merge($defaults, array('modified_exts' => '')))[0],
	'--modified-exts=' . $defaults['modified_exts']);

// --- The panel checks and tidies the same way ---------------------------------------
$panel = malwatch_config_defaults();
foreach (array('modified_exts', 'script_hosts', 'verify_hosts', 'verify_max_downloads', 'verify_max_mb', 'verify_timeout',
	'verify_retry_hours', 'verify_composer', 'verify_originals', 'hashlookup', 'hashlookup_url', 'vanished_check_rows') as $key) {
	expect_same('same default for ' . $key, (string) $panel[$key], (string) $defaults[$key]);
}
expect_same('tidy list', malwatch_list_tidy(' PHP, .js ,, txt '), 'php,js,txt');
expect_same('extensions accepted', preg_match(malwatch_list_regex('modified_exts'), 'php,js,txt'), 1);
expect_same('extension with a dot refused', preg_match(malwatch_list_regex('modified_exts'), 'php,p.hp'), 0);
expect_same('empty extensions refused', preg_match(malwatch_list_regex('modified_exts'), ''), 0);
expect_same('empty hosts accepted', preg_match(malwatch_list_regex('script_hosts'), ''), 1);
expect_same('hosts accepted', preg_match(malwatch_list_regex('verify_hosts'), 'codeload.github.com,gitlab.com'), 1);
expect_same('host with scheme refused', preg_match(malwatch_list_regex('verify_hosts'), 'https://github.com'), 0);
expect_same('too many hosts refused', preg_match(malwatch_list_regex('verify_hosts'), implode(',', array_fill(0, 17, 'a.example'))), 0);
expect_same('range', malwatch_verify_range('verify_timeout'), '1:600');
expect_same('https address accepted', preg_match(malwatch_hashlookup_url_regex(), 'https://hashlookup.circl.lu'), 1);
expect_same('http address refused', preg_match(malwatch_hashlookup_url_regex(), 'http://hashlookup.circl.lu'), 0);
// The address goes to the scanner on its command line, where every user of
// the server can read it: a login in it is refused on both sides.
$login = 'https://user:secret@hashlookup.circl.lu';
expect_same('address with a login refused', preg_match(malwatch_hashlookup_url_regex(), $login), 0);
expect_same('address with a login asks nobody', in_array('--hashlookup-url=' . $login,
	$helper->verify_arguments(array_merge($defaults, array('hashlookup' => 'y', 'hashlookup_url' => $login))), true), false);
expect_same('address with port and path accepted', preg_match(malwatch_hashlookup_url_regex(), 'https://lookup.example.org:8443/api'), 1);
expect_same('address with port and path goes out', in_array('--hashlookup-url=https://lookup.example.org:8443/api',
	$helper->verify_arguments(array_merge($defaults, array('hashlookup' => 'y', 'hashlookup_url' => 'https://lookup.example.org:8443/api'))), true), true);

// --- The automatic quarantine moves findings of a high level only ------------------
$actions = new malwatch_actions();
$new = array(
	array('rule_id' => 'php.dynamic.request_call', 'severity' => 'critical', 'file_path' => '/web/a.php'),
	array('rule_id' => 'php.dynamic.request_call', 'severity' => 'medium', 'file_path' => '/web/guarded.php'),
	array('rule_id' => 'php.eval.variable', 'severity' => 'high', 'file_path' => '/web/b.php'),
);
$rules = array('php.dynamic.request_call' => true);
expect_same('safe: rule listed and high', $actions->select_auto($new, 'safe', $rules, '/web'), array('a.php'));
expect_same('preset: rule listed and high', $actions->select_auto($new, 'preset', $rules, '/web'), array('a.php'));
expect_same('critical: by level', $actions->select_auto($new, 'critical', null, '/web'), array('a.php'));

if ($failures > 0) {
	exit(1);
}
echo "verify settings OK\n";
