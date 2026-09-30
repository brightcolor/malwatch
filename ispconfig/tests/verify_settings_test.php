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

/**
 * The database of the server as the helper reads it: the settings row and the
 * rule catalog, as malwatch_rule holds it.
 */
class mw_fake_db
{
	public $config = array();
	public $rules = array();

	public function queryOneRecord($sql)
	{
		return strpos($sql, 'malwatch_config') !== false ? $this->config : null;
	}

	public function queryAllRecords($sql)
	{
		return strpos($sql, 'malwatch_rule') !== false ? $this->rules : array();
	}
}

$catalog = array(
	array('rule_id' => 'php.exec.background', 'severity' => 'medium', 'auto_safe' => 'n'),
	array('rule_id' => 'php.eval.variable', 'severity' => 'medium', 'auto_safe' => 'n'),
	array('rule_id' => 'binary.elf', 'severity' => 'medium', 'auto_safe' => 'n'),
	array('rule_id' => 'php.upload.unchecked', 'severity' => 'medium', 'auto_safe' => 'n'),
	array('rule_id' => 'php.stealth.touch_mtime', 'severity' => 'high', 'auto_safe' => 'n'),
	array('rule_id' => 'php.eval.request', 'severity' => 'critical', 'auto_safe' => 'y'),
);
$app = new stdClass();
$app->dbmaster = new mw_fake_db();
$app->dbmaster->rules = $catalog;

/** The value of a switch among the arguments, null when it is missing. */
function switch_value($args, $switch)
{
	foreach ($args as $arg) {
		if (strpos($arg, $switch . '=') === 0) {
			return substr($arg, strlen($switch) + 1);
		}
	}
	return null;
}

$helper = new malwatch_helper();
$defaults = $helper->config_defaults();

// --- The switches with the defaults --------------------------------------------
$args = $helper->verify_arguments($defaults);
expect_same('defaults', $args, array(
	'--modified-exts=php,php3,php4,php5,php7,php8,phtml,phps,phar,inc,module,tpl,twig,js,mjs,cjs,html,htm,svg,htaccess,ini',
	'--script-hosts=google-analytics.com,www.google-analytics.com,ssl.google-analytics.com,ajax.googleapis.com,code.jquery.com',
	'--verify-hosts=codeload.github.com,api.github.com,github.com,gitlab.com,bitbucket.org',
	'--test-dirs=test,tests,test-suite,testsuite,fixtures,__tests__',
	'--library-dirs=vendor,vendors,node_modules,bower_components',
	'--test-rules=php.exec.background,php.eval.variable,binary.elf',
	'--verify-packagist-url=https://repo.packagist.org',
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
	'test_dirs' => 'Spec, fixtures',
	'library_dirs' => 'lib',
	'test_rules' => 'php.upload.unchecked',
	'verify_max_downloads' => '3',
	'verify_max_mb' => '10',
	'verify_timeout' => '20',
	'verify_retry_hours' => '0',
	'verify_composer' => 'n',
	'verify_originals' => 'n',
	'hashlookup' => 'y',
	'hashlookup_url' => 'https://hashlookup.example.org',
	'verify_packagist_url' => 'https://packages.example.org/composer',
));
expect_same('other values', $helper->verify_arguments($custom), array(
	'--modified-exts=php,js,txt',
	'--script-hosts=',
	'--verify-hosts=codeload.github.com',
	'--test-dirs=spec,fixtures',
	'--library-dirs=lib',
	'--test-rules=php.upload.unchecked',
	'--verify-packagist-url=https://packages.example.org/composer',
	'--verify-max-downloads=3',
	'--verify-max-mb=10',
	'--verify-timeout=20',
	'--verify-retry-hours=0',
	'--no-verify-composer',
	'--no-verify-originals',
	'--hashlookup-url=https://hashlookup.example.org',
));
expect_same('no rule silenced', switch_value($helper->verify_arguments(array_merge($defaults, array('test_rules' => ''))),
	'--test-rules'), '');

// --- A stored value the page would refuse holds no scan up ------------------------
$broken = array_merge($defaults, array(
	'modified_exts' => 'php,p.hp',
	'script_hosts' => 'https://x.example',
	'test_dirs' => '../x',
	'library_dirs' => '',
	'verify_max_downloads' => '99999',
	'verify_timeout' => 'x',
	'hashlookup' => 'y',
	'hashlookup_url' => 'http://hashlookup.circl.lu',
	'verify_packagist_url' => 'https://user:secret@repo.packagist.org',
));
$args = $helper->verify_arguments($broken);
expect_same('broken list gets the default', switch_value($args, '--modified-exts'), $defaults['modified_exts']);
expect_same('broken hosts get the default', switch_value($args, '--script-hosts'), $defaults['script_hosts']);
expect_same('broken test folders get the default', switch_value($args, '--test-dirs'), $defaults['test_dirs']);
expect_same('no library folders get the default', switch_value($args, '--library-dirs'), $defaults['library_dirs']);
expect_same('a register with a login gets the default', switch_value($args, '--verify-packagist-url'), 'https://repo.packagist.org');
expect_same('number out of bounds gets the default', switch_value($args, '--verify-max-downloads'), '50');
expect_same('no number gets the default', switch_value($args, '--verify-timeout'), '60');

// --- Only hints fall silent in the tests of a library -------------------------------
foreach (array('a critical rule' => 'php.exec.background,php.eval.request', 'a high rule' => 'php.stealth.touch_mtime',
	'an unknown rule' => 'php.nope') as $name => $value) {
	expect_same($name . ' gets the default', switch_value($helper->verify_arguments(array_merge($defaults,
		array('test_rules' => $value))), '--test-rules'), $defaults['test_rules']);
}
$app->dbmaster->rules = array();
expect_same('without the catalog the default goes out', switch_value($helper->verify_arguments(array_merge($defaults,
	array('test_rules' => 'php.upload.unchecked'))), '--test-rules'), $defaults['test_rules']);
$app->dbmaster->rules = $catalog;

// --- An empty list that may be empty stays empty ------------------------------------
$app->dbmaster->config = array('config_id' => 1, 'test_rules' => '', 'script_hosts' => '', 'modified_exts' => '');
$stored = $helper->get_config();
expect_same('empty rule list kept', $stored['test_rules'], '');
expect_same('empty host list kept', $stored['script_hosts'], '');
expect_same('empty extensions get the default', $stored['modified_exts'], $defaults['modified_exts']);
$fresh = new malwatch_helper();
$app->dbmaster->config = array('config_id' => 1);
$stored = $fresh->get_config();
expect_same('missing column gets the default', $stored['test_rules'], $defaults['test_rules']);
expect_same('an address without https asks nobody', in_array('--hashlookup-url=http://hashlookup.circl.lu', $args, true), false);
expect_same('an empty list of extensions gets the default', $helper->verify_arguments(array_merge($defaults, array('modified_exts' => '')))[0],
	'--modified-exts=' . $defaults['modified_exts']);

// --- The panel checks and tidies the same way ---------------------------------------
$panel = malwatch_config_defaults();
foreach (array('modified_exts', 'script_hosts', 'verify_hosts', 'verify_packagist_url', 'verify_max_downloads', 'verify_max_mb',
	'verify_timeout', 'verify_retry_hours', 'verify_composer', 'verify_originals', 'hashlookup', 'hashlookup_url',
	'vanished_check_rows', 'test_dirs', 'library_dirs', 'test_rules') as $key) {
	expect_same('same default for ' . $key, (string) $panel[$key], (string) $defaults[$key]);
}
expect_same('test folders accepted', preg_match(malwatch_list_regex('test_dirs'), malwatch_list_tidy('Test, __tests__,test-suite')), 1);
expect_same('folder with a slash refused', preg_match(malwatch_list_regex('test_dirs'), malwatch_list_tidy('../x')), 0);
expect_same('no library folder refused', preg_match(malwatch_list_regex('library_dirs'), ''), 0);
expect_same('empty rule list accepted', preg_match(malwatch_list_regex('test_rules'), ''), 1);
expect_same('rule ids accepted', preg_match(malwatch_list_regex('test_rules'), 'php.exec.background,binary.elf'), 1);
expect_same('word without a dot refused', preg_match(malwatch_list_regex('test_rules'), 'php'), 0);
expect_same('page refuses strong and unknown rules', malwatch_test_rules_refused($catalog,
	'php.exec.background, PHP.EVAL.REQUEST,php.stealth.touch_mtime,php.nope'),
	array('php.eval.request', 'php.stealth.touch_mtime', 'php.nope'));
expect_same('page takes hints', malwatch_test_rules_refused($catalog, 'php.exec.background,binary.elf'), array());
expect_same('page without catalog refuses nothing', malwatch_test_rules_refused(array(), 'php.nope'), array());
expect_same('tidy list', malwatch_list_tidy(' PHP, .js ,, txt '), 'php,js,txt');
expect_same('extensions accepted', preg_match(malwatch_list_regex('modified_exts'), 'php,js,txt'), 1);
expect_same('extension with a dot refused', preg_match(malwatch_list_regex('modified_exts'), 'php,p.hp'), 0);
expect_same('empty extensions refused', preg_match(malwatch_list_regex('modified_exts'), ''), 0);
expect_same('empty hosts accepted', preg_match(malwatch_list_regex('script_hosts'), ''), 1);
expect_same('hosts accepted', preg_match(malwatch_list_regex('verify_hosts'), 'codeload.github.com,gitlab.com'), 1);
expect_same('host with scheme refused', preg_match(malwatch_list_regex('verify_hosts'), 'https://github.com'), 0);
expect_same('too many hosts refused', preg_match(malwatch_list_regex('verify_hosts'), implode(',', array_fill(0, 17, 'a.example'))), 0);
expect_same('range', malwatch_verify_range('verify_timeout'), '1:600');
expect_same('https address accepted', preg_match(malwatch_service_url_regex(), 'https://hashlookup.circl.lu'), 1);
expect_same('http address refused', preg_match(malwatch_service_url_regex(), 'http://hashlookup.circl.lu'), 0);
// The address goes to the scanner on its command line, where every user of
// the server can read it: a login in it is refused on both sides.
$login = 'https://user:secret@hashlookup.circl.lu';
expect_same('address with a login refused', preg_match(malwatch_service_url_regex(), $login), 0);
expect_same('address with a login asks nobody', in_array('--hashlookup-url=' . $login,
	$helper->verify_arguments(array_merge($defaults, array('hashlookup' => 'y', 'hashlookup_url' => $login))), true), false);
expect_same('address with port and path accepted', preg_match(malwatch_service_url_regex(), 'https://lookup.example.org:8443/api'), 1);
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
