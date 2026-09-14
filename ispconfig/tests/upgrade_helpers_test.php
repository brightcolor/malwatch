<?php
/**
 * Checks the pure helpers an upgrade job is built from.
 *
 *   php ispconfig/tests/upgrade_helpers_test.php
 */
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

expect_same('cgi with version', malwatch_helper::cli_php_path('/usr/bin/php-cgi8.2'), '/usr/bin/php8.2');
expect_same('cgi without version', malwatch_helper::cli_php_path('/opt/php-8.1/bin/php-cgi'), '/opt/php-8.1/bin/php');
expect_same('not a cgi binary', malwatch_helper::cli_php_path('/usr/sbin/php-fpm8.2'), '');
expect_same('shell characters', malwatch_helper::cli_php_path('/usr/bin/php-cgi8.2; rm -rf /'), '');

expect_same('any address', malwatch_helper::connect_address(array('ip_address' => '*')), '127.0.0.1');
expect_same('empty address', malwatch_helper::connect_address(array('ip_address' => '')), '127.0.0.1');
expect_same('vhost address', malwatch_helper::connect_address(array('ip_address' => '10.50.0.11')), '10.50.0.11');
expect_same('garbage address', malwatch_helper::connect_address(array('ip_address' => 'localhost;')), '127.0.0.1');

$root = '/var/www/clients/client3/web12/web';
expect_same('install at the root', malwatch_helper::install_url('beispiel.de', true, $root, $root), 'https://beispiel.de/');
expect_same('install in a folder', malwatch_helper::install_url('beispiel.de', false, $root, $root . '/blog'), 'http://beispiel.de/blog/');
expect_same('folder with a space', malwatch_helper::install_url('beispiel.de', true, $root, $root . '/alte seite'), 'https://beispiel.de/alte%20seite/');

expect_same('plugin install', malwatch_helper::install_of($root . '/blog/wp-content/plugins/akismet', 'plugin'), $root . '/blog');
expect_same('theme in a renamed content directory', malwatch_helper::install_of($root . '/inhalt/themes/vier', 'theme'), $root);
expect_same('plugin outside plugins/', malwatch_helper::install_of($root . '/wp-content/akismet', 'plugin'), '');
expect_same('core', malwatch_helper::install_of($root, 'core'), '');

// The wait before the check: revalidate_freq of the pool plus one second.
$php_ini = "[PHP]\nengine = On\n[opcache]\n;opcache.enable=1\n;opcache.revalidate_freq=0\n";
expect_same('defaults', malwatch_helper::opcache_settle(array($php_ini), ''), array('seconds' => 3));
expect_same('conf.d after php.ini', malwatch_helper::opcache_settle(
	array("opcache.revalidate_freq=2\n", "opcache.revalidate_freq = 10 ; checked\n"), ''), array('seconds' => 11));
expect_same('pool value wins', malwatch_helper::opcache_settle(
	array("opcache.revalidate_freq=2\n"), "[web21]\nphp_admin_value[opcache.revalidate_freq] = 60\n"), array('seconds' => 61));
expect_same('enable_cli is another key', malwatch_helper::opcache_settle(array("opcache.enable_cli=0\n"), ''), array('seconds' => 3));
expect_same('opcache off', malwatch_helper::opcache_settle(array("opcache.enable=0\n"), ''), array('seconds' => 0));
$refused = malwatch_helper::opcache_settle(array(), "php_admin_flag[opcache.validate_timestamps] = off\n");
expect_same('timestamps off refused', isset($refused['error']) && strpos($refused['error'], 'validate_timestamps') !== false, true);

// The releases a report lists as target versions: plain release numbers,
// stored as JSON.
expect_same('release list', malwatch_helper::release_list(
	array('6.6.2', '6.5.5', 'trunk', '6.6-RC1', 7, str_repeat('1.', 20) . '1')), '["6.6.2","6.5.5"]');
expect_same('release list that is none', malwatch_helper::release_list('6.6.2'), '');
expect_same('empty release list', malwatch_helper::release_list(array()), '');

if ($failures > 0) {
	exit(1);
}
echo "upgrade helpers OK\n";
