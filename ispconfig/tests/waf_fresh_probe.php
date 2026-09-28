<?php
/**
 * Loads malwatch_waf the way the ISPConfig cron job does - the class file
 * alone, no library before it - and asks what the cron job asks first:
 *
 *   php waf_fresh_probe.php <stage>/ispconfig
 *
 * From 2026-09-26 to 2026-09-28 every run of the malwatch cron job ended right
 * here with "Call to undefined function waf_settings()", and ISPConfig kept
 * the job marked as running for 24 hours at a time.
 *
 * Runs as root on the server. It reads the settings of the installed
 * malwatch and changes nothing; the libraries come from their installed place,
 * because that is where the class looks for them.
 */
if (php_sapi_name() !== 'cli' || !isset($argv[1])) {
	fwrite(STDERR, "usage: php waf_fresh_probe.php <stage>/ispconfig\n");
	exit(2);
}
$stage = rtrim($argv[1], '/');

require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require SCRIPT_PATH . '/lib/app.inc.php';
// Nothing of the probe reaches the ISPConfig log.
$conf['log_priority'] = 9;

$failures = 0;

function expect_true($name, $value, $detail = '')
{
	global $failures;
	if ($value !== true) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ($detail !== '' ? ': ' . $detail : '') . "\n");
	}
}

expect_true('Bibliothek vorher nicht geladen', !function_exists('waf_settings'));

require_once $stage . '/server/lib/classes/malwatch_waf.inc.php';
$waf = new malwatch_waf();
expect_true('Bibliothek nach dem Anlegen geladen', function_exists('waf_settings'));

try {
	$fresh = $waf->tick_is_fresh();
	expect_true('tick_is_fresh() antwortet mit ja oder nein', is_bool($fresh), var_export($fresh, true));
	$settings = $waf->settings();
	expect_true('settings() liefert die Einstellungen', is_array($settings) && isset($settings['waf_tick_fresh_seconds']));
} catch (Throwable $e) {
	expect_true('kein Abbruch', false, get_class($e) . ': ' . $e->getMessage());
}

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_fresh_probe: OK\n";
