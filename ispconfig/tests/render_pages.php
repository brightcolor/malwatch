<?php

/**
 * Renders every malwatch page against a live ISPConfig install.
 *
 * Run as root on the master:
 *
 *   php /usr/local/ispconfig/extensions/malwatch/tests/render_pages.php [domain_id]
 *
 * This cannot run in CI, because it needs a real ISPConfig and a real
 * database. It is here because a page that passes php -l can still be broken
 * in every way that matters: a missing form definition, a template that is
 * not there, a language file whose name does not match. All three happened
 * during the first install, and only rendering the page showed it.
 *
 * Each page runs in its own process: the two form pages both declare a class
 * called page_action, which is fine for the panel, where every request is its
 * own process, and a fatal when one process includes both.
 */

if (php_sapi_name() != 'cli') {
	die("This script must be run from the command line.\n");
}

$domain_id = isset($argv[1]) ? (int) $argv[1] : 0;
$page = isset($argv[2]) ? $argv[2] : '';

$pages = array(
	'malwatch_site_list.php',
	'malwatch_site_show.php',
	'malwatch_site_edit.php',
	'malwatch_finding_list.php',
	'malwatch_scan_list.php',
	'malwatch_config_edit.php',
);

// Parent process: pick a website, then run each page as a child.
if ($page === '') {
	$status = 0;
	foreach ($pages as $candidate) {
		$cmd = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg(__FILE__)
			. ' ' . escapeshellarg((string) $domain_id) . ' ' . escapeshellarg($candidate) . ' 2>&1';
		$output = array();
		$code = 0;
		exec($cmd, $output, $code);
		echo implode("\n", $output), "\n";
		if ($code !== 0) {
			$status = 1;
		}
	}
	echo $status === 0 ? "\nAll pages render.\n" : "\nSome pages failed.\n";
	exit($status);
}

// Child process: render one page.
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
chdir('/usr/local/ispconfig/interface/web/sites');

require '/usr/local/ispconfig/interface/lib/config.inc.php';
require '/usr/local/ispconfig/interface/lib/app.inc.php';

if ($domain_id < 1) {
	$web = $app->db->queryOneRecord("SELECT domain_id FROM web_domain WHERE type = 'vhost' ORDER BY domain_id LIMIT 1");
	$domain_id = is_array($web) ? (int) $web['domain_id'] : 0;
}

$_SESSION['s']['user'] = array(
	'userid' => 1, 'typ' => 'admin', 'active' => 1, 'default_group' => 1,
	'groups' => '1', 'modules' => 'dashboard,sites,admin', 'language' => 'de',
	'startmodule' => 'sites', 'theme' => 'default',
);
$_SESSION['s']['module'] = array('name' => 'sites');
$_SESSION['s']['language'] = 'de';
$_SESSION['s']['theme'] = 'default';

$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_FILENAME'] = '/usr/local/ispconfig/interface/web/sites/' . $page;
$_SERVER['SCRIPT_NAME'] = '/sites/' . $page;
$_SERVER['REQUEST_URI'] = '/sites/' . $page;
$_GET = $_REQUEST = array('id' => $domain_id, 'domain_id' => $domain_id);
$_POST = array();

ob_start();
try {
	include $page;
	$out = ob_get_clean();
} catch (\Throwable $e) {
	ob_end_clean();
	printf("%-28s FATAL %s @ %s:%d\n", $page, $e->getMessage(), basename($e->getFile()), $e->getLine());
	exit(1);
}

$length = strlen(trim($out));
$broken = (stripos($out, 'Fatal error') !== false || stripos($out, 'Uncaught') !== false);

// A page that renders the ISPConfig error box is not a working page, even
// though it produced HTML and returned without throwing.
$denied = (strpos($out, 'alert-danger') !== false && stripos($out, 'Berechtigung') !== false);

// The form pages must render their tab exactly once. Rendering it twice is
// what an overridden onShowNew() that calls onShowEnd() itself produces.
$tabs = substr_count($out, 'content-tab-wrapper');

if ($broken || $denied || $length < 400 || $tabs > 1) {
	$why = $broken ? 'fatal in the output' : ($denied ? 'permission error box' : ($tabs > 1 ? 'rendered ' . $tabs . ' times' : 'too little content'));
	printf("%-28s FAIL  %6d bytes  (%s)\n", $page, $length, $why);
	echo '   ', substr(preg_replace('/\s+/', ' ', strip_tags($out)), 0, 300), "\n";
	exit(1);
}

printf("%-28s ok    %6d bytes\n", $page, $length);
exit(0);
