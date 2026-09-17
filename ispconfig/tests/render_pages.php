<?php

/**
 * Renders every malwatch page against a live ISPConfig install.
 *
 * Run as root on the master:
 *
 *   php /usr/local/ispconfig/extensions/malwatch/tests/render_pages.php [domain_id]
 *
 * MW_SECURITY_DIR renders a build before it is installed: copy its files the
 * way install/file.list places them below interface/web/security in another
 * directory, and link that directory's ../../lib to the panel's lib.
 *
 *   MW_SECURITY_DIR=/root/mwstage/interface/web/security php render_pages.php
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

// Prefixed, because the included page assigns to $page itself. Without the
// prefix the loop variable becomes the page object and the report line turns
// into a fatal about converting an object to a string.
$mw_page = isset($argv[2]) ? $argv[2] : '';

$pages = array(
	'status.php',
	'malwatch_site_show.php',
	// Opened at a section, as the buttons of the vulnerability list do.
	'malwatch_site_show.php?show=vulns',
	'malwatch_site_edit.php',
	'malwatch_finding_list.php',
	'malwatch_scan_list.php',
	'malwatch_config_edit.php',
	'malwatch_quarantine_list.php',
	// The website with the most entries; see the child below.
	'malwatch_quarantine_list.php?site=quarantined',
	'malwatch_repair_start.php',
	'malwatch_upgrade_start.php',
	// JSON for "Weitere Versionen laden", for a row with a release list.
	'malwatch_upgrade_versions.php?software_id=listed',
	'malwatch_vuln_list.php',
	'malwatch_dump_list.php',
	// JSON for the database picker, for the website the run picked.
	'malwatch_dump_databases.php',
	// JSON of the WAF jobs and of an exception preview on the website the run picked.
	'malwatch_waf_jobs.php',
	'malwatch_waf_preview.php?exc_scope=site&exc_rule=942100',
);

// Parent process: pick a website, then run each page as a child.
if ($mw_page === '') {
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
$mw_dir = getenv('MW_SECURITY_DIR');
if (!is_string($mw_dir) || $mw_dir === '') {
	$mw_dir = '/usr/local/ispconfig/interface/web/security';
}
chdir($mw_dir);

$mw_file = $mw_page;
$mw_query = array();
if (strpos($mw_page, '?') !== false) {
	list($mw_file, $mw_query_string) = explode('?', $mw_page, 2);
	parse_str($mw_query_string, $mw_query);
}

require '/usr/local/ispconfig/interface/lib/config.inc.php';
require '/usr/local/ispconfig/interface/lib/app.inc.php';

if ($domain_id < 1) {
	$web = $app->db->queryOneRecord("SELECT domain_id FROM web_domain WHERE type = 'vhost' ORDER BY domain_id LIMIT 1");
	$domain_id = is_array($web) ? (int) $web['domain_id'] : 0;
}

// Filtered by the website with the most entries, so the filter runs on rows
// that exist. An empty quarantine leaves the list unfiltered.
if (isset($mw_query['site']) && $mw_query['site'] === 'quarantined') {
	$busiest = $app->db->queryOneRecord(
		'SELECT parent_domain_id FROM malwatch_quarantine GROUP BY parent_domain_id ORDER BY COUNT(*) DESC LIMIT 1');
	$mw_query['site'] = is_array($busiest) ? (string) $busiest['parent_domain_id'] : '';
}

// A row of the website that has a release list, the case the JSON exists for.
if (isset($mw_query['software_id']) && $mw_query['software_id'] === 'listed') {
	$listed = $app->db->queryOneRecord(
		"SELECT software_id FROM malwatch_software WHERE parent_domain_id = ? AND product = 'wordpress' "
		. "AND versions IS NOT NULL AND versions != '' ORDER BY software_id", $domain_id);
	$mw_query['software_id'] = is_array($listed) ? (string) $listed['software_id'] : '';
}

$_SESSION['s']['user'] = array(
	'userid' => 1, 'typ' => 'admin', 'active' => 1, 'default_group' => 1,
	'groups' => '1', 'modules' => 'dashboard,security,admin', 'language' => 'de',
	'startmodule' => 'security', 'theme' => 'default',
);
$_SESSION['s']['module'] = array('name' => 'security');
$_SESSION['s']['language'] = 'de';
$_SESSION['s']['theme'] = 'default';

$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_FILENAME'] = $mw_dir . '/' . $mw_file;
$_SERVER['SCRIPT_NAME'] = '/security/' . $mw_file;
$_SERVER['REQUEST_URI'] = '/security/' . $mw_page;
$_GET = $_REQUEST = array_merge(array('id' => $domain_id, 'domain_id' => $domain_id), $mw_query);
$_POST = array();

ob_start();
try {
	include $mw_file;
	$out = ob_get_clean();
} catch (\Throwable $e) {
	ob_end_clean();
	printf("%-46s FATAL %s @ %s:%d\n", $mw_page, $e->getMessage(), basename($e->getFile()), $e->getLine());
	exit(1);
}

// The pages that answer with JSON carry their list and nothing of the panel.
// The version list must offer at least one version, because the child above
// picked a row that has one; the database picker may answer with an empty
// list, because a website is allowed to have no database at all.
$mw_json = array(
	'malwatch_upgrade_versions.php' => array('key' => 'choices', 'least' => 1, 'what' => 'versions'),
	'malwatch_dump_databases.php' => array('key' => 'rows', 'least' => 0, 'what' => 'databases'),
	'malwatch_waf_jobs.php' => array('key' => 'jobs', 'least' => 0, 'what' => 'jobs'),
	'malwatch_waf_preview.php' => array('key' => 'preview', 'least' => 2, 'what' => 'figures'),
);
if (isset($mw_json[$mw_file])) {
	$expect = $mw_json[$mw_file];
	$doc = json_decode($out, true);
	$count = (is_array($doc) && isset($doc[$expect['key']]) && is_array($doc[$expect['key']]))
		? count($doc[$expect['key']]) : -1;
	if ($count < $expect['least']) {
		printf("%-46s FAIL  %6d bytes  (%s)\n", $mw_page, strlen($out),
			$count < 0 ? 'no JSON with ' . $expect['key'] : 'nothing in ' . $expect['key']);
		echo '   ', substr(preg_replace('/\s+/', ' ', $out), 0, 300), "\n";
		exit(1);
	}
	printf("%-46s ok    %6d bytes  (%d %s)\n", $mw_page, strlen($out), $count, $expect['what']);
	exit(0);
}

$length = strlen(trim($out));
$broken = (stripos($out, 'Fatal error') !== false || stripos($out, 'Uncaught') !== false);

// A page that renders the ISPConfig error box is not a working page, even
// though it produced HTML and returned without throwing.
$denied = (strpos($out, 'alert-danger') !== false && stripos($out, 'Berechtigung') !== false);

// The form pages must render their tab exactly once. Rendering it twice is
// what an overridden onShowNew() that calls onShowEnd() itself produces.
$tabs = substr_count($out, 'content-tab-wrapper');

// The dialog takes its cancel label from the language file of the page that
// includes it; a page without the line renders a blank button.
$no_cancel = preg_match('/mw-modal-cancel"[^>]*>\s*</', $out) === 1;

// A filtered list marks its website in the overview.
$unmarked = isset($mw_query['site']) && $mw_query['site'] !== ''
	&& preg_match('/\?site=' . preg_quote($mw_query['site'], '/') . '"[^>]*aria-current="true"/', $out) !== 1;

// A page opened at a section says which one its script scrolls to.
$unjumped = isset($mw_query['show']) && strpos($out, 'data-mw-jump="mw-') === false;

// A button that needs ticked rows answers a click with a hint from the page's
// language file, in the dialog with its close button.
$hintless = strpos($out, 'data-mw-hint=""') !== false;
$no_close = strpos($out, 'mw-needs-selection') !== false
	&& preg_match('/mw-modal-close"[^>]*>\s*</', $out) === 1;

// The repair page builds its question from pieces of its language file.
$pieceless = preg_match('/data-mw-q-[a-z-]+=""/', $out) === 1;

$why = '';
if ($broken) {
	$why = 'fatal in the output';
} elseif ($denied) {
	$why = 'permission error box';
} elseif ($tabs > 1) {
	$why = 'rendered ' . $tabs . ' times';
} elseif ($length < 400) {
	$why = 'too little content';
} elseif ($no_cancel) {
	$why = 'dialog without a cancel label';
} elseif ($unmarked) {
	$why = 'website ' . $mw_query['site'] . ' not marked in the overview';
} elseif ($unjumped) {
	$why = 'no section to open at for show=' . $mw_query['show'];
} elseif ($hintless) {
	$why = 'button with an empty hint';
} elseif ($no_close) {
	$why = 'dialog without a close label';
} elseif ($pieceless) {
	$why = 'repair question piece without text';
}

if ($why !== '') {
	printf("%-46s FAIL  %6d bytes  (%s)\n", $mw_page, $length, $why);
	echo '   ', substr(preg_replace('/\s+/', ' ', strip_tags($out)), 0, 300), "\n";
	exit(1);
}

printf("%-46s ok    %6d bytes\n", $mw_page, $length);
exit(0);
