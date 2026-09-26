<?php
/**
 * Checks the pure helpers behind the quarantine overview and the dialog that
 * asks before an action.
 *
 *   php ispconfig/tests/panel_helpers_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';

$wb = array('overview_no_site_txt' => 'ohne Website');

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

// One row per website, the most entries first, equal counts by name.
$groups = array(
	array('site' => '12', 'domain' => 'beispiel.de', 'entries' => '3', 'bytes' => '2048', 'latest' => '2026-09-10 08:00:00'),
	array('site' => '0', 'domain' => '', 'entries' => '5', 'bytes' => '0', 'latest' => '2026-09-12 09:30:00'),
	array('site' => '7', 'domain' => 'alt.beispiel.de', 'entries' => '3', 'bytes' => '512', 'latest' => '2026-09-01 10:00:00'),
);
$overview = malwatch_quarantine_overview($groups, $wb);
expect_same('order', array_map(function ($row) { return $row['site']; }, $overview), array(0, 7, 12));
expect_same('entries without website', $overview[0]['label'], 'ohne Website');
expect_same('website', $overview[2]['label'], 'beispiel.de');
expect_same('entries as number', $overview[1]['entries'], 3);
expect_same('bytes as number', $overview[2]['bytes'], 2048.0);
expect_same('latest entry', $overview[0]['latest'], '2026-09-12 09:30:00');
expect_same('empty quarantine', malwatch_quarantine_overview(array(), $wb), array());

// site= narrows the list to one row of the overview; anything else shows all.
expect_same('site', malwatch_quarantine_site('12', $overview), 12);
expect_same('site without website', malwatch_quarantine_site('0', $overview), 0);
expect_same('no parameter', malwatch_quarantine_site(null, $overview), -1);
expect_same('empty parameter', malwatch_quarantine_site('', $overview), -1);
expect_same('trailing letters', malwatch_quarantine_site('12abc', $overview), -1);
expect_same('negative', malwatch_quarantine_site('-12', $overview), -1);
expect_same('array', malwatch_quarantine_site(array('12'), $overview), -1);
expect_same('site with nothing in quarantine', malwatch_quarantine_site('99', $overview), -1);

// Language lines bound for an HTML attribute of a button.
$texts = malwatch_attr_texts(array(
	'size_txt' => 'Die Spalte „Größe" sagt',
	'files_txt' => "the customer's files",
	'markup_txt' => '<b>fett</b> & mehr',
), array('size_txt', 'files_txt', 'markup_txt', 'missing_txt'));
expect_same('straight double quote', $texts['size_txt'], 'Die Spalte „Größe&quot; sagt');
expect_same('apostrophe', $texts['files_txt'], 'the customer&#039;s files');
expect_same('markup', $texts['markup_txt'], '&lt;b&gt;fett&lt;/b&gt; &amp; mehr');
expect_same('missing key', array_key_exists('missing_txt', $texts), false);

// The folder of a WordPress installation below the scan path, "." for the
// scan path itself and "" for a path outside it.
$base = '/var/www/clients/client3/web12/web';
expect_same('folder', malwatch_install_folder($base . '/campus', $base), 'campus');
expect_same('nested folder', malwatch_install_folder($base . '/campus/blog/', $base . '/'), 'campus/blog');
expect_same('scan path itself', malwatch_install_folder($base, $base), '.');
expect_same('sibling with the same start', malwatch_install_folder($base . '2/campus', $base), '');
expect_same('elsewhere', malwatch_install_folder('/var/www/clients/client3/web13/web', $base), '');

// A folder button keeps the elements of its folder; no folder keeps all.
$only = array('core@.', 'plugin:akismet@.', 'plugin:akismet@campus', 'theme:vier@campus/blog');
expect_same('root folder', malwatch_only_in_folder($only, '.'), array('core@.', 'plugin:akismet@.'));
expect_same('sub folder', malwatch_only_in_folder($only, 'campus'), array('plugin:akismet@campus'));
expect_same('every folder', malwatch_only_in_folder($only, ''), $only);
// The folder starts after the first @, as in repair --only; a slug has none.
expect_same('folder with an @', malwatch_only_in_folder(array('plugin:akismet@alt@2024', 'core@2024'), 'alt@2024'),
	array('plugin:akismet@alt@2024'));

// show= on the website page names the section it opens at.
expect_same('jump to the vulnerabilities', malwatch_site_jump('vulns'), 'mw-software');
expect_same('jump to the malware findings', malwatch_site_jump('malware'), 'mw-findings');
expect_same('no jump', malwatch_site_jump(''), '');
expect_same('unknown section', malwatch_site_jump('findings'), '');
expect_same('parameter that is no string', malwatch_site_jump(array('vulns')), '');

// A setting missing in the row, e.g. between an update of the files and of the
// database, comes from malwatch_config_defaults().
class ConfigDbStub
{
	public $row;
	public function queryOneRecord()
	{
		return $this->row;
	}
}
$stub = new stdClass();
$stub->db = new ConfigDbStub();
$stub->db->row = null;
$config = malwatch_get_config($stub);
expect_same('no row: scanner', $config['binary_path'], '/usr/local/bin/malwatch');
expect_same('no row: refresh', $config['poll_seconds'], 2);
$stub->db->row = array('config_id' => '1', 'binary_path' => '/opt/malwatch/bin', 'poll_seconds' => '7');
$config = malwatch_get_config($stub);
expect_same('row: refresh kept', $config['poll_seconds'], '7');
expect_same('row: scanner kept', $config['binary_path'], '/opt/malwatch/bin');
$stub->db->row = array('config_id' => '1', 'binary_path' => '/opt/malwatch/bin');
$config = malwatch_get_config($stub);
expect_same('row from before the column', $config['poll_seconds'], 2);

// How often the scanner pages ask for a running scan, in milliseconds.
expect_same('refresh', malwatch_poll_ms(array('poll_seconds' => '7')), 7000);
expect_same('refresh of zero', malwatch_poll_ms(array('poll_seconds' => '0')), 2000);
expect_same('refresh without the key', malwatch_poll_ms(array()), 2000);

if ($failures > 0) {
	exit(1);
}
echo "panel helpers OK\n";
