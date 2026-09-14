<?php
/**
 * Checks the target versions the page "Updates" offers.
 *
 *   php ispconfig/tests/upgrade_offers_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';

$wb = array(
	'closes_all_txt' => 'schließt alle %s Lücken',
	'closes_one_txt' => 'schließt die bekannte Lücke',
	'closes_some_txt' => 'schließt %s von %s, für %s gibt es keine Korrektur',
	'closes_later_txt' => 'behoben erst ab %s',
	'needs_php_txt' => '%s braucht PHP %s, die Website läuft mit %s',
	'needs_wp_txt' => '%s braucht WordPress %s, installiert ist %s',
	'needs_wp_short_txt' => 'braucht WordPress %s',
	'offer_latest_txt' => 'neueste passende',
	'offer_minimal_txt' => 'kleinste, die alle Lücken schließt',
);

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function software_row(array $fields)
{
	return array_merge(array(
		'software_kind' => 'plugin', 'installed_version' => '5.3.0', 'latest_version' => '',
		'latest_in_branch' => '', 'latest_requires_wp' => '', 'latest_requires_php' => '',
		'vuln_count' => 0, 'vuln_nofix' => 0, 'vuln_fixed_in' => '', 'version_unknown' => 'n', 'versions' => '',
	), $fields);
}

function choice_versions(array $offers)
{
	return array_map(function ($choice) { return $choice['version']; }, $offers['choices']);
}

// The newest release fits the site and fixes both flaws.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'latest_requires_php' => '7.2',
	'vuln_count' => 2, 'vuln_fixed_in' => '5.3.1')), '6.6.2', '8.2.10', $wb);
expect_same('latest offered', $o['latest']['version'], '5.3.7');
expect_same('latest closes all', $o['latest']['closes'], 'schließt alle 2 Lücken');
expect_same('minimal offered', $o['minimal']['version'], '5.3.1');
expect_same('offers are the choices without a release list', choice_versions($o), array('5.3.7', '5.3.1'));

// The newest release asks for more PHP than the site runs.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '3.18.0', 'latest_version' => '3.25.1',
	'latest_requires_php' => '8.1', 'vuln_count' => 7, 'vuln_fixed_in' => '3.18.2')), '6.6.2', '7.4.33', $wb);
expect_same('latest withheld', $o['latest'], null);
expect_same('php reason', $o['reason'], '3.25.1 braucht PHP 8.1, die Website läuft mit 7.4.33');
expect_same('minimal remains', $o['minimal']['version'], '3.18.2');

// The newest release asks for a newer WordPress.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '1.0', 'latest_version' => '2.0',
	'latest_requires_wp' => '6.6')), '6.4.5', '8.2.10', $wb);
expect_same('wordpress reason', $o['reason'], '2.0 braucht WordPress 6.6, installiert ist 6.4.5');

// The core stays on its branch; a fix that only a newer branch carries is named.
$o = malwatch_upgrade_offers(software_row(array('software_kind' => 'core', 'installed_version' => '6.4.2',
	'latest_version' => '7.1', 'latest_in_branch' => '6.4.5', 'vuln_count' => 3, 'vuln_fixed_in' => '6.5.2')),
	'6.4.2', '8.2.10', $wb);
expect_same('core latest is the branch', $o['latest']['version'], '6.4.5');
expect_same('branch fixes later', $o['latest']['closes'], 'behoben erst ab 6.5.2');
expect_same('core minimal', $o['minimal']['version'], '6.5.2');

// Flaws without a fix are counted apart, and one version is offered once.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'vuln_count' => 3, 'vuln_nofix' => 1,
	'vuln_fixed_in' => '5.3.7')), '6.6.2', '8.2.10', $wb);
expect_same('one offer when both agree', $o['minimal'], null);
expect_same('some closed', $o['latest']['closes'], 'schließt 2 von 3, für 1 gibt es keine Korrektur');

// A single flaw reads as one.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'vuln_count' => 1,
	'vuln_fixed_in' => '5.3.7')), '6.6.2', '8.2.10', $wb);
expect_same('one flaw', $o['latest']['closes'], 'schließt die bekannte Lücke');

// Nothing newer: nothing to offer.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.0')), '6.6.2', '8.2.10', $wb);
expect_same('current: latest', $o['latest'], null);
expect_same('current: minimal', $o['minimal'], null);
expect_same('current: reason', $o['reason'], '');

// An unknown PHP version checks nothing here; the scanner checks in phase 3.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'latest_requires_php' => '8.1')),
	'6.6.2', '', $wb);
expect_same('unknown php', $o['latest']['version'], '5.3.7');

// Every release above the installed one is a choice, newest first. The two
// offers carry their mark, and a release below the fix says so.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '5.3.0', 'latest_version' => '5.3.7',
	'vuln_count' => 2, 'vuln_fixed_in' => '5.3.4',
	'versions' => '["5.3.7","5.3.5","5.3.4","5.3.2","5.3.0","5.2.9","trunk","5.4-beta1"]')), '6.6.2', '8.2.10', $wb);
expect_same('choices newest first', choice_versions($o), array('5.3.7', '5.3.5', '5.3.4', '5.3.2'));
expect_same('latest marked', $o['choices'][0]['mark'], 'neueste passende');
expect_same('plain release', $o['choices'][1]['mark'], '');
expect_same('minimal marked', $o['choices'][2]['mark'], 'kleinste, die alle Lücken schließt');
expect_same('release below the fix', $o['choices'][3]['closes'], 'behoben erst ab 5.3.4');
expect_same('starts on latest', $o['default'], '5.3.7');

// A newest release that needs more PHP stays out of the choices, since the
// run cannot change PHP; the select starts on the fix.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '3.18.0', 'latest_version' => '3.25.1',
	'latest_requires_php' => '8.1', 'vuln_count' => 7, 'vuln_fixed_in' => '3.18.2',
	'versions' => '["3.25.1","3.20.0","3.18.2"]')), '6.6.2', '7.4.33', $wb);
expect_same('release needing more php left out', choice_versions($o), array('3.20.0', '3.18.2'));
expect_same('starts on the fix', $o['default'], '3.18.2');

// One that needs a newer WordPress stays a choice with that mark: a core
// update in the same run can meet it, and phase 3 checks.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '1.0', 'latest_version' => '2.0',
	'latest_requires_wp' => '6.6', 'versions' => '["2.0","1.5"]')), '6.4.5', '8.2.10', $wb);
expect_same('release needing a newer wordpress marked', $o['choices'][0]['mark'], 'braucht WordPress 6.6');
expect_same('starts below it', $o['default'], '1.5');

// Nothing newer in the list either: no choice, nothing to start on.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.0', 'versions' => '["5.3.0","5.2.9"]')),
	'6.6.2', '8.2.10', $wb);
expect_same('current: no choices', $o['choices'], array());
expect_same('current: no default', $o['default'], '');

expect_same('plugin install', malwatch_install_of('/w/blog/wp-content/plugins/akismet', 'plugin'), '/w/blog');
expect_same('theme install', malwatch_install_of('/w/inhalt/themes/vier', 'theme'), '/w');
expect_same('stray plugin path', malwatch_install_of('/w/wp-content/akismet', 'plugin'), '');

// Nothing is ticked unless the row link of one element opened the page.
$flawed = array('software_id' => 12, 'vuln_count' => 3);
expect_same('flawed row stays unticked', malwatch_upgrade_checked($flawed, true, 0), false);
expect_same('row link ticks its element', malwatch_upgrade_checked($flawed, true, 12), true);
expect_same('row link ticks nothing else', malwatch_upgrade_checked($flawed, true, 13), false);
expect_same('row without an offer stays unticked', malwatch_upgrade_checked($flawed, false, 12), false);

if ($failures > 0) {
	exit(1);
}
echo "upgrade offers OK\n";
