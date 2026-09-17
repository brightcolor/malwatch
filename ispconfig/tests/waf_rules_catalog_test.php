<?php
/**
 * Checks the rule catalog of the Abwehr pages: the rules CRS 3.3.5 runs at
 * paranoia level 1 (tests/fixtures/crs-3.3.5-pl1-rule-ids.txt) have a German
 * and an English entry, every group has its texts, and both files agree.
 *
 *   php ispconfig/tests/waf_rules_catalog_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function catalog_words($lang)
{
	$wb = array();
	$file = __DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_rules.lng';
	if (is_file($file)) {
		include $file;
	}
	return $wb;
}

$ids = array();
foreach (file(__DIR__ . '/fixtures/crs-3.3.5-pl1-rule-ids.txt') as $line) {
	$line = trim($line);
	if ($line !== '' && $line[0] !== '#') {
		$ids[] = $line;
	}
}
expect_same('fixture size', count($ids), 170);

// The groups the catalog covers so far; the following tasks add theirs.
$covered = array('910', '911', '912', '913', '920', '921', '922');
$all_groups = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934',
	'941', '942', '943', '944', '949', '950', '951', '952', '953', '954', '959', '980');

$words = array('de' => catalog_words('de'), 'en' => catalog_words('en'));
expect_same('same keys in both languages', array(
	array_values(array_diff(array_keys($words['de']), array_keys($words['en']))),
	array_values(array_diff(array_keys($words['en']), array_keys($words['de']))),
), array(array(), array()));

$catalogs = array();
foreach (array('de', 'en') as $lang) {
	$catalogs[$lang] = waf_panel_rule_catalog(__DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_rules.lng');
	foreach (array_keys($words[$lang]) as $key) {
		expect_same("$lang key $key has a known form",
			preg_match('/^(rule_\d{3,7}_(title|what|class|note|trigger)|group_\d{3}_(what|class))$/', (string) $key), 1);
	}
	foreach (array_keys($catalogs[$lang]['rules']) as $id) {
		expect_same("$lang rule $id is in the fixture", in_array((string) $id, $ids, true), true);
	}
}

foreach ($ids as $id) {
	if (!in_array(substr($id, 0, 3), $covered, true)) {
		continue;
	}
	foreach (array('de', 'en') as $lang) {
		$entry = isset($catalogs[$lang]['rules'][$id]) ? $catalogs[$lang]['rules'][$id] : array();
		$title = isset($entry['title']) ? $entry['title'] : '';
		expect_same("$lang $id title", $title !== '' && preg_match_all('/./u', $title) <= 48, true);
		expect_same("$lang $id what", isset($entry['what']) && trim($entry['what']) !== '', true);
		expect_same("$lang $id class", isset($entry['class']) && in_array($entry['class'], waf_panel_rule_classes(), true), true);
		if (isset($entry['trigger'])) {
			expect_same("$lang $id trigger holds one %s", preg_match('/^[^%]*%s[^%]*$/', $entry['trigger']), 1);
		}
	}
	expect_same("$id same class in both languages",
		isset($catalogs['de']['rules'][$id]['class'], $catalogs['en']['rules'][$id]['class'])
			&& $catalogs['de']['rules'][$id]['class'] === $catalogs['en']['rules'][$id]['class'], true);
	expect_same("$id same optional fields in both languages",
		array_keys(isset($catalogs['de']['rules'][$id]) ? $catalogs['de']['rules'][$id] : array()),
		array_keys(isset($catalogs['en']['rules'][$id]) ? $catalogs['en']['rules'][$id] : array()));
}

foreach ($all_groups as $group) {
	foreach (array('de', 'en') as $lang) {
		$entry = isset($catalogs[$lang]['groups'][$group]) ? $catalogs[$lang]['groups'][$group] : array();
		expect_same("$lang group $group what", isset($entry['what']) && trim($entry['what']) !== '', true);
		expect_same("$lang group $group class", isset($entry['class']) && in_array($entry['class'], waf_panel_rule_classes(), true), true);
	}
	expect_same("group $group same class in both languages",
		isset($catalogs['de']['groups'][$group]['class'], $catalogs['en']['groups'][$group]['class'])
			&& $catalogs['de']['groups'][$group]['class'] === $catalogs['en']['groups'][$group]['class'], true);
}

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_rules_catalog: alle Prüfungen bestanden\n";
