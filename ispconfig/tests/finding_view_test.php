<?php
/**
 * Checks the finding view (0.39.0): marks and escaping in the code, the rows
 * of the view, how the server reads views and marks from a report, the view
 * settings on both sides, and the new findings in the mail.
 *
 *   php ispconfig/tests/finding_view_test.php
 *
 * The samples are put together from pieces: the virus scanner on the
 * workstation deletes a test file that spells out a script tag or a webshell
 * call in one piece.
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_ingest.inc.php';
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

$lt = '<';
$tag = $lt . 'scr' . 'ipt>';
$end_tag = $lt . '/scr' . 'ipt>';
$call = 'ev' . 'al(';
$request = '$_PO' . 'ST';

// --- The code is escaped, whatever the file holds ---------------------------
$attack = $lt . '?php echo "' . $lt . '/td>' . $tag . 'x(1)' . $end_tag . '"; ?>';
$html = malwatch_mark_line($attack, 0, array());
expect_same('no tag of the file survives', array(strpos($html, $lt . 'scr'), strpos($html, $lt . '/td>'), strpos($html, $lt . '?php')),
	array(false, false, false));
expect_same('the text is still there, escaped', strpos($html, '&lt;scr' . 'ipt&gt;x(1)&lt;/scr' . 'ipt&gt;') !== false, true);

// A mark wraps exactly its bytes; the rest stays plain.
$line = '$a = ' . $call . $request . '["x"]);';
$html = malwatch_mark_line($line, 0, array(array('col' => 5, 'len' => 5, 'class' => 'mw-m-critical')));
expect_same('one mark', $html, '$a = ' . $lt . 'mark class="mw-m-critical">' . $call . $lt . '/mark>' . $request . '[&quot;x&quot;]);');

// The line was cut: Col counts from the start of the whole line, the text
// starts at its offset.
$html = malwatch_mark_line('call($x)', 100, array(array('col' => 100, 'len' => 4, 'class' => 'mw-m-high')));
expect_same('offset of a cut line', $html, $lt . 'mark class="mw-m-high">call' . $lt . '/mark>($x)');
$html = malwatch_mark_line('abc', 100, array(array('col' => 10, 'len' => 4, 'class' => 'mw-m-high')));
expect_same('a mark outside the kept part is left out', $html, 'abc');

// Overlapping marks merge, the stronger class wins.
$html = malwatch_mark_line('abcdefgh', 0, array(
	array('col' => 1, 'len' => 3, 'class' => 'mw-m-guard'),
	array('col' => 2, 'len' => 4, 'class' => 'mw-m-critical'),
));
expect_same('overlap', $html, 'a' . $lt . 'mark class="mw-m-critical">bcdef' . $lt . '/mark>gh');

// A mark never splits a character in two.
$html = malwatch_mark_line('äöü', 0, array(array('col' => 1, 'len' => 2, 'class' => 'mw-m-info')));
expect_same('multibyte stays whole', $html, $lt . 'mark class="mw-m-info">ä' . $lt . '/mark>öü');

// Marks without length colour the row, not the text.
$html = malwatch_mark_line('whole line', 0, array(array('col' => 0, 'len' => 0, 'class' => 'mw-m-risk')));
expect_same('length 0 marks nothing inline', $html, 'whole line');

// A class that came from somewhere odd cannot leave its attribute.
$html = malwatch_mark_line('abc', 0, array(array('col' => 0, 'len' => 1, 'class' => 'x" onmouseover="y')));
expect_same('class is escaped', strpos($html, '" onmouseover'), false);

// --- Rows of the view --------------------------------------------------------
$rows = malwatch_code_rows(
	array(array('n' => 1, 't' => 'a'), array('n' => 2, 't' => 'b'), array('n' => 9, 't' => 'c', 'o' => 5, 'c' => true)),
	array(2 => array(array('col' => 0, 'len' => 1, 'class' => 'mw-m-guard'), array('col' => 0, 'len' => 0, 'class' => 'mw-m-high')))
);
expect_same('three rows', count($rows), 3);
expect_same('the strongest mark colours the row', $rows[1]['row_class'], 'mw-row mw-r-high');
expect_same('an unmarked row has no class', $rows[0]['row_class'], '');
expect_same('a gap before line 9', array($rows[2]['gap'], $rows[2]['skipped']), array(1, 6));
expect_same('cut on both sides', array($rows[2]['cut_left'], $rows[2]['cut_right']), array(1, 1));

// --- Marks from the database ---------------------------------------------------
expect_same('marks from JSON', malwatch_decode_marks('[{"line":3,"col":2,"len":4},{"line":0},"x"]'),
	array(array('line' => 3, 'col' => 2, 'len' => 4)));
expect_same('marks from nothing', malwatch_decode_marks(null), array());
expect_same('marks from broken JSON', malwatch_decode_marks('{'), array());

// --- The server reads marks and views from the report --------------------------
expect_same('marks_json keeps whole numbers', malwatch_ingest::marks_json(array(array('line' => '4', 'col' => '-3', 'len' => 2))),
	'[{"line":4,"col":0,"len":2}]');
expect_same('marks_json of none', malwatch_ingest::marks_json(array()), null);
$many = array();
for ($i = 1; $i <= 300; $i++) {
	$many[] = array('line' => $i, 'col' => 0, 'len' => 1);
}
expect_same('marks_json is capped', count(json_decode(malwatch_ingest::marks_json($many), true)), malwatch_ingest::MARKS_MAX);

$row = malwatch_ingest::file_row(array(
	'kind' => 'text', 'lines' => 12, 'whole' => true,
	'show' => array(array('n' => 1, 't' => $lt . '?php', 'o' => 0), array('n' => 2, 't' => 'x', 'c' => true), 'junk'),
	'traits' => array(
		array('id' => 'exec.shell', 'label' => 'führt Befehle aus', 'kind' => 'risk', 'marks' => array(array('line' => 2, 'col' => 0, 'len' => 1))),
		array('id' => 'x', 'label' => 'y', 'kind' => 'strange'),
		array('label' => 'no id'),
	),
));
expect_same('file row columns', array($row['kind'], $row['line_count'], $row['whole'], $row['omitted']), array('text', 12, 'y', 'n'));
$view = json_decode($row['view'], true);
expect_same('view lines kept, junk dropped', array(count($view), $view[0]['t'], $view[1]['c']), array(2, $lt . '?php', true));
$traits = json_decode($row['traits'], true);
expect_same('traits kept with their marks, unknown kind as info', array(count($traits), $traits[0]['marks'][0]['line'], $traits[1]['kind']),
	array(2, 2, 'info'));
$binary = malwatch_ingest::file_row(array('kind' => 'binary', 'omitted' => true));
expect_same('a binary without lines', array($binary['kind'], $binary['view'], $binary['omitted']), array('binary', null, 'y'));

// --- The settings of the view, the same on both sides -------------------------
$panel = malwatch_view_settings();
foreach (malwatch_helper::VIEW_SETTINGS as $key => $setting) {
	expect_same('panel and server agree on ' . $key, $panel[$key], array($setting[0], $setting[1], $setting[2]));
	expect_same('default of ' . $key, malwatch_config_defaults()[$key], $setting[2]);
}
expect_same('keep days agree', $panel['view_keep_days'], malwatch_helper::VIEW_KEEP_DAYS);
expect_same('range for the form', malwatch_view_range('view_context'), '0:50');

$helper = new malwatch_helper();
expect_same('view switches from the settings', $helper->view_arguments(array('view_lines' => '120', 'view_context' => '3',
	'view_line_length' => '500', 'view_marks' => '7', 'view_budget' => '16')),
	array('--view-lines=120', '--view-context=3', '--view-line-length=500', '--view-marks=7', '--view-budget=16'));
expect_same('a stored value out of bounds gets the default', $helper->view_arguments(array('view_lines' => '99999',
	'view_context' => 'x', 'view_line_length' => '10', 'view_marks' => '0', 'view_budget' => '9999')),
	array('--view-lines=400', '--view-context=5', '--view-line-length=300', '--view-marks=20', '--view-budget=32'));
expect_same('keep days within bounds', array($helper->view_keep_days(array('view_keep_days' => '7')),
	$helper->view_keep_days(array('view_keep_days' => '0')), $helper->view_keep_days(array())), array(7, 30, 30));

// --- The address of the panel ----------------------------------------------------
$regex = malwatch_panel_url_regex();
foreach (array('', 'https://panel.example.de:8080', 'http://10.0.0.5:8080/', 'https://example.de/ispconfig') as $ok) {
	expect_same('panel_url accepts ' . $ok, preg_match($regex, $ok), 1);
}
foreach (array('panel.example.de', 'java' . 'script:x(1)', 'https://a b', 'ftp://x', 'https://x?y=1') as $bad) {
	expect_same('panel_url refuses ' . $bad, preg_match($regex, $bad), 0);
}
expect_same('guess with https', malwatch_panel_url_guess(array('HTTP_HOST' => 'panel.example.de:8080', 'HTTPS' => 'on')),
	'https://panel.example.de:8080');
expect_same('guess without https', malwatch_panel_url_guess(array('HTTP_HOST' => 'panel.example.de:8080')),
	'http://panel.example.de:8080');
expect_same('guess refuses a strange host', malwatch_panel_url_guess(array('HTTP_HOST' => 'x">' . $tag)), '');

// --- The findings in the mail -----------------------------------------------------
class mail_under_test extends malwatch_actions
{
	protected function rule_row($rule_id, $engine)
	{
		if ($rule_id === 'vendor.foreign_file') {
			return array('title' => 'gehört nicht zur Auslieferung des Herstellers',
				'explanation' => 'Die Datei liegt in einem Ordner, dessen Inhalt der Hersteller vollständig kennt, gehört aber nicht zur Auslieferung.',
				'advice' => '');
		}
		return null;
	}

	protected function trait_labels($sha)
	{
		return $sha === str_repeat('a', 64) ? array('nimmt hochgeladene Dateien an', 'prüft die Rechte des Benutzers') : array();
	}
}

$mail = new mail_under_test();
$lines = $mail->finding_lines(array(
	array('finding_id' => 7, 'file_path' => '/var/www/x/web/wp-admin/plugin-uploader.php', 'severity' => 'high',
		'rule_id' => 'vendor.foreign_file', 'engine' => 'herstellerdateien', 'file_sha256' => str_repeat('a', 64)),
	array('finding_id' => 8, 'file_path' => '/var/www/x/web/wp-content/uploads/a.php', 'severity' => 'critical',
		'rule_id' => 'php.eval.request', 'engine' => 'heuristic', 'file_sha256' => str_repeat('b', 64)),
), '/var/www/x/web', 'https://panel.example.de:8080/', 'de');
$text = implode("\n", $lines);
expect_same('worst file first, path below the scan path', $lines[0], '[kritisch] wp-content/uploads/a.php');
expect_same('rule with title', strpos($text, '    gehört nicht zur Auslieferung des Herstellers (vendor.foreign_file)') !== false, true);
expect_same('why', strpos($text, '    Warum: Die Datei liegt in einem Ordner') !== false, true);
expect_same('what it does', strpos($text, '    Tut: nimmt hochgeladene Dateien an; prüft die Rechte des Benutzers') !== false, true);
expect_same('link to the finding', strpos($text, '    Ansehen: https://panel.example.de:8080/index.php#malwatch-finding-7') !== false, true);
$too_long = array_filter($lines, function ($line) {
	return mb_strlen($line, 'UTF-8') > malwatch_actions::MAIL_WIDTH;
});
expect_same('every line fits the width', array_values($too_long), array());
$no_panel = implode("\n", $mail->finding_lines(array(
	array('finding_id' => 7, 'file_path' => '/var/www/x/web/a.php', 'severity' => 'high', 'rule_id' => 'x', 'engine' => '', 'file_sha256' => ''),
), '/var/www/x/web', '', 'de'));
expect_same('without panel address no link', strpos($no_panel, 'Ansehen'), false);

if ($failures > 0) {
	exit(1);
}
echo "finding view OK\n";
