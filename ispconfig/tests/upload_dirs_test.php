<?php
/**
 * Checks the setting "Ordner für hochgeladene Dateien" (upload_dirs, from
 * 0.38.0): its default and limits, the pattern the settings page checks it
 * with, and the names the server hands the scanner (--upload-dirs).
 *
 *   php ispconfig/tests/upload_dirs_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';
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

$defaults = malwatch_config_defaults();
$default_list = 'uploads,attachments,avatars,thumbs,userfiles,user_uploads,file_uploads';
expect_same('the default', $defaults['upload_dirs'], $default_list);
$limits = malwatch_upload_dirs_limits();
expect_same('the limits', $limits, array('max_count' => 16, 'max_length' => 30));

// The page checks the field with this pattern; tform adds the u modifier.
$regex = malwatch_upload_dirs_regex();
$passes = function ($value) use ($regex) {
	return preg_match($regex . 'u', $value) === 1;
};
expect_same('the default passes', $passes($default_list), true);
expect_same('spaces around the commas pass', $passes(' uploads , kundendateien '), true);
expect_same('16 names of 30 characters pass', $passes(implode(',', array_fill(0, 16, str_repeat('a', 30)))), true);
expect_same('17 names fail', $passes(implode(',', array_fill(0, 17, 'a'))), false);
expect_same('31 characters fail', $passes(str_repeat('a', 31)), false);
foreach (array('', '..', '.versteckt', 'wp-content/uploads', 'meine uploads', 'uploads,,thumbs', 'uploads,', 'dateiablage-ä') as $bad) {
	expect_same('refused: "' . $bad . '"', $passes($bad), false);
}
expect_same('other limits make another pattern', preg_match(malwatch_upload_dirs_regex(2, 5) . 'u', 'abcde,fghij'), 1);
expect_same('other limits: a third name fails', preg_match(malwatch_upload_dirs_regex(2, 5) . 'u', 'a,b,c'), 0);
expect_same('other limits: a longer name fails', preg_match(malwatch_upload_dirs_regex(2, 5) . 'u', 'abcdef'), 0);

// The page stores the list without the spaces around its commas; an empty
// entry stays, so the check refuses it.
expect_same('tidied', malwatch_upload_dirs_tidy(" uploads , kundendateien \n"), 'uploads,kundendateien');
expect_same('an empty entry stays for the check', malwatch_upload_dirs_tidy('uploads, ,thumbs'), 'uploads,,thumbs');
expect_same('16 names of 30 characters fit the column', strlen(malwatch_upload_dirs_tidy(implode(' , ',
	array_fill(0, 16, str_repeat('a', 30))))) <= 512, true);

// The server hands the scanner clean names. A stored value that the page would
// refuse - edited in the database, say - must not stop every scan: what is
// left of it counts, and the default when nothing is.
$helper = new malwatch_helper();
expect_same('the server knows the same limits', array(malwatch_helper::UPLOAD_DIRS_MAX, malwatch_helper::UPLOAD_DIR_LENGTH_MAX),
	array($limits['max_count'], $limits['max_length']));
expect_same('split and trimmed', $helper->upload_dirs(' uploads , kundendateien '), array('uploads', 'kundendateien'));
expect_same('bad names dropped, good ones kept', $helper->upload_dirs('uploads,../x,thumbs'), array('uploads', 'thumbs'));
expect_same('nothing usable: the default', $helper->upload_dirs('../x, /etc'), explode(',', $default_list));
expect_same('empty: the default', $helper->upload_dirs(''), explode(',', $default_list));
expect_same('no more names than the limit', count($helper->upload_dirs(implode(',', range(1, 20)))), 16);
expect_same('the server default is the page default', $helper->upload_dirs(null), explode(',', $default_list));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "upload dirs OK\n";
