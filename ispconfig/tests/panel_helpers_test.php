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

// --- The schedule in days (0.37.0) -------------------------------------------

// New websites get the interval of default_scan_days.
$stub->db->row = null;
expect_same('no row: interval for new websites', malwatch_get_config($stub)['default_scan_days'], 7);
$stub->db->row = array('config_id' => '1', 'default_scan_days' => '2');
expect_same('row: interval for new websites kept', malwatch_get_config($stub)['default_scan_days'], '2');
expect_same('the enum of before 0.37.0 is gone from the defaults', array_key_exists('default_schedule',
	malwatch_config_defaults()), false);

// When a website scans next once its settings are saved: the new interval,
// the one before (null for a new row), the last scan and the planned one.
$t = gmmktime(12, 0, 0, 9, 28, 2026);
$day = 86400;
expect_same('0 days: no plan', malwatch_plan_next_run(0, 2, $t - $day, $t + $day, $t), null);
expect_same('a new row with 2 days: at once', malwatch_plan_next_run(2, null, null, null, $t), $t);
expect_same('the same interval keeps the plan', malwatch_plan_next_run(2, 2, $t - $day, $t + 5 * 3600, $t), $t + 5 * 3600);
expect_same('the same interval without a plan: from the last scan', malwatch_plan_next_run(2, 2, $t - $day, null, $t),
	$t + $day);
expect_same('switched on a day after a scan: two days after it', malwatch_plan_next_run(2, 0, $t - $day, null, $t),
	$t + $day);
expect_same('switched on long after the last scan: at once', malwatch_plan_next_run(2, 0, $t - 30 * $day, null, $t), $t);
expect_same('a plan left from before the switch-off counts for nothing',
	malwatch_plan_next_run(2, 0, $t - $day, $t + 9 * $day, $t), $t + $day);
expect_same('a shorter interval pulls the plan in', malwatch_plan_next_run(2, 7, $t - $day, $t + 6 * $day, $t), $t + $day);
expect_same('a shorter interval, already due by it: at once', malwatch_plan_next_run(2, 7, $t - 3 * $day, $t + 4 * $day, $t),
	$t);
expect_same('a longer interval keeps the earlier plan', malwatch_plan_next_run(7, 2, $t - $day, $t + $day, $t), $t + $day);
expect_same('another interval: 5 days after a scan 2 days ago', malwatch_plan_next_run(5, 30, $t - 2 * $day,
	$t + 28 * $day, $t), $t + 3 * $day);
expect_same('numbers as text, as the database returns them', malwatch_plan_next_run('2', '7', (string) ($t - $day),
	(string) ($t + 6 * $day), $t), $t + $day);
expect_same('a zero date counts as no date', array(malwatch_plan_next_run(2, 2, $t - $day, 0, $t),
	malwatch_plan_next_run(2, 2, 0, null, $t)), array($t + $day, $t));

// --- The dialog "Änderungen prüfen" (0.33.0) ---------------------------------

// The stored value of every field of a form; a column the row lacks, or NULL,
// shows the default of the field.
$review_fields = array('max_parallel' => array('default' => '1'), 'poll_seconds' => array('default' => '2'),
	'default_excludes' => array(), 'use_clamav' => array('default' => 'y'));
expect_same('form values: stored, default for a missing column, empty without a default',
	malwatch_form_values($review_fields, array('max_parallel' => '4', 'use_clamav' => 'n', 'default_excludes' => null)),
	array('max_parallel' => '4', 'poll_seconds' => '2', 'default_excludes' => '', 'use_clamav' => 'n'));
expect_same('form values without a row', malwatch_form_values($review_fields, false),
	array('max_parallel' => '1', 'poll_seconds' => '2', 'default_excludes' => '', 'use_clamav' => 'y'));

// A key leaves the server as four characters to recognise it by.
expect_same('key mask', array(malwatch_key_mask(' abcd1234wxyz '), malwatch_key_mask(''), malwatch_key_mask(null)),
	array('••••wxyz', '', ''));

// The automatic action of the scanner as the choice the page checks.
expect_same('automatic action as a choice', array(
	malwatch_auto_choice('', 0, array(3)), malwatch_auto_choice('none', 0, array(3)),
	malwatch_auto_choice('safe', 0, array(3)), malwatch_auto_choice('critical', 5, array(3)),
	malwatch_auto_choice('preset', 3, array(3, 7)), malwatch_auto_choice('preset', '7', array('3', '7')),
	malwatch_auto_choice('preset', 9, array(3, 7)), malwatch_auto_choice('preset', 0, array()),
	malwatch_auto_choice('unbekannt', 0, array()),
), array('none', 'none', 'safe', 'critical', 'preset_3', 'preset_7', 'preset_new', 'preset_new', ''));

$review_words = malwatch_review_words(array('review_title_txt' => 'Änderungen prüfen', 'review_many_txt' => '%s Änderungen'));
expect_same('review words: known keys, a missing one empty',
	array($review_words['title'], $review_words['many'], $review_words['one'], count($review_words)),
	array('Änderungen prüfen', '%s Änderungen', '', 18));

$review_json = malwatch_review_json(
	array('poll_seconds' => '2', 'wpscan_token' => 'geheim-abcd', 'default_excludes' => "a\n</script><b>\"x\""),
	array(
		'secrets' => array('wpscan_token' => array('mask' => '••••abcd', 'clear' => 'wpscan_token_remove')),
		'danger' => array('default_excludes'),
		'labels' => array('auto_choice' => 'Automatische Aktion'),
		'words' => $review_words,
	));
$review = json_decode($review_json, true);
expect_same('review data: the stored values, without the key', $review['values'],
	array('poll_seconds' => '2', 'default_excludes' => "a\n</script><b>\"x\""));
expect_same('review data: the key only as its mask', array(strpos($review_json, 'geheim') === false,
	$review['secrets']['wpscan_token']), array(true, array('mask' => '••••abcd', 'clear' => 'wpscan_token_remove')));
expect_same('review data: protective lists, labels and words', array($review['danger'], $review['labels'],
	$review['words']['title']), array(array('default_excludes'), array('auto_choice' => 'Automatische Aktion'), 'Änderungen prüfen'));
expect_same('review data: no character of it ends a tag or an attribute', array(strpos($review_json, '<'),
	strpos($review_json, '>'), strpos($review_json, "'")), array(false, false, false));
expect_same('review data survives a value that is no UTF-8',
	is_array(json_decode(malwatch_review_json(array('x' => "\xff\xfe"), array()), true)), true);

// The state of a website in the finding list (0.41.0): the scheduler scans
// active websites only, so the findings of the others stay as the last scan
// left them.
expect_same('active website', malwatch_site_state(array('active' => 'y')), '');
expect_same('switched off', malwatch_site_state(array('active' => 'n')), 'inactive');
expect_same('gone from ISPConfig', malwatch_site_state(null), 'gone');
expect_same('gone, as queryOneRecord says it', malwatch_site_state(false), 'gone');

// A list opens on a default filter until the operator picks one (0.43.0).
// "alle" is stored as '', which is a choice too and stays.
$search = array();
malwatch_list_default_filter($search, 'malwatch_finding', 'search_finding_state', 'open');
expect_same('first visit gets the default', $search['malwatch_finding']['search_finding_state'], 'open');
$search = array('malwatch_finding' => array('search_finding_state' => ''));
malwatch_list_default_filter($search, 'malwatch_finding', 'search_finding_state', 'open');
expect_same('"alle" stays', $search['malwatch_finding']['search_finding_state'], '');
$search = array('malwatch_finding' => array('search_finding_state' => 'fixed', 'page' => 2));
malwatch_list_default_filter($search, 'malwatch_finding', 'search_finding_state', 'ignored');
expect_same('a chosen filter stays', $search['malwatch_finding'], array('search_finding_state' => 'fixed', 'page' => 2));
$search = null;
malwatch_list_default_filter($search, 'malwatch_scan', 'search_scan_state', 'findings');
expect_same('no search in the session yet', $search, array('malwatch_scan' => array('search_scan_state' => 'findings')));

// The order of the finding list: open before released before fixed, the worst
// first, the newest first.
$order = malwatch_finding_list_order();
expect_same('order starts with ORDER BY', strpos($order, 'ORDER BY '), 0);
expect_same('state before severity',
	strpos($order, "FIELD(finding_state, 'open', 'ignored', 'fixed')") < strpos($order, "FIELD(severity, 'critical', 'high', 'medium', 'low')"), true);
expect_same('newest last in the order', substr($order, -14), 'last_seen DESC');

// The counts of a scan as words: only the levels that occur, the worst first.
$words = array('sev_critical_txt' => 'kritisch', 'sev_high_txt' => 'hoch', 'sev_medium_txt' => 'mittel',
	'sev_low_txt' => 'gering', 'counts_none_txt' => 'keine');
expect_same('counts as words', malwatch_scan_counts(array('count_critical' => '3', 'count_high' => '8',
	'count_medium' => '0', 'count_low' => '0'), $words), '3 kritisch · 8 hoch');
expect_same('only low', malwatch_scan_counts(array('count_critical' => '0', 'count_high' => '0',
	'count_medium' => '0', 'count_low' => '12'), $words), '12 gering');
expect_same('nothing found', malwatch_scan_counts(array('count_critical' => '0', 'count_high' => '0',
	'count_medium' => '0', 'count_low' => '0'), $words), 'keine');
expect_same('missing columns count as none', malwatch_scan_counts(array(), $words), 'keine');
expect_same('thousands', malwatch_scan_counts(array('count_low' => '1500'), $words), '1.500 gering');

// A failed quarantine job says which job, what it should have done, why it
// failed and what to do now (0.43.0). The banner used to name none of it.
$job_words = array(
	'job_error_head_txt' => 'Auftrag %s vom %s ist gescheitert: %s.',
	'job_action_restore_txt' => 'Einträge zurückholen', 'job_action_add_txt' => 'Dateien verschieben',
	'job_action_unknown_txt' => 'Quarantäneauftrag',
	'job_error_no_log_txt' => 'Der Scanner hat keinen Grund gemeldet (Rückgabewert %s).',
	'job_error_next_txt' => 'Wiederhole die Aktion an den Einträgen.',
);
$job = malwatch_job_error_text(array('job_id' => '42', 'finished_at' => '2026-10-10 14:02:00',
	'options' => '{"action":"restore","ids":["a"]}', 'job_log' => "Ziel belegt\n", 'exit_code' => '1'), $job_words);
expect_same('job error head', $job['head'], 'Auftrag 42 vom 10.10.2026 14:02 ist gescheitert: Einträge zurückholen.');
expect_same('job error reason', $job['reason'], 'Ziel belegt');
expect_same('job error next step', $job['next'], 'Wiederhole die Aktion an den Einträgen.');
$job = malwatch_job_error_text(array('job_id' => '7', 'finished_at' => '2026-10-10 09:05:00',
	'options' => 'kaputt', 'job_log' => '', 'exit_code' => '3'), $job_words);
expect_same('job error unknown action', $job['head'], 'Auftrag 7 vom 10.10.2026 09:05 ist gescheitert: Quarantäneauftrag.');
expect_same('job error without log', $job['reason'], 'Der Scanner hat keinen Grund gemeldet (Rückgabewert 3).');

// A count of known flaws carries the word of its worst level, so the colour
// is never the only signal (0.43.0).
$sev_words = array('severity_high_txt' => 'hoch', 'severity_medium_txt' => 'mittel');
expect_same('count with level', malwatch_with_severity('3 Lücken', $sev_words, 'medium'), '3 Lücken · mittel');
expect_same('count without a known level', malwatch_with_severity('1 Lücke', $sev_words, ''), '1 Lücke');
expect_same('level without a word', malwatch_with_severity('2 Lücken', $sev_words, 'critical'), '2 Lücken · critical');

// ISPConfig's template engine counts an empty loop as one row (_arrayBuild()
// answers true, _tpl_count(true) is 1), so an empty list showed one empty row
// such as "()". malwatch_set_loop() hands the engine only rows, and turns an
// empty list inside a row into null, which counts as none (0.43.0).
class loop_recorder
{
	public $loops = array();
	public function setLoop($k, $v)
	{
		$this->loops[$k] = $v;
	}
}
$fake_app = new stdClass();
$fake_app->tpl = new loop_recorder();
malwatch_set_loop($fake_app, 'actionlog', array());
expect_same('an empty list is not handed over', array_key_exists('actionlog', $fake_app->tpl->loops), false);
malwatch_set_loop($fake_app, 'rows', array(array('ip' => '192.0.2.1', 'chips' => array()),
	array('ip' => '192.0.2.2', 'chips' => array(array('chip' => 'Tor')))));
expect_same('rows are handed over', count($fake_app->tpl->loops['rows']), 2);
expect_same('an empty inner list becomes null', $fake_app->tpl->loops['rows'][0]['chips'], null);
expect_same('a full inner list stays', $fake_app->tpl->loops['rows'][1]['chips'], array(array('chip' => 'Tor')));
malwatch_set_loop($fake_app, 'none', null);
expect_same('no array at all is not handed over', array_key_exists('none', $fake_app->tpl->loops), false);

if ($failures > 0) {
	exit(1);
}
echo "panel helpers OK\n";
