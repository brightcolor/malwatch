<?php
/**
 * Checks the pure helpers behind the page "Dumps": the rows of the database
 * picker, the names it accepts back, and the rows of the dump list.
 *
 *   php ispconfig/tests/dump_helpers_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';

$wb = array(
	'db_tables_txt' => '%s Tabellen',
	'db_no_tables_txt' => 'keine Tabellen',
	'db_used_wordpress_txt' => 'WordPress %s',
	'db_write_txt' => 'zuletzt geschrieben %s',
	'dump_state_pending_txt' => 'wartet',
	'dump_state_running_txt' => 'läuft',
	'dump_state_done_txt' => 'fertig',
	'dump_state_error_txt' => 'gescheitert',
	'dump_content_txt' => '%s Dateien, %s Datenbanken',
	'dump_with_logs_txt' => 'mit Protokollen',
	'dump_valid_txt' => 'gültig bis %s',
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

// One row per database of the website, in the order the caller reads them.
$databases = array(
	array(
		'database_name' => 'web12_shop',
		'table_count' => '38',
		'bytes' => '12400000',
		'last_write' => '2026-09-14 22:31:00',
		'used_kind' => 'wordpress',
		'used_by' => '/shop',
		'checked_at' => '2026-09-15 01:07:00',
	),
	array(
		'database_name' => 'web12_alt',
		'table_count' => '12',
		'bytes' => '1100000',
		'last_write' => '2024-03-02 11:00:00',
		'used_kind' => '',
		'used_by' => '',
		'checked_at' => '2026-09-15 01:07:00',
	),
	array(
		'database_name' => 'web12_leer',
		'table_count' => '0',
		'bytes' => '0',
		'last_write' => null,
		'used_kind' => '',
		'used_by' => '',
		'checked_at' => '2026-09-15 01:07:00',
	),
	// Nothing collected yet: the hourly run has not seen this one.
	array(
		'database_name' => 'web12_neu',
		'table_count' => '0',
		'bytes' => '0',
		'last_write' => null,
		'used_kind' => '',
		'used_by' => '',
		'checked_at' => null,
	),
);

$rows = malwatch_dump_database_rows($databases, $wb);
expect_same('one row per database', count($rows), 4);
expect_same('name', $rows[0]['name'], 'web12_shop');
expect_same('size', $rows[0]['size_label'], '12,4 MB');
expect_same('tables', $rows[0]['tables_label'], '38 Tabellen');
expect_same('installation', $rows[0]['used_label'], 'WordPress /shop');
expect_same('last write', $rows[0]['write_label'], 'zuletzt geschrieben 14.09.2026');
expect_same('marks known', $rows[0]['has_marks'], 1);

expect_same('without installation', $rows[1]['used_label'], '');
expect_same('older write', $rows[1]['write_label'], 'zuletzt geschrieben 02.03.2024');

expect_same('empty database', $rows[2]['tables_label'], 'keine Tabellen');
expect_same('empty size', $rows[2]['size_label'], '0 B');
expect_same('empty database without write', $rows[2]['write_label'], '');

expect_same('nothing collected', $rows[3]['has_marks'], 0);
expect_same('nothing collected has no size', $rows[3]['size_label'], '');
expect_same('nothing collected has no tables', $rows[3]['tables_label'], '');

// The names the page offered are the only ones it takes back.
$known = malwatch_dump_known_names($databases);
expect_same('known names', $known, array('web12_shop', 'web12_alt', 'web12_leer', 'web12_neu'));
expect_same('only what was offered',
	malwatch_dump_filter_names(array('web12_leer', 'fremd_db', 'web12_shop'), $known),
	array('web12_shop', 'web12_leer'));
expect_same('nothing ticked', malwatch_dump_filter_names(array(), $known), array());
expect_same('a name that is no string', malwatch_dump_filter_names(array(array('web12_shop')), $known), array());

// The rows of the list below the form.
$dumps = array(
	array(
		'dump_id' => '4',
		'domain' => 'beispiel.de',
		'dump_state' => 'done',
		'token' => 'a1b2c3',
		'archive_bytes' => '482000000',
		'file_count' => '128',
		'database_count' => '2',
		'with_logs' => 'y',
		'error_reason' => '',
		'job_log' => '',
		'created_at' => '2026-09-15 01:00:00',
		'expires_at' => '2026-09-22 01:00:00',
	),
	array(
		'dump_id' => '3',
		'domain' => 'beispiel.de',
		'dump_state' => 'running',
		'token' => 'b2c3d4',
		'archive_bytes' => '0',
		'file_count' => '0',
		'database_count' => '0',
		'with_logs' => 'n',
		'error_reason' => '',
		'job_log' => '',
		'created_at' => '2026-09-15 00:40:00',
		'expires_at' => null,
	),
	array(
		'dump_id' => '2',
		'domain' => 'alt.beispiel.de',
		'dump_state' => 'error',
		'token' => '',
		'archive_bytes' => '0',
		'file_count' => '0',
		'database_count' => '0',
		'with_logs' => 'n',
		'error_reason' => 'space',
		'job_log' => 'frei sind 100 Bytes, gebraucht werden 900',
		'created_at' => '2026-09-14 23:00:00',
		'expires_at' => null,
	),
	// Done, but the week is over: the file is gone, the row waits for the
	// hourly run.
	array(
		'dump_id' => '1',
		'domain' => 'beispiel.de',
		'dump_state' => 'done',
		'token' => 'c3d4e5',
		'archive_bytes' => '1000',
		'file_count' => '3',
		'database_count' => '1',
		'with_logs' => 'n',
		'error_reason' => '',
		'job_log' => '',
		'created_at' => '2026-09-01 10:00:00',
		'expires_at' => '2026-09-08 10:00:00',
	),
);

// A fixed moment, so "valid until" says the same thing next month.
$now = strtotime('2026-09-15 12:00:00');

$list = malwatch_dump_rows($dumps, $wb, $now);
expect_same('one row per dump', count($list), 4);
expect_same('state done', $list[0]['state_label'], 'fertig');
expect_same('size of the archive', $list[0]['size_label'], '482,0 MB');
expect_same('content', $list[0]['content_label'], '128 Dateien, 2 Datenbanken, mit Protokollen');
expect_same('valid until', $list[0]['valid_label'], 'gültig bis 22.09.2026');
expect_same('download', $list[0]['can_download'], 1);

expect_same('state running', $list[1]['state_label'], 'läuft');
expect_same('running has no download', $list[1]['can_download'], 0);
expect_same('running has no size', $list[1]['size_label'], '');

expect_same('state error', $list[2]['state_label'], 'gescheitert');
expect_same('error keeps its message', $list[2]['message'], 'frei sind 100 Bytes, gebraucht werden 900');
expect_same('error has no download', $list[2]['can_download'], 0);

expect_same('expired has no download', $list[3]['can_download'], 0);

// The public link: one row per dump says whether it is shared, how long, and
// how often it was fetched.
$wb['dump_public_until_txt'] = 'öffentlich bis %s';
$wb['dump_public_once_txt'] = 'öffentlich, ein Abruf';
$wb['dump_public_hits_txt'] = '%s Abrufe, zuletzt %s';

$shared = array(
	// Shared until the dump itself goes.
	array(
		'dump_id' => '9', 'domain' => 'beispiel.de', 'dump_state' => 'done', 'token' => 'a1',
		'archive_bytes' => '1000', 'file_count' => '3', 'database_count' => '1', 'with_logs' => 'n',
		'error_reason' => '', 'job_log' => '', 'created_at' => '2026-09-15 01:00:00',
		'expires_at' => '2026-09-22 01:00:00',
		'public_token' => 'p1', 'public_mode' => 'expiry', 'public_until' => '2026-09-22 01:00:00',
		'public_password' => '', 'public_hits' => '3', 'public_last_at' => '2026-09-15 02:10:00',
	),
	// Shared for one fetch, none so far.
	array(
		'dump_id' => '8', 'domain' => 'beispiel.de', 'dump_state' => 'done', 'token' => 'a2',
		'archive_bytes' => '1000', 'file_count' => '3', 'database_count' => '1', 'with_logs' => 'n',
		'error_reason' => '', 'job_log' => '', 'created_at' => '2026-09-15 01:00:00',
		'expires_at' => '2026-09-22 01:00:00',
		'public_token' => 'p2', 'public_mode' => 'once', 'public_until' => null,
		'public_password' => 'hash', 'public_hits' => '0', 'public_last_at' => null,
	),
	// The 24 hours are over: the dump stays, the link is done.
	array(
		'dump_id' => '7', 'domain' => 'beispiel.de', 'dump_state' => 'done', 'token' => 'a3',
		'archive_bytes' => '1000', 'file_count' => '3', 'database_count' => '1', 'with_logs' => 'n',
		'error_reason' => '', 'job_log' => '', 'created_at' => '2026-09-14 01:00:00',
		'expires_at' => '2026-09-21 01:00:00',
		'public_token' => 'p3', 'public_mode' => 'day', 'public_until' => '2026-09-15 01:00:00',
		'public_password' => '', 'public_hits' => '1', 'public_last_at' => '2026-09-14 12:00:00',
	),
	// Still running: nothing to share yet.
	array(
		'dump_id' => '6', 'domain' => 'beispiel.de', 'dump_state' => 'running', 'token' => 'a4',
		'archive_bytes' => '0', 'file_count' => '0', 'database_count' => '0', 'with_logs' => 'n',
		'error_reason' => '', 'job_log' => '', 'created_at' => '2026-09-15 01:30:00',
		'expires_at' => null,
		'public_token' => '', 'public_mode' => 'none', 'public_until' => null,
		'public_password' => '', 'public_hits' => '0', 'public_last_at' => null,
	),
);

$public = malwatch_dump_rows($shared, $wb, $now);
expect_same('shared', $public[0]['is_public'], 1);
expect_same('shared until', $public[0]['public_label'], 'öffentlich bis 22.09.2026');
expect_same('fetches', $public[0]['public_hits_label'], '3 Abrufe, zuletzt 15.09.2026');
expect_same('shared needs no second share', $public[0]['can_share'], 0);
expect_same('has a password', $public[0]['has_password'], 0);

expect_same('one fetch', $public[1]['public_label'], 'öffentlich, ein Abruf');
expect_same('no fetch yet', $public[1]['public_hits_label'], '');
expect_same('password set', $public[1]['has_password'], 1);

expect_same('day over', $public[2]['is_public'], 0);
expect_same('day over can be shared again', $public[2]['can_share'], 1);
expect_same('day over has no label', $public[2]['public_label'], '');

expect_same('running cannot be shared', $public[3]['can_share'], 0);
expect_same('running is not public', $public[3]['is_public'], 0);

// The three ways a share may last, and nothing else.
expect_same('mode expiry', malwatch_dump_public_mode('expiry'), 'expiry');
expect_same('mode day', malwatch_dump_public_mode('day'), 'day');
expect_same('mode once', malwatch_dump_public_mode('once'), 'once');
expect_same('unknown mode', malwatch_dump_public_mode('für immer'), '');
expect_same('empty mode', malwatch_dump_public_mode(''), '');

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "dump helpers OK\n";
