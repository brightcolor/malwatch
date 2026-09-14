<?php

/**
 * Streams one dump archive.
 *
 * No template and nothing before the headers: the whole response is the file.
 * The archive lies in a directory the panel may read and nothing else on the
 * server can, and this page is the one door into it.
 *
 * The token stays valid for as long as the dump lies there, which is the
 * difference to the quarantine download: a dump can be many gigabytes, and a
 * connection that breaks halfway must not cost a whole new run.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

// Out of the dump list's language file: the sentences below belong to the
// screen the link was clicked on. Included rather than fetched through
// $app->load_language_file(), see malwatch_dump_list.php.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_dump.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_dump.lng';
}
include $lng_file;

$token = isset($_REQUEST['token']) ? (string) $_REQUEST['token'] : '';

// The shape is checked before the value ever names a path: a token from a
// request must not be trusted to point at a file just because it found no
// row.
if ($token === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $token)) {
	die($wb['err_dl_bad_link_txt']);
}

$row = $app->db->queryOneRecord(
	"SELECT dump_id, domain, token, created_at FROM malwatch_dump WHERE token = ? AND dump_state = 'done' "
	. 'AND expires_at IS NOT NULL AND expires_at > NOW()',
	$token);

// MySQL compares under the table's collation, which ignores case, so an
// upper-cased copy of a token would find the row. The comparison that decides
// is this one; the = above stays so the query keeps using the index.
if (!is_array($row) || !hash_equals((string) $row['token'], $token)) {
	die($wb['err_dl_expired_txt']);
}

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/dumps/' . $token . '.tar.gz';

if (!is_file($file)) {
	die($wb['err_dl_gone_txt']);
}

$name = 'malwatch-dump-'
	. preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $row['domain'])
	. '-' . substr((string) $row['created_at'], 0, 10) . '.tar.gz';

header('Content-Type: application/gzip');
header('Content-Disposition: attachment; filename="' . $name . '"');
header('Content-Length: ' . filesize($file));
header('Cache-Control: no-store');

// Emptied first: left alone, PHP holds the whole archive in the output buffer
// before readfile() streams a byte, and a dump is the largest file this panel
// ever hands out.
while (ob_get_level() > 0) {
	ob_end_clean();
}
readfile($file);
exit;
