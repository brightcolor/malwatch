<?php

/**
 * Streams one dump archive. Two doors lead here, and nothing else does.
 *
 * The panel's door takes token= and goes through the module permission like
 * every other page of the addon. The public door takes public= and opens for
 * a share that exists, still counts and - when one was set - answers its
 * password. A request with neither key reaches nothing.
 *
 * No template and nothing before the headers: the whole response is the file.
 * The one exception is the password form below, which is a page of its own.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

// A public visitor has no session language, so the fallback decides.
$language = isset($_SESSION['s']['language']) ? (string) $_SESSION['s']['language'] : '';
$lng_file = 'lib/lang/' . $app->functions->check_language($language !== '' ? $language : 'de') . '_malwatch_dump.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_dump.lng';
}
include $lng_file;

$public = isset($_REQUEST['public']) ? (string) $_REQUEST['public'] : '';
$token = isset($_REQUEST['token']) ? (string) $_REQUEST['token'] : '';
$shape = '/^[A-Za-z0-9_-]+$/';

if ($public === '') {
	// --- The panel's own way in -------------------------------------------
	$app->auth->check_module_permissions('security');
	if (!$app->auth->is_admin()) {
		die('Nur für Administratoren.');
	}

	// The shape is checked before the value ever names a path: a token from a
	// request must not be trusted to point at a file just because it found no
	// row.
	if ($token === '' || !preg_match($shape, $token)) {
		die($wb['err_dl_bad_link_txt']);
	}

	$row = $app->db->queryOneRecord(
		"SELECT dump_id, domain, token, created_at FROM malwatch_dump WHERE token = ? AND dump_state = 'done' "
		. 'AND expires_at IS NOT NULL AND expires_at > NOW()',
		$token);

	// MySQL compares under the table's collation, which ignores case, so an
	// upper-cased copy of a token would find the row. The comparison that
	// decides is this one; the = above stays so the query keeps using the
	// index.
	if (!is_array($row) || !hash_equals((string) $row['token'], $token)) {
		die($wb['err_dl_expired_txt']);
	}

	malwatch_dump_stream($app, $wb, $row, $token);
}

// --- The public door ---------------------------------------------------------
if (!preg_match($shape, $public)) {
	die($wb['err_public_gone_txt']);
}

// A share counts while the dump itself lies there and while its own end has
// not come: a share by time until public_until, a share for one fetch until
// the download below burns its key.
$row = $app->db->queryOneRecord(
	'SELECT dump_id, domain, token, public_token, public_mode, public_password, created_at '
	. "FROM malwatch_dump WHERE public_token = ? AND dump_state = 'done' "
	. 'AND expires_at IS NOT NULL AND expires_at > NOW() '
	. "AND ((public_mode = 'once') OR (public_until IS NOT NULL AND public_until > NOW()))",
	$public);

if (!is_array($row) || !hash_equals((string) $row['public_token'], $public)) {
	die($wb['err_public_gone_txt']);
}

$hash = (string) $row['public_password'];
if ($hash !== '') {
	$given = isset($_POST['password']) ? (string) $_POST['password'] : '';
	if ($given === '' || !password_verify($given, $hash)) {
		malwatch_dump_password_form($app, $wb, $public, $given !== '');
	}
}

// Every fetch is noted: the list says how often and from where.
$app->db->query(
	'UPDATE malwatch_dump SET public_hits = public_hits + 1, public_last_at = NOW(), public_last_ip = ? '
	. 'WHERE dump_id = ?',
	substr((string) (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''), 0, 45),
	$app->functions->intval($row['dump_id']));

malwatch_dump_stream($app, $wb, $row, (string) $row['token'], (string) $row['public_mode'] === 'once'
	? $app->functions->intval($row['dump_id']) : 0);

/**
 * Sends the archive of one row and ends the request.
 *
 * $burn names the dump whose share ends with this fetch: the key goes after
 * the file is out, so a connection that breaks halfway leaves the share
 * usable - which is the whole point of handing someone a link.
 */
function malwatch_dump_stream($app, $wb, $row, $token, $burn = 0)
{
	$config = malwatch_get_config($app);
	$file = rtrim((string) $config['state_dir'], '/') . '/dumps/' . $token . '.tar.gz';

	if ($token === '' || !is_file($file)) {
		die($wb['err_dl_gone_txt']);
	}

	$name = 'malwatch-dump-'
		. preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $row['domain'])
		. '-' . substr((string) $row['created_at'], 0, 10) . '.tar.gz';

	header('Content-Type: application/gzip');
	header('Content-Disposition: attachment; filename="' . $name . '"');
	header('Content-Length: ' . filesize($file));
	header('Cache-Control: no-store');

	// Emptied first: left alone, PHP holds the whole archive in the output
	// buffer before readfile() streams a byte, and a dump is the largest file
	// this panel ever hands out.
	while (ob_get_level() > 0) {
		ob_end_clean();
	}
	readfile($file);

	if ($burn > 0) {
		$app->db->query(
			"UPDATE malwatch_dump SET public_token = '', public_mode = 'none', public_until = NULL, "
			. "public_password = '' WHERE dump_id = ?",
			$burn);
	}
	exit;
}

/** Asks for the password of a share and ends the request. */
function malwatch_dump_password_form($app, $wb, $public, $wrong)
{
	$key = htmlspecialchars($public, ENT_QUOTES, 'UTF-8');
	$head = htmlspecialchars($wb['public_head_txt'], ENT_QUOTES, 'UTF-8');
	$label = htmlspecialchars($wb['public_password_txt'], ENT_QUOTES, 'UTF-8');
	$button = htmlspecialchars($wb['btn_public_fetch_txt'], ENT_QUOTES, 'UTF-8');
	$note = $wrong ? '<p style="color:#b3261e">' . htmlspecialchars($wb['err_public_password_txt'], ENT_QUOTES, 'UTF-8') . '</p>' : '';

	header('Content-Type: text/html; charset=utf-8');
	header('Cache-Control: no-store');

	// A page of its own, without the panel around it: whoever opens this has
	// no session here and needs nothing but the one field.
	echo '<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">'
		. '<meta name="viewport" content="width=device-width, initial-scale=1">'
		. '<title>' . $head . '</title></head>'
		. '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">'
		. '<h1 style="font-size:1.25rem">' . $head . '</h1>' . $note
		. '<form method="post" action="?public=' . $key . '">'
		. '<label>' . $label . '<br><input type="password" name="password" autofocus '
		. 'style="padding:.5rem;width:100%;box-sizing:border-box"></label><br><br>'
		. '<button type="submit" style="padding:.5rem 1rem">' . $button . '</button>'
		. '</form></body></html>';
	exit;
}
