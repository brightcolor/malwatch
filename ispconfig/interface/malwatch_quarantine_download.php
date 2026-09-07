<?php

/**
 * Streams one quarantine export ZIP and burns its token.
 *
 * No template and nothing may reach stdout before the headers below - the
 * whole response IS the file, not a page describing it. The panel never
 * reads the store directly (that is where the malware lives); this is the
 * one narrow door a token opens for 24 hours, once.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

$token = isset($_REQUEST['token']) ? (string) $_REQUEST['token'] : '';

// The token only ever matches a row if it is exactly what the server wrote,
// so a value that fails this shape never reaches the database - but the
// filesystem path built from it below gets the same defence the store
// itself uses for entry ids: a value from a request must not be trusted to
// name a path just because it happened not to match anything.
if ($token === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $token)) {
	die('Kein gültiger Verweis.');
}

$row = $app->db->queryOneRecord(
	'SELECT quarantine_id, entry_id FROM malwatch_quarantine WHERE export_token = ? '
	. 'AND export_ready_at IS NOT NULL AND export_ready_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
	$token);
if (!is_array($row)) {
	die('Der Verweis ist ungültig oder abgelaufen.');
}

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/spool/' . $token . '.zip';

// The token is single use either way: found or not, a second click on the
// same link must not work twice, and the row goes back to offering a fresh
// "Herunterladen" button instead of one that quietly keeps failing.
$app->db->query(
	"UPDATE malwatch_quarantine SET export_token = '', export_bytes = 0, export_ready_at = NULL WHERE quarantine_id = ?",
	$app->functions->intval($row['quarantine_id']));

if (!is_file($file)) {
	die('Die Datei liegt nicht mehr vor.');
}

$name = 'malwatch-quarantine-' . preg_replace('/[^A-Za-z0-9_-]/', '_', (string) $row['entry_id']) . '.zip';

header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="' . $name . '"');
header('Content-Length: ' . filesize($file));
header('Cache-Control: no-store');

// Emptied first: left alone, PHP holds the whole file in the output buffer
// before readfile() ever streams a byte of it, and a 40 MB archive against
// the panel's ordinary memory_limit is exactly the case that then fails.
while (ob_get_level() > 0) {
	ob_end_clean();
}
readfile($file);
exit;
