<?php

/**
 * The database rows of one website as JSON, for the picker on the page
 * "Dumps" when someone picks another website.
 *
 * Same shape as malwatch_upgrade_versions.php: no template, administrators
 * only, and the labels come from the same helper the page itself renders
 * with, so both ways into the list say the same thing.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');

header('Content-Type: application/json');

if (!$app->auth->is_admin()) {
	echo json_encode(array('rows' => array(), 'none' => ''));
	return;
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_dump.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_dump.lng';
}
include $lng_file;

$domain_id = isset($_REQUEST['id']) ? $app->functions->intval($_REQUEST['id']) : 0;
$web = $domain_id > 0
	? $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ? AND type = 'vhost'", $domain_id)
	: false;

$rows = array();
if (is_array($web)) {
	foreach (malwatch_dump_database_rows(malwatch_dump_databases($app, $web), $wb) as $row) {
		// The page builds its markup from these, so every field arrives
		// escaped; name_attr is the one that ends up inside an attribute.
		$rows[] = array(
			'name' => $app->functions->htmlentities($row['name']),
			'name_attr' => htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'),
			'size_label' => $app->functions->htmlentities($row['size_label']),
			'tables_label' => $app->functions->htmlentities($row['tables_label']),
			'used_label' => $app->functions->htmlentities($row['used_label']),
			'write_label' => $app->functions->htmlentities($row['write_label']),
			'has_marks' => $row['has_marks'],
		);
	}
}

echo json_encode(array(
	'rows' => $rows,
	'none' => $app->functions->htmlentities($wb['db_none_txt']),
	'hint' => $app->functions->htmlentities($wb['db_hint_pending_txt']),
));
