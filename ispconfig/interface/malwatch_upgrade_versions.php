<?php

/**
 * Serves every target version of one row of the page "Updates" as JSON, for
 * its entry "Weitere Versionen laden". The page carries the short list
 * (malwatch_upgrade_offers(), short); the labels here come from the same
 * function, so both lists name a version alike.
 *
 * Reached as malwatch_upgrade_versions.php?id=<domain_id>&software_id=<id>.
 * No template, see malwatch_progress.php.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('error' => 'denied', 'choices' => array()));
} else {
	$app->uses('functions');
	require_once 'lib/malwatch_lib.inc.php';

	// Included, see malwatch_progress.php for why load_language_file() would
	// leave $wb empty here.
	$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_upgrade.lng';
	if (!file_exists($lng_file)) {
		$lng_file = 'lib/lang/en_malwatch_upgrade.lng';
	}
	include $lng_file;

	$domain_id = $app->functions->intval(isset($_GET['id']) ? $_GET['id'] : 0);
	$software_id = $app->functions->intval(isset($_GET['software_id']) ? $_GET['software_id'] : 0);

	// The row as the page lists it: malwatch_upgrade_candidates() is what the
	// page and malwatch_queue_upgrade() read as well.
	$found = null;
	if ($domain_id > 0 && $software_id > 0) {
		list($installs) = malwatch_upgrade_candidates($app, $domain_id, $wb, 100000);
		foreach ($installs as $install) {
			foreach ($install['rows'] as $row) {
				if ($row['software_id'] === $software_id) {
					$found = $row;
				}
			}
		}
	}

	if ($found === null) {
		echo json_encode(array('error' => 'not found', 'choices' => array()));
	} else {
		$choices = array();
		foreach ($found['offers']['choices'] as $choice) {
			$choices[] = array('version' => $choice['version'], 'label' => $choice['label'], 'closes' => $choice['closes']);
		}
		echo json_encode(array('choices' => $choices, 'default' => $found['offers']['default']));
	}
}
