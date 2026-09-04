<?php

/**
 * Adds the malwatch entries to the navigation of the Websites module.
 *
 * The extension has no module of its own on purpose: a separate module name
 * would have to be written into sys_user.modules for every operator, which
 * means changing core data on install. Hooking into the existing module
 * through menu.d is the path the 3.3 extension mechanism provides.
 */

if ($app->auth->is_admin()) {

	$items = array();

	$items[] = array(
		'title'   => 'Übersicht',
		'target'  => 'content',
		'link'    => 'sites/malwatch_site_list.php',
		'html_id' => 'malwatch_site_list'
	);

	$items[] = array(
		'title'   => 'Funde',
		'target'  => 'content',
		'link'    => 'sites/malwatch_finding_list.php',
		'html_id' => 'malwatch_finding_list'
	);

	$items[] = array(
		'title'   => 'Prüfläufe',
		'target'  => 'content',
		'link'    => 'sites/malwatch_scan_list.php',
		'html_id' => 'malwatch_scan_list'
	);

	$items[] = array(
		'title'   => 'Einstellungen',
		'target'  => 'content',
		'link'    => 'sites/malwatch_config_edit.php',
		'html_id' => 'malwatch_config_edit'
	);

	$module['nav'][] = array(
		'title' => 'malwatch',
		'open'  => 1,
		'items' => $items
	);

	unset($items);
}
