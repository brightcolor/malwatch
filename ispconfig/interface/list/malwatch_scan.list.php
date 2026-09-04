<?php

/**
 * History of finished scans.
 */

$liste['name'] = 'malwatch_scan';
$liste['table'] = 'malwatch_scan';
$liste['table_idx'] = 'scan_id';
$liste['search_prefix'] = 'search_';
$liste['records_per_page'] = '25';
$liste['file'] = 'malwatch_scan_list.php';
$liste['edit_file'] = 'malwatch_site_show.php';
$liste['delete_file'] = '';
$liste['paging_tpl'] = 'templates/paging.tpl.htm';
$liste['auth'] = 'no';

$liste['item'][] = array(
	'field' => 'domain',
	'datatype' => 'VARCHAR',
	'formtype' => 'TEXT',
	'op' => 'like',
	'prefix' => '%',
	'suffix' => '%',
	'width' => '',
	'value' => ''
);

$liste['item'][] = array(
	'field' => 'scan_state',
	'datatype' => 'VARCHAR',
	'formtype' => 'SELECT',
	'op' => '=',
	'prefix' => '',
	'suffix' => '',
	'width' => '',
	'value' => array('' => 'alle', 'clean' => 'sauber', 'findings' => 'Funde', 'outdated' => 'veraltet', 'error' => 'Fehler')
);
