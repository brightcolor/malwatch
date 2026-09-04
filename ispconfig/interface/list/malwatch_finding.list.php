<?php

/**
 * List of all findings across every website.
 */

$liste['name'] = 'malwatch_finding';
$liste['table'] = 'malwatch_finding';
$liste['table_idx'] = 'finding_id';
$liste['search_prefix'] = 'search_';
$liste['records_per_page'] = '25';
$liste['file'] = 'malwatch_finding_list.php';
$liste['edit_file'] = 'malwatch_site_show.php';
$liste['delete_file'] = '';
$liste['paging_tpl'] = 'templates/paging.tpl.htm';
$liste['auth'] = 'no';

// The default view shows what still needs attention. Released and fixed
// findings are reachable through the filter, they just do not lead the list.
$liste['item'][] = array(
	'field' => 'finding_state',
	'datatype' => 'VARCHAR',
	'formtype' => 'SELECT',
	'op' => '=',
	'prefix' => '',
	'suffix' => '',
	'width' => '',
	'value' => array('' => 'alle', 'open' => 'offen', 'ignored' => 'freigegeben', 'fixed' => 'behoben')
);

$liste['item'][] = array(
	'field' => 'severity',
	'datatype' => 'VARCHAR',
	'formtype' => 'SELECT',
	'op' => '=',
	'prefix' => '',
	'suffix' => '',
	'width' => '',
	'value' => array('' => 'alle', 'critical' => 'kritisch', 'high' => 'hoch', 'medium' => 'mittel', 'low' => 'gering')
);

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
	'field' => 'rule_id',
	'datatype' => 'VARCHAR',
	'formtype' => 'TEXT',
	'op' => 'like',
	'prefix' => '%',
	'suffix' => '%',
	'width' => '',
	'value' => ''
);

$liste['item'][] = array(
	'field' => 'file_path',
	'datatype' => 'VARCHAR',
	'formtype' => 'TEXT',
	'op' => 'like',
	'prefix' => '%',
	'suffix' => '%',
	'width' => '',
	'value' => ''
);
