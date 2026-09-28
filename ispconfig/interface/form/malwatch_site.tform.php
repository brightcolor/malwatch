<?php

/**
 * Form definition for the per website malwatch settings.
 */

$form['title'] = 'malwatch';
$form['description'] = '';
$form['name'] = 'malwatch_site';
$form['action'] = 'malwatch_site_edit.php';
$form['db_table'] = 'malwatch_site';
$form['db_table_idx'] = 'site_id';
$form['db_history'] = 'no';
$form['tab_default'] = 'settings';
$form['list_default'] = 'status.php';
$form['auth'] = 'yes';

$form['auth_preset']['userid'] = 0;
$form['auth_preset']['groupid'] = 0;
$form['auth_preset']['perm_user'] = 'riud';
$form['auth_preset']['perm_group'] = 'riud';
$form['auth_preset']['perm_other'] = '';

$severity_values = array(
	'low' => 'gering',
	'medium' => 'mittel',
	'high' => 'hoch',
	'critical' => 'kritisch'
);

$form['tabs']['settings'] = array(
	'title' => 'Einstellungen',
	'width' => 100,
	'template' => 'templates/malwatch_site_edit.htm',
	'fields' => array(
		// Every how many days the scanner checks the website on its own, 0 for
		// never. A new row starts from default_scan_days (see onShowNew() in
		// malwatch_site_edit.php).
		'scan_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '0',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:365',
					'errmsg' => 'scan_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'max_age' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '0',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:3650',
					'errmsg' => 'max_age_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'version_scan' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value' => array(0 => 'n', 1 => 'y')
		),
		'excludes' => array(
			'datatype' => 'TEXT',
			'formtype' => 'TEXTAREA',
			'default' => '',
			'cols' => '30',
			'rows' => '6'
		),
		'notify_admin' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value' => array(0 => 'n', 1 => 'y')
		),
		'notify_admin_severity' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'high',
			'value' => $severity_values
		),
		'notify_client' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value' => array(0 => 'n', 1 => 'y')
		),
		'notify_client_severity' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'critical',
			'value' => $severity_values
		),
		'disable_site' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value' => array(0 => 'n', 1 => 'y')
		),
		'disable_severity' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'critical',
			'value' => $severity_values
		)
	)
);

unset($severity_values);
