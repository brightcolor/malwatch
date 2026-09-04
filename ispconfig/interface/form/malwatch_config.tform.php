<?php

/**
 * Form definition for the global malwatch settings. Exactly one record.
 */

$form['title'] = 'malwatch';
$form['description'] = '';
$form['name'] = 'malwatch_config';
$form['action'] = 'malwatch_config_edit.php';
$form['db_table'] = 'malwatch_config';
$form['db_table_idx'] = 'config_id';
$form['db_history'] = 'no';
$form['tab_default'] = 'settings';
$form['list_default'] = 'malwatch_site_list.php';
$form['auth'] = 'no';

$form['tabs']['settings'] = array(
	'title' => 'Einstellungen',
	'width' => 100,
	'template' => 'templates/malwatch_config_edit.htm',
	'fields' => array(
		'binary_path' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '/usr/local/bin/malwatch',
			'validators' => array(
				array(
					'type' => 'NOTEMPTY',
					'errmsg' => 'binary_path_error_empty'
				),
				array(
					'type' => 'REGEX',
					'regex' => '/^\/[a-zA-Z0-9\/_.-]{2,250}$/',
					'errmsg' => 'binary_path_error_regex'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		'state_dir' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '/var/lib/malwatch',
			'validators' => array(
				array(
					'type' => 'NOTEMPTY',
					'errmsg' => 'state_dir_error_empty'
				),
				array(
					'type' => 'REGEX',
					'regex' => '/^\/[a-zA-Z0-9\/_.-]{2,250}$/',
					'errmsg' => 'state_dir_error_regex'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		'admin_email' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'ISEMAIL',
					'allowempty' => 'y',
					'errmsg' => 'admin_email_error_isemail'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		'sender_email' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'ISEMAIL',
					'allowempty' => 'y',
					'errmsg' => 'sender_email_error_isemail'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		'default_schedule' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'weekly',
			'value' => array(
				'off' => 'kein Zeitplan',
				'daily' => 'täglich',
				'weekly' => 'wöchentlich',
				'monthly' => 'monatlich'
			)
		),
		'default_excludes' => array(
			'datatype' => 'TEXT',
			'formtype' => 'TEXTAREA',
			'default' => '',
			'cols' => '30',
			'rows' => '6'
		),
		'scan_max_age' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '0',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:3650',
					'errmsg' => 'scan_max_age_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'max_parallel' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:16',
					'errmsg' => 'max_parallel_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'job_timeout_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '6',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:168',
					'errmsg' => 'job_timeout_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'keep_scans' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '30',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:1000',
					'errmsg' => 'keep_scans_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'use_clamav' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value' => array(0 => 'n', 1 => 'y')
		),
		'auto_update_signatures' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value' => array(0 => 'n', 1 => 'y')
		)
	)
);
