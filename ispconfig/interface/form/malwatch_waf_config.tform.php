<?php

/**
 * Form definition for the settings of the Abwehr: the numbers and periods of
 * the WAF on the settings row of malwatch (config_id 1). The ranges are those
 * of waf_settings_limits(), the defaults those of waf_settings_defaults();
 * waf_panel_test.php holds the three together. Paths, response body and
 * emergency stop are no fields here: install.sh sets the paths, the overview
 * switches the other two through jobs.
 */

$form['title'] = 'waf_config_head_txt';
$form['description'] = '';
$form['name'] = 'malwatch_waf_config';
$form['action'] = 'malwatch_waf_config_edit.php';
$form['db_table'] = 'malwatch_config';
$form['db_table_idx'] = 'config_id';
$form['db_history'] = 'no';
$form['tab_default'] = 'waf';
$form['list_default'] = 'malwatch_waf_list.php';
$form['auth'] = 'no';

$form['tabs']['waf'] = array(
	'title' => 'waf_tab_txt',
	'width' => 100,
	'template' => 'templates/malwatch_waf_config_edit.htm',
	'fields' => array(
		'waf_detail_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:3650',
					'errmsg' => 'waf_detail_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_stats_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '90',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:3650',
					'errmsg' => 'waf_stats_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_log_keep_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:365',
					'errmsg' => 'waf_log_keep_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_preview_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:365',
					'errmsg' => 'waf_preview_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_min_detect_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:365',
					'errmsg' => 'waf_min_detect_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ingest_max_lines' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '100:100000',
					'errmsg' => 'waf_ingest_max_lines_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_job_deadline_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '2:120',
					'errmsg' => 'waf_job_deadline_minutes_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		)
	)
);
