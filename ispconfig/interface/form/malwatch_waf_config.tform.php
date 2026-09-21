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
		),
		'waf_card_hits' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '100:100000',
					'errmsg' => 'waf_card_hits_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_origin_geo' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'dbip' => 'origin_geo_dbip_txt',
				'maxmind' => 'origin_geo_maxmind_txt'
			)
		),
		'waf_origin_maxmind_account' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^\d{0,32}$/',
					'errmsg' => 'waf_origin_maxmind_account_error'
				)
			),
			'value' => '',
			'width' => '20',
			'maxlength' => '32'
		),
		'waf_origin_maxmind_key' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9_]{0,128}$/',
					'errmsg' => 'waf_origin_maxmind_key_error'
				)
			),
			'value' => '',
			'width' => '30',
			'maxlength' => '128'
		),
		'waf_origin_tor' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'torproject' => 'origin_tor_torproject_txt'
			)
		),
		'waf_origin_net' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'origin_off_txt',
				'x4b' => 'origin_net_x4b_txt',
				'proxycheck' => 'origin_net_proxycheck_txt'
			)
		),
		'waf_origin_proxycheck_key' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9-]{0,128}$/',
					'errmsg' => 'waf_origin_proxycheck_key_error'
				)
			),
			'value' => '',
			'width' => '30',
			'maxlength' => '128'
		),
		'waf_origin_proxycheck_daily' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '500',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:100000',
					'errmsg' => 'waf_origin_proxycheck_daily_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_ban_mode' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_mode_off_txt',
				'propose' => 'ban_mode_propose_txt',
				'block' => 'ban_mode_block_txt'
			)
		),
		'waf_ban_score' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:10000', 'errmsg' => 'waf_ban_score_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '5'
		),
		'waf_ban_window_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1440', 'errmsg' => 'waf_ban_window_minutes_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_first' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_first_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_second' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_second_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_third' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '168',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_third_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_max' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '100:100000', 'errmsg' => 'waf_ban_max_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_ban_keep_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '30',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:365', 'errmsg' => 'waf_ban_keep_days_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ban_proposal_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:365', 'errmsg' => 'waf_ban_proposal_days_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ban_page_rows' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '200',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '20:5000', 'errmsg' => 'waf_ban_page_rows_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_bots' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'on',
			'value' => array(
				'on' => 'ban_bots_on_txt',
				'off' => 'ban_bots_off_txt'
			)
		),
		'waf_ban_origin' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_origin_off_txt',
				'on' => 'ban_origin_on_txt'
			)
		),
		'waf_ban_origin_score' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:10000', 'errmsg' => 'waf_ban_origin_score_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '5'
		),
		'waf_ban_origin_factor' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '200',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '100:1000', 'errmsg' => 'waf_ban_origin_factor_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_origin_now' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_origin_now_off_txt',
				'on' => 'ban_origin_now_on_txt'
			)
		),
		'waf_ban_origin_hosting' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_origin_kind_off_txt',
				'on' => 'ban_origin_kind_on_txt'
			)
		),
		'waf_ban_origin_vpn' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_origin_kind_off_txt',
				'on' => 'ban_origin_kind_on_txt'
			)
		),
		'waf_ban_origin_tor' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_origin_kind_off_txt',
				'on' => 'ban_origin_kind_on_txt'
			)
		),
		'waf_origin_tor_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:168',
					'errmsg' => 'waf_origin_tor_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_origin_list_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:720',
					'errmsg' => 'waf_origin_list_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_origin_db_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:720',
					'errmsg' => 'waf_origin_db_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		)
	)
);
