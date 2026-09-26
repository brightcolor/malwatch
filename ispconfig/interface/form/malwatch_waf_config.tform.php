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
		'waf_tick_wait_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '30',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:50', 'errmsg' => 'waf_tick_wait_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
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
		'waf_ban_logged_in_percent' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:100', 'errmsg' => 'waf_ban_logged_in_percent_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		// Lists, stored with commas and checked on the page (waf_config_lists()).
		'waf_ban_logged_in_paths' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '/wp-admin/,/wp-json/',
			'value' => '',
			'width' => '40',
			'maxlength' => '1024'
		),
		'waf_ban_full_paths' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'wp-login.php,xmlrpc.php',
			'value' => '',
			'width' => '40',
			'maxlength' => '1024'
		),
		'waf_login_cookies' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'wordpress_logged_in_',
			'value' => '',
			'width' => '40',
			'maxlength' => '1024'
		),
		'waf_own_networks' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '127.0.0.0/8,::1/128,10.50.0.0/24',
			'value' => '',
			'width' => '40',
			'maxlength' => '1024'
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
		'waf_ban_page_step' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '25',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:500', 'errmsg' => 'waf_ban_page_step_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ban_page_rows' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '20:5000', 'errmsg' => 'waf_ban_page_rows_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_page_timeout' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '30',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:300', 'errmsg' => 'waf_ban_page_timeout_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
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
		'waf_f2b' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'on',
			'value' => array(
				'on' => 'f2b_on_txt',
				'off' => 'f2b_off_txt'
			)
		),
		'waf_everywhere_mode' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'web_jail',
			'value' => array(
				'web_jail' => 'everywhere_web_jail_txt',
				'web_forever_jail' => 'everywhere_web_forever_jail_txt',
				'jail_only' => 'everywhere_jail_only_txt'
			)
		),
		'waf_everywhere_jail' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'recidive',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9_.-]{1,64}$/',
					'errmsg' => 'waf_everywhere_jail_error'
				)
			),
			'value' => '',
			'width' => '20',
			'maxlength' => '64'
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
		),
		'waf_ban_origin_rows' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '25',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:200', 'errmsg' => 'waf_ban_origin_rows_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_poll_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '2:60', 'errmsg' => 'waf_poll_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_tick_fresh_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '180',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '120:3600', 'errmsg' => 'waf_tick_fresh_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_lock_retry_ms' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '250',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '50:5000', 'errmsg' => 'waf_lock_retry_ms_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_rule_hits' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '200',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '50:5000', 'errmsg' => 'waf_ban_rule_hits_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_periods' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '1,7,30,90',
			'value' => '',
			'width' => '40',
			'maxlength' => '1024'
		),
		'waf_period_default' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:3650', 'errmsg' => 'waf_period_default_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_dbip_country_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_dbip_country_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_dbip_country_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_dbip_country_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '80',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_dbip_country_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_dbip_asn_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_dbip_asn_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_dbip_asn_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_dbip_asn_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '80',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_dbip_asn_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_maxmind_country_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_maxmind_country_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_maxmind_country_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_maxmind_country_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '80',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_maxmind_country_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_maxmind_asn_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_maxmind_asn_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_maxmind_asn_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_maxmind_asn_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '80',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_maxmind_asn_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_tor_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://check.torproject.org/torbulkexitlist',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_tor_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_tor_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_tor_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_tor_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_x4b_vpn_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt,https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_x4b_vpn_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_x4b_vpn_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_x4b_vpn_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_x4b_vpn_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_x4b_datacenter_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt,https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_x4b_datacenter_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_x4b_datacenter_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_x4b_datacenter_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_x4b_datacenter_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_src_searchbots_urls' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://developers.google.com/static/search/apis/ipranges/googlebot.json,https://www.bing.com/toolbox/bingbot.json',
			'value' => '',
			'width' => '40',
			'maxlength' => '512'
		),
		'waf_src_searchbots_min' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10000000', 'errmsg' => 'waf_src_searchbots_min_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '8'
		),
		'waf_src_searchbots_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '8',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1024', 'errmsg' => 'waf_src_searchbots_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_origin_bad_percent' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:50', 'errmsg' => 'waf_origin_bad_percent_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_origin_keep_percent' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:100', 'errmsg' => 'waf_origin_keep_percent_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_fetch_connect_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:120', 'errmsg' => 'waf_fetch_connect_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_fetch_timeout_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '120',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '10:3600', 'errmsg' => 'waf_fetch_timeout_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_fetch_redirects' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '3',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:10', 'errmsg' => 'waf_fetch_redirects_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_proxycheck_url' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => 'https://proxycheck.io/v3/',
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		'waf_proxycheck_batch' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '100',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1000', 'errmsg' => 'waf_proxycheck_batch_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_proxycheck_answer_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '2',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:50', 'errmsg' => 'waf_proxycheck_answer_mb_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_proxycheck_connect_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:60', 'errmsg' => 'waf_proxycheck_connect_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_proxycheck_timeout_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '2:300', 'errmsg' => 'waf_proxycheck_timeout_seconds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_proxycheck_retry_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '60',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:1440', 'errmsg' => 'waf_proxycheck_retry_minutes_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_proxycheck_tries' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '3',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:10', 'errmsg' => 'waf_proxycheck_tries_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'waf_origin_lookup_batch' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '500',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:100000', 'errmsg' => 'waf_origin_lookup_batch_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_cleanup_batch' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '100:100000', 'errmsg' => 'waf_cleanup_batch_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_cleanup_rounds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1000', 'errmsg' => 'waf_cleanup_rounds_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_response_grace_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '60',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:10080', 'errmsg' => 'waf_response_grace_minutes_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '5'
		),
		'waf_blocked_lines' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1000000', 'errmsg' => 'waf_blocked_lines_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '7'
		),
		'waf_hit_rules_max' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:500', 'errmsg' => 'waf_hit_rules_max_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_show_paths' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '10:1000', 'errmsg' => 'waf_show_paths_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_preview_delay_ms' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '300',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '50:5000', 'errmsg' => 'waf_preview_delay_ms_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_cli_jobs' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '20',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:500', 'errmsg' => 'waf_cli_jobs_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_cli_wait_margin_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '2',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '0:60', 'errmsg' => 'waf_cli_wait_margin_minutes_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		)
	)
);
