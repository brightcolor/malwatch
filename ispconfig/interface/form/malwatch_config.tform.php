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
$form['list_default'] = 'status.php';
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
		// The interval of websites without a row of their own, in days; the
		// scheduler gives them a row with it (560-malwatch.inc.php).
		'default_scan_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:365',
					'errmsg' => 'default_scan_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
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
		// The directories that hold nothing but uploads, for the rules that
		// judge a file by lying below one; the runner hands them to the scanner
		// (--upload-dirs). Default and limits: malwatch_config_defaults() and
		// malwatch_upload_dirs_limits().
		'upload_dirs' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['upload_dirs'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_upload_dirs_regex(),
					'errmsg' => 'upload_dirs_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '512'
		),
		// How the scanner tells a vendor's file from a finding (Abgleich mit
		// den Herstellern, 0.41.0). The runner hands every value to the
		// scanner (malwatch_helper::verify_arguments()); defaults and limits:
		// malwatch_config_defaults(), malwatch_list_settings() and
		// malwatch_verify_settings(). The lists are stored tidied, see
		// malwatch_config_edit.php.
		'modified_exts' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['modified_exts'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_list_regex('modified_exts'),
					'errmsg' => 'modified_exts_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '520'
		),
		'script_hosts' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['script_hosts'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_list_regex('script_hosts'),
					'errmsg' => 'script_hosts_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '3231'
		),
		'verify_composer' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => malwatch_config_defaults()['verify_composer'],
			'value' => array(0 => 'n', 1 => 'y')
		),
		'verify_originals' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => malwatch_config_defaults()['verify_originals'],
			'value' => array(0 => 'n', 1 => 'y')
		),
		'verify_hosts' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['verify_hosts'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_list_regex('verify_hosts'),
					'errmsg' => 'verify_hosts_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '1615'
		),
		'verify_max_downloads' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['verify_max_downloads'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_verify_range('verify_max_downloads'),
					'errmsg' => 'verify_max_downloads_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'verify_max_mb' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['verify_max_mb'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_verify_range('verify_max_mb'),
					'errmsg' => 'verify_max_mb_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'verify_timeout' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['verify_timeout'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_verify_range('verify_timeout'),
					'errmsg' => 'verify_timeout_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'verify_retry_hours' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['verify_retry_hours'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_verify_range('verify_retry_hours'),
					'errmsg' => 'verify_retry_hours_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		// The database of known files, off by default. Only the SHA-1 sums of
		// files with a finding go out; the address travels on the command
		// line of the scanner and so carries no login.
		'hashlookup' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => malwatch_config_defaults()['hashlookup'],
			'value' => array(0 => 'n', 1 => 'y')
		),
		'hashlookup_url' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['hashlookup_url'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_hashlookup_url_regex(),
					'errmsg' => 'hashlookup_url_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '255'
		),
		// What the finding page gets to see of a file (Fundansicht). The
		// scanner has the same bounds; see malwatch_view_settings().
		'view_lines' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_lines'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_lines'),
					'errmsg' => 'view_lines_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'view_context' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_context'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_context'),
					'errmsg' => 'view_context_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'view_line_length' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_line_length'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_line_length'),
					'errmsg' => 'view_line_length_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'view_marks' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_marks'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_marks'),
					'errmsg' => 'view_marks_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'view_budget' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_budget'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_budget'),
					'errmsg' => 'view_budget_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'view_keep_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['view_keep_days'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_view_range('view_keep_days'),
					'errmsg' => 'view_keep_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		// The mails: HTML with the text as alternative, or text only; the
		// name next to the sender; whether the SMTP relay's certificate is
		// checked. See malwatch_mailer.
		'mail_format' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => malwatch_config_defaults()['mail_format'],
			'value' => array('html' => 'mail_format_html_txt', 'text' => 'mail_format_text_txt')
		),
		'mail_from_name' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => malwatch_config_defaults()['mail_from_name'],
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[^\\x00-\\x1f"<>]{0,64}$/u',
					'errmsg' => 'mail_from_name_error_regex'
				)
			),
			'value' => '',
			'width' => '30',
			'maxlength' => '64'
		),
		'mail_smtp_verify' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => malwatch_config_defaults()['mail_smtp_verify'],
			'value' => array(0 => 'n', 1 => 'y')
		),
		// The address of the panel, for the links in the mails; empty sends
		// mails without links.
		'panel_url' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => malwatch_panel_url_regex(),
					'errmsg' => 'panel_url_error_regex'
				)
			),
			'value' => '',
			'width' => '60',
			'maxlength' => '255'
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
		// The hourly part of the cron job (0.41.0): its minute, how long
		// finished jobs and fixed findings stay, and how many open findings a
		// run checks for a file that is gone. Defaults and limits:
		// malwatch_housekeeping_settings().
		'housekeeping_minute' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['housekeeping_minute'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_housekeeping_range('housekeeping_minute'),
					'errmsg' => 'housekeeping_minute_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
		),
		'keep_job_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['keep_job_days'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_housekeeping_range('keep_job_days'),
					'errmsg' => 'keep_job_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'keep_fixed_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['keep_fixed_days'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_housekeeping_range('keep_fixed_days'),
					'errmsg' => 'keep_fixed_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'vanished_check_rows' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => (string) malwatch_config_defaults()['vanished_check_rows'],
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => malwatch_housekeeping_range('vanished_check_rows'),
					'errmsg' => 'vanished_check_rows_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '5'
		),
		'poll_seconds' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '2',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:60',
					'errmsg' => 'poll_seconds_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '2'
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
		),
		'vuln_scan' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value' => array(0 => 'n', 1 => 'y')
		),
		// A WPScan token is 43 letters and digits today. The pattern leaves
		// room for a longer one and keeps anything that could break out of
		// the file the runner writes it into (see malwatch_runner).
		'wpscan_token' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^[A-Za-z0-9_-]{0,128}$/',
					'errmsg' => 'wpscan_token_error_regex'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '128'
		),
		// The command line of WP-CLI. The runner hands it to malwatch upgrade;
		// a core update that raises the database needs it. Empty means the
		// default, /usr/local/bin/wp.
		'wp_cli_path' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '/usr/local/bin/wp',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^(\/[a-zA-Z0-9\/_.-]{2,250})?$/',
					'errmsg' => 'wp_cli_path_error_regex'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
		// The template does not use the auto-generated widget for either
		// field below - the "choice card" markup in malwatch_config_edit.htm
		// is hand-written, because none of tform's stock formtypes render a
		// priced decision with a description under each option. Both fields
		// are declared here anyway so tform validates and persists them the
		// same way it does every other column on this row: 'value' fixes the
		// four columns malwatch_config.auto_action actually allows (see
		// schema.sql), so a tampered POST cannot write anything else, and
		// auto_preset_id rides along as a plain integer the template's own
		// script keeps in sync with which "choice card" is selected.
		'auto_action' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'none',
			'value' => array(
				'none' => 'none',
				'safe' => 'safe',
				'critical' => 'critical',
				'preset' => 'preset',
			),
		),
		'auto_preset_id' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '0',
			'value' => '',
		)
	)
);
