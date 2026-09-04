<?php

/**
 * Shared helpers for the malwatch pages in the Websites module.
 *
 * Plain functions rather than a class: ISPConfig loads interface pages
 * directly, and a class would have to be registered with $app->uses(), which
 * only looks in the core library directory.
 */

/** Returns the global settings plus whether the scanner is actually there. */
function malwatch_get_config($app)
{
	$row = $app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1');
	if (!is_array($row)) {
		$row = array(
			'binary_path' => '/usr/local/bin/malwatch',
			'state_dir' => '/var/lib/malwatch',
			'default_schedule' => 'weekly',
			'default_excludes' => '',
		);
	}
	// The panel may run on a different machine than the web server, in which
	// case the file is not visible from here. An unreadable path is reported
	// as "unknown", never as "missing" - a false alarm on the settings page
	// would send an operator hunting for a problem that is not there.
	$row['binary_ready'] = true;
	if (php_uname('n') !== '' && is_dir(dirname((string) $row['binary_path']))) {
		$row['binary_ready'] = is_file((string) $row['binary_path']);
	}
	return $row;
}

/**
 * Queues a scan for one website.
 *
 * Returns true, or a German message explaining why nothing was queued.
 */
function malwatch_queue_scan($app, $domain_id)
{
	$domain_id = $app->functions->intval($domain_id);
	if ($domain_id < 1) {
		return 'Ungültige Website.';
	}

	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}

	$running = $app->db->queryOneRecord(
		"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
		$domain_id);
	if (is_array($running)) {
		return 'Für diese Website läuft bereits eine Prüfung.';
	}

	$path = malwatch_scan_path($web);
	if ($path === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

	$site = $app->db->queryOneRecord('SELECT * FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
	$options = array(
		'excludes' => is_array($site) ? (string) $site['excludes'] : '',
		'max_age' => is_array($site) ? $app->functions->intval($site['max_age']) : 0,
		'version_scan' => is_array($site) ? (string) $site['version_scan'] : 'y',
	);

	// The insert goes through the datalog so the server plugin sees it.
	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $_SESSION['s']['user']['userid'],
		'sys_groupid' => $app->functions->intval($web['sys_groupid']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => $app->functions->intval($web['server_id']),
		'parent_domain_id' => $domain_id,
		'domain' => (string) $web['domain'],
		'scan_path' => $path,
		'job_source' => 'manual',
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');

	return true;
}

/** The directory of a website that actually holds the customer's files. */
function malwatch_scan_path($web)
{
	if (!is_array($web) || (string) $web['document_root'] === '') {
		return '';
	}
	$folder = isset($web['web_folder']) ? trim((string) $web['web_folder'], '/') : '';
	if (($web['type'] === 'vhostsubdomain' || $web['type'] === 'vhostalias') && $folder !== '') {
		return rtrim((string) $web['document_root'], '/') . '/' . $folder;
	}
	return rtrim((string) $web['document_root'], '/') . '/web';
}

/** Severity names, weakest first. */
function malwatch_severities()
{
	return array('low', 'medium', 'high', 'critical');
}

function malwatch_severity_label($wb, $severity)
{
	$key = 'severity_' . (string) $severity . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $severity;
}

function malwatch_state_label($wb, $state)
{
	$key = 'state_' . (string) $state . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $state;
}

function malwatch_schedule_label($wb, $schedule)
{
	if ($schedule === null || $schedule === '') {
		$schedule = 'off';
	}
	$key = 'schedule_' . (string) $schedule . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $schedule;
}

/** Bootstrap label class for a website state. */
function malwatch_state_class($state)
{
	switch ($state) {
		case 'findings':
			return 'label-danger';
		case 'outdated':
			return 'label-warning';
		case 'clean':
			return 'label-success';
		case 'error':
			return 'label-danger';
	}
	return 'label-default';
}

/** Bootstrap label class for a severity. */
function malwatch_severity_class($severity)
{
	switch ($severity) {
		case 'critical':
			return 'label-danger';
		case 'high':
			return 'label-warning';
		case 'medium':
			return 'label-info';
		case 'low':
			return 'label-default';
	}
	return 'label-default';
}

/** Short text listing which actions a website has switched on. */
function malwatch_action_summary($wb, $row)
{
	$parts = array();
	if (isset($row['notify_admin']) && $row['notify_admin'] === 'y') {
		$parts[] = isset($wb['action_admin_txt']) ? $wb['action_admin_txt'] : 'Betreiber';
	}
	if (isset($row['notify_client']) && $row['notify_client'] === 'y') {
		$parts[] = isset($wb['action_client_txt']) ? $wb['action_client_txt'] : 'Kunde';
	}
	if (isset($row['disable_site']) && $row['disable_site'] === 'y') {
		$parts[] = isset($wb['action_disable_txt']) ? $wb['action_disable_txt'] : 'Abschalten';
	}
	if (empty($parts)) {
		return isset($wb['action_none_txt']) ? $wb['action_none_txt'] : '–';
	}
	return implode(', ', $parts);
}

/** Formats a database timestamp, or a dash when there is none. */
function malwatch_datetime($value)
{
	$value = (string) $value;
	if ($value === '' || $value === '0000-00-00 00:00:00' || $value === null) {
		return '–';
	}
	$time = strtotime($value);
	if ($time === false || $time <= 0) {
		return '–';
	}
	return date('d.m.Y H:i', $time);
}

/** Formats a duration in seconds as a short human string. */
function malwatch_duration($seconds)
{
	$seconds = (int) $seconds;
	if ($seconds < 60) {
		return $seconds . ' s';
	}
	if ($seconds < 3600) {
		return floor($seconds / 60) . ' min ' . ($seconds % 60) . ' s';
	}
	return floor($seconds / 3600) . ' h ' . floor(($seconds % 3600) / 60) . ' min';
}
