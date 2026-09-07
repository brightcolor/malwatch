<?php

/**
 * Shared helpers for the malwatch pages in the Security module.
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

/**
 * Queues a restore of the vendor files.
 *
 * The website is switched off for the duration by the caller, not here: an
 * installation that is half exchanged has no business being served, and a
 * backdoor that is still reachable would write again while it happens.
 *
 * $mode, $no_original and $only travel straight into options under the exact
 * keys malwatch_runner::build_arguments() reads for a 'repair' job - see
 * that method before renaming any of them. Defaults match its own fallback
 * ("unset or empty means the default"), so a caller that skips them gets the
 * same behaviour a job queued before these options existed would.
 */
function malwatch_queue_repair($app, $domain_id, $dry_run = false, $previous_active = 'y',
	$mode = 'replace', $no_original = 'keep', array $only = array())
{
	// The state before the run travels with the job: switching back has to
	// restore what was, not guess that every website was online.
	return malwatch_queue_job($app, $domain_id, 'repair', array(
		'dry_run' => $dry_run ? 1 : 0,
		'previous_active' => $previous_active === 'y' ? 'y' : 'n',
		'mode' => $mode === 'overlay' ? 'overlay' : 'replace',
		'no_original' => $no_original === 'quarantine' ? 'quarantine' : 'keep',
		'only' => array_values($only),
	));
}

/**
 * Queues the removal of single files.
 *
 * Only paths that stand as a finding of this very website are accepted. The
 * value arrives from a form field, and a path is one unlink away from being
 * anything on the disk; the binary checks the boundary a second time.
 */
function malwatch_queue_quarantine($app, $domain_id, array $paths)
{
	$domain_id = $app->functions->intval($domain_id);
	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}
	$base = malwatch_scan_path($web);
	if ($base === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

	$accepted = array();
	foreach ($paths as $path) {
		$path = (string) $path;
		$row = $app->db->queryOneRecord(
			'SELECT file_path FROM malwatch_finding WHERE parent_domain_id = ? AND file_path = ? '
			. "AND finding_state IN ('open','ignored') LIMIT 1",
			$domain_id, $path);
		if (!is_array($row)) {
			continue;
		}
		if (strpos($path, $base . '/') !== 0) {
			continue;
		}
		$accepted[] = substr($path, strlen($base) + 1);
	}
	if (count($accepted) === 0) {
		return 'Keiner der Pfade steht als Fund dieser Website.';
	}

	$queued = malwatch_queue_job($app, $domain_id, 'quarantine', array('files' => $accepted));
	return $queued === true ? count($accepted) : $queued;
}

/**
 * The WHERE fragment and bind params one automatic-action mode filters open
 * findings by, or null for a mode that covers nothing ('none', or 'preset'
 * with no rule to go by).
 *
 * Mirrors malwatch_actions::auto_paths() on the server side exactly - 'safe'
 * goes by malwatch_rule.auto_safe, 'critical' by the finding's own severity,
 * never the rule catalogue's. The two are not one a subset of the other; a
 * measurement against real findings found 767 files under 'safe' and 472
 * under 'critical' out of 1511 open ones, so keeping both queries faithful
 * to auto_paths() rather than approximating one from the other matters.
 */
function malwatch_auto_mode_filter($app, $mode, array $rule_ids = array())
{
	if ($mode === 'critical') {
		return array("severity = 'critical'", array());
	}
	if ($mode === 'safe') {
		return array("rule_id IN (SELECT rule_id FROM malwatch_rule WHERE auto_safe = 'y')", array());
	}
	if ($mode === 'preset' && count($rule_ids) > 0) {
		$placeholders = implode(',', array_fill(0, count($rule_ids), '?'));
		return array("rule_id IN ($placeholders)", array_values($rule_ids));
	}
	return null;
}

/**
 * How many currently open findings - counted as distinct files, the way a
 * human reads "how many files", not as raw rule hits - a mode would cover
 * right now. The only honest preview for a setting that moves files on its
 * own: a rule count from the catalogue says nothing about what is actually
 * sitting on real websites today.
 */
function malwatch_auto_mode_finding_count($app, $mode, array $rule_ids = array())
{
	$filter = malwatch_auto_mode_filter($app, $mode, $rule_ids);
	if ($filter === null) {
		return 0;
	}
	list($where, $params) = $filter;
	$row = call_user_func_array(array($app->db, 'queryOneRecord'), array_merge(
		array('SELECT COUNT(DISTINCT parent_domain_id, file_path) AS n FROM malwatch_finding '
			. "WHERE finding_state = 'open' AND $where"),
		$params));
	return is_array($row) ? $app->functions->intval($row['n']) : 0;
}

/**
 * Open finding paths a mode currently covers, grouped by website - the
 * shape malwatch_queue_quarantine() wants, one call per parent_domain_id.
 *
 * Only 'open' findings qualify, never 'ignored': an ignored finding was a
 * person's own call that this file is not a problem, and a sweep like this
 * has no business overriding that on its own.
 */
function malwatch_auto_mode_paths_by_domain($app, $mode, array $rule_ids = array())
{
	$filter = malwatch_auto_mode_filter($app, $mode, $rule_ids);
	if ($filter === null) {
		return array();
	}
	list($where, $params) = $filter;
	$rows = call_user_func_array(array($app->db, 'queryAllRecords'), array_merge(
		array('SELECT parent_domain_id, file_path FROM malwatch_finding '
			. "WHERE finding_state = 'open' AND $where"),
		$params));

	// Keyed by path first, so a file two different rules both hit (a real
	// case for 'preset', which can name several rule_ids at once) ends up
	// in the job's file list once, not once per matching rule.
	$by_domain = array();
	foreach ((array) $rows as $row) {
		$domain_id = $app->functions->intval($row['parent_domain_id']);
		if ($domain_id < 1) {
			continue;
		}
		if (!isset($by_domain[$domain_id])) {
			$by_domain[$domain_id] = array();
		}
		$by_domain[$domain_id][(string) $row['file_path']] = true;
	}
	foreach ($by_domain as $domain_id => $paths) {
		$by_domain[$domain_id] = array_keys($paths);
	}
	return $by_domain;
}

/** Puts one job of any kind into the queue. */
function malwatch_queue_job($app, $domain_id, $kind, array $options)
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
		return 'Für diese Website läuft bereits ein Auftrag.';
	}
	$path = malwatch_scan_path($web);
	if ($path === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

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
		'job_kind' => $kind,
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');

	return true;
}

/**
 * Queues a restore, download or permanent delete for one or more quarantine
 * entries.
 *
 * The quarantine list spans every website on the server, so a batch of ids
 * can belong to more than one domain at once - unlike malwatch_queue_job,
 * which is always about a single site. What ties a job to one machine is
 * server_id, not parent_domain_id: the store the CLI opens with
 * --quarantine-dir lives on one server's disk, and that is what its cron
 * uses to find its own work.
 *
 * restore and delete both end in a full-list resync of the store
 * (malwatch_ingest::sync_quarantine), so several ids from the same server
 * are safe to queue as one job. export is different: the runner writes one
 * zip per job, named after options['token'], and malwatch_ingest::
 * finish_export() only ever files that token onto the FIRST id of the job's
 * list - a second id quietly never leaves "wird vorbereitet". So every
 * export gets its own job and its own token, one entry at a time, the same
 * one-id shape internal/quarantine.Export() already has below the CLI.
 *
 * Returns the number of ids queued, or a German message explaining why
 * nothing was queued.
 */
function malwatch_queue_quarantine_action($app, array $ids, $action)
{
	if (!in_array($action, array('restore', 'delete', 'export'), true)) {
		return 'Unbekannte Aktion.';
	}

	$valid = array();
	foreach ($ids as $id) {
		$id = (string) $id;
		if ($id === '') {
			continue;
		}
		// Only an id actually in the store may be queued - it came back from
		// a form field, and a stale or tampered value must not reach the
		// binary as if it named a real entry.
		$row = $app->db->queryOneRecord(
			'SELECT entry_id, server_id FROM malwatch_quarantine WHERE entry_id = ?', $id);
		if (!is_array($row)) {
			continue;
		}
		$valid[] = array(
			'entry_id' => (string) $row['entry_id'],
			'server_id' => $app->functions->intval($row['server_id']),
		);
	}
	if (count($valid) === 0) {
		return 'Keiner der ausgewählten Einträge wurde gefunden.';
	}

	if ($action === 'export') {
		foreach ($valid as $entry) {
			$options = array(
				'action' => 'export',
				'ids' => array($entry['entry_id']),
				'token' => bin2hex(random_bytes(20)),
			);
			malwatch_insert_quarantine_job($app, $entry['server_id'], $options);
		}
		return count($valid);
	}

	$by_server = array();
	foreach ($valid as $entry) {
		if (!isset($by_server[$entry['server_id']])) {
			$by_server[$entry['server_id']] = array();
		}
		$by_server[$entry['server_id']][] = $entry['entry_id'];
	}
	foreach ($by_server as $server_id => $group_ids) {
		malwatch_insert_quarantine_job($app, $server_id, array('action' => $action, 'ids' => $group_ids));
	}
	return count($valid);
}

/**
 * Inserts one malwatch_job row of kind 'quarantine'.
 *
 * parent_domain_id and domain stay empty on purpose: nothing reads them for
 * this job kind once options['action'] is not 'add' - the runner works
 * entirely from --id, and a job's ids can span more than one website anyway,
 * so neither field could name a single one honestly.
 */
function malwatch_insert_quarantine_job($app, $server_id, array $options)
{
	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $_SESSION['s']['user']['userid'],
		'sys_groupid' => $app->functions->intval($_SESSION['s']['user']['default_group']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => $server_id,
		'parent_domain_id' => 0,
		'domain' => '',
		'scan_path' => '',
		'job_source' => 'manual',
		'job_kind' => 'quarantine',
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');
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

/** How a quarantine entry got there: manual, auto or repair. */
function malwatch_origin_label($wb, $origin)
{
	$key = 'origin_' . (string) $origin . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $origin;
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

/**
 * Splits a file path into the part worth reading and the part that is only
 * noise.
 *
 * Every path on the server starts with the same twenty characters of
 * /var/www/clients/clientN/webN/. Printing that in front of each of forty
 * findings hides the one thing the reader is looking for, which is the file
 * name. The base is cut off, the directory is kept for orientation and the
 * file name is returned on its own so the template can lift it out.
 *
 * Returns an array with 'dir', 'file' and 'full'.
 */
function malwatch_split_path($full, $base = '')
{
	$full = (string) $full;
	$rest = $full;

	$base = rtrim((string) $base, '/');
	if ($base !== '' && strpos($full, $base . '/') === 0) {
		$rest = substr($full, strlen($base) + 1);
	}

	$slash = strrpos($rest, '/');
	if ($slash === false) {
		return array('dir' => '', 'file' => $rest, 'full' => $full);
	}

	return array(
		'dir' => substr($rest, 0, $slash + 1),
		'file' => substr($rest, $slash + 1),
		'full' => $full,
	);
}

/**
 * Groups findings by file.
 *
 * One infected file often trips several rules. Listed one row per rule the
 * same path appears four times and the number of affected files is no longer
 * readable at all - which is the first thing anyone wants to know.
 */
function malwatch_group_findings($app, $rows, $wb, $base = '')
{
	$groups = array();

	foreach ($rows as $row) {
		$key = (string) $row['file_path'];
		if (!isset($groups[$key])) {
			$parts = malwatch_split_path($key, $base);
			$groups[$key] = array(
				// Carried on every row on purpose: a template loop must not
				// depend on an outer variable being visible inside it.
				'domain_id' => $app->functions->intval($row['parent_domain_id']),
				'dir' => $app->functions->htmlentities($parts['dir']),
				'file' => $app->functions->htmlentities($parts['file']),
				'full_path' => $app->functions->htmlentities($parts['full']),
				'has_dir' => $parts['dir'] !== '' ? 1 : 0,
				'severity' => '',
				'severity_label' => '',
				'severity_class' => '',
				'first_seen' => $app->functions->htmlentities(malwatch_datetime($row['first_seen'])),
				'is_ignored' => 1,
				'hits' => array(),
				'hit_count' => 0,
			);
		}

		// The block carries the worst severity of its file, so sorting and
		// colouring follow the file rather than whichever rule came first.
		if (malwatch_severity_rank($row['severity']) > malwatch_severity_rank($groups[$key]['severity'])) {
			$groups[$key]['severity'] = (string) $row['severity'];
			$groups[$key]['severity_label'] = $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity']));
			$groups[$key]['severity_class'] = malwatch_severity_class($row['severity']);
		}
		// A file counts as released only when every one of its findings is.
		if ($row['finding_state'] !== 'ignored') {
			$groups[$key]['is_ignored'] = 0;
		}

		$groups[$key]['hits'][] = array(
			'finding_id' => $app->functions->intval($row['finding_id']),
			'rule_id' => $app->functions->htmlentities($row['rule_id']),
			'engine' => $app->functions->htmlentities($row['engine']),
			'line_number' => $app->functions->intval($row['line_number']),
			'has_line' => $app->functions->intval($row['line_number']) > 0 ? 1 : 0,
			'excerpt' => $app->functions->htmlentities($row['excerpt']),
			'severity_label' => $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity'])),
			'severity_class' => malwatch_severity_class($row['severity']),
			'is_ignored' => $row['finding_state'] === 'ignored' ? 1 : 0,
		);
		$groups[$key]['hit_count'] = count($groups[$key]['hits']);
	}

	// Worst first, then by path, so the same scan always reads the same way.
	uasort($groups, function ($a, $b) {
		$diff = malwatch_severity_rank($b['severity']) - malwatch_severity_rank($a['severity']);
		if ($diff !== 0) {
			return $diff;
		}
		return strcmp($a['full_path'], $b['full_path']);
	});

	return array_values($groups);
}

/** Numeric weight of a severity, 0 for an unknown value. */
function malwatch_severity_rank($severity)
{
	$rank = array_search((string) $severity, malwatch_severities(), true);
	return $rank === false ? 0 : $rank + 1;
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

/**
 * Formats a byte count the way a human reads it: "169 B", "5,4 kB",
 * "41,8 MB" - decimal units and a German comma, not the binary kind an
 * administrator's tools would show.
 */
function malwatch_bytes($n)
{
	$n = (float) $n;
	$units = array('B', 'kB', 'MB', 'GB', 'TB');
	$i = 0;
	while ($n >= 1000 && $i < count($units) - 1) {
		$n /= 1000;
		$i++;
	}
	if ($i === 0) {
		return number_format($n, 0, ',', '.') . ' B';
	}
	return number_format($n, 1, ',', '.') . ' ' . $units[$i];
}

/**
 * Liefert die Websites, die etwas brauchen, und die Zahl der uebrigen.
 *
 * Reihenfolge: kritische Funde, dann laufende Pruefungen, dann hohe Funde.
 * Wer morgens hinsieht, soll die dringendste Website oben finden und nicht
 * suchen muessen.
 */
function malwatch_status_rows($app)
{
	$sql = "SELECT w.domain_id, w.domain,
			COALESCE(f.total, 0) AS findings,
			COALESCE(f.urgent, 0) AS urgent,
			s.finished_at, s.files_scanned,
			j.job_id AS running_job
		FROM web_domain w
		LEFT JOIN (
			SELECT parent_domain_id,
				COUNT(*) AS total,
				SUM(severity = 'critical') AS urgent
			FROM malwatch_finding
			WHERE finding_state = 'open'
			GROUP BY parent_domain_id
		) f ON f.parent_domain_id = w.domain_id
		LEFT JOIN malwatch_scan s ON s.scan_id = (
			SELECT scan_id FROM malwatch_scan
			WHERE parent_domain_id = w.domain_id
				AND scan_state IN ('clean','findings','outdated')
			ORDER BY scan_id DESC LIMIT 1
		)
		LEFT JOIN malwatch_job j ON j.job_id = (
			SELECT job_id FROM malwatch_job
			WHERE parent_domain_id = w.domain_id
				AND job_status IN ('pending','running')
			ORDER BY job_id DESC LIMIT 1
		)
		WHERE w.type IN ('vhost','vhostsubdomain','vhostalias') AND w.active = 'y'
		ORDER BY COALESCE(f.urgent, 0) DESC, j.job_id DESC,
			COALESCE(f.total, 0) DESC, w.domain ASC";

	$all = $app->db->queryAllRecords($sql);
	if (!is_array($all)) {
		$all = array();
	}

	$attention = array();
	$quiet = 0;
	$newest = 0;

	foreach ($all as $row) {
		if (!empty($row['finished_at'])) {
			$stamp = strtotime($row['finished_at']);
			if ($stamp > $newest) {
				$newest = $stamp;
			}
		}
		$running  = intval($row['running_job']) > 0;
		$findings = intval($row['findings']);
		if (!$running && $findings < 1) {
			$quiet++;
			continue;
		}
		$row['is_running']  = $running ? 'y' : 'n';
		$row['urgent']      = intval($row['urgent']);
		$row['findings']    = $findings;
		$row['state_class'] = $running ? 'busy' : ($row['urgent'] > 0 ? 'bad' : 'warn');
		$attention[] = $row;
	}

	$next = malwatch_next_run($app);

	return array(
		'attention'      => $attention,
		'quiet_count'    => $quiet,
		'as_of'          => $newest ? malwatch_when($newest) : '—',
		'next_run_state' => $next['state'],
		'next_run'       => $next['when'],
	);
}

/**
 * Ein Zeitpunkt so, wie ein Mensch ihn sagt: "heute 03:14 Uhr", "gestern
 * 21:12 Uhr", sonst "6. September, 21:12 Uhr".
 *
 * Gilt fuer Zeitpunkte in der Vergangenheit (as_of - ein Scan-Ende) genauso
 * wie in der Zukunft (next_run - ein geplanter Lauf): "heute" und "gestern"
 * brauchen dafuer beide eine obere Grenze. Ohne sie prueft "heute" nur
 * "$stamp >= Mitternacht heute", was fuer einen ausschliesslich in der
 * Vergangenheit liegenden Zeitpunkt (der nie nach "jetzt" liegen kann)
 * zufaellig richtig war, aber jeden kuenftigen Zeitpunkt - auch naechste
 * Woche oder naechsten Monat - ebenfalls "heute" nennen wuerde.
 *
 * Bleibt absichtlich bei deutschen Wortbestandteilen ("heute", "gestern",
 * den Monatsnamen, "Uhr"), unabhaengig von der Sprache des Bedieners - das
 * ist kein Versehen. Der Rueckgabewert dieser Funktion steckt bereits seit
 * dem vorigen Bündel unveraendert in as_of_txt und erscheint dort auch auf
 * der englischen Oberflaeche; next_run tritt dieser bestehenden Abweichung
 * lediglich bei, statt eine neue zu schaffen. Eine echte Uebersetzung ist
 * kein Ersetzen einzelner Woerter: die Monatsnamen muessten in beide
 * Sprachdateien wandern, "Uhr" hat im Englischen keine Entsprechung
 * ("3:14 PM", nicht "3:14 PM o'clock"), und die dritte Form dreht die
 * Reihenfolge von Tag/Monat auf Monat/Tag um ("6. September" gegenueber
 * "September 6") - das ist ein Umbau der Funktionslogik, nicht nur ihrer
 * Zeichenketten, und damit ausserhalb dessen, was diese Aenderung beheben
 * soll: next_run war falsch (ein erfundenes 03:00 Uhr), nicht unuebersetzt.
 * Wer das fuer die englische Oberflaeche vervollstaendigen will, sollte
 * as_of gleich mit erledigen - beide teilen sich diese Funktion.
 */
function malwatch_when($stamp)
{
	$monate = array('', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
		'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember');
	$heute  = strtotime('today');
	$zeit   = date('H:i', $stamp) . ' Uhr';
	if ($stamp >= $heute && $stamp < $heute + 86400) {
		return 'heute ' . $zeit;
	}
	if ($stamp >= $heute - 86400 && $stamp < $heute) {
		return 'gestern ' . $zeit;
	}
	return intval(date('j', $stamp)) . '. ' . $monate[intval(date('n', $stamp))] . ', ' . $zeit;
}

/**
 * Der naechste anstehende Lauf ueber alle Websites - oder der Grund, warum
 * es keinen gibt.
 *
 * Es gibt keine feste Uhrzeit: next_run gehoert der einzelnen Website
 * (malwatch_site.next_run), jede hat ihren eigenen schedule, und der Cron
 * (server/lib/classes/cron.d/560-malwatch.inc.php, '* * * * *') greift jede
 * Minute auf, was faellig ist. Der richtige Wert ist deshalb das Minimum von
 * next_run ueber alle Websites, deren schedule nicht 'off' ist - aber nur
 * unter denen, die tatsaechlich noch in der Zukunft liegen.
 *
 * Liefert ein Array mit 'state' und 'when':
 *   - 'scheduled': 'when' ist ein mit malwatch_when() formatierter Zeitpunkt.
 *   - 'due': ein Zeitplan ist eingeschaltet, aber sein faelliger Zeitpunkt
 *     liegt nicht (mehr) in der Zukunft. Das deckt zwei Faelle ab, die von
 *     hier aus nicht zu unterscheiden sind: eine Website, die gerade erst
 *     eingeschaltet wurde (next_run steht auf NOW(), siehe scheduleNextRun()
 *     in malwatch_site_edit.php) und binnen einer Minute vom naechsten
 *     Cron-Tick abgeholt wird - der Normalfall - oder ein Cron, der laenger
 *     nicht lief. Eine erfundene Uhrzeit waere in beiden Faellen falsch
 *     ("gestern 03:00 Uhr" fuer etwas, das die Seite als kuenftig
 *     ankuendigt); 'due' behauptet nur, dass eine Pruefung ansteht, nicht
 *     wann - keine Diagnose, nur eine ehrliche Aussage ueber die Tabelle.
 *   - 'none': keine Website hat ueberhaupt einen Zeitplan (alle 'off', oder
 *     die Tabelle ist leer). Anders als 'due' behauptet das nicht, dass
 *     gleich etwas passiert.
 *
 * Gezaehlt werden nur Websites, deren angekuendigter Lauf auch stattfinden
 * kann. Zwei Faelle, in denen er das nicht tut, und beide stehen in
 * queue_due_scans() (server/lib/classes/cron.d/560-malwatch.inc.php):
 *
 *   - Eine abgeschaltete Website (web_domain.active = 'n'). Der Cron liest die
 *     Zeile, sieht active != 'y' und schiebt next_run nur weiter, ohne einen
 *     Auftrag anzulegen. Die Seite haette einen Lauf angekuendigt, der nie
 *     kommt. malwatch_status_rows() blendet abgeschaltete Websites ohnehin
 *     aus - die Kopfzeile darf nicht ueber eine Website sprechen, die
 *     darunter nicht steht.
 *   - Eine Zeile, deren server_id nicht die der Website ist. Der Cron holt
 *     sich seine Zeilen ueber malwatch_site.server_id = eigene ID: der dort
 *     genannte Server findet das Verzeichnis der Website bei sich nicht
 *     (create_job() bricht mit "no scan path" ab), und der Server, auf dem
 *     die Website wirklich liegt, sieht die Zeile nie. Auf einer
 *     Mehrserver-Installation kuendigte die Seite so den Lauf eines fremden
 *     Servers an, den es nicht geben wird.
 *
 * Der Typfilter ist derselbe wie in malwatch_status_rows(): worueber die
 * Kopfzeile spricht, muss darunter auch auftauchen koennen.
 */
function malwatch_next_run($app)
{
	// Beide Abfragen sehen dieselbe Menge an Websites an. Sonst koennte die
	// zweite 'due' melden fuer eine Website, die die erste zu Recht nicht
	// mitzaehlt - und die Seite behauptete, gleich passiere etwas.
	$scope = ' FROM malwatch_site s'
		. ' JOIN web_domain w ON w.domain_id = s.parent_domain_id'
		. " WHERE s.schedule != 'off'"
		. " AND w.active = 'y'"
		. " AND w.type IN ('vhost','vhostsubdomain','vhostalias')"
		. ' AND s.server_id = w.server_id';

	$upcoming = $app->db->queryOneRecord(
		'SELECT MIN(s.next_run) AS next_run' . $scope . ' AND s.next_run > NOW()');
	if (is_array($upcoming) && !empty($upcoming['next_run'])) {
		$stamp = strtotime($upcoming['next_run']);
		if ($stamp !== false && $stamp > 0) {
			return array('state' => 'scheduled', 'when' => malwatch_when($stamp));
		}
	}

	$any = $app->db->queryOneRecord('SELECT s.site_id' . $scope . ' LIMIT 1');
	if (is_array($any)) {
		return array('state' => 'due', 'when' => '');
	}

	return array('state' => 'none', 'when' => '');
}
