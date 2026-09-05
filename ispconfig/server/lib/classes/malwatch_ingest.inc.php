<?php

/**
 * Reads a finished scan report and turns it into rows.
 */
class malwatch_ingest
{
	/** The report format this class understands. */
	const SCHEMA = 1;

	/**
	 * Ingests the result of one job. Returns the scan id, or 0 on failure.
	 */
	public function ingest($job)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		if ($file === '' || !is_file($file)) {
			$helper->fail_job($job['job_id'], 'Der Scanner hat keinen Bericht hinterlassen. '
				. $this->tail_log($job) );
			return 0;
		}

		$raw = file_get_contents($file);
		$report = json_decode((string) $raw, true);
		if (!is_array($report) || !isset($report['schema'])) {
			$helper->fail_job($job['job_id'], 'Der Bericht ist unlesbar. ' . $this->tail_log($job));
			return 0;
		}
		if (intval($report['schema']) !== self::SCHEMA) {
			// A newer scanner writing an unknown format must not be parsed by
			// guesswork; half understood findings are worse than none.
			$helper->fail_job($job['job_id'], 'Der Bericht hat Format ' . intval($report['schema'])
				. ', erwartet wird ' . self::SCHEMA . '. Bitte Erweiterung und Scanner auf denselben Stand bringen.');
			return 0;
		}

		$web = $helper->get_web($job['parent_domain_id']);
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;

		$scan_id = $this->store_scan($job, $report, $sys_groupid);
		if ($scan_id === 0) {
			$helper->fail_job($job['job_id'], 'Der Bericht konnte nicht gespeichert werden.');
			return 0;
		}

		$new_findings = $this->store_findings($job, $report, $scan_id, $sys_groupid);
		$this->store_software($job, $report, $scan_id, $sys_groupid);

		$app->dbmaster->query('UPDATE malwatch_scan SET new_findings = ? WHERE scan_id = ?',
			$new_findings, $scan_id);

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW(), job_log = ? WHERE job_id = ?",
			'Bericht eingelesen, Prüflauf ' . $scan_id . '.', $job['job_id']);

		// The report names infected paths of a customer. It is not kept around
		// after it has been read into the database.
		@unlink($file);
		@unlink(preg_replace('/\.json$/', '.log', $file));

		return $scan_id;
	}

	/** Writes the malwatch_scan row and returns its id. */
	/**
	 * Reads the report of a restore into malwatch_repair and its elements.
	 *
	 * Returns the repair_id, or 0 when there was nothing readable to read.
	 */
	public function ingest_repair($job)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		$report = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
		if (!is_array($report) || !isset($report['schema'])) {
			$helper->fail_job($job['job_id'], 'Die Wiederherstellung hat keinen lesbaren Bericht hinterlassen. '
				. $this->tail_log($job));
			return 0;
		}

		$web = $helper->get_web($job['parent_domain_id']);
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;

		$counts = array('replaced' => 0, 'deleted' => 0, 'failed' => 0);
		foreach ((array) (isset($report['elements']) ? $report['elements'] : array()) as $element) {
			$outcome = (string) $element['outcome'];
			if ($outcome === 'replaced') {
				$counts['replaced']++;
			} elseif ($outcome === 'deleted-no-origin') {
				$counts['deleted']++;
			} elseif ($outcome === 'failed') {
				$counts['failed']++;
			}
		}

		$app->dbmaster->query(
			'INSERT INTO malwatch_repair (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
			. 'sys_perm_other, server_id, job_id, parent_domain_id, domain, started_at, finished_at, '
			. 'dry_run, backup_dir, count_replaced, count_deleted, count_failed, exit_code, raw_report) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$sys_groupid, intval($job['server_id']), intval($job['job_id']),
			intval($job['parent_domain_id']), (string) $job['domain'],
			$this->to_datetime(isset($report['started_at']) ? $report['started_at'] : ''),
			$this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : ''),
			!empty($report['dry_run']) ? 'y' : 'n',
			(string) (isset($report['backup_dir']) ? $report['backup_dir'] : ''),
			$counts['replaced'], $counts['deleted'], $counts['failed'],
			intval($job['exit_code']), (string) file_get_contents($file));

		$repair_id = intval($app->dbmaster->insertID());

		foreach ((array) (isset($report['elements']) ? $report['elements'] : array()) as $element) {
			$app->dbmaster->query(
				'INSERT INTO malwatch_repair_element (sys_userid, sys_groupid, sys_perm_user, '
				. 'sys_perm_group, sys_perm_other, server_id, repair_id, parent_domain_id, '
				. 'element_kind, slug, element_version, outcome, files, backup, message) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($job['server_id']), $repair_id, intval($job['parent_domain_id']),
				(string) $element['kind'], (string) (isset($element['slug']) ? $element['slug'] : ''),
				(string) $element['version'], (string) $element['outcome'],
				intval(isset($element['files']) ? $element['files'] : 0),
				(string) (isset($element['backup']) ? $element['backup'] : ''),
				substr((string) (isset($element['message']) ? $element['message'] : ''), 0, 255));
		}

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW() WHERE job_id = ?",
			intval($job['job_id']));
		return $repair_id;
	}

	/**
	 * Marks the findings of the files a quarantine job removed as fixed.
	 *
	 * The paths come from the job itself, not from the disk: the files are gone
	 * by now, and their absence is exactly what makes them fixed.
	 */
	public function ingest_quarantine($job)
	{
		global $app;

		$app->uses('malwatch_helper');
		$options = json_decode((string) $job['options'], true);
		$base = rtrim((string) $job['scan_path'], '/');
		$removed = 0;

		foreach ((array) (is_array($options) && isset($options['files']) ? $options['files'] : array()) as $rel) {
			$full = $base . '/' . ltrim((string) $rel, '/');
			if (is_file($full)) {
				// Still there: the binary refused it or failed on it, and
				// calling the finding fixed would be a lie.
				continue;
			}
			$app->dbmaster->query(
				"UPDATE malwatch_finding SET finding_state = 'fixed' WHERE parent_domain_id = ? "
				. "AND file_path = ? AND finding_state IN ('open','ignored')",
				intval($job['parent_domain_id']), $full);
			$removed++;
		}

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW() WHERE job_id = ?",
			intval($job['job_id']));
		return $removed;
	}

	private function store_scan($job, $report, $sys_groupid)
	{
		global $app, $conf;

		$counts = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0);
		$findings = isset($report['findings']) && is_array($report['findings']) ? $report['findings'] : array();
		foreach ($findings as $finding) {
			$severity = isset($finding['severity']) ? (string) $finding['severity'] : 'medium';
			if (isset($counts[$severity])) {
				$counts[$severity]++;
			}
		}

		$outdated = 0;
		$software = isset($report['software']) && is_array($report['software']) ? $report['software'] : array();
		foreach ($software as $entry) {
			if (!empty($entry['outdated'])) {
				$outdated++;
			}
		}

		$started = $this->to_datetime(isset($report['started_at']) ? $report['started_at'] : '');
		$finished = $this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : '');
		$duration = 0;
		if ($started !== null && $finished !== null) {
			$duration = max(0, strtotime($finished) - strtotime($started));
		}

		$state = 'clean';
		if (array_sum($counts) > 0) {
			$state = 'findings';
		} elseif ($outdated > 0) {
			$state = 'outdated';
		}

		$stats = isset($report['stats']) && is_array($report['stats']) ? $report['stats'] : array();
		$engines = array();
		if (isset($report['engines']) && is_array($report['engines'])) {
			foreach ($report['engines'] as $name => $value) {
				$engines[] = $name . ': ' . $value;
			}
		}
		$notes = array();
		if (isset($report['errors']) && is_array($report['errors'])) {
			$notes = array_slice($report['errors'], 0, 50);
		}

		$insert = array(
			'sys_userid' => 1,
			'sys_groupid' => $sys_groupid,
			'sys_perm_user' => 'riud',
			'sys_perm_group' => 'r',
			'sys_perm_other' => '',
			'server_id' => intval($conf['server_id']),
			'job_id' => intval($job['job_id']),
			'parent_domain_id' => intval($job['parent_domain_id']),
			'domain' => (string) $job['domain'],
			'scan_path' => (string) $job['scan_path'],
			'started_at' => $started,
			'finished_at' => $finished,
			'duration_seconds' => $duration,
			'files_scanned' => isset($stats['files_scanned']) ? intval($stats['files_scanned']) : 0,
			'files_skipped' => isset($stats['files_skipped']) ? intval($stats['files_skipped']) : 0,
			'count_critical' => $counts['critical'],
			'count_high' => $counts['high'],
			'count_medium' => $counts['medium'],
			'count_low' => $counts['low'],
			'count_outdated' => $outdated,
			'exit_code' => intval($job['exit_code']),
			'scan_state' => $state,
			'engines' => substr(implode(', ', $engines), 0, 255),
			'notes' => implode("\n", $notes),
		);

		$app->dbmaster->query(
			'INSERT INTO malwatch_scan (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, job_id, parent_domain_id, domain, scan_path, started_at, finished_at, duration_seconds, '
			. 'files_scanned, files_skipped, count_critical, count_high, count_medium, count_low, count_outdated, '
			. 'exit_code, scan_state, engines, notes) '
			. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			$insert['sys_userid'], $insert['sys_groupid'], $insert['sys_perm_user'], $insert['sys_perm_group'],
			$insert['sys_perm_other'], $insert['server_id'], $insert['job_id'], $insert['parent_domain_id'],
			$insert['domain'], $insert['scan_path'], $insert['started_at'], $insert['finished_at'],
			$insert['duration_seconds'], $insert['files_scanned'], $insert['files_skipped'],
			$insert['count_critical'], $insert['count_high'], $insert['count_medium'], $insert['count_low'],
			$insert['count_outdated'], $insert['exit_code'], $insert['scan_state'], $insert['engines'], $insert['notes']);

		$row = $app->dbmaster->queryOneRecord('SELECT scan_id FROM malwatch_scan WHERE job_id = ? ORDER BY scan_id DESC',
			intval($job['job_id']));

		return is_array($row) ? intval($row['scan_id']) : 0;
	}

	/**
	 * Merges the findings of this run with what was already recorded.
	 *
	 * A finding keeps its identity across runs, so the extension can tell a
	 * problem that is still there from one that appeared since the last scan.
	 * The actions key on the new ones only - without that a site would be
	 * disabled again on every run for a finding the operator has decided to
	 * leave alone.
	 */
	private function store_findings($job, $report, $scan_id, $sys_groupid)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;
		$domain_id = intval($job['parent_domain_id']);
		$now = date('Y-m-d H:i:s');
		$new = 0;

		$findings = isset($report['findings']) && is_array($report['findings']) ? $report['findings'] : array();
		$seen = array();

		foreach ($findings as $finding) {
			$path = isset($finding['path']) ? (string) $finding['path'] : '';
			$rule = isset($finding['rule']) ? (string) $finding['rule'] : '';
			if ($path === '' || $rule === '') {
				continue;
			}
			$hash = $helper->path_hash($path);
			$key = $hash . '|' . $rule;
			if (isset($seen[$key])) {
				continue;
			}
			$seen[$key] = true;

			$existing = $app->dbmaster->queryOneRecord(
				'SELECT finding_id, finding_state FROM malwatch_finding WHERE parent_domain_id = ? AND path_hash = ? AND rule_id = ?',
				$domain_id, $hash, $rule);

			$severity = isset($finding['severity']) ? (string) $finding['severity'] : 'medium';
			$excerpt = isset($finding['excerpt']) ? substr((string) $finding['excerpt'], 0, 255) : '';
			$mtime = $this->to_datetime(isset($finding['mtime']) ? $finding['mtime'] : '');

			if (is_array($existing)) {
				// A finding the operator released stays released, even when
				// the scanner reports it again.
				$state = $existing['finding_state'] === 'ignored' ? 'ignored' : 'open';
				$app->dbmaster->query(
					'UPDATE malwatch_finding SET scan_id = ?, line_number = ?, severity = ?, engine = ?, '
					. 'file_sha256 = ?, excerpt = ?, file_size = ?, file_mtime = ?, finding_state = ?, last_seen = ? '
					. 'WHERE finding_id = ?',
					$scan_id, intval(isset($finding['line']) ? $finding['line'] : 0), $severity,
					substr((string) (isset($finding['engine']) ? $finding['engine'] : ''), 0, 32),
					(string) (isset($finding['sha256']) ? $finding['sha256'] : ''), $excerpt,
					intval(isset($finding['size']) ? $finding['size'] : 0), $mtime, $state, $now,
					intval($existing['finding_id']));
				continue;
			}

			$app->dbmaster->query(
				'INSERT INTO malwatch_finding (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, parent_domain_id, domain, scan_id, file_path, path_hash, line_number, rule_id, severity, '
				. 'engine, file_sha256, excerpt, file_size, file_mtime, finding_state, first_seen, last_seen) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)",
				$sys_groupid, intval($conf['server_id']), $domain_id, (string) $job['domain'], $scan_id,
				substr($path, 0, 1024), $hash, intval(isset($finding['line']) ? $finding['line'] : 0), $rule,
				$severity, substr((string) (isset($finding['engine']) ? $finding['engine'] : ''), 0, 32),
				(string) (isset($finding['sha256']) ? $finding['sha256'] : ''), $excerpt,
				intval(isset($finding['size']) ? $finding['size'] : 0), $mtime, $now, $now);
			$new++;
		}

		// Anything not seen in this run is gone from disk. It is marked fixed
		// rather than deleted, so the history stays readable.
		$app->dbmaster->query(
			"UPDATE malwatch_finding SET finding_state = 'fixed' "
			. 'WHERE parent_domain_id = ? AND last_seen < ? AND finding_state = ?',
			$domain_id, $now, 'open');

		return $new;
	}

	/** Records the detected web software of this run. */
	private function store_software($job, $report, $scan_id, $sys_groupid)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;
		$domain_id = intval($job['parent_domain_id']);
		$now = date('Y-m-d H:i:s');

		$software = isset($report['software']) && is_array($report['software']) ? $report['software'] : array();
		foreach ($software as $entry) {
			$path = isset($entry['path']) ? (string) $entry['path'] : '';
			if ($path === '') {
				continue;
			}
			$hash = $helper->path_hash($path);
			$kind = isset($entry['kind']) ? (string) $entry['kind'] : 'core';
			$slug = isset($entry['slug']) ? (string) $entry['slug'] : '';

			$existing = $app->dbmaster->queryOneRecord(
				'SELECT software_id FROM malwatch_software WHERE parent_domain_id = ? AND path_hash = ? AND software_kind = ? AND slug = ?',
				$domain_id, $hash, $kind, $slug);

			$outdated = !empty($entry['outdated']) ? 'y' : 'n';
			$unknown = !empty($entry['unknown']) ? 'y' : 'n';

			if (is_array($existing)) {
				$app->dbmaster->query(
					'UPDATE malwatch_software SET scan_id = ?, installed_version = ?, latest_version = ?, '
					. 'outdated = ?, version_unknown = ?, last_seen = ? WHERE software_id = ?',
					$scan_id, (string) $entry['version'], (string) (isset($entry['latest']) ? $entry['latest'] : ''),
					$outdated, $unknown, $now, intval($existing['software_id']));
				continue;
			}

			$app->dbmaster->query(
				'INSERT INTO malwatch_software (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, parent_domain_id, domain, scan_id, install_path, path_hash, product, software_kind, slug, '
				. 'installed_version, latest_version, outdated, version_unknown, last_seen) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($conf['server_id']), $domain_id, (string) $job['domain'], $scan_id,
				substr($path, 0, 1024), $hash, substr((string) $entry['product'], 0, 64), substr($kind, 0, 16),
				substr($slug, 0, 128), (string) $entry['version'],
				(string) (isset($entry['latest']) ? $entry['latest'] : ''), $outdated, $unknown, $now);
		}

		// Installations that disappeared are removed: unlike a finding, a
		// deleted CMS is not history worth keeping.
		$app->dbmaster->query('DELETE FROM malwatch_software WHERE parent_domain_id = ? AND last_seen < ?',
			$domain_id, $now);
	}

	/** Converts an RFC 3339 timestamp into a MySQL datetime. */
	private function to_datetime($value)
	{
		$value = trim((string) $value);
		if ($value === '') {
			return null;
		}
		$time = strtotime($value);
		if ($time === false || $time <= 0) {
			return null;
		}
		return date('Y-m-d H:i:s', $time);
	}

	/** Returns the last lines the scanner printed, for the job log. */
	private function tail_log($job)
	{
		$log = preg_replace('/\.json$/', '.log', (string) $job['result_file']);
		if ($log === '' || !is_file($log)) {
			return '';
		}
		$content = trim((string) file_get_contents($log));
		if ($content === '') {
			return '';
		}
		$lines = preg_split('/[\r\n]+/', $content);
		$lines = array_slice($lines, -5);
		return 'Ausgabe: ' . substr(implode(' | ', $lines), 0, 400);
	}
}
