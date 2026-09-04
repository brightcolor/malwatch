<?php

/**
 * Shared helpers for the malwatch extension on the server side: settings,
 * job bookkeeping and the small conversions the other classes need.
 */
class malwatch_helper
{
	/** Severity names in order, weakest first. */
	public static $severities = array('low', 'medium', 'high', 'critical');

	private $config = null;

	/** Returns the global settings, with defaults for a missing row. */
	public function get_config()
	{
		global $app;

		if (is_array($this->config)) {
			return $this->config;
		}
		$row = $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1');
		if (!is_array($row)) {
			$row = array();
		}
		$defaults = array(
			'binary_path' => '/usr/local/bin/malwatch',
			'state_dir' => '/var/lib/malwatch',
			'admin_email' => '',
			'sender_email' => '',
			'default_schedule' => 'weekly',
			'default_excludes' => '',
			'max_parallel' => 1,
			'job_timeout_hours' => 6,
			'keep_scans' => 30,
			'scan_max_age' => 0,
			'use_clamav' => 'y',
			'auto_update_signatures' => 'y',
		);
		foreach ($defaults as $key => $value) {
			if (!isset($row[$key]) || $row[$key] === '' || $row[$key] === null) {
				$row[$key] = $value;
			}
		}
		$this->config = $row;
		return $row;
	}

	/**
	 * Marks a job as running, but only if it is still pending.
	 *
	 * The condition is part of the UPDATE, not a separate check: two datalog
	 * passes running at the same time would both pass a read-then-write test
	 * and start the scanner twice.
	 */
	public function claim_job($job_id)
	{
		global $app, $conf;

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'running', started_at = NOW() "
				. 'WHERE job_id = ? AND job_status = ? AND server_id = ?',
			$job_id, 'pending', $conf['server_id']
		);
		$row = $app->dbmaster->queryOneRecord(
			'SELECT job_status FROM malwatch_job WHERE job_id = ?', $job_id);

		return is_array($row) && $row['job_status'] === 'running';
	}

	/** Puts a claimed job back into the queue. */
	public function release_job($job_id, $reason = '')
	{
		global $app;
		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'pending', started_at = NULL, job_log = ? WHERE job_id = ?",
			$reason, $job_id);
	}

	/** Marks a job as failed. */
	public function fail_job($job_id, $message)
	{
		global $app;
		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'error', finished_at = NOW(), job_log = ? WHERE job_id = ?",
			$message, $job_id);
	}

	/** Counts jobs currently running on this server, excluding one id. */
	public function count_running_jobs($except_job_id = 0)
	{
		global $app, $conf;

		$row = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_id != ?",
			$conf['server_id'], intval($except_job_id));

		return is_array($row) ? intval($row['n']) : 0;
	}

	/** Returns the website record for a job. */
	public function get_web($parent_domain_id)
	{
		global $app;
		return $app->dbmaster->queryOneRecord(
			'SELECT * FROM web_domain WHERE domain_id = ?', intval($parent_domain_id));
	}

	/** Returns the malwatch settings of a website, or null. */
	public function get_site($parent_domain_id)
	{
		global $app;
		return $app->dbmaster->queryOneRecord(
			'SELECT * FROM malwatch_site WHERE parent_domain_id = ?', intval($parent_domain_id));
	}

	/**
	 * Returns the directory to scan for a website: the document root plus the
	 * web folder, which is where the customer's files actually are. Scanning
	 * the document root itself would include log and backup directories that
	 * belong to the server, not to the site.
	 */
	public function scan_path($web)
	{
		if (!is_array($web) || $web['document_root'] === '') {
			return '';
		}
		$folder = isset($web['web_folder']) ? trim((string) $web['web_folder'], '/') : '';
		if ($web['type'] === 'vhostsubdomain' || $web['type'] === 'vhostalias') {
			if ($folder !== '') {
				return rtrim($web['document_root'], '/') . '/' . $folder;
			}
		}
		return rtrim($web['document_root'], '/') . '/web';
	}

	/** Numeric weight of a severity, 0 for an unknown value. */
	public function severity_rank($severity)
	{
		$rank = array_search((string) $severity, self::$severities, true);
		return $rank === false ? 0 : $rank + 1;
	}

	/** True when $severity is at least as severe as $minimum. */
	public function severity_at_least($severity, $minimum)
	{
		return $this->severity_rank($severity) >= $this->severity_rank($minimum);
	}

	/** Stable identity of a file path, for the finding uniqueness key. */
	public function path_hash($path)
	{
		return hash('sha256', (string) $path);
	}

	/** Computes the next run time for a schedule, or null when off. */
	public function next_run($schedule, $from = null)
	{
		if ($from === null) {
			$from = time();
		}
		switch ($schedule) {
			case 'daily':
				return date('Y-m-d H:i:s', $from + 86400);
			case 'weekly':
				return date('Y-m-d H:i:s', $from + 7 * 86400);
			case 'monthly':
				return date('Y-m-d H:i:s', $from + 30 * 86400);
		}
		return null;
	}

	/** Writes a line into the ISPConfig log with a common prefix. */
	public function log($message, $level = LOGLEVEL_DEBUG)
	{
		global $app;
		$app->log('malwatch: ' . $message, $level);
	}
}
