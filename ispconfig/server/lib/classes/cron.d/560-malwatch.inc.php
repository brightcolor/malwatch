<?php

/**
 * The heartbeat of the malwatch extension. Runs every minute and does four
 * things, each cheap when there is nothing to do:
 *
 *   1. turn due schedules into jobs
 *   2. read the reports of finished scans and act on them
 *   3. start queued jobs when a slot is free
 *   4. clear out jobs that died and scans nobody needs any more
 */
class cronjob_malwatch extends cronjob
{
	protected $_schedule = '* * * * *';
	protected $_run_at_new = true;

	public function onRunJob()
	{
		global $app, $conf;

		$app->uses('malwatch_helper,malwatch_runner,malwatch_ingest,malwatch_actions,getconf');
		$config = $app->malwatch_helper->get_config();

		try {
			$this->collect_finished($config);
		} catch (Exception $e) {
			$app->log('malwatch: collecting results failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		}

		try {
			$this->queue_due_scans($config);
		} catch (Exception $e) {
			$app->log('malwatch: scheduling failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		}

		try {
			$this->start_pending($config);
		} catch (Exception $e) {
			$app->log('malwatch: starting a queued scan failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		}

		try {
			$this->housekeeping($config);
		} catch (Exception $e) {
			$app->log('malwatch: housekeeping failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		}

		parent::onRunJob();
	}

	/** Reads the reports of scans whose process has ended. */
	private function collect_finished($config)
	{
		global $app, $conf;

		$jobs = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'running' ORDER BY job_id ASC LIMIT 20",
			$conf['server_id']);

		if (!is_array($jobs)) {
			return;
		}

		foreach ($jobs as $job) {
			$code = $app->malwatch_runner->finished_code($job);
			if ($code === null) {
				continue;
			}
			// The scanner has ended and left its exit code behind. Either it
			// wrote a report or it died; ingest() tells the two apart.
			$app->dbmaster->query('UPDATE malwatch_job SET exit_code = ? WHERE job_id = ?',
				$code, intval($job['job_id']));
			$job['exit_code'] = $code;

			$kind = isset($job['job_kind']) ? (string) $job['job_kind'] : 'scan';

			if ($kind === 'repair') {
				$repair_id = $app->malwatch_ingest->ingest_repair($job);
				$app->malwatch_runner->clear_marker($job);
				$this->finish_repair($job, $repair_id);
				continue;
			}
			if ($kind === 'quarantine') {
				$app->malwatch_ingest->ingest_quarantine($job);
				$app->malwatch_runner->clear_marker($job);
				continue;
			}

			$scan_id = $app->malwatch_ingest->ingest($job);
			$app->malwatch_runner->clear_marker($job);

			if ($scan_id > 0) {
				$app->malwatch_actions->run($scan_id);
			}
		}
	}

	/**
	 * Brings a website back after a restore, and queues the scan that shows
	 * what is left.
	 *
	 * A half exchanged installation must not go back online, so only a clean
	 * run switches it back: exit code 0 means everything came back, 2 means
	 * elements without an original were deleted, which is a decision the
	 * operator already took when starting the run. Anything else leaves the
	 * website off and says so in the log, because somebody has to look first.
	 */
	private function finish_repair($job, $repair_id)
	{
		global $app;

		$options = json_decode((string) $job['options'], true);
		$dry = is_array($options) && !empty($options['dry_run']);
		$previous = is_array($options) && isset($options['previous_active'])
			? (string) $options['previous_active'] : 'y';
		$code = intval($job['exit_code']);

		if ($repair_id < 1 || ($code !== 0 && $code !== 2)) {
			$app->log('malwatch: die Wiederherstellung von ' . $job['domain']
				. ' ist gescheitert, die Website bleibt abgeschaltet.', LOGLEVEL_WARN);
			return;
		}

		if (!$dry && $previous === 'y') {
			$app->dbmaster->datalogUpdate('web_domain', array('active' => 'y'), 'domain_id',
				intval($job['parent_domain_id']));
		}

		if ($dry) {
			return;
		}

		// The scan afterwards is the point of the exercise: what it reports now
		// is by definition not part of the software.
		$site = $app->malwatch_helper->get_site($job['parent_domain_id']);
		$web = $app->malwatch_helper->get_web($job['parent_domain_id']);
		if (is_array($web)) {
			$this->create_job(is_array($site) ? $site : array('parent_domain_id' => $job['parent_domain_id']),
				$web, 'schedule');
		}
	}

	/** Creates jobs for websites whose schedule has come round. */
	private function queue_due_scans($config)
	{
		global $app, $conf;

		$sites = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_site WHERE server_id = ? AND schedule != 'off' "
			. 'AND (next_run IS NULL OR next_run <= NOW()) ORDER BY next_run ASC LIMIT 20',
			$conf['server_id']);

		if (!is_array($sites)) {
			return;
		}

		foreach ($sites as $site) {
			$pending = $app->dbmaster->queryOneRecord(
				"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
				intval($site['parent_domain_id']));

			if (is_array($pending)) {
				// One scan per site at a time. Otherwise a slow site would
				// accumulate a queue of identical scans.
				continue;
			}

			$web = $app->malwatch_helper->get_web($site['parent_domain_id']);
			if (!is_array($web) || $web['active'] !== 'y') {
				// Push the schedule forward so a disabled site does not get
				// looked at every single minute.
				$app->dbmaster->query('UPDATE malwatch_site SET next_run = ? WHERE site_id = ?',
					$app->malwatch_helper->next_run($site['schedule']), intval($site['site_id']));
				continue;
			}

			$this->create_job($site, $web, 'schedule');

			$app->dbmaster->query('UPDATE malwatch_site SET next_run = ? WHERE site_id = ?',
				$app->malwatch_helper->next_run($site['schedule']), intval($site['site_id']));
		}
	}

	/** Inserts one job row. */
	private function create_job($site, $web, $source)
	{
		global $app, $conf;

		$path = $app->malwatch_helper->scan_path($web);
		if ($path === '' || !is_dir($path)) {
			$app->log('malwatch: no scan path for ' . $web['domain'], LOGLEVEL_WARN);
			return;
		}

		$options = json_encode(array(
			'excludes' => (string) $site['excludes'],
			'max_age' => intval($site['max_age']),
			'version_scan' => $site['version_scan'],
		));

		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_path, job_source, job_status, options, created_at) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, 'pending', ?, NOW())",
			intval($web['sys_groupid']), intval($conf['server_id']), intval($web['domain_id']),
			(string) $web['domain'], $path, $source, $options);
	}

	/**
	 * Starts queued jobs while there is room.
	 *
	 * Jobs created here, by the cron class, never pass through the datalog and
	 * so never reach the server plugin. Without this step a scheduled scan
	 * would sit in the queue for ever.
	 */
	private function start_pending($config)
	{
		global $app, $conf;

		$limit = max(1, intval($config['max_parallel']));
		$running = $app->malwatch_helper->count_running_jobs();
		if ($running >= $limit) {
			return;
		}

		$jobs = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'pending' ORDER BY job_id ASC LIMIT ?",
			$conf['server_id'], $limit - $running);

		if (!is_array($jobs)) {
			return;
		}

		foreach ($jobs as $job) {
			if (!$app->malwatch_helper->claim_job($job['job_id'])) {
				continue;
			}
			$app->malwatch_runner->start($job, $config);
		}
	}

	/** Times out dead jobs and trims the history. */
	private function housekeeping($config)
	{
		global $app, $conf;

		$timeout = max(1, intval($config['job_timeout_hours']));

		// A finished scan is collected by collect_finished. This catches the
		// opposite case: a scanner that hangs. Without it a stuck job would
		// hold its slot for ever and no further scan would ever start.
		$stale = $app->dbmaster->queryAllRecords(
			"SELECT job_id, pid, domain, result_file FROM malwatch_job WHERE server_id = ? AND job_status = 'running' "
			. 'AND started_at < DATE_SUB(NOW(), INTERVAL ? HOUR)',
			$conf['server_id'], $timeout);

		if (is_array($stale)) {
			foreach ($stale as $job) {
				$pid = intval($job['pid']);
				if ($pid > 0 && is_dir('/proc/' . $pid) && function_exists('posix_kill')) {
					posix_kill($pid, 15);
				}
				$app->malwatch_runner->clear_marker($job);
				$app->dbmaster->query(
					"UPDATE malwatch_job SET job_status = 'error', finished_at = NOW(), job_log = ? WHERE job_id = ?",
					'Abgebrochen: der Lauf dauerte länger als ' . $timeout . ' Stunden.', intval($job['job_id']));
				$app->log('malwatch: scan for ' . $job['domain'] . ' timed out after ' . $timeout . ' hours',
					LOGLEVEL_WARN);
			}
		}

		// Only once an hour: the queries below scan whole tables and there is
		// nothing to gain from running them every minute.
		if (intval(date('i')) !== 7) {
			return;
		}

		$keep = max(1, intval($config['keep_scans']));
		$domains = $app->dbmaster->queryAllRecords(
			'SELECT DISTINCT parent_domain_id FROM malwatch_scan WHERE server_id = ?', $conf['server_id']);

		if (is_array($domains)) {
			foreach ($domains as $row) {
				$cutoff = $app->dbmaster->queryOneRecord(
					'SELECT scan_id FROM malwatch_scan WHERE parent_domain_id = ? ORDER BY scan_id DESC LIMIT ?, 1',
					intval($row['parent_domain_id']), $keep);

				if (is_array($cutoff)) {
					$app->dbmaster->query('DELETE FROM malwatch_scan WHERE parent_domain_id = ? AND scan_id <= ?',
						intval($row['parent_domain_id']), intval($cutoff['scan_id']));
				}
			}
		}

		$app->dbmaster->query(
			"DELETE FROM malwatch_job WHERE server_id = ? AND job_status IN ('done','error') "
			. 'AND finished_at < DATE_SUB(NOW(), INTERVAL 30 DAY)', $conf['server_id']);

		$app->dbmaster->query(
			"DELETE FROM malwatch_finding WHERE finding_state = 'fixed' "
			. 'AND last_seen < DATE_SUB(NOW(), INTERVAL 90 DAY)');

		$this->refresh_signatures($config);
	}

	/** Loads new malware signatures once a day. */
	private function refresh_signatures($config)
	{
		global $app;

		if ($config['auto_update_signatures'] !== 'y') {
			return;
		}
		if (!empty($config['last_signature_update'])
			&& strtotime((string) $config['last_signature_update']) > time() - 82800) {
			return;
		}

		$binary = (string) $config['binary_path'];
		if ($binary === '' || !is_executable($binary)) {
			return;
		}

		$cmd = escapeshellcmd($binary) . ' update --sig-dir='
			. escapeshellarg(rtrim((string) $config['state_dir'], '/') . '/signatures') . ' --quiet 2>&1';
		$output = array();
		$status = 0;
		exec($cmd, $output, $status);

		if ($status === 0) {
			$app->dbmaster->query('UPDATE malwatch_config SET last_signature_update = NOW() WHERE config_id = 1');
			$app->log('malwatch: signatures updated.', LOGLEVEL_DEBUG);
		} else {
			$app->log('malwatch: the signature update failed: ' . implode(' ', $output), LOGLEVEL_WARN);
		}
	}
}
