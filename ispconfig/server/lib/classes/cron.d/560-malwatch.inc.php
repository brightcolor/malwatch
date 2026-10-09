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

	/** True once onRunJob() got to its end; after_crash() looks at it. */
	private $finished = false;

	public function onRunJob()
	{
		global $app, $conf;

		// Every section catches Throwable, not only Exception. An Error that
		// escapes ends cron.php: ISPConfig never clears the running flag of this
		// job and skips it for 24 hours, and the ISPConfig jobs after it lose
		// that run. From 2026-09-26 to 2026-09-28 an undefined function in the
		// WAF part did exactly that, and no website was scanned.
		try {
			$app->uses('malwatch_helper,malwatch_runner,malwatch_ingest,malwatch_actions,malwatch_waf,getconf');
			$config = $app->malwatch_helper->get_config();
		} catch (Throwable $e) {
			$app->log('malwatch: Die Helfer von malwatch ließen sich nicht laden (' . $this->failure_text($e)
				. '). malwatch ist vermutlich unvollständig installiert; bitte das Paket erneut einspielen.', LOGLEVEL_WARN);
			parent::onRunJob();
			return;
		}

		// The guard for a crash no catch reaches, see after_crash(). Its pause
		// comes from the settings; without them it only reports.
		$pause = 0;
		try {
			$guard_settings = $app->malwatch_waf->settings();
			$pause = (int) $guard_settings['waf_watch_crash_pause'];
		} catch (Throwable $e) {
			$pause = 0;
		}
		register_shutdown_function(array($this, 'after_crash'), $pause);

		try {
			$this->collect_finished($config);
		} catch (Throwable $e) {
			$app->log('malwatch: Fertige Prüfläufe ließen sich nicht einlesen (' . $this->failure_text($e)
				. '). Der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		try {
			$this->queue_due_scans($config);
		} catch (Throwable $e) {
			$app->log('malwatch: Fällige Prüfungen ließen sich nicht einplanen (' . $this->failure_text($e)
				. '). Der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		try {
			$this->queue_due_vulnchecks($config);
		} catch (Throwable $e) {
			$app->log('malwatch: Der Schwachstellenabgleich ließ sich nicht einplanen (' . $this->failure_text($e)
				. '). Der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		// The WAF part reads its log and works on its own jobs, under its own
		// lock; see malwatch_waf. The runner never starts one of them.
		try {
			// The Abwehr has its own clock (waf-switch tick in the cron file of the
			// Abwehr). While it runs, this job leaves both passes to it; without it,
			// they run here: the hourly one at the minute of waf_hourly_minute, the
			// same minute the clock would use. The minute counts from the start.
			if (!$app->malwatch_waf->tick_is_fresh()) {
				$minute = intval(date('i'));
				$app->malwatch_waf->cron_minute();
				$waf_settings = $app->malwatch_waf->settings();
				if ($minute === intval($waf_settings['waf_hourly_minute'])) {
					$app->malwatch_waf->cron_hourly();
				}
			}
		} catch (Throwable $e) {
			$app->log('malwatch: Der WAF-Teil ist gescheitert (' . $this->failure_text($e)
				. '). Die übrigen Aufgaben laufen weiter, der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		try {
			$this->start_pending($config);
		} catch (Throwable $e) {
			$app->log('malwatch: Ein wartender Auftrag ließ sich nicht starten (' . $this->failure_text($e)
				. '). Der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		try {
			$this->housekeeping($config);
		} catch (Throwable $e) {
			$app->log('malwatch: Die Aufräumarbeiten sind gescheitert (' . $this->failure_text($e)
				. '). Der nächste Lauf versucht es erneut.', LOGLEVEL_WARN);
		}

		parent::onRunJob();
		$this->finished = true;
	}

	/**
	 * Runs when PHP ends. After a run that got to its end it does nothing. A run
	 * that ended before - memory, a compile error in an included file, anything
	 * no catch reaches - would stay marked as running in sys_cron for 24 hours,
	 * and no scan would start. The guard clears the mark and sets the next run
	 * after the pause of the settings (waf_watch_crash_pause): the job neither
	 * stops for a day nor ends the cron of ISPConfig every minute, and the watch
	 * over the scanner reports the crash. Without a pause it only reports and
	 * leaves the mark to the watch.
	 */
	public function after_crash($pause)
	{
		global $app;

		if ($this->finished) {
			return;
		}
		$error = error_get_last();
		$text = is_array($error)
			? basename((string) $error['file']) . ':' . (int) $error['line'] . ': ' . (string) $error['message']
			: 'Der Lauf endete vorzeitig ohne Fehlermeldung.';
		try {
			if ((int) $pause > 0) {
				$app->db->query('UPDATE sys_cron SET running = 0, next_run = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE name = ?',
					(int) $pause, get_class($this));
			}
			$app->malwatch_waf->record_cron_crash($text, (int) $pause);
		} catch (Throwable $e) {
			// Nothing more to do from here; the log line below says what happened.
		}
		$app->log('malwatch: Der Cron-Job ist abgestürzt (' . $text . '). '
			. ((int) $pause > 0 ? 'Er gibt sich frei und startet nach der Pause von ' . (int) $pause . ' Minuten neu. '
				: 'Die Markierung „läuft“ bleibt, bis die Wache über den Scanner sie löst. ')
			. 'Die Wache meldet den Absturz.', LOGLEVEL_WARN);
	}

	/** Kind, place and message of a failure, for the ISPConfig log. */
	private function failure_text($e)
	{
		return get_class($e) . ' in ' . basename($e->getFile()) . ':' . $e->getLine() . ': ' . $e->getMessage();
	}

	/** Reads the reports of scans whose process has ended. */
	private function collect_finished($config)
	{
		global $app, $conf;

		$jobs = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_kind != 'waf' ORDER BY job_id ASC LIMIT 20",
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
			if ($kind === 'upgrade') {
				$upgrade_id = $app->malwatch_ingest->ingest_upgrade($job);
				$app->malwatch_runner->clear_marker($job);
				@unlink(preg_replace('/\.json$/', '.plan.json', (string) $job['result_file']));
				$this->finish_upgrade($job, $upgrade_id);
				continue;
			}
			if ($kind === 'quarantine') {
				$app->malwatch_ingest->ingest_quarantine($job);
				$app->malwatch_runner->clear_marker($job);
				continue;
			}
			if ($kind === 'dump') {
				// No actions afterwards: a dump reads a website, it changes
				// nothing on it.
				$app->malwatch_ingest->ingest_dump($job);
				$app->malwatch_runner->clear_marker($job);
				continue;
			}
			if ($kind === 'vulncheck') {
				// No actions afterwards: those key on new findings, and this
				// run never produces one.
				$app->malwatch_ingest->ingest_vulncheck($job);
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

	/**
	 * After an upgrade: the notifications about whatever came back or failed,
	 * and a check of the website, so versions, flaws and state describe what
	 * is installed now. A dry run changed nothing and needs neither.
	 */
	private function finish_upgrade($job, $upgrade_id)
	{
		global $app;

		$options = json_decode((string) $job['options'], true);
		if (is_array($options) && !empty($options['dry_run'])) {
			return;
		}

		// A missing report is a run nobody can vouch for: notify_upgrade()
		// tells the operator with upgrade_id 0 as well.
		$app->malwatch_actions->notify_upgrade($job, $upgrade_id);

		$web = $app->malwatch_helper->get_web($job['parent_domain_id']);
		if (!is_array($web)) {
			return;
		}
		$site = $app->malwatch_helper->get_site($job['parent_domain_id']);
		if (!is_array($site)) {
			$site = array('excludes' => '', 'max_age' => 0, 'version_scan' => 'y');
		}
		$this->create_job($site, $web, 'schedule', 'vulncheck');
	}

	/**
	 * Creates jobs for websites whose interval has come round. A website
	 * without a settings row gets one first, with the interval for new
	 * websites, as long as that is not 0.
	 */
	private function queue_due_scans($config)
	{
		global $app, $conf;

		if ((int) $config['default_scan_days'] > 0) {
			$this->add_missing_sites();
		}

		$sites = $app->dbmaster->queryAllRecords(
			'SELECT * FROM malwatch_site WHERE server_id = ? AND scan_days > 0 '
			. 'AND (next_run IS NULL OR next_run <= NOW()) ORDER BY next_run ASC LIMIT 20',
			$conf['server_id']);

		if (!is_array($sites)) {
			return;
		}

		foreach ($sites as $site) {
			// A vulnerability check still waiting gives way to the scan that
			// is due: the scan looks the flaws up as well.
			$app->dbmaster->query(
				"DELETE FROM malwatch_job WHERE parent_domain_id = ? AND job_kind = 'vulncheck' AND job_status = 'pending'",
				intval($site['parent_domain_id']));
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
				$app->dbmaster->query('UPDATE malwatch_site SET next_run = FROM_UNIXTIME(?) WHERE site_id = ?',
					$app->malwatch_helper->next_run($site['scan_days']), intval($site['site_id']));
				continue;
			}

			$this->create_job($site, $web, 'schedule');

			$app->dbmaster->query('UPDATE malwatch_site SET next_run = FROM_UNIXTIME(?) WHERE site_id = ?',
				$app->malwatch_helper->next_run($site['scan_days']), intval($site['site_id']));
		}
	}

	/**
	 * Gives every active website of this server that has no settings row one,
	 * see malwatch_helper::ensure_site_row(). The same types as the daily
	 * vulnerability check and the overview.
	 */
	private function add_missing_sites()
	{
		global $app, $conf;

		$webs = $app->dbmaster->queryAllRecords(
			'SELECT w.domain_id, w.domain, w.server_id, w.sys_groupid FROM web_domain w '
			. 'LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id '
			. "WHERE w.server_id = ? AND w.type IN ('vhost','vhostsubdomain','vhostalias') AND w.active = 'y' "
			. 'AND s.site_id IS NULL',
			$conf['server_id']);
		foreach ((array) $webs as $web) {
			$app->malwatch_helper->ensure_site_row($web);
		}
	}

	/**
	 * Queues the daily vulnerability check for every active website.
	 *
	 * Flaws are published every day while the installed software stays the
	 * same; the weekly malware scan alone would learn of one up to a week
	 * late. The check reads no file for malware and asks each source once per
	 * component a day, most of it answered from the cache.
	 *
	 * Once a day per server, from four in the morning on. The marker is a
	 * file in the state directory: malwatch_config is a single row for all
	 * servers, and a date stored there would let the first server that gets
	 * to it take the day for all of them.
	 */
	private function queue_due_vulnchecks($config)
	{
		global $app, $conf;

		if (isset($config['vuln_scan']) && $config['vuln_scan'] === 'n') {
			return;
		}
		if (intval(date('G')) < 4) {
			return;
		}
		$marker = rtrim((string) $config['state_dir'], '/') . '/state/vulncheck.last';
		$today = date('Y-m-d');
		if (is_file($marker) && trim((string) @file_get_contents($marker)) === $today) {
			return;
		}
		if (!is_dir(dirname($marker))) {
			@mkdir(dirname($marker), 0750, true);
		}
		// Written before anything is queued, and nothing is queued when it
		// cannot be written: a marker that does not stick would queue the
		// whole round again every minute.
		if (@file_put_contents($marker, $today) === false) {
			return;
		}

		$webs = $app->dbmaster->queryAllRecords(
			"SELECT * FROM web_domain WHERE server_id = ? AND type IN ('vhost','vhostsubdomain','vhostalias') "
			. "AND active = 'y' ORDER BY domain_id ASC",
			$conf['server_id']);
		foreach ((array) $webs as $web) {
			$busy = $app->dbmaster->queryOneRecord(
				"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
				intval($web['domain_id']));
			if (is_array($busy)) {
				// A scan that is already queued looks the flaws up as well.
				continue;
			}
			$site = $app->malwatch_helper->get_site($web['domain_id']);
			if (!is_array($site)) {
				$site = array('excludes' => '', 'max_age' => 0, 'version_scan' => 'y');
			}
			if ($site['version_scan'] === 'n') {
				// "Veraltete Software suchen: nein" on this website.
				continue;
			}
			$this->create_job($site, $web, 'schedule', 'vulncheck');
		}
	}

	/** Inserts one job row. */
	private function create_job($site, $web, $source, $kind = 'scan')
	{
		global $app, $conf;

		$path = $app->malwatch_helper->scan_path($web);
		if ($path === '' || !is_dir($path)) {
			$app->log('malwatch: ' . $web['domain'] . ' wurde nicht geprüft, das Webverzeichnis '
				. ($path === '' ? 'ist in ISPConfig nicht eingetragen' : $path . ' fehlt')
				. '. Bitte die Website in ISPConfig prüfen; der nächste geplante Lauf versucht es erneut.', LOGLEVEL_WARN);
			return;
		}

		$options = json_encode(array(
			'excludes' => (string) $site['excludes'],
			'max_age' => intval($site['max_age']),
			'version_scan' => $site['version_scan'],
		));

		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, 'pending', ?, NOW())",
			intval($web['sys_groupid']), intval($conf['server_id']), intval($web['domain_id']),
			(string) $web['domain'], $path, $source, $kind, $options);
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
		if ($running < $limit) {
			$this->start_jobs($config, "job_kind NOT IN ('vulncheck','waf')", $limit - $running);
		}

		// Vulnerability checks have their own slots beside the scans: behind a
		// scan of several hours the daily round would reach the last website
		// a day late.
		$checks = $app->malwatch_helper->count_running_jobs(0, 'vulncheck');
		if ($checks < malwatch_helper::VULNCHECK_PARALLEL) {
			$this->start_jobs($config, "job_kind = 'vulncheck'", malwatch_helper::VULNCHECK_PARALLEL - $checks);
		}
	}

	/** Claims and starts up to $count pending jobs matching $kind_sql. */
	private function start_jobs($config, $kind_sql, $count)
	{
		global $app, $conf;

		$jobs = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_status = 'pending' AND " . $kind_sql
			. ' ORDER BY job_id ASC LIMIT ?',
			$conf['server_id'], intval($count));

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
			"SELECT job_id, pid, domain, result_file FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_kind != 'waf' "
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

		// Diese drei stehen vor der Stundensperre unten, weil sie schnell auf
		// etwas Neues reagieren sollen: hinter ihr zeigte die
		// Einstellungsseite nach einer frischen Installation bis zu eine
		// Stunde lang „0 Prüfungen" neben jeder Möglichkeit, weil der Katalog
		// noch leer war. Jeder der drei bremst sich selbst - auch auf dem
		// Fehlerweg, siehe retry_blocked(): ihre eigenen Bremsen (eine
		// Spalte, das Alter einer Datei, eine vollständige Zeile) greifen
		// ausschließlich im Erfolgsfall, und die Stundensperre war vorher
		// zugleich der Deckel für den Fehlerweg.
		$this->refresh_signatures($config);
		$this->refresh_rules($config);
		$this->complete_quarantine_index($config);

		// Only once an hour, at the minute of housekeeping_minute: the queries
		// below scan whole tables and there is nothing to gain from running
		// them every minute.
		if (intval(date('i')) !== $app->malwatch_helper->housekeeping_value($config, 'housekeeping_minute')) {
			return;
		}

		// Hier und nicht oben: der Spool wird nach Alter geräumt, mit einer
		// Frist von einem Tag - dafür reicht ein Lauf je Stunde, und genau
		// den setzt malwatch_quarantine_list.php voraus, wenn es einen Token
		// noch bis zu einer Stunde über seine Frist hinaus gelten lässt. Oben
		// war es ein scandir je Minute für nichts.
		$this->clean_spool($config);
		$this->clean_quarantine_scratch($config);
		// Die Dumps: erst aufräumen, was abgelaufen ist, dann nachsehen, was
		// die Datenbanken der Websites gerade wiegen. Beides gehört hierher
		// und nicht in den Minutentakt - das eine liest ein Verzeichnis, das
		// andere information_schema über alle Datenbanken des Servers.
		$this->clean_dumps($config);
		$this->collect_databases($config);

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
			. 'AND finished_at < DATE_SUB(NOW(), INTERVAL ? DAY)', $conf['server_id'],
			$app->malwatch_helper->housekeeping_value($config, 'keep_job_days'));

		$this->clean_vanished($config);

		// A fixed finding stays keep_fixed_days after a scan last saw it,
		// whoever closed it: a scan, the quarantine, or clean_vanished().
		$app->dbmaster->query(
			"DELETE FROM malwatch_finding WHERE finding_state = 'fixed' "
			. 'AND last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)',
			$app->malwatch_helper->housekeeping_value($config, 'keep_fixed_days'));

		$this->clean_views($config);
	}

	/**
	 * Closes the open findings of this server whose file is gone, see
	 * malwatch_helper::vanished_ids(). Each run checks vanished_check_rows of
	 * them, from where the last run stopped, so the stat calls of a server with
	 * many findings spread over several runs; 0 turns the check off. Where a
	 * run stopped is kept per server in state/vanished.cursor, because
	 * malwatch_config is one row for all servers.
	 */
	private function clean_vanished($config)
	{
		global $app, $conf;

		$rows = $app->malwatch_helper->housekeeping_value($config, 'vanished_check_rows');
		if ($rows === 0) {
			return;
		}
		$cursor_file = rtrim((string) $config['state_dir'], '/') . '/state/vanished.cursor';
		$cursor = is_file($cursor_file) ? intval(trim((string) file_get_contents($cursor_file))) : 0;
		$findings = $app->dbmaster->queryAllRecords(
			'SELECT f.finding_id, f.file_path, w.document_root FROM malwatch_finding f '
			. 'LEFT JOIN web_domain w ON w.domain_id = f.parent_domain_id '
			. "WHERE f.server_id = ? AND f.finding_state = 'open' AND f.finding_id > ? "
			. 'ORDER BY f.finding_id LIMIT ?',
			$conf['server_id'], $cursor, $rows);
		$findings = is_array($findings) ? $findings : array();

		$ids = $app->malwatch_helper->vanished_ids($findings);
		if (count($ids) > 0) {
			$app->dbmaster->query(
				"UPDATE malwatch_finding SET finding_state = 'fixed' WHERE finding_state = 'open' AND finding_id IN ("
				. implode(',', array_map('intval', $ids)) . ')');
		}

		// A run that got fewer rows than it asked for reached the end, and the
		// next one starts from the beginning.
		$next = count($findings) < $rows ? 0 : intval($findings[count($findings) - 1]['finding_id']);
		if (file_put_contents($cursor_file, $next . "\n") === false) {
			$app->log('malwatch: ' . $cursor_file . ' ließ sich nicht schreiben; die Suche nach Funden, deren Datei '
				. 'fehlt, beginnt deshalb jedes Mal von vorn. Bitte die Rechte des Ordners prüfen.', LOGLEVEL_WARN);
		}
		if (count($ids) === 1) {
			$app->log('malwatch: 1 offener Fund geschlossen, weil seine Datei nicht mehr da ist.', LOGLEVEL_DEBUG);
		} elseif (count($ids) > 1) {
			$app->log('malwatch: ' . count($ids) . ' offene Funde geschlossen, weil ihre Datei nicht mehr da ist.',
				LOGLEVEL_DEBUG);
		}
	}

	/**
	 * Drops the views (malwatch_file) no open or released finding points to
	 * any more, once they are older than view_keep_days. A fixed finding keeps
	 * its view that long, so the page of a file that was just moved to the
	 * quarantine still shows what it was.
	 */
	private function clean_views($config)
	{
		global $app;

		$app->uses('malwatch_helper');
		$days = $app->malwatch_helper->view_keep_days($config);
		$app->dbmaster->query(
			'DELETE FROM malwatch_file WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY) '
			. 'AND file_sha256 NOT IN (SELECT file_sha256 FROM malwatch_finding '
			. "WHERE finding_state IN ('open','ignored') AND file_sha256 <> '')",
			$days);
	}

	/**
	 * Whether a step that runs every minute may try again after it failed.
	 *
	 * The three steps ahead of the hour lock each brake on their own result:
	 * a config column, the mtime of the file they write, a row they filled
	 * in. Every one of those is written only when the step succeeded, so on
	 * the failure path there was no brake at all - a signature update with no
	 * route to the mirror fetched 1440 times a day instead of 24, each with
	 * its own warning line in the log. Until the steps were pulled out of it,
	 * the hour lock was that cap.
	 *
	 * The marker is written before the attempt and removed only once it
	 * worked, so a run that dies part way - killed, timed out, the machine
	 * rebooted - leaves the brake engaged rather than clearing it.
	 */
	private function retry_blocked($config, $name)
	{
		$marker = $this->retry_marker($config, $name);
		return is_file($marker) && filemtime($marker) > time() - 3600;
	}

	/** Notes that an attempt is being made now. Its mtime is the whole record. */
	private function note_attempt($config, $name)
	{
		@touch($this->retry_marker($config, $name));
	}

	/** Lifts the brake after the step actually did its job. */
	private function clear_attempt($config, $name)
	{
		@unlink($this->retry_marker($config, $name));
	}

	/**
	 * Where a step's brake lives. In state/ next to the other state files, so
	 * an operator clearing the state directory clears these with it.
	 */
	private function retry_marker($config, $name)
	{
		return rtrim((string) $config['state_dir'], '/') . '/state/.retry-' . $name;
	}

	/**
	 * Fills in what a repair could not know about the entries it filed.
	 *
	 * A repair reports the ids it created and nothing else - size, file count
	 * and kind live in the store's own listing, which only a quarantine job
	 * produces. Until one ran, thirteen rows in the panel said "noch
	 * unbekannt" in the size column and the footprint in the header stood at
	 * zero, which is exactly the information someone opens that page for.
	 *
	 * Costs one query per minute and nothing else while every row is
	 * complete. There is no index on archive_bytes, so that query walks this
	 * server's rows - which is why the brake below matters: a row that stays
	 * incomplete would otherwise start the whole binary once a minute for
	 * ever.
	 */
	private function complete_quarantine_index($config)
	{
		global $app, $conf;

		$incomplete = $app->dbmaster->queryOneRecord(
			'SELECT quarantine_id FROM malwatch_quarantine WHERE server_id = ? AND archive_bytes = 0 LIMIT 1',
			$conf['server_id']);
		if (!is_array($incomplete)) {
			return;
		}

		$binary = (string) $config['binary_path'];
		$store = rtrim((string) $config['state_dir'], '/') . '/quarantine';
		if ($binary === '' || !is_executable($binary) || !is_dir($store)) {
			return;
		}

		if ($this->retry_blocked($config, 'quarantine-index')) {
			return;
		}
		$this->note_attempt($config, 'quarantine-index');

		$out = rtrim((string) $config['state_dir'], '/') . '/state/quarantine-index.json';
		$cmd = escapeshellcmd($binary) . ' quarantine list --quarantine-dir=' . escapeshellarg($store)
			. ' --json --out=' . escapeshellarg($out) . ' 2>&1';
		$output = array();
		$status = 0;
		exec($cmd, $output, $status);
		if ($status !== 0) {
			$app->log('malwatch: reading the quarantine store failed: ' . implode(' ', $output), LOGLEVEL_WARN);
			return;
		}

		$doc = json_decode((string) @file_get_contents($out), true);
		if (!is_array($doc) || !isset($doc['entries']) || !is_array($doc['entries'])) {
			return;
		}
		$app->uses('malwatch_ingest');
		$app->malwatch_ingest->sync_quarantine($conf['server_id'], $doc['entries'],
			isset($doc['skipped']) ? intval($doc['skipped']) : 0,
			isset($doc['skipped_ids']) && is_array($doc['skipped_ids']) ? $doc['skipped_ids'] : array());

		// Der Rückgabecode allein sagt hier nicht, ob der Schritt sein Ziel
		// erreicht hat: bleibt eine Zeile unvollständig - der Speicher kennt
		// den Eintrag nicht mehr, und eine der beiden Bremsen in
		// sync_quarantine hat das Aufräumen deshalb ausgelassen -, dann
		// findet die Abfrage oben sie in der nächsten Minute wieder und alles
		// begänne von vorn. Die Bremse fällt darum erst, wenn nichts mehr
		// offen ist.
		$still_incomplete = $app->dbmaster->queryOneRecord(
			'SELECT quarantine_id FROM malwatch_quarantine WHERE server_id = ? AND archive_bytes = 0 LIMIT 1',
			$conf['server_id']);
		if (!is_array($still_incomplete)) {
			$this->clear_attempt($config, 'quarantine-index');
		}
	}

	/**
	 * Removes zips nobody downloaded within a day and clears the row that
	 * pointed at them.
	 *
	 * Without the second half a stale export_token would still look valid
	 * to malwatch_quarantine_download.php and offer a link to a file that
	 * is no longer on disk.
	 */
	/**
	 * Removes the dumps whose week is over, and archives no row claims.
	 *
	 * Deleting in the panel takes the row out and leaves the file: the
	 * archive belongs to root, and the panel may read that directory and
	 * nothing more. Both halves end up here - a row past its expiry loses its
	 * file, and a file without a row is the leftover of exactly that case.
	 *
	 * Only names ending in .tar.gz count as archives. A run that is packing
	 * right now has its database export lying next to the archive as
	 * <token>.tar.gz.<name>.part, and taking that away mid-run would break a
	 * dump that is doing nothing wrong.
	 */
	private function clean_dumps($config)
	{
		global $app, $conf;

		$dir = rtrim((string) $config['state_dir'], '/') . '/dumps';
		if (!is_dir($dir)) {
			return;
		}

		$expired = $app->dbmaster->queryAllRecords(
			'SELECT dump_id, token FROM malwatch_dump WHERE server_id = ? '
			. 'AND expires_at IS NOT NULL AND expires_at < NOW()',
			$conf['server_id']);
		foreach ((array) $expired as $row) {
			$token = (string) $row['token'];
			if ($token !== '' && preg_match('/^[A-Za-z0-9_-]+$/', $token)) {
				@unlink($dir . '/' . $token . '.tar.gz');
			}
			$app->dbmaster->query('DELETE FROM malwatch_dump WHERE dump_id = ?', intval($row['dump_id']));
		}

		$names = scandir($dir);
		if ($names === false) {
			return;
		}

		$scratch_cutoff = time() - 86400;
		foreach ($names as $name) {
			if ($name === '.' || $name === '..') {
				continue;
			}
			$full = $dir . '/' . $name;
			if (!is_file($full)) {
				continue;
			}

			// A database export of a run that was killed: it hangs on a defer
			// the process never reached.
			if (substr($name, -5) === '.part') {
				if (filemtime($full) < $scratch_cutoff) {
					@unlink($full);
				}
				continue;
			}
			if (substr($name, -7) !== '.tar.gz') {
				continue;
			}

			// The token is the file name without its extension - the one
			// naming rule shared with malwatch_runner::build_arguments().
			$token = substr($name, 0, strlen($name) - 7);
			$row = $app->dbmaster->queryOneRecord(
				'SELECT dump_id FROM malwatch_dump WHERE server_id = ? AND token = ?',
				$conf['server_id'], $token);
			if (!is_array($row)) {
				@unlink($full);
			}
		}
	}

	/**
	 * Fills malwatch_database: what each database of a website weighs, how
	 * many tables it holds, when it was last written, and which WordPress
	 * installation uses it.
	 *
	 * The panel reaches neither the customer's files nor these figures, so
	 * they are collected here, where the cron runs as root. One statement
	 * covers every database on the machine, and one wp-config.php is read per
	 * WordPress installation the last scan reported - that is what keeps this
	 * in the hourly block instead of the minute one.
	 *
	 * A database the connection cannot see keeps its zeros: the picker then
	 * shows the name without marks, which is honest, rather than claiming a
	 * measurement nobody took.
	 */
	private function collect_databases($config)
	{
		global $app, $conf;

		$databases = $app->dbmaster->queryAllRecords(
			'SELECT database_name, parent_domain_id FROM web_database '
			. "WHERE server_id = ? AND active = 'y' AND type = 'mysql'",
			$conf['server_id']);
		if (!is_array($databases) || count($databases) === 0) {
			return;
		}

		$facts = array();
		$rows = $app->dbmaster->queryAllRecords(
			'SELECT table_schema, COUNT(*) AS table_count, '
			. 'COALESCE(SUM(data_length + index_length), 0) AS bytes, MAX(update_time) AS last_write '
			. 'FROM information_schema.tables GROUP BY table_schema');
		foreach ((array) $rows as $row) {
			$facts[(string) $row['table_schema']] = $row;
		}

		// Which database belongs to which installation: wp-config.php says so
		// itself, and the first 64 KB hold the define in every layout seen so
		// far.
		$used = array();
		$installs = $app->dbmaster->queryAllRecords(
			'SELECT install_path FROM malwatch_software WHERE server_id = ? '
			. "AND product = 'wordpress' AND software_kind = 'core'",
			$conf['server_id']);
		foreach ((array) $installs as $install) {
			$path = rtrim((string) $install['install_path'], '/');
			$file = $path . '/wp-config.php';
			if ($path === '' || !is_file($file) || !is_readable($file)) {
				continue;
			}
			$raw = (string) @file_get_contents($file, false, null, 0, 65536);
			if ($raw === '') {
				continue;
			}
			if (preg_match('/define\s*\(\s*[\'"]DB_NAME[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]/', $raw, $found)) {
				$used[$found[1]] = $path;
			}
		}

		foreach ($databases as $db) {
			$name = (string) $db['database_name'];
			$fact = isset($facts[$name]) ? $facts[$name] : array('table_count' => 0, 'bytes' => 0, 'last_write' => null);
			$last_write = isset($fact['last_write']) && $fact['last_write'] !== null
				? (string) $fact['last_write'] : null;

			$app->dbmaster->query(
				'INSERT INTO malwatch_database (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
				. 'sys_perm_other, server_id, parent_domain_id, database_name, table_count, bytes, last_write, '
				. "used_kind, used_by, checked_at) VALUES (1, 0, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, NOW()) "
				. 'ON DUPLICATE KEY UPDATE parent_domain_id = VALUES(parent_domain_id), '
				. 'table_count = VALUES(table_count), bytes = VALUES(bytes), last_write = VALUES(last_write), '
				. 'used_kind = VALUES(used_kind), used_by = VALUES(used_by), checked_at = VALUES(checked_at)',
				$conf['server_id'], intval($db['parent_domain_id']), $name,
				intval($fact['table_count']), (float) $fact['bytes'], $last_write,
				isset($used[$name]) ? 'wordpress' : '',
				isset($used[$name]) ? $used[$name] : '');
		}

		// A database that ISPConfig no longer lists stops being refreshed and
		// leaves after a day, so the picker follows what the panel knows.
		$app->dbmaster->query(
			'DELETE FROM malwatch_database WHERE server_id = ? AND checked_at < DATE_SUB(NOW(), INTERVAL 1 DAY)',
			$conf['server_id']);
	}

	private function clean_spool($config)
	{
		global $app, $conf;

		$spool_dir = rtrim((string) $config['state_dir'], '/') . '/spool';
		if (!is_dir($spool_dir)) {
			return;
		}

		$names = scandir($spool_dir);
		if ($names === false) {
			return;
		}

		$cutoff = time() - 86400;
		foreach ($names as $name) {
			if ($name === '.' || $name === '..') {
				continue;
			}
			$full = $spool_dir . '/' . $name;
			if (!is_file($full) || filemtime($full) >= $cutoff) {
				continue;
			}

			@unlink($full);

			// The token is the file name without its extension - the only
			// naming rule shared between build_arguments() and here.
			$token = preg_replace('/\.zip$/', '', $name);
			if ($token === '') {
				continue;
			}
			$app->dbmaster->query(
				"UPDATE malwatch_quarantine SET export_token = '', export_bytes = 0, export_ready_at = NULL "
				. 'WHERE server_id = ? AND export_token = ?',
				$conf['server_id'], $token);
		}
	}

	/**
	 * Removes the scratch directories a killed run left behind in the store.
	 *
	 * StoreCopy unpacks its archive into <id>.verify to prove it can be read
	 * back; Restore unpacks into <id>.restore before it removes what is at
	 * the target. Both hang on a defer, and a process that dies - the OOM
	 * killer, a reboot, job_timeout - never reaches it. The listing rightly
	 * ignores such a directory, which makes it invisible as well as
	 * permanent: an aborted restore of a WordPress core leaves 50 to 80 MB
	 * lying in the one directory that is already tight whenever somebody is
	 * clearing space, and clean_spool() next door never looks here.
	 *
	 * An hour is the cut-off rather than clean_spool's day: nothing keeps one
	 * of these alive that long - the longest it ever lives is one unpack -
	 * while a shorter window could take the scratch directory out from under
	 * a restore that is still running.
	 */
	private function clean_quarantine_scratch($config)
	{
		$store = rtrim((string) $config['state_dir'], '/') . '/quarantine';
		if (!is_dir($store)) {
			return;
		}

		$names = scandir($store);
		if ($names === false) {
			return;
		}

		$cutoff = time() - 3600;
		foreach ($names as $name) {
			if (!preg_match('/\.(verify|restore)$/', $name)) {
				continue;
			}
			$full = $store . '/' . $name;
			// is_dir und kein Link: ein Link mit passendem Namen zeigt
			// woandershin, und dorthin geht das Aufräumen nicht.
			if (!is_dir($full) || is_link($full) || filemtime($full) >= $cutoff) {
				continue;
			}
			$this->remove_tree($full);
		}
	}

	/**
	 * Removes a directory and everything below it.
	 *
	 * Symlinks are unlinked, never walked: the payload of a quarantine entry
	 * comes off a compromised website and keeps its symlinks as symlinks
	 * (internal/quarantine/archive.go), so one pointing at /etc must not turn
	 * a cleanup into a deletion somewhere else. RecursiveDirectoryIterator
	 * does not descend into links on its own, and the check below keeps rmdir
	 * off the link itself.
	 *
	 * CATCH_GET_CHILD, because a subdirectory that cannot be opened is a
	 * reason to leave that one alone, not to throw the rest of housekeeping -
	 * the thirty and ninety day cleanups below - out of this run with it.
	 */
	private function remove_tree($dir)
	{
		$items = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST,
			RecursiveIteratorIterator::CATCH_GET_CHILD);

		foreach ($items as $item) {
			$path = $item->getPathname();
			if ($item->isLink() || !$item->isDir()) {
				@unlink($path);
				continue;
			}
			@rmdir($path);
		}
		@rmdir($dir);
	}

	/**
	 * Refreshes malwatch_rule from the scanner's own catalogue, once a day.
	 *
	 * Unlike signature updates there is no config column to remember the
	 * last run in - the state file the run itself writes is already proof
	 * of when that was, so its mtime is the only marker this needs.
	 */
	private function refresh_rules($config)
	{
		global $app;

		$binary = (string) $config['binary_path'];
		if ($binary === '' || !is_executable($binary)) {
			return;
		}

		$out = rtrim((string) $config['state_dir'], '/') . '/state/rules.json';
		// Once a day, and at once after the scanner was replaced: a new
		// version brings new rules and new explanations, and the pages should
		// not name a rule they cannot explain for up to a day.
		if (is_file($out) && filemtime($out) > time() - 82800 && filemtime($out) >= filemtime($binary)) {
			return;
		}

		// Die mtime oben bremst nur den Erfolgsfall: scheitert der Aufruf,
		// entsteht die Datei gar nicht erst.
		if ($this->retry_blocked($config, 'rules')) {
			return;
		}
		$this->note_attempt($config, 'rules');

		$cmd = escapeshellcmd($binary) . ' rules --json --out=' . escapeshellarg($out) . ' 2>&1';
		$output = array();
		$status = 0;
		exec($cmd, $output, $status);

		if ($status !== 0) {
			$app->log('malwatch: refreshing the rule catalogue failed: ' . implode(' ', $output), LOGLEVEL_WARN);
			return;
		}
		$this->clear_attempt($config, 'rules');

		$doc = json_decode((string) @file_get_contents($out), true);
		$rules = is_array($doc) && isset($doc['rules']) && is_array($doc['rules']) ? $doc['rules'] : array();
		// The sources outside the catalogue (vendor checksums, signature
		// engines) come as extras since 0.39.0; they explain findings too.
		$extras = is_array($doc) && isset($doc['extras']) && is_array($doc['extras']) ? $doc['extras'] : array();
		$now = date('Y-m-d H:i:s');

		foreach (array_merge($rules, $extras) as $rule) {
			$rule_id = isset($rule['id']) ? (string) $rule['id'] : '';
			if ($rule_id === '') {
				continue;
			}
			$app->dbmaster->query(
				'INSERT INTO malwatch_rule (rule_id, title, severity, auto_safe, explanation, advice, last_seen) '
				. 'VALUES (?, ?, ?, ?, ?, ?, ?) '
				. 'ON DUPLICATE KEY UPDATE title = VALUES(title), severity = VALUES(severity), '
				. 'auto_safe = VALUES(auto_safe), explanation = VALUES(explanation), advice = VALUES(advice), '
				. 'last_seen = VALUES(last_seen)',
				$rule_id, substr((string) (isset($rule['title']) ? $rule['title'] : ''), 0, 255),
				substr((string) (isset($rule['severity']) ? $rule['severity'] : ''), 0, 10),
				!empty($rule['auto_safe']) ? 'y' : 'n',
				(string) (isset($rule['explain']) ? $rule['explain'] : ''),
				(string) (isset($rule['advice']) ? $rule['advice'] : ''), $now);
		}

		$app->log('malwatch: rule catalogue refreshed (' . count($rules) . ').', LOGLEVEL_DEBUG);
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

		// last_signature_update wird nur bei Erfolg geschrieben - ohne die
		// zweite Bremse hier lief ein Update ohne Netz, ohne Spiegel oder
		// hinter einem toten Proxy jede Minute erneut.
		if ($this->retry_blocked($config, 'signatures')) {
			return;
		}
		$this->note_attempt($config, 'signatures');

		$cmd = escapeshellcmd($binary) . ' update --sig-dir='
			. escapeshellarg(rtrim((string) $config['state_dir'], '/') . '/signatures') . ' --quiet 2>&1';
		$output = array();
		$status = 0;
		exec($cmd, $output, $status);

		if ($status === 0) {
			$this->clear_attempt($config, 'signatures');
			$app->dbmaster->query('UPDATE malwatch_config SET last_signature_update = NOW() WHERE config_id = 1');
			$app->log('malwatch: signatures updated.', LOGLEVEL_DEBUG);
		} else {
			$app->log('malwatch: the signature update failed: ' . implode(' ', $output), LOGLEVEL_WARN);
		}
	}
}
