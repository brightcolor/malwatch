<?php

/**
 * Starts the scanner for one job, detached from the ISPConfig process.
 */
class malwatch_runner
{
	/**
	 * Launches the scan. Returns true when the process was started.
	 *
	 * The command is built as a list of separately escaped arguments and run
	 * through setsid, so the scanner survives the end of the datalog pass, and
	 * through nice and ionice, so a scan cannot starve the web server it runs
	 * next to.
	 */
	public function start($job, $config)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$binary = (string) $config['binary_path'];
		if ($binary === '' || !is_file($binary) || !is_executable($binary)) {
			$helper->fail_job($job['job_id'], 'Der Scanner wurde unter ' . $binary . ' nicht gefunden.');
			$helper->log('binary not found at ' . $binary, LOGLEVEL_WARN);
			return false;
		}

		$path = (string) $job['scan_path'];
		if ($path === '' || !is_dir($path)) {
			$helper->fail_job($job['job_id'], 'Der zu prüfende Pfad ' . $path . ' existiert nicht.');
			return false;
		}

		$state_dir = rtrim((string) $config['state_dir'], '/');
		$runs_dir = $state_dir . '/runs';
		$this->ensure_shared_dir($runs_dir);
		$this->ensure_shared_dir($state_dir . '/spool');
		$result_file = $runs_dir . '/job-' . intval($job['job_id']) . '.json';
		$log_file = $runs_dir . '/job-' . intval($job['job_id']) . '.log';
		$done_file = $this->done_file($result_file);
		@unlink($result_file);
		@unlink($done_file);

		$args = $this->build_arguments($job, $config, $path, $result_file);
		$command = escapeshellarg($binary);
		foreach ($args as $arg) {
			$command .= ' ' . escapeshellarg($arg);
		}

		// setsid detaches the scanner from this process group, so it keeps
		// running after server.php exits. Without it the scan would be killed
		// halfway through and the job would hang in "running" until the
		// timeout sweep.
		//
		// The inner shell writes the exit code to a marker file when the
		// scanner is done. The job is finished when that file appears, not
		// when the recorded pid disappears: setsid only forks when it is not
		// already a process group leader, so the pid may belong to a process
		// that exits immediately, and the collector would then read a report
		// that has not been written yet.
		$inner = 'nice -n 15 ionice -c 3 ' . $command
			. ' > ' . escapeshellarg($log_file) . ' 2>&1; '
			. 'echo $? > ' . escapeshellarg($done_file);

		$wrapper = 'setsid sh -c ' . escapeshellarg($inner) . ' > /dev/null 2>&1 & echo $!';

		$output = array();
		$status = 0;
		exec($wrapper, $output, $status);

		$pid = 0;
		if (!empty($output)) {
			$pid = intval(trim((string) $output[count($output) - 1]));
		}

		$app->dbmaster->query(
			'UPDATE malwatch_job SET result_file = ?, pid = ? WHERE job_id = ?',
			$result_file, $pid, $job['job_id']);

		$helper->log('scan started for ' . $job['domain'] . ' (job ' . $job['job_id'] . ', pid ' . $pid . ')', LOGLEVEL_DEBUG);
		return true;
	}

	/**
	 * Creates a directory the interface has to be able to read.
	 *
	 * The installer sets these up, but a job may arrive before an upgrade has
	 * run, and a directory created here with the plain 0750 the old code used
	 * would be root-only - which is exactly how the progress counter came to
	 * show zero files on a live install for a whole release. Setgid so new
	 * files inherit the group instead of being root:root one by one.
	 */
	private function ensure_shared_dir($dir)
	{
		if (is_dir($dir)) {
			return;
		}
		if (!@mkdir($dir, 02750, true)) {
			return;
		}
		@chmod($dir, 02750);
		foreach (array('ispconfig', 'ispapps', 'www-data') as $group) {
			if (@chgrp($dir, $group)) {
				break;
			}
		}
	}

	/** Assembles the scanner arguments for one job. */
	private function build_arguments($job, $config, $path, $result_file)
	{
		global $app;

		$app->uses('malwatch_helper');
		$state_dir = rtrim((string) $config['state_dir'], '/');

		$progress = $state_dir . '/runs/job-' . intval($job['job_id']) . '.progress';
		$kind = isset($job['job_kind']) ? (string) $job['job_kind'] : 'scan';
		$options = json_decode((string) $job['options'], true);
		if (!is_array($options)) {
			$options = array();
		}

		if ($kind === 'repair') {
			// Both switches take the same "unset or empty means the default"
			// rule the CLI itself uses, so a job queued before an option
			// existed still resolves to the old behaviour.
			$mode = isset($options['mode']) && $options['mode'] !== '' ? (string) $options['mode'] : 'replace';
			$no_original = isset($options['no_original']) && $options['no_original'] !== ''
				? (string) $options['no_original'] : 'keep';

			$repair = array(
				'repair',
				'--path=' . $path,
				'--quarantine-dir=' . $state_dir . '/quarantine',
				'--domain=' . $job['domain'],
				'--mode=' . $mode,
				'--no-original=' . $no_original,
			);
			foreach ((array) (isset($options['only']) ? $options['only'] : array()) as $only) {
				$repair[] = '--only=' . $only;
			}
			$repair[] = '--progress=' . $progress;
			$repair[] = '--json';
			$repair[] = '--out=' . $result_file;
			if (!empty($options['dry_run'])) {
				$repair[] = '--dry-run';
			}
			return $repair;
		}

		if ($kind === 'quarantine') {
			// The action is the first, positional argument; add/restore/
			// delete/export all still get --quarantine-dir, --json and
			// --out, since every one of them ends by reporting the store's
			// full list (see malwatch_ingest::sync_quarantine).
			$action = isset($options['action']) && $options['action'] !== '' ? (string) $options['action'] : 'add';
			$quarantine = array(
				// Der Befehl selbst zuerst, dann die Aktion. Ohne ihn rief der
				// Auftrag "malwatch add …" auf, und der Scanner antwortete mit
				// seiner Hilfe und Rückgabecode 3 - im Panel als "Die
				// Quarantäne hat keinen Bericht hinterlassen" zu sehen.
				'quarantine',
				$action,
				'--quarantine-dir=' . $state_dir . '/quarantine',
				'--json',
				'--out=' . $result_file,
			);

			if ($action === 'add') {
				$quarantine[] = '--path=' . $path;
				$quarantine[] = '--domain=' . $job['domain'];
				$quarantine[] = '--origin=' . (isset($options['origin']) ? (string) $options['origin'] : 'manual');
				$quarantine[] = '--reason=' . (isset($options['reason']) ? (string) $options['reason'] : '');
				// The paths were checked against malwatch_finding before the job
				// was queued; the binary checks the boundary a second time.
				foreach ((array) (isset($options['files']) ? $options['files'] : array()) as $rel) {
					$quarantine[] = '--file=' . $rel;
				}
				return $quarantine;
			}

			// restore, delete and export all act on entries the store
			// already holds, named by the id it gave them - never by path.
			foreach ((array) (isset($options['ids']) ? $options['ids'] : array()) as $id) {
				$quarantine[] = '--id=' . $id;
			}

			if ($action === 'export') {
				// The zip switch is deliberately not --out: --out is the JSON
				// report on every action including this one, and reusing it
				// for the archive would make the two overwrite each other.
				$token = isset($options['token']) ? (string) $options['token'] : '';
				$quarantine[] = '--zip=' . $state_dir . '/spool/' . $token . '.zip';
			}

			return $quarantine;
		}

		$args = array(
			'scan',
			'--path=' . $path,
			'--progress=' . $progress,
			'--json',
			'--out=' . $result_file,
			'--quiet',
			'--sig-dir=' . $state_dir . '/signatures',
			'--state-dir=' . $state_dir . '/state',
			'--cache=' . $state_dir . '/state/clean-' . intval($job['parent_domain_id']) . '.json',
			'--whitelist-path=' . $state_dir . '/whitelist',
		);

		// Der Nenner ist die Zahl der Dateien, die der juengste abgeschlossene
		// Lauf derselben Website ANGESEHEN hat: files_scanned + files_skipped.
		// Nicht files_scanned allein - der Scanner erhoeht diesen Zaehler nur
		// fuer Dateien, die den Cache verfehlen; ein Cache-Treffer geht auf
		// files_skipped (internal/scanner/scanner.go, festgehalten in
		// scanner_test.go: zweiter Lauf -> FilesScanned == 0). Nach einem
		// kalten Lauf ueber 193.888 Dateien bekam der naechste, warme Lauf
		// --expect=193888 und stand bei 0 Prozent, bis er auf 100 sprang.
		//
		// Zaehler und Nenner zaehlen jetzt dasselbe: der Scanner meldet ueber
		// --progress ebenfalls geprueft + uebersprungen. Der Weg ueber die
		// betrachteten Dateien und nicht ueber die geprueften ist der einzig
		// moegliche - wie viele Dateien ein Lauf tatsaechlich pruefen wird,
		// haengt am Cache und weiss vorher niemand, waehrend die Zahl der
		// betrachteten Dateien von Lauf zu Lauf nahezu gleich bleibt. Genau
		// das macht sie zu einem brauchbaren Nenner.
		//
		// Beim ersten Lauf einer Website gibt es keinen Vorlauf, dann entfaellt
		// der Schalter und die Anzeige zaehlt ohne Prozentangabe.
		$last = $app->db->queryOneRecord(
			'SELECT files_scanned, files_skipped FROM malwatch_scan WHERE parent_domain_id = ? '
			. "AND scan_state IN ('clean','findings','outdated') "
			. 'AND (files_scanned + files_skipped) > 0 '
			. 'ORDER BY scan_id DESC LIMIT 1',
			intval($job['parent_domain_id'])
		);
		if (is_array($last)) {
			$expect = intval($last['files_scanned']) + intval($last['files_skipped']);
			if ($expect > 0) {
				$args[] = '--expect=' . $expect;
			}
		}

		foreach ($this->exclude_patterns($options, $config) as $pattern) {
			$args[] = '--exclude=' . $pattern;
		}

		$max_age = isset($options['max_age']) ? intval($options['max_age']) : intval($config['scan_max_age']);
		if ($max_age > 0) {
			$args[] = '--max-age=' . $max_age;
		}

		if (isset($options['version_scan']) && $options['version_scan'] === 'n') {
			$args[] = '--no-version-scan';
		}
		if ($config['use_clamav'] !== 'y') {
			$args[] = '--no-clamav';
		}

		// The exit code must not depend on the operator's notification
		// thresholds: the addon decides what to act on from the findings
		// themselves. Reporting every finding keeps the two apart.
		$args[] = '--min-severity=low';

		return $args;
	}

	/** Merges the global and per site exclude patterns. */
	private function exclude_patterns($options, $config)
	{
		$patterns = array();
		foreach (array((string) $config['default_excludes'], isset($options['excludes']) ? (string) $options['excludes'] : '') as $block) {
			foreach (preg_split('/[\r\n]+/', $block) as $line) {
				$line = trim($line);
				if ($line === '' || substr($line, 0, 1) === '#') {
					continue;
				}
				$patterns[$line] = true;
			}
		}
		return array_keys($patterns);
	}

	/** Path of the marker the wrapper writes when the scanner has finished. */
	public function done_file($result_file)
	{
		return preg_replace('/\.json$/', '.done', (string) $result_file);
	}

	/**
	 * Returns the exit code of a finished scan, or null while it still runs.
	 */
	public function finished_code($job)
	{
		$done = $this->done_file((string) $job['result_file']);
		if ($done === '' || !is_file($done)) {
			return null;
		}
		$raw = trim((string) @file_get_contents($done));
		if ($raw === '' || !preg_match('/^\d{1,3}$/', $raw)) {
			// The marker exists but holds nothing usable. The scan is over
			// either way; ingest() decides what to make of the report.
			return -1;
		}
		return intval($raw);
	}

	/** Removes the marker once a job has been collected. */
	public function clear_marker($job)
	{
		$done = $this->done_file((string) $job['result_file']);
		if ($done !== '' && is_file($done)) {
			@unlink($done);
		}
	}

	/** True when a process with this id is still alive. */
	public function is_running($pid)
	{
		$pid = intval($pid);
		if ($pid <= 0) {
			return false;
		}
		return is_dir('/proc/' . $pid);
	}
}
