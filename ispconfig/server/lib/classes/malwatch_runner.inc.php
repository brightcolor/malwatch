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
		if (!is_dir($runs_dir)) {
			@mkdir($runs_dir, 0750, true);
		}
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

	/** Assembles the scanner arguments for one job. */
	private function build_arguments($job, $config, $path, $result_file)
	{
		global $app;

		$app->uses('malwatch_helper');
		$state_dir = rtrim((string) $config['state_dir'], '/');

		$args = array(
			'scan',
			'--path=' . $path,
			'--json',
			'--out=' . $result_file,
			'--quiet',
			'--sig-dir=' . $state_dir . '/signatures',
			'--state-dir=' . $state_dir . '/state',
			'--cache=' . $state_dir . '/state/clean-' . intval($job['parent_domain_id']) . '.json',
			'--whitelist-path=' . $state_dir . '/whitelist',
		);

		$options = json_decode((string) $job['options'], true);
		if (!is_array($options)) {
			$options = array();
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
