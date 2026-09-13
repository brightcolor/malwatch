<?php

/**
 * Shared helpers for the malwatch extension on the server side: settings,
 * job bookkeeping and the small conversions the other classes need.
 */
class malwatch_helper
{
	/** Severity names in order, weakest first. */
	public static $severities = array('low', 'medium', 'high', 'critical');

	/**
	 * How many vulnerability checks may run at once, beside the scans. A check
	 * reads no file for malware; three at a time keep the requests to the
	 * vulnerability databases at a pace their operators ask for.
	 */
	const VULNCHECK_PARALLEL = 3;

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

	/**
	 * Counts jobs currently running on this server, excluding one id.
	 *
	 * Vulnerability checks are counted apart from everything else: they have
	 * their own limit (VULNCHECK_PARALLEL) and take no slot of max_parallel.
	 * Pass 'vulncheck' as $kind to count them, anything else for the rest.
	 */
	public function count_running_jobs($except_job_id = 0, $kind = '')
	{
		global $app, $conf;

		$kind_sql = $kind === 'vulncheck' ? "job_kind = 'vulncheck'" : "job_kind != 'vulncheck'";
		$row = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_status = 'running' AND job_id != ? AND "
			. $kind_sql,
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

	/**
	 * The PHP command line binary for the PHP version a website runs.
	 *
	 * ISPConfig records the CGI binary of an additional PHP version
	 * (/usr/bin/php-cgi8.2); its command line twin sits next to it
	 * (/usr/bin/php8.2). A website on the default PHP uses /usr/bin/php.
	 * Returns '' when that file is missing.
	 */
	public function php_cli_binary($web)
	{
		global $app;

		$id = intval(isset($web['server_php_id']) ? $web['server_php_id'] : 0);
		$candidate = '/usr/bin/php';
		if ($id > 0) {
			$row = $app->dbmaster->queryOneRecord(
				'SELECT php_fastcgi_binary FROM server_php WHERE server_php_id = ?', $id);
			$candidate = is_array($row) ? self::cli_php_path((string) $row['php_fastcgi_binary']) : '';
		}
		return ($candidate !== '' && is_file($candidate) && is_executable($candidate)) ? $candidate : '';
	}

	/** /usr/bin/php-cgi8.2 becomes /usr/bin/php8.2; anything that is no CGI binary ''. */
	public static function cli_php_path($cgi_binary)
	{
		if (!preg_match('#^(/[A-Za-z0-9._/-]*/)php-cgi([0-9][0-9.]*)?$#', trim((string) $cgi_binary), $m)) {
			return '';
		}
		return $m[1] . 'php' . (isset($m[2]) ? $m[2] : '');
	}

	/** Where the check after an upgrade connects: the IP of the vhost, 127.0.0.1 for '*'. */
	public static function connect_address($web)
	{
		$ip = trim((string) (isset($web['ip_address']) ? $web['ip_address'] : ''));
		if ($ip === '' || $ip === '*' || !filter_var($ip, FILTER_VALIDATE_IP)) {
			return '127.0.0.1';
		}
		return $ip;
	}

	/**
	 * The address of a WordPress installation: the domain of the website and
	 * the path of the installation below its web root, with a closing slash.
	 */
	public static function install_url($domain, $https, $scan_path, $install_path)
	{
		$base = rtrim((string) $scan_path, '/');
		$rel = trim((string) substr(rtrim((string) $install_path, '/'), strlen($base)), '/');
		$path = '/';
		if ($rel !== '') {
			$path .= implode('/', array_map('rawurlencode', explode('/', $rel))) . '/';
		}
		return ($https ? 'https://' : 'http://') . $domain . $path;
	}

	/**
	 * The WordPress installation a plugin or theme directory belongs to:
	 * <installation>/<content directory>/plugins/<slug>. '' for anything else.
	 */
	public static function install_of($element_path, $kind)
	{
		$path = rtrim((string) $element_path, '/');
		$parent = $kind === 'plugin' ? 'plugins' : ($kind === 'theme' ? 'themes' : '');
		if ($parent === '' || basename(dirname($path)) !== $parent) {
			return '';
		}
		return dirname(dirname(dirname($path)));
	}

	/**
	 * Turns the elements of an upgrade job into the installations of its plan
	 * file. Every element names a software row of this website; kind, slug and
	 * path come from that row, the job carries nothing but its id and the
	 * target version.
	 */
	public function upgrade_installs($job, $web, $scan_path, $options)
	{
		global $app;

		$by_install = array();
		$elements = isset($options['elements']) && is_array($options['elements']) ? $options['elements'] : array();
		foreach ($elements as $choice) {
			$software_id = isset($choice['software_id']) ? intval($choice['software_id']) : 0;
			$version = isset($choice['version']) ? (string) $choice['version'] : '';
			if ($software_id < 1 || !preg_match('/^[0-9A-Za-z._-]{1,40}$/', $version)) {
				continue;
			}
			$row = $app->dbmaster->queryOneRecord(
				"SELECT software_kind, slug, install_path FROM malwatch_software "
				. "WHERE software_id = ? AND parent_domain_id = ? AND product = 'wordpress'",
				$software_id, intval($job['parent_domain_id']));
			if (!is_array($row)) {
				continue;
			}
			$kind = (string) $row['software_kind'];
			$install = $kind === 'core' ? rtrim((string) $row['install_path'], '/')
				: self::install_of((string) $row['install_path'], $kind);
			if ($install === '' || strpos($install . '/', rtrim($scan_path, '/') . '/') !== 0) {
				continue;
			}
			if (!isset($by_install[$install])) {
				$by_install[$install] = array(
					'path' => $install,
					'url' => self::install_url((string) $web['domain'], (string) $web['ssl'] === 'y', $scan_path, $install),
					'elements' => array(),
				);
			}
			$element = array('kind' => $kind, 'version' => $version);
			if ($kind !== 'core') {
				$element['slug'] = (string) $row['slug'];
			}
			$by_install[$install]['elements'][] = $element;
		}
		return array_values($by_install);
	}

	/** Writes a line into the ISPConfig log with a common prefix. */
	public function log($message, $level = LOGLEVEL_DEBUG)
	{
		global $app;
		$app->log('malwatch: ' . $message, $level);
	}
}
