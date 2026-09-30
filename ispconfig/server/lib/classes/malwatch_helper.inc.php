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

	/**
	 * The limits of the setting upload_dirs, as malwatch_upload_dirs_limits()
	 * in the panel and MaxUploadDirs and MaxUploadDirLength in the scanner.
	 */
	const UPLOAD_DIRS_MAX = 16;
	const UPLOAD_DIR_LENGTH_MAX = 30;

	/**
	 * The settings of the finding view: column => array(min, max, default,
	 * switch of the scanner). The scanner has the same bounds and defaults
	 * (Limits and Default in internal/fileview/fileview.go), the panel as well
	 * (malwatch_view_settings()).
	 */
	const VIEW_SETTINGS = array(
		'view_lines' => array(0, 2000, 400, '--view-lines'),
		'view_context' => array(0, 50, 5, '--view-context'),
		'view_line_length' => array(60, 2000, 300, '--view-line-length'),
		'view_marks' => array(1, 200, 20, '--view-marks'),
		'view_budget' => array(1, 512, 32, '--view-budget'),
	);

	/** How long a view outlives its last finding, in days: default and bounds. */
	const VIEW_KEEP_DAYS = array(1, 365, 30);

	/**
	 * The numbers of the check against the vendors (0.41.0), with the bounds
	 * and defaults the scanner has (internal/composer):
	 * key => array(min, max, default, switch). The panel has the same
	 * (malwatch_verify_settings()).
	 */
	const VERIFY_SETTINGS = array(
		'verify_max_downloads' => array(1, 1000, 50, '--verify-max-downloads'),
		'verify_max_mb' => array(1, 500, 50, '--verify-max-mb'),
		'verify_timeout' => array(1, 600, 60, '--verify-timeout'),
		'verify_retry_hours' => array(0, 720, 24, '--verify-retry-hours'),
	);

	/** A host name as the lists of hosts take it. */
	const HOST_PATTERN = '/^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/';

	/**
	 * The lists the scanner takes as comma separated switches:
	 * key => array(switch, most items, longest item, pattern of one item,
	 * fewest items). An empty list of hosts is a choice - only the site itself,
	 * or load nothing; the extensions need one. The panel has the same
	 * (malwatch_list_settings()).
	 */
	const LIST_SETTINGS = array(
		'modified_exts' => array('--modified-exts', 40, 12, '/^[a-z0-9]+$/', 1),
		'script_hosts' => array('--script-hosts', 32, 100, self::HOST_PATTERN, 0),
		'verify_hosts' => array('--verify-hosts', 16, 100, self::HOST_PATTERN, 0),
	);

	/**
	 * The hourly part of the cron job: key => array(min, max, default). The
	 * minute of the hour it runs at, how long finished jobs and fixed findings
	 * stay, and how many open findings one run checks for a file that is gone
	 * (0 turns that check off). The panel has the same
	 * (malwatch_housekeeping_settings()).
	 */
	const HOUSEKEEPING_SETTINGS = array(
		'housekeeping_minute' => array(0, 59, 7),
		'keep_job_days' => array(1, 3650, 30),
		'keep_fixed_days' => array(1, 3650, 90),
		'vanished_check_rows' => array(0, 10000, 500),
	);

	/**
	 * The address of the database of known files: https, a host name, a port
	 * and a path if need be, and no login, because the scanner gets it on its
	 * command line. The panel checks with the same (malwatch_hashlookup_url_regex()).
	 */
	const HASHLOOKUP_URL_PATTERN = '#^https://[a-zA-Z0-9.-]{1,120}(?::[0-9]{1,5})?(?:/[a-zA-Z0-9._~%/-]{0,80})?$#';

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
		foreach ($this->config_defaults() as $key => $value) {
			if (!isset($row[$key]) || $row[$key] === '' || $row[$key] === null) {
				$row[$key] = $value;
			}
		}
		$this->config = $row;
		return $row;
	}

	/**
	 * The values the settings fall back to while the row or one of its columns
	 * is missing. The panel has the same (malwatch_config_defaults()).
	 */
	public function config_defaults()
	{
		return array(
			'binary_path' => '/usr/local/bin/malwatch',
			'state_dir' => '/var/lib/malwatch',
			'admin_email' => '',
			'sender_email' => '',
			'default_scan_days' => 7,
			'default_excludes' => '',
			'max_parallel' => 1,
			'job_timeout_hours' => 6,
			'keep_scans' => 30,
			'scan_max_age' => 0,
			'use_clamav' => 'y',
			'auto_update_signatures' => 'y',
			'upload_dirs' => 'uploads,attachments,avatars,thumbs,userfiles,user_uploads,file_uploads',
			'view_lines' => 400,
			'view_context' => 5,
			'view_line_length' => 300,
			'view_marks' => 20,
			'view_budget' => 32,
			'view_keep_days' => 30,
			'panel_url' => '',
			'mail_format' => 'html',
			'mail_from_name' => 'malwatch',
			'mail_smtp_verify' => 'y',
			'modified_exts' => 'php,php3,php4,php5,php7,php8,phtml,phps,phar,inc,module,tpl,twig,js,mjs,cjs,html,htm,svg,htaccess,ini',
			'script_hosts' => 'google-analytics.com,www.google-analytics.com,ssl.google-analytics.com,ajax.googleapis.com,code.jquery.com',
			'verify_composer' => 'y',
			'verify_originals' => 'y',
			'verify_hosts' => 'codeload.github.com,api.github.com,github.com,gitlab.com,bitbucket.org',
			'verify_max_downloads' => 50,
			'verify_max_mb' => 50,
			'verify_timeout' => 60,
			'verify_retry_hours' => 24,
			'hashlookup' => 'n',
			'hashlookup_url' => 'https://hashlookup.circl.lu',
			'housekeeping_minute' => 7,
			'keep_job_days' => 30,
			'keep_fixed_days' => 90,
			'vanished_check_rows' => 500,
		);
	}

	/**
	 * The switches of the check against the vendors (0.41.0). A stored value
	 * the settings page would refuse holds no scan up: it gets the default,
	 * because the scanner refuses a value out of its bounds and the whole scan
	 * with it.
	 */
	public function verify_arguments($config)
	{
		$defaults = $this->config_defaults();
		$args = array();
		foreach (self::LIST_SETTINGS as $key => $setting) {
			list($switch, $max_items, $max_length, $pattern, $min_items) = $setting;
			$items = $this->list_items(isset($config[$key]) ? $config[$key] : $defaults[$key], $max_items, $max_length, $pattern);
			if ($items === null || count($items) < $min_items) {
				$items = $this->list_items($defaults[$key], $max_items, $max_length, $pattern);
			}
			$args[] = $switch . '=' . implode(',', $items);
		}
		foreach (self::VERIFY_SETTINGS as $key => $setting) {
			list($min, $max, $default, $switch) = $setting;
			$value = isset($config[$key]) && is_numeric($config[$key]) ? (int) $config[$key] : $default;
			if ($value < $min || $value > $max) {
				$value = $default;
			}
			$args[] = $switch . '=' . $value;
		}
		if (isset($config['verify_composer']) && $config['verify_composer'] === 'n') {
			$args[] = '--no-verify-composer';
		}
		if (isset($config['verify_originals']) && $config['verify_originals'] === 'n') {
			$args[] = '--no-verify-originals';
		}
		$url = isset($config['hashlookup_url']) ? trim((string) $config['hashlookup_url']) : '';
		if (isset($config['hashlookup']) && $config['hashlookup'] === 'y' && preg_match(self::HASHLOOKUP_URL_PATTERN, $url)) {
			$args[] = '--hashlookup-url=' . $url;
		}
		return $args;
	}

	/**
	 * The items of a stored list, lower case, without spaces and empty ones;
	 * null when one of them breaks the pattern or the list is too long.
	 */
	private function list_items($value, $max_items, $max_length, $pattern)
	{
		$items = array();
		foreach (explode(',', strtolower((string) $value)) as $item) {
			$item = ltrim(trim($item), '.');
			if ($item === '') {
				continue;
			}
			if (strlen($item) > $max_length || !preg_match($pattern, $item)) {
				return null;
			}
			$items[] = $item;
		}
		return count($items) > $max_items ? null : $items;
	}

	/**
	 * A setting of the hourly part (HOUSEKEEPING_SETTINGS) as a whole number
	 * within its bounds. A stored value the settings page would refuse gets the
	 * default.
	 */
	public function housekeeping_value($config, $key)
	{
		list($min, $max, $default) = self::HOUSEKEEPING_SETTINGS[$key];
		$value = isset($config[$key]) && is_numeric($config[$key]) && (string) (int) $config[$key] === trim((string) $config[$key])
			? (int) $config[$key] : $default;
		return ($value < $min || $value > $max) ? $default : $value;
	}

	/**
	 * The ids of the open findings in $rows (finding_id, file_path,
	 * document_root) whose file is gone, for the cron job to close.
	 *
	 * A scan closes the findings of its website that it no longer sees. A
	 * website nobody scans any more - switched off in ISPConfig, or with
	 * scan_days 0 - keeps its findings open, even after its files were
	 * deleted, and they stand in every list and count. This closes those.
	 * Something still at the path - a file, a directory, a link that points
	 * nowhere - keeps its finding. So does a website whose web root is missing
	 * while ISPConfig still has it: an unmounted disk or a move in progress.
	 * A website ISPConfig no longer has (document_root null) went with its
	 * files.
	 */
	public function vanished_ids(array $rows)
	{
		$ids = array();
		foreach ($rows as $row) {
			$path = isset($row['file_path']) ? (string) $row['file_path'] : '';
			if ($path === '' || $path[0] !== '/') {
				continue;
			}
			if (file_exists($path) || is_link($path)) {
				continue;
			}
			$root = isset($row['document_root']) ? (string) $row['document_root'] : '';
			if ($root !== '' && !is_dir($root)) {
				continue;
			}
			$ids[] = (int) $row['finding_id'];
		}
		return $ids;
	}

	/**
	 * The names of the setting upload_dirs as the scanner takes them
	 * (--upload-dirs). A stored value the settings page would refuse, edited in
	 * the database, say, must not stop every scan: its usable names count, at
	 * most UPLOAD_DIRS_MAX of them, and the default when none is left.
	 */
	public function upload_dirs($value)
	{
		$names = array();
		foreach (explode(',', (string) $value) as $name) {
			$name = trim($name);
			if (count($names) < self::UPLOAD_DIRS_MAX && strlen($name) <= self::UPLOAD_DIR_LENGTH_MAX
				&& preg_match('/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/', $name)) {
				$names[] = $name;
			}
		}
		if (count($names) === 0) {
			$defaults = $this->config_defaults();
			return explode(',', $defaults['upload_dirs']);
		}
		return $names;
	}

	/**
	 * The switches that hand the view settings to the scanner. A stored value
	 * the settings page would refuse holds no scan up: it gets the default,
	 * because the scanner refuses a value out of its bounds and the whole
	 * scan with it.
	 */
	public function view_arguments($config)
	{
		$args = array();
		foreach (self::VIEW_SETTINGS as $key => $setting) {
			list($min, $max, $default, $switch) = $setting;
			$value = isset($config[$key]) && is_numeric($config[$key]) ? (int) $config[$key] : $default;
			if ($value < $min || $value > $max) {
				$value = $default;
			}
			$args[] = $switch . '=' . $value;
		}
		return $args;
	}

	/** Days a view outlives its last finding, within VIEW_KEEP_DAYS. */
	public function view_keep_days($config)
	{
		list($min, $max, $default) = self::VIEW_KEEP_DAYS;
		$days = isset($config['view_keep_days']) && is_numeric($config['view_keep_days']) ? (int) $config['view_keep_days'] : $default;
		return ($days < $min || $days > $max) ? $default : $days;
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

		// WAF jobs take no slot at all: the cron works on them itself.
		$kind_sql = $kind === 'vulncheck' ? "job_kind = 'vulncheck'" : "job_kind NOT IN ('vulncheck','waf')";
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

	/**
	 * When a website scanned every $days days is due next, counted from $from
	 * (default now), as a Unix time; null for 0 days.
	 *
	 * Store it with FROM_UNIXTIME(?): the scheduler compares next_run with
	 * NOW(), and ISPConfig may run PHP in another zone than MySQL (web.herkules:
	 * PHP in Etc/UTC, MySQL in Europe/Berlin). A text from date() made every
	 * scan due two hours early there.
	 */
	public function next_run($days, $from = null)
	{
		$days = (int) $days;
		if ($days < 1) {
			return null;
		}
		if ($from === null) {
			$from = time();
		}
		return (int) $from + $days * 86400;
	}

	/**
	 * The first scan of a website that gets its settings row now: a random
	 * moment within its interval, so websites that arrive together spread over
	 * it. A Unix time like next_run(), null for 0 days.
	 */
	public function first_run($days, $now = null)
	{
		$days = (int) $days;
		if ($days < 1) {
			return null;
		}
		if ($now === null) {
			$now = time();
		}
		return (int) $now + mt_rand(0, $days * 86400 - 1);
	}

	/**
	 * Gives a website without a settings row one, with the interval for new
	 * websites (default_scan_days) and its first scan from first_run(). A row
	 * that exists stays as it is. $web is the web_domain row.
	 */
	public function ensure_site_row($web)
	{
		global $app;

		$config = $this->get_config();
		$days = max(0, (int) $config['default_scan_days']);
		$app->dbmaster->query(
			'INSERT IGNORE INTO malwatch_site (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. "server_id, parent_domain_id, domain, scan_days, next_run) VALUES (1, ?, 'riud', 'riud', '', ?, ?, ?, ?, FROM_UNIXTIME(?))",
			(int) $web['sys_groupid'], (int) $web['server_id'], (int) $web['domain_id'], (string) $web['domain'],
			$days, $this->first_run($days));
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
	 * The target versions a report lists for one element, as JSON for
	 * malwatch_software.versions: plain release numbers of at most 32
	 * characters, at most 500 of them. '' when there are none.
	 */
	public static function release_list($versions)
	{
		if (!is_array($versions)) {
			return '';
		}
		$kept = array();
		foreach ($versions as $version) {
			if (is_string($version) && strlen($version) <= 32 && preg_match('/^[0-9]+(\.[0-9]+)*$/', $version)) {
				$kept[] = $version;
				if (count($kept) === 500) {
					break;
				}
			}
		}
		return count($kept) > 0 ? json_encode($kept) : '';
	}

	/**
	 * How long an upgrade waits after an exchange before it checks the site.
	 *
	 * PHP keeps running the compiled old files until OPcache looks at them
	 * again, revalidate_freq seconds after it last did; a check before that
	 * moment judges the old release. The value comes from the PHP-FPM
	 * configuration of the website: php.ini, conf.d and the pool file, which
	 * may override both. array('seconds' => n) or array('error' => reason).
	 */
	public function fpm_settle($web)
	{
		global $app, $conf;

		if (!is_array($web) || (string) $web['php'] !== 'php-fpm') {
			return array('seconds' => 3);
		}
		$id = intval(isset($web['server_php_id']) ? $web['server_php_id'] : 0);
		$ini_file = '';
		$pool_dir = '';
		if ($id > 0) {
			$row = $app->dbmaster->queryOneRecord(
				'SELECT php_fpm_ini_dir, php_fpm_pool_dir FROM server_php WHERE server_php_id = ?', $id);
			if (is_array($row)) {
				$ini_file = rtrim((string) $row['php_fpm_ini_dir'], '/') . '/php.ini';
				$pool_dir = rtrim((string) $row['php_fpm_pool_dir'], '/');
			}
		} else {
			$app->uses('getconf');
			$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');
			$ini_file = isset($web_config['php_fpm_ini_path']) ? (string) $web_config['php_fpm_ini_path'] : '';
			$pool_dir = isset($web_config['php_fpm_pool_dir']) ? rtrim((string) $web_config['php_fpm_pool_dir'], '/') : '';
		}

		$texts = array();
		if ($ini_file !== '' && is_file($ini_file)) {
			$texts[] = (string) file_get_contents($ini_file);
			$extra = glob(dirname($ini_file) . '/conf.d/*.ini');
			if (is_array($extra)) {
				sort($extra);
				foreach ($extra as $file) {
					$texts[] = (string) file_get_contents($file);
				}
			}
		}
		$pool = $pool_dir !== '' ? $pool_dir . '/web' . intval($web['domain_id']) . '.conf' : '';
		$pool_text = ($pool !== '' && is_file($pool)) ? (string) file_get_contents($pool) : '';
		return self::opcache_settle($texts, $pool_text);
	}

	/**
	 * The wait for php.ini texts in load order and a pool configuration. A
	 * later text wins over an earlier one and the pool over all of them, the
	 * order PHP-FPM applies them in.
	 */
	public static function opcache_settle($ini_texts, $pool_text)
	{
		$values = array('opcache.enable' => '1', 'opcache.validate_timestamps' => '1', 'opcache.revalidate_freq' => '2');
		$keys = 'opcache\.(?:enable|validate_timestamps|revalidate_freq)';
		foreach ((array) $ini_texts as $text) {
			if (preg_match_all('/^[ \t]*(' . $keys . ')[ \t]*=[ \t]*"?([^";\r\n]*?)"?[ \t]*(?:;.*)?$/m', (string) $text, $hits, PREG_SET_ORDER)) {
				foreach ($hits as $hit) {
					$values[$hit[1]] = trim($hit[2]);
				}
			}
		}
		if (preg_match_all('/^[ \t]*php_(?:admin_)?(?:value|flag)\[(' . $keys . ')\][ \t]*=[ \t]*"?([^";\r\n]*?)"?[ \t]*(?:;.*)?$/m', (string) $pool_text, $hits, PREG_SET_ORDER)) {
			foreach ($hits as $hit) {
				$values[$hit[1]] = trim($hit[2]);
			}
		}

		$on = array('1', 'on', 'yes', 'true');
		if (!in_array(strtolower($values['opcache.enable']), $on, true)) {
			return array('seconds' => 0);
		}
		if (!in_array(strtolower($values['opcache.validate_timestamps']), $on, true)) {
			return array('error' => 'In diesem PHP-Pool prüft OPcache keine Zeitstempel (opcache.validate_timestamps). '
				. 'malwatch kann dort nicht erkennen, wann PHP die neuen Dateien liest, und aktualisiert die Website deshalb nicht.');
		}
		return array('seconds' => max(0, intval($values['opcache.revalidate_freq'])) + 1);
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
