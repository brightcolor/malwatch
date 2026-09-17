<?php

/**
 * The WAF part of malwatch on the server ("Abwehr" in the panel).
 *
 * Reads the ModSecurity audit log into the database, clears out what is past
 * its time and carries out the jobs the panel and waf-switch queue. Runs as
 * root: every minute from the malwatch cron (cleanup once an hour), and from
 * waf-switch and waf-guard.
 *
 * Every change to nginx goes through waf_apply_files() or through
 * ISPConfig's own vhost writer, so the running web server only ever reloads a
 * configuration that passed nginx -t. The decisions live in
 * interface/lib/malwatch_waf_lib.inc.php and are tested there; this class
 * carries the database, the files and the commands.
 *
 * Time arithmetic stays in SQL: ISPConfig runs its server scripts in UTC,
 * the database in the server's local time.
 */
class malwatch_waf
{
	/** Where install/file.list puts the shared functions. */
	const LIB = '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php';
	/** The functions of the origin sources, installed next to the shared ones. */
	const LIB_ORIGIN = '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_origin.inc.php';

	/**
	 * Paths outside the WAF directory. Public so tests/waf_class_probe.php can
	 * point them at a scratch directory. vhost_dir comes from the ISPConfig
	 * server settings and state_dir from malwatch_config while they are null.
	 */
	public $paths = array(
		'vhost_dir' => null,
		'state_dir' => null,
		'backup_dir' => '/var/backups/waf-switch',
		'guard_log' => '/var/log/waf/guard.log',
		'conf_include' => '/etc/nginx/conf.d/waf.conf',
		'logrotate' => '/etc/logrotate.d/waf',
	);

	/** Takes the place of the real commands when set: function ($name, $argument) returning array(code, output). */

	/**
	 * Takes the place of the download when set: function ($url, $target,
	 * $limit, $auth) returning array(ok, error). $auth is 'account:key' for
	 * MaxMind and '' for every other source.
	 */
	public $fetcher = null;
	public $runner = null;

	/** The handle of the lock file while this process holds it. */
	private $lock = null;

	/** Loads the shared functions; false when malwatch is not installed completely. */
	public function ready()
	{
		if (!function_exists('waf_states') && is_file(self::LIB)) {
			require_once self::LIB;
		}
		if (!function_exists('waf_origin_sources') && is_file(self::LIB_ORIGIN)) {
			require_once self::LIB_ORIGIN;
		}
		return function_exists('waf_states');
	}

	/** The WAF settings, with defaults for columns an older schema lacks. */
	public function settings()
	{
		global $app;
		return waf_settings($app->dbmaster->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
	}

	/** One job row, or null. */
	public function job($job_id)
	{
		global $app;
		return $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_job WHERE job_id = ?', (int) $job_id);
	}

	/**
	 * Reads new lines of the audit log into malwatch_waf_hit and the day
	 * tables. With 'dry_run' it only counts: it writes nothing and reads
	 * 'file' (or the configured log) from the start. Returns the counts.
	 * Lines of hosts without a website are counted and left out.
	 */
	public function ingest($opts)
	{
		global $app;

		$settings = $this->settings();
		$dry = !empty($opts['dry_run']);
		$file = ($dry && !empty($opts['file'])) ? (string) $opts['file'] : $settings['waf_audit_log'];
		$stats = array('lines' => 0, 'hits' => 0, 'new' => 0, 'broken' => 0, 'unknown' => 0,
			'unknown_hosts' => array(), 'sites' => array(), 'more' => false);
		clearstatcache();
		$stat = @stat($file);
		if ($stat === false) {
			return $stats;
		}
		if ($dry) {
			$offset = 0;
			$max = 100000;
		} else {
			$reader = $this->reader_state();
			$offset = waf_reader_start($reader['inode'], $reader['offset'], $stat['ino'], $stat['size']);
			$max = $settings['waf_ingest_max_lines'];
		}
		$read = waf_read_lines($file, $offset, $max);
		if ($read === null) {
			return $stats;
		}

		$rows = $this->web_rows();
		$map = waf_host_map($rows);
		$names = array();
		foreach ($rows as $row) {
			if ((string) $row['type'] === 'vhost') {
				$names[(int) $row['domain_id']] = (string) $row['domain'];
			}
		}
		foreach ($read['lines'] as $line) {
			$stats['lines']++;
			$hit = waf_audit_parse_line($line);
			if ($hit === null) {
				$stats['broken']++;
				continue;
			}
			$site = waf_host_lookup($map, $hit['host']);
			if ($site < 1) {
				$host = $hit['host'] === '' ? '?' : $hit['host'];
				$stats['unknown']++;
				$stats['unknown_hosts'][$host] = isset($stats['unknown_hosts'][$host]) ? $stats['unknown_hosts'][$host] + 1 : 1;
				continue;
			}
			$stats['hits']++;
			$stats['sites'][$site] = isset($stats['sites'][$site]) ? $stats['sites'][$site] + 1 : 1;
			if (!$dry && $this->store_hit($site, isset($names[$site]) ? $names[$site] : '', $hit)) {
				$stats['new']++;
			}
		}
		$stats['more'] = $read['more'];

		if (!$dry) {
			$this->save_reader_state($stat['ino'], $read['offset']);
			if ($stats['broken'] > 0 || $stats['unknown'] > 0) {
				$app->log('malwatch: WAF log read, ' . $stats['new'] . ' new hits, ' . $stats['broken']
					. ' unreadable lines, ' . $stats['unknown'] . ' hits for unknown hosts ('
					. implode(', ', array_slice(array_keys($stats['unknown_hosts']), 0, 10)) . ').', LOGLEVEL_DEBUG);
			}
		}
		return $stats;
	}

	/** ingest() under the lock, for waf-switch ingest. Null when the lock or the functions are missing. */
	public function ingest_locked()
	{
		if (!$this->ready() || !$this->lock(true)) {
			return null;
		}
		try {
			return $this->ingest(array());
		} finally {
			$this->unlock();
		}
	}

	/**
	 * The hourly cleanup: hits past waf_detail_days with their response files,
	 * day figures past waf_stats_days, response files without a hit, and the
	 * working directories of jobs that no longer run.
	 */
	public function cleanup()
	{
		global $app, $conf;

		$settings = $this->settings();
		$dir = $this->ensure_dirs();
		$counts = array('hits' => 0, 'days' => 0, 'files' => 0, 'staging' => 0, 'addresses' => 0);

		for ($round = 0; $round < 50; $round++) {
			$old = $this->rows($app->dbmaster->queryAllRecords(
				'SELECT hit_id, response_file FROM malwatch_waf_hit WHERE server_id = ? '
				. 'AND seen_at < DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY hit_id LIMIT 1000',
				$conf['server_id'], $settings['waf_detail_days']));
			if (count($old) === 0) {
				break;
			}
			$ids = array();
			foreach ($old as $row) {
				$ids[] = (int) $row['hit_id'];
				$this->remove_response((string) $row['response_file']);
			}
			$app->dbmaster->query('DELETE FROM malwatch_waf_hit WHERE hit_id IN ?', $ids);
			$counts['hits'] += count($ids);
		}

		foreach (array('malwatch_waf_site_day', 'malwatch_waf_day') as $table) {
			$app->dbmaster->query('DELETE FROM ?? WHERE server_id = ? AND day < DATE_SUB(CURDATE(), INTERVAL ? DAY)',
				$table, $conf['server_id'], $settings['waf_stats_days']);
			$counts['days'] += (int) $app->dbmaster->affectedRows();
		}

		// The origin of an address lives as long as its last hit.
		$app->dbmaster->query('DELETE p FROM malwatch_waf_ip p LEFT JOIN malwatch_waf_hit h '
			. 'ON h.server_id = p.server_id AND h.client_ip = p.ip WHERE p.server_id = ? AND h.hit_id IS NULL',
			$conf['server_id']);
		$counts['addresses'] = (int) $app->dbmaster->affectedRows();

		$known = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT response_file FROM malwatch_waf_hit WHERE server_id = ? AND response_file != ''",
			$conf['server_id'])) as $row) {
			$known[(string) $row['response_file']] = true;
		}
		$names = @scandir($dir . '/responses');
		foreach (is_array($names) ? $names : array() as $name) {
			$file = $dir . '/responses/' . $name;
			if ($name === '.' || $name === '..' || isset($known[$name]) || !is_file($file)) {
				continue;
			}
			// A younger file may belong to a hit that is being written right now.
			if (filemtime($file) < time() - 3600 && @unlink($file)) {
				$counts['files']++;
			}
		}

		$running = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT job_id FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running'",
			$conf['server_id'])) as $job) {
			$running[(string) (int) $job['job_id']] = true;
		}
		$names = @scandir($dir . '/staging');
		foreach (is_array($names) ? $names : array() as $name) {
			if (!preg_match('/^(\d+)/', $name, $m) || isset($running[$m[1]])) {
				continue;
			}
			$path = $dir . '/staging/' . $name;
			if (is_dir($path) && !is_link($path)) {
				waf_remove_dir($path);
			} else {
				@unlink($path);
			}
			$counts['staging']++;
		}
		return $counts;
	}

	/** What the vhost file of a website shows; 'off' without a file or for an odd name. */
	public function vhost_state($domain)
	{
		$domain = (string) $domain;
		if ($domain === '' || waf_host_normalize($domain) !== strtolower($domain)) {
			return 'off';
		}
		$file = $this->vhost_file($domain);
		return is_file($file) ? waf_vhost_state((string) file_get_contents($file)) : 'off';
	}

	/** Runs one of the few commands the WAF needs; returns array(exit code, output). */
	public function run_command($name, $argument)
	{
		if ($this->runner !== null) {
			return call_user_func($this->runner, $name, $argument);
		}
		$systemctl = $this->binary(array('/usr/bin/systemctl', '/bin/systemctl'));
		switch ($name) {
			case 'rules_check':
				$found = glob('/usr/lib/*/libexec/modsec-rules-check');
				$tool = $this->binary(array_merge(is_array($found) ? $found : array(),
					array('/usr/bin/modsec-rules-check', '/usr/local/bin/modsec-rules-check')));
				if ($tool === '') {
					return array(0, 'modsec-rules-check fehlt, nginx -t entscheidet.');
				}
				$command = escapeshellarg($tool) . ' ' . escapeshellarg($argument);
				break;
			case 'nginx_test':
				$command = escapeshellarg($this->binary(array('/usr/sbin/nginx', '/usr/bin/nginx'))) . ' -t';
				break;
			case 'nginx_reload':
				$command = escapeshellarg($systemctl) . ' reload nginx';
				break;
			case 'nginx_active':
				$command = escapeshellarg($systemctl) . ' is-active --quiet nginx';
				break;
			case 'nginx_start':
				$command = escapeshellarg($systemctl) . ' start nginx';
				break;
			case 'logrotate_check':
				$command = escapeshellarg($this->binary(array('/usr/sbin/logrotate', '/usr/bin/logrotate')))
					. ' -d ' . escapeshellarg($argument);
				break;
			default:
				return array(1, 'Unbekannter Befehl: ' . $name);
		}
		$output = array();
		$code = 0;
		exec($command . ' 2>&1', $output, $code);
		return array((int) $code, implode("\n", $output));
	}

	/**
	 * Loads one address into $target. Returns array(ok, error); the error text
	 * never carries the licence key. A download larger than $limit bytes is
	 * cut off and counts as failed.
	 */
	public function fetch($url, $target, $limit, $auth)
	{
		if ($this->fetcher !== null) {
			return call_user_func($this->fetcher, $url, $target, $limit, $auth);
		}
		if (!function_exists('curl_init')) {
			return array(false, 'Die PHP-Erweiterung curl fehlt. Bitte php-curl nachinstallieren; ohne sie lädt der Server keine Liste.');
		}
		$handle = @fopen($target, 'wb');
		if ($handle === false) {
			return array(false, 'Die Datei ' . basename($target) . ' ließ sich nicht anlegen. Bitte Platz und Rechte unter dem Arbeitsverzeichnis prüfen.');
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_FILE, $handle);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 10);
		curl_setopt($curl, CURLOPT_TIMEOUT, 120);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt($curl, CURLOPT_USERAGENT, 'malwatch/' . $this->version());
		if ((string) $auth !== '') {
			curl_setopt($curl, CURLOPT_USERPWD, (string) $auth);
			curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		}
		curl_setopt($curl, CURLOPT_NOPROGRESS, false);
		curl_setopt($curl, CURLOPT_PROGRESSFUNCTION, function ($curl, $expected, $loaded) use ($limit) {
			return $loaded > $limit || $expected > $limit ? 1 : 0;
		});
		$ok = curl_exec($curl) !== false;
		$status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
		$error = $ok ? '' : curl_error($curl);
		$aborted = curl_errno($curl) === CURLE_ABORTED_BY_CALLBACK;
		curl_close($curl);
		fclose($handle);
		if ($aborted) {
			@unlink($target);
			return array(false, 'Die Datei ist größer als ' . (int) ($limit / 1048576) . ' MB. Der Abruf wurde abgebrochen.');
		}
		if (!$ok) {
			@unlink($target);
			return array(false, 'Der Abruf scheiterte: ' . waf_cut(preg_replace('/\s+/', ' ', $error), 150));
		}
		if ($status >= 400) {
			@unlink($target);
			return array(false, 'Die Quelle antwortete mit ' . $status . '.');
		}
		return array(true, '');
	}

	/** The version of the addon, for the user agent of a download. */
	private function version()
	{
		$file = '/usr/local/ispconfig/extensions/malwatch/version';
		$version = is_file($file) ? trim((string) file_get_contents($file)) : '';
		return preg_match('/^[0-9.]{1,16}$/', $version) ? $version : '0';
	}

	/** Stores one hit; true when it was new. Only a new hit counts in the day tables. */
	private function store_hit($site, $domain, $hit)
	{
		global $app, $conf;

		$app->dbmaster->query(
			'INSERT IGNORE INTO malwatch_waf_hit (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, method, uri, path, status, '
			. 'anomaly_score, would_block, logged_in, rules, request_headers, request_body) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$conf['server_id'], (int) $site, (string) $domain, $hit['unique_id'], $hit['seen_at'], $hit['client_ip'],
			$hit['method'], $hit['uri'], $hit['path'], (int) $hit['status'], (int) $hit['anomaly_score'],
			$hit['would_block'] ? 'y' : 'n', $hit['logged_in'] ? 'y' : 'n',
			waf_json($hit['rules']), waf_json($hit['headers']), $hit['body']);
		if ((int) $app->dbmaster->affectedRows() !== 1) {
			return false;
		}
		$hit_id = (int) $app->dbmaster->insertID();

		if ($hit['response_body'] !== null && $hit['response_body'] !== '') {
			$name = $this->store_response($hit['unique_id'], $hit['response_body']);
			if ($name !== '') {
				$app->dbmaster->query('UPDATE malwatch_waf_hit SET response_file = ?, response_bytes = ? WHERE hit_id = ?',
					$name, strlen($hit['response_body']), $hit_id);
			}
		}

		$day = substr($hit['seen_at'], 0, 10);
		$block = $hit['would_block'] ? 1 : 0;
		$logged_in = $hit['logged_in'] ? 1 : 0;
		$app->dbmaster->query(
			'INSERT INTO malwatch_waf_site_day (server_id, day, parent_domain_id, domain, hits, would_block, '
			. 'logged_in_hits, would_block_logged_in) VALUES (?, ?, ?, ?, 1, ?, ?, ?) '
			. 'ON DUPLICATE KEY UPDATE hits = hits + 1, would_block = would_block + VALUES(would_block), '
			. 'logged_in_hits = logged_in_hits + VALUES(logged_in_hits), '
			. 'would_block_logged_in = would_block_logged_in + VALUES(would_block_logged_in)',
			$conf['server_id'], $day, (int) $site, (string) $domain, $block, $logged_in, $block * $logged_in);
		foreach ($hit['rules'] as $rule) {
			if (waf_is_scoring_rule($rule['id'])) {
				continue;
			}
			$app->dbmaster->query(
				'INSERT INTO malwatch_waf_day (server_id, day, parent_domain_id, domain, rule_id, rule_msg, path, '
				. 'path_hash, hits, would_block_hits) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?) '
				. 'ON DUPLICATE KEY UPDATE hits = hits + 1, would_block_hits = would_block_hits + VALUES(would_block_hits), '
				. 'rule_msg = VALUES(rule_msg)',
				$conf['server_id'], $day, (int) $site, (string) $domain, $rule['id'], $rule['msg'],
				$hit['path'], sha1($hit['path']), $block);
		}
		return true;
	}

	/** Packs a response body into <state_dir>/waf/responses; returns the file name or ''. */
	private function store_response($unique_id, $body)
	{
		$dir = $this->ensure_dirs() . '/responses';
		$name = preg_replace('/[^A-Za-z0-9._-]/', '_', $unique_id) . '.html.gz';
		$tmp = $dir . '/.' . $name . '.tmp';
		$data = gzencode($body, 6);
		if ($data === false || @file_put_contents($tmp, $data) === false) {
			@unlink($tmp);
			return '';
		}
		// The directory's setgid bit hands the file the panel's group.
		@chmod($tmp, 0640);
		if (!@rename($tmp, $dir . '/' . $name)) {
			@unlink($tmp);
			return '';
		}
		return $name;
	}

	private function remove_response($name)
	{
		$name = basename((string) $name);
		if ($name !== '' && $name !== '.' && $name !== '..') {
			@unlink($this->state_dir() . '/responses/' . $name);
		}
	}

	/** Where the last run stopped reading; a missing file means from the start. */
	private function reader_state()
	{
		$doc = json_decode((string) @file_get_contents($this->ensure_dirs() . '/reader.json'), true);
		return array(
			'inode' => is_array($doc) && isset($doc['inode']) ? (int) $doc['inode'] : 0,
			'offset' => is_array($doc) && isset($doc['offset']) ? (int) $doc['offset'] : 0,
		);
	}

	private function save_reader_state($inode, $offset)
	{
		waf_write_atomic($this->ensure_dirs() . '/reader.json',
			json_encode(array('inode' => (int) $inode, 'offset' => (int) $offset)) . "\n");
	}

	/** <state_dir>/waf. */
	private function state_dir()
	{
		global $app;
		$base = $this->paths['state_dir'];
		if ($base === null) {
			$app->uses('malwatch_helper');
			$config = $app->malwatch_helper->get_config();
			$base = (string) $config['state_dir'];
		}
		return rtrim($base, '/') . '/waf';
	}

	/**
	 * Creates the working directories an update has not created yet and
	 * returns <state_dir>/waf. Existing directories keep what the installer
	 * gave them.
	 */
	private function ensure_dirs()
	{
		$base = $this->state_dir();
		$group = @filegroup(dirname($base));
		foreach (array('', '/responses') as $sub) {
			if (!is_dir($base . $sub)) {
				@mkdir($base . $sub, 02750, true);
				@chmod($base . $sub, 02750);
				if ($group !== false) {
					@chgrp($base . $sub, $group);
				}
			}
		}
		foreach (array('/staging', '/last-good', '/origin', '/origin/tmp') as $sub) {
			if (!is_dir($base . $sub)) {
				@mkdir($base . $sub, 0750, true);
			}
		}
		return $base;
	}

	/** One WAF worker at a time: the cron, waf-switch and waf-guard share this lock. */
	private function lock($wait)
	{
		if ($this->lock !== null) {
			return true;
		}
		$handle = @fopen($this->ensure_dirs() . '/lock', 'c');
		if ($handle === false) {
			return false;
		}
		if (!flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
			fclose($handle);
			return false;
		}
		$this->lock = $handle;
		return true;
	}

	private function unlock()
	{
		if ($this->lock !== null) {
			flock($this->lock, LOCK_UN);
			fclose($this->lock);
			$this->lock = null;
		}
	}

	/** The web_domain rows of this server that the host map needs. */
	private function web_rows()
	{
		global $app, $conf;
		return $this->rows($app->dbmaster->queryAllRecords(
			'SELECT domain_id, parent_domain_id, type, domain, subdomain, active FROM web_domain WHERE server_id = ?',
			$conf['server_id']));
	}

	/** Where ISPConfig writes the vhost files of this server. */
	private function vhost_dir()
	{
		global $app, $conf;
		$dir = $this->paths['vhost_dir'];
		if ($dir === null) {
			$app->uses('getconf');
			$web = $app->getconf->get_server_config($conf['server_id'], 'web');
			$dir = !empty($web['nginx_vhost_conf_dir']) ? $web['nginx_vhost_conf_dir'] : '/etc/nginx/sites-available';
		}
		return rtrim($dir, '/');
	}

	private function vhost_file($domain)
	{
		return $this->vhost_dir() . '/' . $domain . '.vhost';
	}

	/** The first path that exists and may be run; '' when none does. */
	private function binary($candidates)
	{
		foreach ($candidates as $path) {
			if (is_string($path) && is_file($path) && is_executable($path)) {
				return $path;
			}
		}
		return '';
	}

	private function rows($result)
	{
		return is_array($result) ? $result : array();
	}

	// --- Entry points --------------------------------------------------------

	/** One cron pass: read the log, then the jobs. Skipped while another worker holds the lock. */
	public function cron_minute()
	{
		global $app;
		if (!$this->ready() || !$this->lock(false)) {
			return;
		}
		try {
			$this->ingest(array());
			$this->origin_lookup();
			$this->run_jobs();
		} catch (Throwable $e) {
			$app->log('malwatch: the WAF pass failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		} finally {
			$this->unlock();
		}
	}

	/** The hourly part of the cron. */
	public function cron_hourly()
	{
		global $app;
		if (!$this->ready() || !$this->lock(false)) {
			return;
		}
		try {
			$this->cleanup();
			$this->queue_origin_update();
		} catch (Throwable $e) {
			$app->log('malwatch: the WAF cleanup failed: ' . $e->getMessage(), LOGLEVEL_WARN);
		} finally {
			$this->unlock();
		}
	}

	/**
	 * Queues origin_update when a chosen source is due and no job of that kind
	 * waits already. The settings page queues one right after a save.
	 */
	private function queue_origin_update()
	{
		global $app, $conf;

		$settings = $this->settings();
		$states = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT * FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$now = $this->now();
		$due = false;
		foreach (waf_origin_chosen($settings) as $name) {
			$due = $due || waf_origin_due($name, isset($states[$name]) ? $states[$name] : null, $settings, $now);
		}
		if (!$due) {
			return;
		}
		$open = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' "
			. "AND job_status IN ('pending','running') AND options LIKE '%\"action\":\"origin_update\"%'",
			$conf['server_id']);
		if (is_array($open) && (int) $open['n'] > 0) {
			return;
		}
		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, server_id, '
			. "parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) "
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', '', 'cron', 'waf', 'pending', ?, ?)",
			$conf['server_id'], waf_json(array('action' => 'origin_update', 'user' => 'cron')), $now);
	}

	/** One round of run_jobs() under the lock, for waf-switch set --wait. */
	public function pass()
	{
		if (!$this->ready() || !$this->lock(true)) {
			return;
		}
		try {
			$this->run_jobs();
		} finally {
			$this->unlock();
		}
	}

	/**
	 * Loads every source that is due and swaps its range file in. A source the
	 * settings left off loses its file and its row. The log names sources and
	 * numbers, never a key and never an address.
	 */
	private function run_origin_update($job)
	{
		global $app, $conf;

		$settings = $this->settings();
		$states = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT * FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			$states[(string) $row['source']] = $row;
		}
		$notes = array();
		$failed = false;
		$dir = $this->ensure_dirs() . '/origin';

		foreach ($states as $name => $row) {
			if (in_array($name, waf_origin_chosen($settings), true)) {
				continue;
			}
			@unlink($dir . '/' . $name . '.bin');
			$app->dbmaster->query('DELETE FROM malwatch_waf_origin_source WHERE server_id = ? AND source = ?',
				$conf['server_id'], $name);
			$app->dbmaster->query('UPDATE malwatch_waf_ip SET local_at = NULL WHERE server_id = ?', $conf['server_id']);
			$notes[] = $name . ': abgeschaltet, Datei entfernt';
		}

		$results = $this->origin_update_sources($settings, $states, $this->now());
		foreach ($results as $name => $result) {
			$notes[] = $name . ': ' . $result['note'];
			$failed = $failed || !$result['ok'];
		}
		if (count($notes) === 0) {
			return $this->finish($job, true, 'Keine Quelle war fällig.');
		}
		return $this->finish($job, !$failed, waf_cut(implode('; ', $notes), 60000));
	}

	/**
	 * Works through the sources that are due and returns one entry per source
	 * with ok, note and the counts. Public so tests/waf_class_probe.php can
	 * call it with its own fetcher.
	 */
	public function origin_update_sources($settings, $states, $now)
	{
		$results = array();
		$dir = $this->ensure_dirs() . '/origin';
		foreach (waf_origin_chosen($settings) as $name) {
			$row = isset($states[$name]) ? $states[$name] : null;
			if (!waf_origin_due($name, $row, $settings, $now)) {
				continue;
			}
			$results[$name] = $this->origin_update_source($name, $settings, $row, $dir, $now);
		}
		return $results;
	}

	/** One source: load, read, check, swap. Returns array(ok, note, entries, version). */
	private function origin_update_source($name, $settings, $row, $dir, $now)
	{
		$sources = waf_origin_sources();
		$source = $sources[$name];
		$tmp = $dir . '/tmp';
		$target = $dir . '/' . $name . '.bin';
		$previous = is_file($target) ? waf_origin_ranges(waf_origin_open($target)) : 0;
		$version = strpos($name, 'dbip_') === 0 ? gmdate('Y-m', strtotime((string) $now)) : '';
		$auth = '';
		if (strpos($name, 'maxmind_') === 0) {
			if (!class_exists('ZipArchive')) {
				return $this->origin_note($name, false, 'Die PHP-Erweiterung zip fehlt. Bitte php-zip nachinstallieren oder bei „Land und Provider“ DB-IP wählen.', $row, $now);
			}
			if ((string) $settings['waf_origin_maxmind_account'] === '' || (string) $settings['waf_origin_maxmind_key'] === '') {
				return $this->origin_note($name, false, 'Konto-ID oder Lizenzschlüssel fehlt. Bitte beide in den Einstellungen der Abwehr eintragen.', $row, $now);
			}
			$auth = $settings['waf_origin_maxmind_account'] . ':' . $settings['waf_origin_maxmind_key'];
		}
		// DB-IP publishes one file per month; at the turn of the month the new
		// one may be missing, then the one of last month still counts.
		$months = strpos($name, 'dbip_') === 0
			? array($version, gmdate('Y-m', strtotime((string) $now) - 15 * 86400)) : array('');
		$files = array();
		$error = '';
		foreach ($months as $month) {
			$files = array();
			$error = '';
			$version = $month;
			foreach (waf_origin_urls($name, $month) as $index => $url) {
				$file = $tmp . '/' . $name . '-' . $index . '.tmp';
				@unlink($file);
				$loaded = $this->fetch($url, $file, (int) $source['bytes'], $auth);
				if (!$loaded[0]) {
					$error = $loaded[1];
					break;
				}
				$files[] = $file;
			}
			if ($error === '') {
				break;
			}
		}
		if ($error !== '') {
			$this->origin_clean($files);
			if (strpos($name, 'maxmind_') === 0 && strpos($error, '401') !== false) {
				$error = 'MaxMind hat Konto-ID oder Lizenzschlüssel abgelehnt. Bitte beide in den Einstellungen der Abwehr prüfen.';
			}
			return $this->origin_note($name, false, $error, $row, $now);
		}
		if (strpos($name, 'maxmind_') === 0) {
			$unpacked = $this->origin_unzip($name, $files[0], $tmp);
			$this->origin_clean($files);
			if ($unpacked === null) {
				return $this->origin_note($name, false, 'Das Archiv ließ sich nicht entpacken. Der nächste Abruf versucht es erneut.', $row, $now);
			}
			$files = $unpacked['files'];
			$version = $unpacked['version'];
		}
		// A release that is already in use needs no rebuild.
		if ($version !== '' && is_array($row) && (string) $row['version'] === $version && $previous > 0) {
			$this->origin_clean($files);
			return $this->origin_note($name, true, 'Stand ' . $version . ' unverändert, ' . $previous . ' Bereiche.', $row, $now, $version, $previous, true);
		}
		$fresh = $tmp . '/' . $name . '.bin';
		@unlink($fresh);
		$counts = $this->origin_read($name, $files, $fresh);
		$this->origin_clean($files);
		if ($counts === null) {
			@unlink($fresh);
			return $this->origin_note($name, false, 'Die Datei ließ sich nicht umbauen. Bitte Platz unter ' . $dir . ' prüfen.', $row, $now);
		}
		$refused = waf_origin_check($name, $counts, $previous);
		if ($refused !== '') {
			@unlink($fresh);
			return $this->origin_note($name, false, $refused, $row, $now);
		}
		if (!@rename($fresh, $target)) {
			@unlink($fresh);
			return $this->origin_note($name, false, 'Die neue Datei ließ sich nicht an ihren Platz legen. Der bisherige Stand bleibt aktiv.', $row, $now);
		}
		@chmod($target, 0640);
		return $this->origin_note($name, true, $counts['ranges'] . ' Bereiche, ' . $counts['bad'] . ' unbrauchbare Zeilen'
			. ($version === '' ? '' : ', Stand ' . $version) . '.', $row, $now, $version, $counts['ranges']);
	}

	/** Reads the files of one source into the range file $fresh. */
	private function origin_read($name, $files, $fresh)
	{
		switch ($name) {
			case 'dbip_country':
				return waf_origin_read_dbip_country($files, $fresh);
			case 'dbip_asn':
				return waf_origin_read_dbip_asn($files, $fresh);
			case 'maxmind_country':
				$blocks = array();
				$locations = '';
				foreach ($files as $file) {
					if (strpos($file, 'Locations') !== false) {
						$locations = $file;
					} elseif (strpos($file, 'Blocks') !== false) {
						$blocks[] = $file;
					}
				}
				return $locations === '' ? null : waf_origin_read_maxmind_country($blocks, $locations, $fresh);
			case 'maxmind_asn':
				return waf_origin_read_maxmind_asn($files, $fresh);
		}
		return waf_origin_read_list($files, $fresh);
	}

	/** Unpacks the GeoLite2 archive; returns array(files, version) or null. */
	private function origin_unzip($name, $archive, $tmp)
	{
		$zip = new ZipArchive();
		if ($zip->open($archive) !== true) {
			return null;
		}
		$files = array();
		$version = '';
		for ($i = 0; $i < $zip->numFiles; $i++) {
			$inside = (string) $zip->getNameIndex($i);
			if (preg_match('/_(\d{8})\//', $inside, $m)) {
				$version = $m[1];
			}
			if (substr($inside, -4) !== '.csv') {
				continue;
			}
			$plain = basename($inside);
			// The country archive holds the locations in every language; German
			// and English carry the same country codes.
			if (strpos($plain, 'Locations') !== false && strpos($plain, 'Locations-en') === false) {
				continue;
			}
			$file = $tmp . '/' . $name . '-' . $plain;
			$stream = $zip->getStream($inside);
			$out = $stream === false ? false : @fopen($file, 'wb');
			if ($out === false) {
				continue;
			}
			while (!feof($stream)) {
				fwrite($out, (string) fread($stream, 65536));
			}
			fclose($out);
			fclose($stream);
			$files[] = $file;
		}
		$zip->close();
		sort($files, SORT_STRING);
		return count($files) === 0 ? null : array('files' => $files, 'version' => $version);
	}

	/** Removes the temporary files of one source. */
	private function origin_clean($files)
	{
		foreach (is_array($files) ? $files : array() as $file) {
			@unlink($file);
		}
	}

	/** Writes the state of one source and returns what the job log says about it. */
	private function origin_note($name, $ok, $note, $row, $now, $version = '', $entries = 0, $unchanged = false)
	{
		global $app, $conf;

		$keep = is_array($row);
		$fetched = $ok && !$unchanged ? $now : ($keep ? $row['fetched_at'] : null);
		$app->dbmaster->query(
			'INSERT INTO malwatch_waf_origin_source (server_id, source, version, checked_at, fetched_at, entries, error, error_at) '
			. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE version = VALUES(version), '
			. 'checked_at = VALUES(checked_at), fetched_at = VALUES(fetched_at), entries = VALUES(entries), '
			. 'error = VALUES(error), error_at = VALUES(error_at)',
			$conf['server_id'], $name,
			$ok ? $version : ($keep ? (string) $row['version'] : ''),
			$now, $fetched,
			$ok ? (int) $entries : ($keep ? (int) $row['entries'] : 0),
			$ok ? '' : waf_cut($note, 255),
			$ok ? null : $now);
		return array('ok' => $ok, 'note' => $note, 'entries' => (int) $entries, 'version' => (string) $version);
	}

	/** The time of the database, as the jobs write it. */
	private function now()
	{
		global $app;
		$row = $app->dbmaster->queryOneRecord('SELECT NOW() AS now_at');
		return is_array($row) ? (string) $row['now_at'] : date('Y-m-d H:i:s');
	}

	/**
	 * Fills malwatch_waf_ip for the addresses of the stored hits: every address
	 * without a row, and every row that is older than the newest range file.
	 * One pass looks at most at $limit addresses, so a burst of a scanner never
	 * holds the cron.
	 */
	public function origin_lookup($limit = 500)
	{
		global $app, $conf;

		$settings = $this->settings();
		$chosen = waf_origin_chosen($settings);
		if (count($chosen) === 0) {
			return 0;
		}
		$newest = '';
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT source, fetched_at FROM malwatch_waf_origin_source WHERE server_id = ?', $conf['server_id'])) as $row) {
			if (in_array((string) $row['source'], $chosen, true) && (string) $row['fetched_at'] > $newest) {
				$newest = (string) $row['fetched_at'];
			}
		}
		if ($newest === '') {
			return 0;
		}
		$rows = $this->rows($app->dbmaster->queryAllRecords(
			'SELECT h.client_ip, p.local_at FROM malwatch_waf_hit h '
			. 'LEFT JOIN malwatch_waf_ip p ON p.server_id = h.server_id AND p.ip = h.client_ip '
			. "WHERE h.server_id = ? AND h.client_ip != '' AND (p.ip IS NULL OR p.local_at IS NULL OR p.local_at < ?) "
			. 'GROUP BY h.client_ip, p.local_at LIMIT ?', $conf['server_id'], $newest, (int) $limit));
		if (count($rows) === 0) {
			return 0;
		}
		$readers = waf_origin_readers($this->ensure_dirs() . '/origin', $chosen);
		$now = $this->now();
		$done = 0;
		foreach ($rows as $row) {
			$ip = (string) $row['client_ip'];
			$facts = waf_origin_facts($readers, $ip);
			$app->dbmaster->query(
				'INSERT INTO malwatch_waf_ip (server_id, ip, country, asn, as_org, is_tor, is_vpn, is_hosting, local_at) '
				. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE country = VALUES(country), '
				. 'asn = VALUES(asn), as_org = VALUES(as_org), is_tor = VALUES(is_tor), is_vpn = VALUES(is_vpn), '
				. 'is_hosting = VALUES(is_hosting), local_at = VALUES(local_at)',
				$conf['server_id'], $ip, $facts['country'], (int) $facts['asn'], $facts['as_org'],
				$facts['is_tor'], $facts['is_vpn'], $facts['is_hosting'], $now);
			$done++;
		}
		waf_origin_readers_close($readers);
		return $done;
	}

	/** Queues a WAF job for this server and returns its id. $user names the person in the action log. */
	public function queue($action, $fields, $user)
	{
		global $app, $conf;
		$options = array_merge(is_array($fields) ? $fields : array(),
			array('action' => (string) $action, 'user' => (string) $user));
		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', '', 'manual', 'waf', 'pending', ?, NOW())",
			$conf['server_id'], waf_json($options));
		return (int) $app->dbmaster->insertID();
	}

	/** Queues a job and carries it out at once under the lock; returns the job row afterwards, or null. */
	public function execute_now($action, $fields, $user)
	{
		if (!$this->ready() || !$this->lock(true)) {
			return null;
		}
		try {
			$job_id = $this->queue($action, $fields, $user);
			$this->start_job($this->job($job_id));
			return $this->job($job_id);
		} finally {
			$this->unlock();
		}
	}

	/**
	 * Works on the queue of this server: an emergency stop first, then the
	 * jobs that wait for ISPConfig, then the queued jobs one after the other
	 * as long as none of them keeps waiting. The caller holds the lock.
	 */
	public function run_jobs()
	{
		global $app, $conf;

		$pending = $this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'pending' ORDER BY job_id",
			$conf['server_id']));
		foreach ($pending as $job) {
			if ($this->job_action($job) === 'emergency') {
				$this->start_job($job);
			}
		}

		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running' ORDER BY job_id",
			$conf['server_id'])) as $job) {
			$this->continue_job($job);
		}

		foreach ($pending as $job) {
			if ($this->job_action($job) === 'emergency' || $this->running_count() > 0) {
				continue;
			}
			$this->start_job($job);
		}
	}

	/**
	 * The hourly check behind waf-guard: 0 when nginx -t passes (the jobs get
	 * their pass as well), 1 when something was found, repaired or not.
	 */
	public function guard()
	{
		if (!$this->ready()) {
			return 1;
		}
		if (!$this->lock(true)) {
			$this->guard_log('Sperre nicht erhalten, nichts geprüft.');
			return 1;
		}
		try {
			$test = $this->run_command('nginx_test', '');
			if ($test[0] === 0) {
				$this->guard_log('nginx -t in Ordnung.');
				$this->run_jobs();
				return 0;
			}
			$this->guard_log('nginx -t fehlgeschlagen: ' . preg_replace('/\s+/', ' ', $test[1]));
			$this->guard_repair($test[1]);
			return 1;
		} finally {
			$this->unlock();
		}
	}

	/** Copies the WAF directory to last-good; waf/install.sh calls it after a successful check. */
	public function snapshot()
	{
		if (!$this->ready()) {
			return false;
		}
		$settings = $this->settings();
		waf_snapshot($settings['waf_conf_dir'], $this->ensure_dirs() . '/last-good');
		return true;
	}

	// --- Jobs ----------------------------------------------------------------

	private function start_job($job)
	{
		global $app;
		if (!is_array($job)) {
			return;
		}
		$app->uses('malwatch_helper');
		if (!$app->malwatch_helper->claim_job($job['job_id'])) {
			return;
		}
		$job = $this->job($job['job_id']);
		$options = $this->job_options($job);
		switch ($this->job_action($job)) {
			case 'set_state':
				$this->start_set_state($job, $options, 'set');
				break;
			case 'migrate_markers':
				$this->start_migrate($job, $options);
				break;
			case 'exception_add':
			case 'exception_remove':
				$this->run_exception($job, $options);
				break;
			case 'emergency':
				$this->run_emergency($job, $options);
				break;
			case 'response_body':
				$this->run_response_body($job, $options);
				break;
			case 'apply_settings':
				$this->run_apply_settings($job);
				break;
			case 'origin_update':
				$this->run_origin_update($job);
				break;
			default:
				$this->finish($job, false, 'Unbekannte Aktion: ' . $this->job_action($job));
		}
	}

	private function continue_job($job)
	{
		$options = $this->job_options($job);
		if (isset($options['progress']) && is_array($options['progress'])) {
			$this->continue_set_state($job, $options);
			return;
		}
		// Every other job ends within its own pass; one that still runs was cut
		// off. nginx -t says whether the files it may have touched are sound.
		$test = $this->run_command('nginx_test', '');
		if ($test[0] !== 0) {
			$this->guard_repair($test[1]);
		}
		$this->finish($job, false, 'Der Auftrag wurde unterbrochen. '
			. ($test[0] === 0 ? 'nginx -t ist in Ordnung.' : 'nginx -t meldete einen Fehler, siehe ' . $this->paths['guard_log'] . '.'));
	}

	private function running_count()
	{
		global $app, $conf;
		$row = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n FROM malwatch_job WHERE server_id = ? AND job_kind = 'waf' AND job_status = 'running'",
			$conf['server_id']);
		return is_array($row) ? (int) $row['n'] : 0;
	}

	/** Phase one: back up and write the field of every website, then look once at the vhosts. */
	private function start_set_state($job, $options, $mode)
	{
		global $app, $conf;

		$settings = $this->settings();
		$target = isset($options['state']) ? (string) $options['state'] : '';
		$ids = isset($options['domain_ids']) && is_array($options['domain_ids']) ? $options['domain_ids'] : array();
		$now = $this->db_value('SELECT NOW() AS value');
		$options['backup_dir'] = $this->backup_dir($job);
		$options['progress'] = array();

		foreach (array_values(array_unique(array_map('intval', $ids))) as $id) {
			$web = $app->dbmaster->queryOneRecord(
				'SELECT domain_id, domain, type, server_id, sys_groupid, nginx_directives FROM web_domain WHERE domain_id = ?', $id);
			$site = $app->dbmaster->queryOneRecord(
				'SELECT waf_state, waf_state_since FROM malwatch_site WHERE parent_domain_id = ?', $id);
			$domain = is_array($web) ? (string) $web['domain'] : '#' . $id;
			$plan = waf_site_plan($web, $site, $target, $mode, $conf['server_id'],
				is_array($web) ? $this->vhost_state($domain) : 'off', $now, $settings);
			$entry = array('domain_id' => $id, 'domain' => $domain, 'target' => $plan['target'], 'status' => 'waiting',
				'reason' => $plan['reason'], 'backup' => '', 'written_hash' => '', 'rollback' => '', 'detail' => '');

			if ($plan['action'] === 'skip') {
				$entry['status'] = 'skipped';
			} elseif ($plan['action'] === 'confirm') {
				if ($plan['target'] !== 'off') {
					$this->ensure_site_row($web);
				}
				$this->confirm_site($id, $plan['target'], $job);
				$entry['status'] = 'confirmed';
			} else {
				$this->ensure_site_row($web);
				if ($plan['action'] === 'write') {
					$entry['backup'] = $this->backup_field($options['backup_dir'], $domain, (string) $web['nginx_directives']);
					if ($entry['backup'] === '') {
						$entry['status'] = 'failed';
						$entry['reason'] = 'backup';
					} else {
						$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $plan['text']), 'domain_id', $id);
					}
				}
				if ($entry['status'] === 'waiting') {
					$entry['written_hash'] = sha1($plan['text']);
					$app->dbmaster->query('UPDATE malwatch_site SET waf_pending_state = ?, waf_job_id = ? WHERE parent_domain_id = ?',
						$plan['target'], (int) $job['job_id'], $id);
				}
			}
			$options['progress'][] = $entry;
			// Saved after every website: a job cut off here still knows what it wrote.
			$this->save_options($job, $options);
		}
		$this->save_options($job, $options);
		$this->continue_set_state($job, $options);
	}

	/** Phase two: which vhosts show their state, which ran out of time; one nginx -t for all confirmations. */
	private function continue_set_state($job, $options)
	{
		global $app;

		$settings = $this->settings();
		$row = $app->dbmaster->queryOneRecord(
			'SELECT UNIX_TIMESTAMP(started_at) AS started, '
			. '(started_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)) AS overdue FROM malwatch_job WHERE job_id = ?',
			$settings['waf_job_deadline_minutes'], (int) $job['job_id']);
		$started = is_array($row) ? (int) $row['started'] : time();
		$overdue = is_array($row) && (int) $row['overdue'] === 1;

		$confirmed = array();
		$waiting = 0;
		foreach ($options['progress'] as $i => $entry) {
			if ($entry['status'] !== 'waiting') {
				continue;
			}
			$file = $this->vhost_file($entry['domain']);
			clearstatcache();
			$rejected = is_file($file . '.err') && filemtime($file . '.err') >= $started;
			$state = waf_site_progress($entry, $this->vhost_state($entry['domain']), $rejected, $overdue);
			if ($state === 'waiting') {
				$waiting++;
			} elseif ($state === 'confirmed') {
				$confirmed[] = $i;
			} else {
				$options['progress'][$i] = $this->fail_site($entry, substr($state, 7), '');
			}
		}

		if (count($confirmed) > 0) {
			$test = $this->run_command('nginx_test', '');
			foreach ($confirmed as $i) {
				$entry = $options['progress'][$i];
				if ($test[0] === 0) {
					$entry['status'] = 'confirmed';
					$this->confirm_site($entry['domain_id'], $entry['target'], $job);
					$options['progress'][$i] = $entry;
				} else {
					$options['progress'][$i] = $this->fail_site($entry, 'nginx_test', $test[1]);
				}
			}
		}
		$this->save_options($job, $options);
		if ($waiting === 0) {
			$this->finish_set_state($job, $options);
		}
	}

	private function finish_set_state($job, $options)
	{
		$lines = array();
		$ok = true;
		foreach ($options['progress'] as $entry) {
			$lines[] = $entry['domain'] . ': ' . $this->entry_text($entry);
			if ($entry['status'] === 'failed') {
				$ok = false;
			}
		}
		if (count($lines) === 0) {
			$lines[] = 'Keine Website betroffen.';
		}
		$this->finish($job, $ok, implode("\n", $lines));
	}

	/** Marks a website as failed and puts its field back where that is safe. */
	private function fail_site($entry, $reason, $detail)
	{
		global $app;
		$entry['status'] = 'failed';
		$entry['reason'] = $reason;
		$entry['detail'] = waf_cut($detail, 500);
		$app->dbmaster->query("UPDATE malwatch_site SET waf_pending_state = '' WHERE parent_domain_id = ?", (int) $entry['domain_id']);
		if ($entry['backup'] === '' || !is_file($entry['backup'])) {
			$entry['rollback'] = 'not_written';
			return $entry;
		}
		$web = $app->dbmaster->queryOneRecord('SELECT nginx_directives FROM web_domain WHERE domain_id = ?', (int) $entry['domain_id']);
		if (!is_array($web) || !waf_rollback_allowed((string) $web['nginx_directives'], $entry['written_hash'])) {
			$entry['rollback'] = 'changed_meanwhile';
			return $entry;
		}
		$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => (string) file_get_contents($entry['backup'])),
			'domain_id', (int) $entry['domain_id']);
		$entry['rollback'] = 'rolled_back';
		return $entry;
	}

	/** The confirmed state; since stays when the state does not change. */
	private function confirm_site($domain_id, $target, $job)
	{
		global $app;
		$app->dbmaster->query(
			'UPDATE malwatch_site SET waf_state_since = IF(waf_state = ? AND waf_state_since IS NOT NULL, waf_state_since, NOW()), '
			. "waf_state = ?, waf_pending_state = '', waf_job_id = ? WHERE parent_domain_id = ?",
			$target, $target, (int) $job['job_id'], (int) $domain_id);
	}

	/**
	 * Rewrites old markers and brings malwatch_site in line with the fields:
	 * every website with a block, or with a state on record, keeps the state
	 * its field names. Response body and emergency flag are read back from
	 * their files.
	 */
	private function start_migrate($job, $options)
	{
		global $app, $conf;

		$settings = $this->settings();
		$mode = waf_response_body_mode((string) @file_get_contents($settings['waf_conf_dir'] . '/response-body.conf'));
		$app->dbmaster->query('UPDATE malwatch_config SET waf_response_body = ? WHERE config_id = 1', $mode);
		$emergency = waf_state_file_is_emergency((string) @file_get_contents($settings['waf_conf_dir'] . '/state.conf'))
			|| is_file($this->paths['conf_include'] . '.off');
		if ($emergency !== ($settings['waf_emergency'] === 'y')) {
			$app->dbmaster->query('UPDATE malwatch_config SET waf_emergency = ?, waf_emergency_since = '
				. ($emergency ? 'NOW()' : 'NULL') . ' WHERE config_id = 1', $emergency ? 'y' : 'n');
		}

		$ids = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT w.domain_id FROM web_domain w LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id '
			. "WHERE w.server_id = ? AND w.type = 'vhost' AND (w.nginx_directives LIKE ? OR s.waf_state IN ('detect','enforce'))",
			$conf['server_id'], '%# WAF-%')) as $row) {
			$ids[] = (int) $row['domain_id'];
		}
		$options['domain_ids'] = $ids;
		$options['state'] = '';
		$this->start_set_state($job, $options, 'keep');
	}

	/** Adds or removes one exception: both panel rule files are written from the active rows and this one. */
	private function run_exception($job, $options)
	{
		global $app, $conf;

		$id = isset($options['exception_id']) ? (int) $options['exception_id'] : 0;
		$remove = $this->job_action($job) === 'exception_remove';
		$row = $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_waf_exception WHERE exception_id = ?', $id);
		if (!is_array($row)) {
			return $this->finish($job, false, 'Die Ausnahme ' . $id . ' gibt es nicht mehr.');
		}
		$reason = $remove ? '' : waf_exception_check($row);
		if ($reason !== '') {
			$this->set_exception($id, 'error', 'Ungültige Angabe: ' . $reason, $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ' abgewiesen, ungültige Angabe: ' . $reason . '. Keine Datei geändert.');
		}

		$rows = $this->rows($app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_waf_exception WHERE server_id = ? AND exception_state = 'active' AND exception_id != ?",
			$conf['server_id'], $id));
		if (!$remove) {
			$row['exception_state'] = 'pending';
			$rows[] = $row;
		}
		$map = waf_host_map($this->web_rows());
		$hosts = array();
		foreach ($rows as $exception) {
			$site = (int) $exception['parent_domain_id'];
			if ($site > 0 && !isset($hosts[$site])) {
				$hosts[$site] = waf_hosts_of($map, $site);
			}
		}
		$rules = waf_exception_rules($rows, $hosts);
		if (!$remove && isset($rules['skipped'][$id])) {
			$this->set_exception($id, 'error', 'Nicht übernommen: ' . $rules['skipped'][$id], $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ' nicht übernommen: ' . $rules['skipped'][$id] . '. Keine Datei geändert.');
		}

		$result = $this->apply(array(
			'exclusions-panel-before.conf' => $rules['before'],
			'exclusions-panel-after.conf' => $rules['after'],
		), $job);
		if (!$result['ok']) {
			$text = $this->apply_text($result);
			$this->set_exception($id, $remove ? 'active' : 'error', ($remove ? 'Entfernen gescheitert: ' : '') . $text, $job);
			return $this->finish($job, false, 'Ausnahme ' . $id . ': ' . $text);
		}
		if ($remove) {
			$app->dbmaster->query('DELETE FROM malwatch_waf_exception WHERE exception_id = ?', $id);
			return $this->finish($job, true, 'Ausnahme ' . $id . ' entfernt. ' . $this->apply_text($result));
		}
		$app->dbmaster->query("UPDATE malwatch_waf_exception SET exception_state = 'active', error_reason = '', "
			. 'activated_at = NOW(), job_id = ? WHERE exception_id = ?', (int) $job['job_id'], $id);
		return $this->finish($job, true, 'Ausnahme ' . $id . ' aktiv. ' . $this->apply_text($result));
	}

	private function set_exception($id, $state, $reason, $job)
	{
		global $app;
		$app->dbmaster->query('UPDATE malwatch_waf_exception SET exception_state = ?, error_reason = ?, job_id = ? WHERE exception_id = ?',
			$state, waf_cut($reason, 255), (int) $job['job_id'], (int) $id);
	}

	/** The soft emergency stop through state.conf; enforcing websites follow with a job of their own. */
	private function run_emergency($job, $options)
	{
		global $app;
		if (!empty($options['hard'])) {
			return $this->run_hard_stop($job);
		}
		$on = !empty($options['on']);
		if (!$on && is_file($this->paths['conf_include'] . '.off')) {
			return $this->finish($job, false, 'Der harte Notaus ist aktiv. Wieder eingeschaltet wird über waf/install.sh.');
		}
		$result = $this->apply(array('state.conf' => waf_state_file_text($on)), $job);
		if (!$result['ok']) {
			return $this->finish($job, false, ($on ? 'Notaus' : 'Ende des Notaus') . ' gescheitert: ' . $this->apply_text($result));
		}
		if (!$on) {
			$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'n', waf_emergency_since = NULL WHERE config_id = 1");
			return $this->finish($job, true, 'Notaus beendet. ' . $this->apply_text($result));
		}
		$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'y', "
			. 'waf_emergency_since = IFNULL(waf_emergency_since, NOW()) WHERE config_id = 1');
		$ids = $this->enforcing_sites();
		if (count($ids) > 0) {
			$this->queue('set_state', array('domain_ids' => $ids, 'state' => 'detect'), $this->job_user($job));
		}
		return $this->finish($job, true, 'Notaus aktiv, die Regeln prüfen nicht mehr. ' . $this->apply_text($result)
			. (count($ids) > 0 ? ' ' . count($ids) . ' Websites wechseln von scharf auf mitschreiben.' : ''));
	}

	/**
	 * The hard emergency stop, for an nginx that lost the module: the include
	 * goes to waf.conf.off, every vhost file loses its modsecurity lines,
	 * every field its block, then one nginx -t and one reload. The vhost files
	 * are edited directly because ISPConfig tests nginx before it keeps a
	 * vhost, and that test fails while any file still names the module.
	 * waf/install.sh switches the rules back on.
	 */
	private function run_hard_stop($job)
	{
		global $app, $conf;

		$lines = array();
		$backup = $this->backup_dir($job);
		@mkdir($backup, 0700, true);

		$include = $this->paths['conf_include'];
		if (is_file($include)) {
			@copy($include, $backup . '/' . basename($include));
			$lines[] = @rename($include, $include . '.off')
				? 'Regeln ausgehängt: ' . $include . '.off'
				: 'Die Einbindung ' . $include . ' ließ sich nicht umbenennen.';
		}

		$files = glob($this->vhost_dir() . '/*.vhost');
		foreach (is_array($files) ? $files : array() as $file) {
			if (is_link($file) || !is_file($file)) {
				continue;
			}
			$stripped = waf_vhost_strip((string) file_get_contents($file));
			if ($stripped[1] === 0) {
				continue;
			}
			@copy($file, $backup . '/' . basename($file));
			waf_write_atomic($file, $stripped[0]);
			$lines[] = basename($file) . ': ' . $stripped[1] . ' Zeilen entfernt';
		}

		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT domain_id, domain, nginx_directives FROM web_domain WHERE server_id = ? AND type = 'vhost' AND nginx_directives LIKE ?",
			$conf['server_id'], '%# WAF-%')) as $row) {
			$old = (string) $row['nginx_directives'];
			$new = waf_block_set($old, 'off');
			if ($new !== $old) {
				$this->backup_field($backup, (string) $row['domain'], $old);
				$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $new), 'domain_id', (int) $row['domain_id']);
			}
		}
		$app->dbmaster->query("UPDATE malwatch_site SET waf_state_since = IF(waf_state = 'off', waf_state_since, NOW()), "
			. "waf_state = 'off', waf_pending_state = '' WHERE server_id = ?", $conf['server_id']);
		$app->dbmaster->query("UPDATE malwatch_config SET waf_emergency = 'y', "
			. 'waf_emergency_since = IFNULL(waf_emergency_since, NOW()) WHERE config_id = 1');

		$test = $this->run_command('nginx_test', '');
		if ($test[0] !== 0) {
			$lines[] = 'nginx -t meldet weiter einen Fehler, kein Reload: ' . waf_cut($test[1], 500);
			return $this->finish($job, false, implode("\n", $lines));
		}
		$this->run_command('nginx_reload', '');
		$lines[] = 'nginx -t in Ordnung, nginx neu geladen. Sicherungen: ' . $backup
			. '. Wieder eingeschaltet wird über waf/install.sh.';
		return $this->finish($job, true, implode("\n", $lines));
	}

	private function enforcing_sites()
	{
		global $app, $conf;
		$ids = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT domain_id, nginx_directives FROM web_domain WHERE server_id = ? AND type = 'vhost'",
			$conf['server_id'])) as $row) {
			if (waf_block_state((string) $row['nginx_directives']) === 'enforce') {
				$ids[] = (int) $row['domain_id'];
			}
		}
		return $ids;
	}

	private function run_response_body($job, $options)
	{
		global $app;
		$mode = isset($options['mode']) ? (string) $options['mode'] : '';
		if (!waf_response_body_valid($mode)) {
			return $this->finish($job, false, 'Unbekannter Modus der Seitenantwort: ' . $mode);
		}
		$result = $this->apply(array('response-body.conf' => waf_response_body_text($mode)), $job);
		if (!$result['ok']) {
			return $this->finish($job, false, 'Seitenantwort nicht umgestellt: ' . $this->apply_text($result));
		}
		$app->dbmaster->query('UPDATE malwatch_config SET waf_response_body = ? WHERE config_id = 1', $mode);
		return $this->finish($job, true, 'Seitenantwort im Audit-Log: ' . ($mode === 'lean' ? 'schlank' : 'vollständig')
			. '. ' . $this->apply_text($result));
	}

	/** Writes the logrotate file from the settings; the other settings act without a file. */
	private function run_apply_settings($job)
	{
		$settings = $this->settings();
		$file = $this->paths['logrotate'];
		$text = waf_logrotate_text($settings['waf_log_keep_days'], $settings['waf_audit_log']);
		if (is_file($file) && (string) file_get_contents($file) === $text) {
			return $this->finish($job, true, 'Einstellungen übernommen, logrotate unverändert.');
		}
		$check = $this->ensure_dirs() . '/staging/' . (int) $job['job_id'] . '-logrotate';
		file_put_contents($check, $text);
		@chmod($check, 0644);
		$result = $this->run_command('logrotate_check', $check);
		@unlink($check);
		if ($result[0] !== 0) {
			return $this->finish($job, false, 'logrotate lehnt die Datei ab, nichts geändert: ' . waf_cut($result[1], 500));
		}
		if (!waf_write_atomic($file, $text)) {
			return $this->finish($job, false, $file . ' ließ sich nicht schreiben.');
		}
		return $this->finish($job, true, 'Einstellungen übernommen, logrotate behält '
			. $settings['waf_log_keep_days'] . ' Stände.');
	}

	/** Takes the WAF out of a failing nginx -t as far as the output points at it. The caller holds the lock. */
	private function guard_repair($output)
	{
		$settings = $this->settings();
		if (preg_match('/unknown directive "modsecurity/i', $output)) {
			$this->guard_log('Das Modul fehlt: Notaus hart.');
			$job_id = $this->queue('emergency', array('on' => true, 'hard' => true), 'waf-guard');
			$this->start_job($this->job($job_id));
			$job = $this->job($job_id);
			$this->guard_log('Notaus hart: ' . (is_array($job)
				? $job['job_status'] . ', ' . preg_replace('/\s+/', ' ', (string) $job['job_log']) : 'kein Auftrag'));
			return;
		}
		if (strpos($output, $settings['waf_conf_dir'] . '/') === false && stripos($output, 'modsecurity') === false) {
			$this->guard_log('Kein Bezug zur WAF, nichts unternommen.');
			return;
		}
		$restored = waf_restore_snapshot($this->ensure_dirs() . '/last-good', $settings['waf_conf_dir']);
		$this->guard_log('Letzter geprüfter Stand zurückgelegt: '
			. (count($restored) > 0 ? implode(', ', $restored) : 'keine Abweichung'));
		$again = $this->run_command('nginx_test', '');
		if ($again[0] === 0) {
			$this->run_command('nginx_reload', '');
			$this->guard_log('nginx -t wieder in Ordnung, nginx neu geladen.');
		} else {
			$this->guard_log('Fehler bleibt bestehen, Eingriff nötig: ' . preg_replace('/\s+/', ' ', $again[1]));
		}
	}

	private function guard_log($text)
	{
		@file_put_contents($this->paths['guard_log'], date('Y-m-d H:i:s') . ' ' . $text . "\n", FILE_APPEND);
	}

	// --- Job helpers ---------------------------------------------------------

	/** Ends a job and leaves one line in the action log: person, action, result. */
	private function finish($job, $ok, $log)
	{
		global $app, $conf;
		$app->dbmaster->query('UPDATE malwatch_job SET job_status = ?, finished_at = NOW(), job_log = ? WHERE job_id = ?',
			$ok ? 'done' : 'error', waf_cut($log, 60000), (int) $job['job_id']);
		$app->dbmaster->query(
			'INSERT INTO malwatch_action_log (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_id, action_type, trigger_severity, trigger_findings, '
			. 'recipient, detail, created_at) '
			. "VALUES (1, 1, 'riud', 'r', '', ?, 0, '', 0, 'waf', '', 0, '', ?, NOW())",
			$conf['server_id'], waf_cut($this->job_user($job) . ': ' . $this->job_action($job) . ' '
				. ($ok ? 'erledigt' : 'gescheitert') . "\n" . $log, 60000));
		return $ok;
	}

	private function apply($changes, $job)
	{
		$settings = $this->settings();
		$base = $this->ensure_dirs();
		$waf = $this;
		return waf_apply_files(array(
			'conf_dir' => $settings['waf_conf_dir'],
			'staging' => $base . '/staging/' . (int) $job['job_id'],
			'last_good' => $base . '/last-good',
		), $changes, function ($name, $argument) use ($waf) {
			return $waf->run_command($name, $argument);
		});
	}

	private function apply_text($result)
	{
		$texts = array(
			'' => 'nginx neu geladen.',
			'unchanged' => 'Dateien unverändert, kein Reload.',
			'bad_name' => 'Ungültiger Dateiname, nichts geändert',
			'missing_file' => 'Datei fehlt, erst waf/install.sh ausführen',
			'staging' => 'Arbeitsverzeichnis ließ sich nicht anlegen, nichts geändert',
			'rules_check' => 'Regelprüfung fehlgeschlagen, nichts geändert',
			'nginx_test' => 'nginx -t fehlgeschlagen, alte Dateien zurück, kein Reload',
			'nginx_reload' => 'Reload fehlgeschlagen, alte Dateien zurück',
			'nginx_inactive' => 'nginx lief nach dem Reload nicht, alte Dateien zurück und Start versucht',
		);
		$text = isset($texts[$result['reason']]) ? $texts[$result['reason']] : $result['reason'];
		return $result['detail'] !== '' ? $text . ': ' . $result['detail'] : $text;
	}

	/** One German line per website for job_log. */
	private function entry_text($entry)
	{
		$states = array('off' => 'aus', 'detect' => 'mitschreiben', 'enforce' => 'scharf');
		$reasons = array(
			'not_found' => 'keine Website mit dieser Nummer',
			'other_server' => 'die Website liegt auf einem anderen Server',
			'state' => 'unbekannter Zustand',
			'emergency' => 'der Notaus ist aktiv',
			'not_detect' => 'die Website schreibt noch nicht mit',
			'too_early' => 'die Website schreibt noch nicht lange genug mit',
			'backup' => 'das Feld ließ sich nicht sichern',
			'rejected' => 'ISPConfig hat den vhost verworfen',
			'deadline' => 'der vhost zeigte den Zustand nicht innerhalb der Frist',
			'nginx_test' => 'nginx -t schlug fehl',
		);
		$rollbacks = array(
			'rolled_back' => 'altes Feld zurückgeschrieben',
			'changed_meanwhile' => 'Feld wurde zwischenzeitlich geändert, keine Rücknahme',
			'not_written' => 'Feld war unverändert',
		);
		$state = isset($states[$entry['target']]) ? $states[$entry['target']] : $entry['target'];
		$reason = isset($reasons[$entry['reason']]) ? $reasons[$entry['reason']] : $entry['reason'];
		if ($entry['status'] === 'confirmed') {
			return $state . ' bestätigt';
		}
		if ($entry['status'] === 'skipped') {
			return 'übersprungen, ' . $reason;
		}
		if ($entry['status'] === 'failed') {
			$text = $state . ' gescheitert, ' . $reason;
			if ($entry['rollback'] !== '') {
				$text .= '; ' . (isset($rollbacks[$entry['rollback']]) ? $rollbacks[$entry['rollback']] : $entry['rollback']);
			}
			return $entry['detail'] !== '' ? $text . ' (' . $entry['detail'] . ')' : $text;
		}
		return $state . ' wartet auf ISPConfig';
	}

	private function ensure_site_row($web)
	{
		global $app;
		$app->dbmaster->query(
			'INSERT IGNORE INTO malwatch_site (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. "server_id, parent_domain_id, domain) VALUES (1, ?, 'riud', 'riud', '', ?, ?, ?)",
			(int) $web['sys_groupid'], (int) $web['server_id'], (int) $web['domain_id'], (string) $web['domain']);
	}

	/** Saves the field of one website below the job's backup directory; returns the file or ''. */
	private function backup_field($dir, $domain, $text)
	{
		if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
			return '';
		}
		$file = $dir . '/' . preg_replace('/[^A-Za-z0-9._-]/', '_', $domain) . '.txt';
		if (@file_put_contents($file, $text) === false) {
			return '';
		}
		@chmod($file, 0600);
		return $file;
	}

	private function backup_dir($job)
	{
		return rtrim($this->paths['backup_dir'], '/') . '/'
			. $this->db_value("SELECT DATE_FORMAT(NOW(), '%Y%m%d-%H%i%s') AS value") . '-job' . (int) $job['job_id'];
	}

	private function job_options($job)
	{
		$options = is_array($job) ? json_decode((string) $job['options'], true) : null;
		return is_array($options) ? $options : array();
	}

	private function job_action($job)
	{
		$options = $this->job_options($job);
		return isset($options['action']) ? (string) $options['action'] : '';
	}

	private function job_user($job)
	{
		$options = $this->job_options($job);
		return isset($options['user']) && $options['user'] !== '' ? (string) $options['user'] : 'unbekannt';
	}

	private function save_options($job, $options)
	{
		global $app;
		$app->dbmaster->query('UPDATE malwatch_job SET options = ? WHERE job_id = ?', waf_json($options), (int) $job['job_id']);
	}

	private function db_value($sql)
	{
		global $app;
		$row = $app->dbmaster->queryOneRecord($sql);
		return is_array($row) ? (string) $row['value'] : '';
	}
}
