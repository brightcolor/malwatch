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
	public $runner = null;

	/** The handle of the lock file while this process holds it. */
	private $lock = null;

	/** Loads the shared functions; false when malwatch is not installed completely. */
	public function ready()
	{
		if (!function_exists('waf_states') && is_file(self::LIB)) {
			require_once self::LIB;
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
		$counts = array('hits' => 0, 'days' => 0, 'files' => 0, 'staging' => 0);

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
		foreach (array('/staging', '/last-good') as $sub) {
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
}
