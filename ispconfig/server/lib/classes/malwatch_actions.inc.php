<?php

/**
 * Carries out what a website's settings ask for after a scan: notifications,
 * moving files the operator trusted the scanner to move on its own, and, if
 * the operator asked for it, disabling the site.
 *
 * Four rules hold everywhere in this class:
 *
 *   - Only findings that are new since the last run can trigger an action.
 *     Otherwise a site would be disabled again on every nightly run for a
 *     problem the operator has already looked at.
 *   - Outdated software never disables anything. It is a maintenance matter,
 *     not a break-in.
 *   - A clean run never re-enables a site. Turning a customer's website back
 *     on is a decision for a person, not for a scanner.
 *   - Moving files on its own is reserved for a run nobody is watching. A
 *     scan started by hand has an operator at the screen already; the
 *     scanner does not also reach for their website's files.
 */
class malwatch_actions
{
	/** Runs the actions for one finished scan. */
	public function run($scan_id)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$scan = $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_scan WHERE scan_id = ?', intval($scan_id));
		if (!is_array($scan)) {
			return;
		}
		$site = $helper->get_site($scan['parent_domain_id']);
		if (!is_array($site)) {
			// A website nobody configured is scanned on request but never
			// acted upon on its own.
			$this->update_site_state($scan, null);
			return;
		}

		$this->update_site_state($scan, $site);

		$new = $this->new_findings($scan);
		if (empty($new)) {
			return;
		}
		$worst = $this->worst_severity($new);
		$config = $helper->get_config();

		// Decided once, up front: the notification below and the job queued
		// further down must describe the exact same files, never two
		// selections that could in principle disagree.
		$scheduled = $this->scan_job_source($scan) === 'schedule';
		$auto_candidates = $scheduled ? $this->auto_paths($scan, $site, $config) : array();
		$auto_blocked = !empty($auto_candidates) && $this->job_queued($scan['parent_domain_id']);
		$auto_mail = $auto_blocked ? array() : $auto_candidates;

		if ($site['notify_admin'] === 'y' && $helper->severity_at_least($worst, $site['notify_admin_severity'])) {
			$this->notify_admin($scan, $site, $config, $new, $worst, $auto_mail);
		}
		if ($site['notify_client'] === 'y' && $helper->severity_at_least($worst, $site['notify_client_severity'])) {
			$this->notify_client($scan, $site, $config, $new, $worst, $auto_mail);
		}
		if ($scheduled) {
			$this->auto_quarantine($scan, $worst, $auto_candidates, $auto_blocked);
		}
		if ($site['disable_site'] === 'y' && $helper->severity_at_least($worst, $site['disable_severity'])) {
			$this->disable_site($scan, $site, $new, $worst);
		}
	}

	/** Findings first seen in this scan. */
	private function new_findings($scan)
	{
		global $app;
		$rows = $app->dbmaster->queryAllRecords(
			"SELECT * FROM malwatch_finding WHERE scan_id = ? AND finding_state = 'open' AND first_seen = last_seen "
			. 'ORDER BY FIELD(severity, ?, ?, ?, ?) DESC, file_path ASC',
			intval($scan['scan_id']), 'low', 'medium', 'high', 'critical');

		return is_array($rows) ? $rows : array();
	}

	private function worst_severity($findings)
	{
		global $app;
		$app->uses('malwatch_helper');
		$worst = '';
		foreach ($findings as $finding) {
			if ($app->malwatch_helper->severity_rank($finding['severity']) > $app->malwatch_helper->severity_rank($worst)) {
				$worst = $finding['severity'];
			}
		}
		return $worst;
	}

	/** Writes the summary back onto the website row. */
	private function update_site_state($scan, $site)
	{
		global $app;

		$open = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n, MAX(FIELD(severity, 'low', 'medium', 'high', 'critical')) AS worst "
			. "FROM malwatch_finding WHERE parent_domain_id = ? AND finding_state = 'open'",
			intval($scan['parent_domain_id']));

		$count = is_array($open) ? intval($open['n']) : 0;
		$worst = '';
		if (is_array($open) && intval($open['worst']) > 0) {
			$names = malwatch_helper::$severities;
			$index = intval($open['worst']) - 1;
			if (isset($names[$index])) {
				$worst = $names[$index];
			}
		}

		$state = 'clean';
		if ($count > 0) {
			$state = 'findings';
		} elseif (isset($scan['count_vulnerable']) && intval($scan['count_vulnerable']) > 0) {
			// Before 'outdated': a published flaw is what attackers search
			// for, an old version alone can be harmless for years.
			$state = 'vulnerable';
		} elseif (intval($scan['count_outdated']) > 0) {
			$state = 'outdated';
		}

		// A website only gets a settings row once somebody opens its settings
		// page and saves. Returning here dropped the result of every scan for
		// every other website: sixty sites showed "ungeprüft" in the overview
		// while sixty-six finished scans sat in the database.
		if (!is_array($site)) {
			$site = $this->create_site_row($scan);
			if (!is_array($site)) {
				$app->log('malwatch: Zustand für ' . $scan['domain'] . ' konnte nicht abgelegt werden.',
					LOGLEVEL_WARN);
				return;
			}
		}

		$app->uses('malwatch_helper');
		$next = $app->malwatch_helper->next_run($site['scan_days']);

		$app->dbmaster->query(
			'UPDATE malwatch_site SET last_scan_id = ?, last_run = ?, next_run = FROM_UNIXTIME(?), open_findings = ?, '
			. 'worst_severity = ?, last_state = ? WHERE site_id = ?',
			intval($scan['scan_id']), $scan['finished_at'], $next, $count, $worst, $state, intval($site['site_id']));
	}

	/**
	 * Creates the settings row of a website with the defaults, the interval
	 * for new websites among them (malwatch_helper::ensure_site_row()).
	 *
	 * Every other column below the identity has a default, so the row is the
	 * plain "not configured, but scanned" state - which is exactly what a
	 * website is after a scan that nobody set up beforehand. A website that
	 * is gone by now gets no row.
	 */
	private function create_site_row($scan)
	{
		global $app;

		$domain_id = intval($scan['parent_domain_id']);
		if ($domain_id < 1) {
			return null;
		}
		$app->uses('malwatch_helper');
		$web = $app->malwatch_helper->get_web($domain_id);
		if (!is_array($web)) {
			return null;
		}
		$app->malwatch_helper->ensure_site_row($web);

		return $app->dbmaster->queryOneRecord(
			'SELECT * FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
	}

	private function notify_admin($scan, $site, $config, $findings, $worst, $auto)
	{
		global $app;

		$recipient = trim((string) $config['admin_email']);
		if ($recipient === '') {
			$global = $app->getconf->get_global_config('mail');
			$recipient = isset($global['admin_mail']) ? trim((string) $global['admin_mail']) : '';
		}
		if ($recipient === '') {
			$this->log_action($scan, 'error', $worst, count($findings), '',
				'Keine Empfängeradresse hinterlegt, die Benachrichtigung an den Betreiber wurde nicht versendet.');
			return;
		}
		$this->send($scan, $site, $config, $findings, $worst, $auto, $recipient, 'notify_admin', 'malwatch_notification');
	}

	private function notify_client($scan, $site, $config, $findings, $worst, $auto)
	{
		global $app;

		$client = $app->dbmaster->queryOneRecord(
			'SELECT client.email, client.language FROM client, sys_group '
			. 'WHERE sys_group.client_id = client.client_id AND sys_group.groupid = ?',
			intval($site['sys_groupid']));

		$recipient = is_array($client) ? trim((string) $client['email']) : '';
		if ($recipient === '') {
			$this->log_action($scan, 'error', $worst, count($findings), '',
				'Der Kunde hat keine E-Mail-Adresse, die Benachrichtigung wurde nicht versendet.');
			return;
		}
		$language = is_array($client) && $client['language'] !== '' ? $client['language'] : 'de';
		$this->send($scan, $site, $config, $findings, $worst, $auto, $recipient, 'notify_client',
			'malwatch_client_notification', $language);
	}

	/** Renders a template and hands it to ISPConfig's mailer. */
	private function send($scan, $site, $config, $findings, $worst, $auto, $recipient, $type, $template, $language = 'de')
	{
		global $app, $conf;

		$app->uses('getconf');
		$global = $app->getconf->get_global_config('mail');
		$sender = trim((string) $config['sender_email']);
		if ($sender === '') {
			$sender = isset($global['admin_mail']) && $global['admin_mail'] !== '' ? $global['admin_mail'] : 'root';
		}

		$body = $this->render($template, $language, $scan, $findings, $worst, $auto);
		if ($body === '') {
			$this->log_action($scan, 'error', $worst, count($findings), $recipient,
				'Die Mailvorlage ' . $template . ' fehlt.');
			return;
		}

		$subject = 'malwatch: ' . count($findings) . ' neue Fund(e) auf ' . $scan['domain'];
		if (strpos($body, "\n\n") !== false) {
			// Templates carry their own headers, exactly like the quota mails
			// the ISPConfig core sends.
			list($headers, $text) = explode("\n\n", $body, 2);
			if (preg_match('/^Subject:\s*(.+)$/mi', $headers, $match)) {
				$subject = trim($match[1]);
			}
			$body = $text;
		}

		// The HTML mail, when the settings ask for it and a template exists.
		// It goes out through the scanner; when that fails, the same mail goes
		// out as text through ISPConfig below, and the log says why.
		$app->uses('malwatch_helper');
		$config_all = $app->malwatch_helper->get_config();
		$html_note = '';
		if ((isset($config_all['mail_format']) ? $config_all['mail_format'] : 'html') === 'html') {
			$html_file = $this->template_file($template, $language, 'html');
			if ($html_file !== '') {
				$html_note = $this->send_html($html_file, $language, $scan, $findings, $worst, $auto, $recipient,
					$sender, $subject, $body, $global, $config_all);
				if ($html_note === '') {
					$this->log_action($scan, $type, $worst, count($findings), $recipient, '');
					return;
				}
			}
		}

		$app->uses('functions');
		$app->functions->mail($recipient, $subject, $body, $sender);

		$this->log_action($scan, $type, $worst, count($findings), $recipient, $html_note === ''
			? '' : 'Als Text über ISPConfig verschickt, weil die HTML-Mail scheiterte: ' . $html_note);
	}

	/**
	 * Renders the HTML template and delivers it with the text part through the
	 * scanner. Returns '' when the mail went out, otherwise the reason.
	 */
	private function send_html($file, $language, $scan, $findings, $worst, $auto, $recipient, $sender, $subject, $text,
		array $global, array $config)
	{
		global $app;

		$app->uses('malwatch_mailer,malwatch_mail_html');
		$rendered = $this->render_html($file, $language, $scan, $findings, $worst, $auto, $subject, $config);
		if (count($rendered['missing']) > 0) {
			$app->log('malwatch: the mail template ' . basename($file) . ' asks for images its folder lacks: '
				. implode(', ', $rendered['missing']), LOGLEVEL_WARN);
		}
		$message = malwatch_mailer::build(array(
			'from' => $sender,
			'from_name' => isset($config['mail_from_name']) ? (string) $config['mail_from_name'] : '',
			'to' => array($recipient),
			'subject' => $subject,
			'host' => (string) php_uname('n'),
		), $text, $rendered['html'], $rendered['images']);

		return $app->malwatch_mailer->send((string) $config['binary_path'], $message, $sender, array($recipient), $global,
			isset($config['mail_smtp_verify']) ? (string) $config['mail_smtp_verify'] : 'y');
	}

	/**
	 * The HTML mail from its template: the values of the scan, the optional
	 * parts and every reported file (see malwatch_mail_html).
	 */
	public function render_html($file, $language, $scan, $findings, $worst, $auto, $subject, array $config)
	{
		$de = $language !== 'en';
		$panel = rtrim((string) $config['panel_url'], '/');
		$files = $this->finding_files($findings, (string) $scan['scan_path'], $panel, $language);
		$shown = array_slice($files, 0, self::MAIL_FILES_MAX);

		$quarantine = array_slice(array_map('strval', $auto), 0, 50);
		if (count($auto) > 50) {
			$quarantine[] = ($de ? '… und ' : '… and ') . (count($auto) - 50) . ($de ? ' weitere.' : ' more.');
		}
		$worst_word = $this->severity_word($worst, $de);
		$vars = array(
			'subject' => $subject,
			'preheader' => $de
				? count($files) . ' Datei(en) auf ' . $scan['domain'] . ' gemeldet, die schwerste mit Stufe ' . $worst_word . '.'
				: count($files) . ' file(s) reported on ' . $scan['domain'] . ', the most severe rated ' . $worst_word . '.',
			'domain' => (string) $scan['domain'],
			'hostname' => (string) php_uname('n'),
			'scan_time' => $this->format_time($scan['finished_at'], $de),
			'scan_path' => (string) $scan['scan_path'],
			'count' => (string) count($findings),
			'file_count' => (string) count($files),
			'worst' => (string) $worst,
			'worst_word' => $worst_word,
			'files_scanned' => $this->format_number($scan['files_scanned'], $de),
			'outdated' => (string) $scan['count_outdated'],
			'panel_url' => $panel === '' ? '' : $panel . '/index.php',
			'quarantine_count' => (string) count($auto),
			'more_count' => (string) (count($files) - count($shown)),
		);
		$blocks = array(
			'panel' => $panel !== '',
			'quarantine' => !empty($auto),
			'more' => count($files) > count($shown),
		);
		return malwatch_mail_html::render((string) file_get_contents($file), $vars, $blocks,
			array('quarantine_list' => $quarantine), $shown, dirname($file));
	}

	private function render($template, $language, $scan, $findings, $worst, $auto)
	{
		global $app;

		$file = $this->template_file($template, $language);
		if ($file === '') {
			return '';
		}

		$app->uses('malwatch_helper');
		$config = $app->malwatch_helper->get_config();
		$lines = $this->finding_lines($findings, (string) $scan['scan_path'], (string) $config['panel_url'], $language);

		$auto_lines = array();
		foreach (array_slice($auto, 0, 50) as $rel) {
			$auto_lines[] = '  ' . $rel;
		}
		if (count($auto) > 50) {
			$auto_lines[] = '  … und ' . (count($auto) - 50) . ' weitere.';
		}

		$panel = rtrim((string) $config['panel_url'], '/');
		$replace = array(
			'{panel_url}' => $panel === '' ? '' : $panel . '/index.php',
			'{domain}' => (string) $scan['domain'],
			'{hostname}' => (string) php_uname('n'),
			'{scan_time}' => $this->format_time($scan['finished_at'], $language !== 'en'),
			'{scan_path}' => (string) $scan['scan_path'],
			'{count}' => (string) count($findings),
			'{worst}' => (string) $worst,
			'{files_scanned}' => $this->format_number($scan['files_scanned'], $language !== 'en'),
			'{outdated}' => (string) $scan['count_outdated'],
			'{findings}' => implode("\n", $lines),
			'{quarantine}' => implode("\n", $auto_lines),
			'{quarantine_count}' => (string) count($auto),
		);

		$body = strtr((string) file_get_contents($file), $replace);

		// The paragraph about moved files applies only when this very run
		// queued something; a template written once for both cases needs a
		// way to leave it out on the others, which a plain strtr() cannot do.
		// The same for the link to the panel, which needs its address.
		$body = $this->strip_optional_block($body, 'panel', $panel !== '');
		return $this->strip_optional_block($body, 'quarantine', !empty($auto));
	}

	/** The most files a mail lists; the rest is a line with their number. */
	const MAIL_FILES_MAX = 25;

	/** The width the plain text mail is wrapped at. */
	const MAIL_WIDTH = 78;

	/**
	 * The reported files for a mail, worst first: per file its path below the
	 * scanned folder, its worst severity, the rules with their titles, why
	 * (the explanation of its worst rule), what to do, what the file does
	 * (its traits, dangerous ones first) and the link to its page in the
	 * panel, empty without the panel's address.
	 */
	public function finding_files(array $findings, $scan_path, $panel_url, $language = 'de')
	{
		$de = $language !== 'en';
		$files = array();
		foreach ($findings as $finding) {
			$path = (string) $finding['file_path'];
			if (!isset($files[$path])) {
				$files[$path] = array('rows' => array(), 'worst' => '', 'sha' => '', 'id' => 0);
			}
			$files[$path]['rows'][] = $finding;
			if ($this->severity_rank($finding['severity']) > $this->severity_rank($files[$path]['worst'])) {
				$files[$path]['worst'] = (string) $finding['severity'];
				$files[$path]['id'] = (int) $finding['finding_id'];
			}
			if ((string) $finding['file_sha256'] !== '') {
				$files[$path]['sha'] = strtolower((string) $finding['file_sha256']);
			}
		}
		$self = $this;
		uasort($files, function ($a, $b) use ($self) {
			return $self->severity_rank($b['worst']) - $self->severity_rank($a['worst']);
		});

		$base = rtrim((string) $scan_path, '/') . '/';
		$panel = rtrim((string) $panel_url, '/');
		$out = array();
		foreach ($files as $path => $file) {
			$rules = array();
			$worst_rule = null;
			foreach ($file['rows'] as $row) {
				$rule = $this->rule_row($row['rule_id'], $row['engine']);
				$rules[] = is_array($rule) && (string) $rule['title'] !== ''
					? $rule['title'] . ' (' . $row['rule_id'] . ')' : (string) $row['rule_id'];
				if ($row['severity'] === $file['worst'] && $worst_rule === null) {
					$worst_rule = $rule;
				}
			}
			$out[] = array(
				'path' => strpos($path, $base) === 0 ? substr($path, strlen($base)) : $path,
				'severity' => $file['worst'],
				'severity_word' => $this->severity_word($file['worst'], $de),
				'rules' => $rules,
				'why' => is_array($worst_rule) ? (string) $worst_rule['explanation'] : '',
				'advice' => is_array($worst_rule) ? (string) $worst_rule['advice'] : '',
				'traits' => $this->trait_labels($file['sha']),
				'link' => $panel !== '' && $file['id'] > 0 ? $panel . '/index.php#malwatch-finding-' . $file['id'] : '',
			);
		}
		return $out;
	}

	/**
	 * The new findings for the text mail, one block per file, worst first
	 * (see finding_files()), wrapped at MAIL_WIDTH.
	 */
	public function finding_lines(array $findings, $scan_path, $panel_url, $language = 'de')
	{
		$de = $language !== 'en';
		$files = $this->finding_files($findings, $scan_path, $panel_url, $language);
		$lines = array();
		foreach (array_slice($files, 0, self::MAIL_FILES_MAX) as $file) {
			$lines[] = '[' . $file['severity_word'] . '] ' . $file['path'];
			foreach ($file['rules'] as $rule) {
				$lines[] = '    ' . $rule;
			}
			if ($file['why'] !== '') {
				$lines = array_merge($lines, $this->wrap(($de ? 'Warum: ' : 'Why: ') . $file['why'], '    ', '           '));
			}
			if (count($file['traits']) > 0) {
				$lines = array_merge($lines, $this->wrap(($de ? 'Tut: ' : 'Does: ') . implode('; ', $file['traits']), '    ', '         '));
			}
			if ($file['link'] !== '') {
				$lines[] = '    ' . ($de ? 'Ansehen: ' : 'View: ') . $file['link'];
			}
			$lines[] = '';
		}
		if (count($files) > self::MAIL_FILES_MAX) {
			$lines[] = $de
				? '… und ' . (count($files) - self::MAIL_FILES_MAX) . ' weitere Datei(en).'
				: '… and ' . (count($files) - self::MAIL_FILES_MAX) . ' more file(s).';
		}
		return $lines;
	}

	/** A time from the database as the reader writes it: 29.09.2026, 18:20 or 2026-09-29 18:20. */
	public function format_time($value, $de)
	{
		$stamp = strtotime((string) $value);
		if ($stamp === false || $stamp <= 0) {
			return (string) $value;
		}
		return date($de ? 'd.m.Y, H:i' : 'Y-m-d H:i', $stamp);
	}

	/** A count with thousands separators: 38.619 or 38,619. */
	public function format_number($value, $de)
	{
		return number_format((float) $value, 0, $de ? ',' : '.', $de ? '.' : ',');
	}

	/** A severity in words, as the panel shows it. */
	private function severity_word($severity, $de)
	{
		$words = $de
			? array('critical' => 'kritisch', 'high' => 'hoch', 'medium' => 'mittel', 'low' => 'gering')
			: array('critical' => 'critical', 'high' => 'high', 'medium' => 'medium', 'low' => 'low');
		return isset($words[$severity]) ? $words[$severity] : (string) $severity;
	}

	/** Rank of a severity, 0 for an unknown one. */
	public function severity_rank($severity)
	{
		$ranks = array('low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4);
		return isset($ranks[$severity]) ? $ranks[$severity] : 0;
	}

	/**
	 * The row of a rule in malwatch_rule, or of its engine for the signature
	 * engines (engine:signature, engine:clamav), the way the finding page
	 * looks it up (malwatch_rule_explanation()).
	 */
	protected function rule_row($rule_id, $engine)
	{
		global $app;

		$row = $app->dbmaster->queryOneRecord(
			'SELECT title, explanation, advice FROM malwatch_rule WHERE rule_id = ?', (string) $rule_id);
		if ((!is_array($row) || (string) $row['explanation'] === '') && in_array($engine, array('signature', 'clamav'), true)) {
			$engine_row = $app->dbmaster->queryOneRecord(
				'SELECT title, explanation, advice FROM malwatch_rule WHERE rule_id = ?', 'engine:' . $engine);
			if (is_array($engine_row)) {
				if (is_array($row) && (string) $row['title'] !== '') {
					$engine_row['title'] = $row['title'];
				}
				return $engine_row;
			}
		}
		return is_array($row) ? $row : null;
	}

	/** The traits of a file content, dangerous first, at most five labels. */
	protected function trait_labels($sha)
	{
		global $app;

		if (!preg_match('/^[0-9a-f]{64}$/', (string) $sha)) {
			return array();
		}
		$row = $app->dbmaster->queryOneRecord('SELECT traits FROM malwatch_file WHERE file_sha256 = ?', $sha);
		$traits = is_array($row) ? json_decode((string) $row['traits'], true) : null;
		$order = array('risk' => 0, 'caution' => 1, 'guard' => 2, 'info' => 3);
		$labels = array();
		foreach (is_array($traits) ? $traits : array() as $trait) {
			if (is_array($trait) && isset($trait['label'], $trait['kind'], $order[$trait['kind']])) {
				$labels[] = array($order[$trait['kind']], (string) $trait['label']);
			}
		}
		usort($labels, function ($a, $b) {
			return $a[0] - $b[0];
		});
		$out = array();
		foreach (array_slice($labels, 0, 5) as $label) {
			$out[] = $label[1];
		}
		return $out;
	}

	/** Wraps $text at MAIL_WIDTH: $first before the first line, $rest before the others. */
	private function wrap($text, $first, $rest)
	{
		$out = array();
		$line = $first;
		foreach (preg_split('/\s+/u', trim((string) $text)) as $word) {
			$candidate = $line === $first || $line === $rest ? $line . $word : $line . ' ' . $word;
			if (mb_strlen($candidate, 'UTF-8') > self::MAIL_WIDTH && $line !== $first && $line !== $rest) {
				$out[] = $line;
				$line = $rest . $word;
				continue;
			}
			$line = $candidate;
		}
		$out[] = $line;
		return $out;
	}

	/**
	 * The mail template for a language: custom first, then the shipped one,
	 * German as fallback. $ext is txt for the text or html for the HTML mail.
	 */
	private function template_file($template, $language, $ext = 'txt')
	{
		global $conf;

		$language = preg_match('/^[a-z]{2}$/', (string) $language) ? $language : 'de';
		$ext = $ext === 'html' ? 'html' : 'txt';
		$candidates = array(
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_' . $language . '.' . $ext,
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_de.' . $ext,
			$conf['rootpath'] . '/conf/' . $template . '_' . $language . '.' . $ext,
			$conf['rootpath'] . '/conf/' . $template . '_de.' . $ext,
		);
		foreach ($candidates as $candidate) {
			if (is_file($candidate)) {
				return $candidate;
			}
		}
		return '';
	}

	/**
	 * Cuts a {name_block}...{/name_block} section out of $text, or leaves the
	 * section but drops its two marker lines when $keep is true.
	 */
	private function strip_optional_block($text, $name, $keep)
	{
		$open = '{' . $name . '_block}';
		$close = '{/' . $name . '_block}';
		if ($keep) {
			return str_replace(array($open . "\n", $close . "\n", $open, $close), '', $text);
		}
		return preg_replace('/' . preg_quote($open, '/') . '.*?' . preg_quote($close, '/') . '\n?/s', '', $text);
	}

	/** The job_source of the job that produced this scan, 'manual' when unreadable. */
	private function scan_job_source($scan)
	{
		global $app;

		$job = $app->dbmaster->queryOneRecord('SELECT job_source FROM malwatch_job WHERE job_id = ?',
			intval($scan['job_id']));

		return is_array($job) ? (string) $job['job_source'] : 'manual';
	}

	/** True when a job is already pending or running for a website. */
	private function job_queued($parent_domain_id)
	{
		global $app;

		$row = $app->dbmaster->queryOneRecord(
			"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
			intval($parent_domain_id));

		return is_array($row);
	}

	/**
	 * Selects which of this scan's new findings the operator's auto-action
	 * setting covers, as paths relative to the scan directory - exactly the
	 * form a quarantine job's file list takes.
	 *
	 * Kept apart from auto_quarantine() and free of side effects, so what a
	 * mode would move can be checked on its own before anything is moved.
	 */
	public function auto_paths($scan, $site, $config)
	{
		global $app;

		$inherit = !isset($site['auto_action']) || $site['auto_action'] === '' || $site['auto_action'] === 'inherit';
		$mode = (string) ($inherit
			? (isset($config['auto_action']) ? $config['auto_action'] : '')
			: $site['auto_action']);

		// Nur was ausdruecklich dasteht, handelt. Die Umkehrung - alles ausser
		// 'none' laeuft weiter - hat einen teuren Ausgang: es gibt Wege, auf
		// denen hier ein leerer Wert ankommt (eine malwatch_config-Zeile, die
		// noch nie durch die Einstellungsseite ging, ein Feld, das eine
		// aeltere Abfrage nicht mitliest), und ohne Regelfilter waere die
		// Folge, dass in dieser Nacht JEDER neue Fund verschwindet.
		if (!in_array($mode, array('safe', 'critical', 'preset'), true)) {
			return array();
		}

		$new = $this->new_findings($scan);
		if (empty($new)) {
			return array();
		}

		// null means "no rule filter", used by critical mode, which goes by
		// severity instead. safe and preset build a lookup of the rule ids
		// that qualify.
		$rule_ids = null;
		if ($mode === 'safe') {
			$rule_ids = array();
			$rows = $app->dbmaster->queryAllRecords("SELECT rule_id FROM malwatch_rule WHERE auto_safe = 'y'");
			foreach ((array) $rows as $row) {
				$rule_ids[$row['rule_id']] = true;
			}
		} elseif ($mode === 'preset') {
			$preset_id = intval($inherit ? $config['auto_preset_id'] : $site['auto_preset_id']);
			$preset = $preset_id > 0 ? $app->dbmaster->queryOneRecord(
				'SELECT rule_ids FROM malwatch_auto_preset WHERE preset_id = ?', $preset_id) : null;
			if (!is_array($preset)) {
				// preset mode without a preset that still exists moves
				// nothing - guessing which rules were meant would be worse
				// than leaving the files alone.
				return array();
			}
			$rule_ids = array();
			foreach (explode(',', (string) $preset['rule_ids']) as $id) {
				$id = trim($id);
				if ($id !== '') {
					$rule_ids[$id] = true;
				}
			}
		}

		return $this->select_auto($new, $mode, $rule_ids, (string) $scan['scan_path']);
	}

	/**
	 * The files of $new the automatic quarantine moves, relative to $base:
	 * by level in mode critical, by the rules of $rule_ids in the modes safe
	 * and preset. Only findings of a high level move: the scanner lowers a
	 * finding behind the capability and nonce checks of WordPress to medium,
	 * and such an admin action of a plugin is no way in to move without a look.
	 */
	public function select_auto(array $new, $mode, $rule_ids, $base)
	{
		$base = rtrim((string) $base, '/');
		$paths = array();
		foreach ($new as $finding) {
			if ($mode === 'critical' && $finding['severity'] !== 'critical') {
				continue;
			}
			if (!in_array($finding['severity'], array('high', 'critical'), true)) {
				continue;
			}
			if ($rule_ids !== null && !isset($rule_ids[$finding['rule_id']])) {
				continue;
			}
			$path = (string) $finding['file_path'];
			// The same boundary check malwatch_queue_quarantine() makes for a
			// manual selection: a finding outside the scan directory is not
			// supposed to happen, and reaching outside it silently would be
			// worse than skipping it.
			if ($base === '' || strpos($path, $base . '/') !== 0) {
				continue;
			}
			$paths[substr($path, strlen($base) + 1)] = true;
		}

		return array_keys($paths);
	}

	/**
	 * Queues the quarantine job an operator's auto-action setting calls for.
	 *
	 * Takes the selection run() already made - and, where a notification went
	 * out, already told someone about - instead of choosing again: the mail
	 * and the queued job must never end up describing two different sets of
	 * files. Only ever reached for a scheduled run (the caller checks
	 * job_source): a scan started by hand already has someone looking at the
	 * result, and that person decides what happens to the files, not the
	 * scanner.
	 */
	private function auto_quarantine($scan, $worst, $paths, $blocked)
	{
		global $app;

		if (empty($paths)) {
			return;
		}
		if ($blocked) {
			// Silence here would mean files a notification just promised were
			// moved are actually still sitting on the site with no record
			// saying why.
			$this->log_action($scan, 'quarantine', $worst, count($paths), (string) $scan['domain'],
				'Für diese Website läuft bereits ein Auftrag, die automatische Maßnahme wurde nicht eingereiht.');
			return;
		}

		$options = json_encode(array(
			'action' => 'add',
			'origin' => 'auto',
			'reason' => 'Automatische Maßnahme nach dem geplanten Lauf',
			'files' => $paths,
		));

		$app->dbmaster->query(
			'INSERT INTO malwatch_job (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_path, job_source, job_kind, job_status, options, created_at) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, 'schedule', 'quarantine', 'pending', ?, NOW())",
			intval($scan['sys_groupid']), intval($scan['server_id']), intval($scan['parent_domain_id']),
			(string) $scan['domain'], (string) $scan['scan_path'], $options);

		// The paths are the record of what happened to a customer's files
		// without anyone watching; better logged in full up to the cap than
		// left to be reconstructed later from a website that looks smaller.
		$this->log_action($scan, 'quarantine', $worst, count($paths), (string) $scan['domain'],
			implode("\n", array_slice($paths, 0, 50)));
	}

	/**
	 * Switches the website off through the datalog, the same way the core
	 * does when a site runs over its traffic quota. Going through the datalog
	 * is what makes the change visible in the panel and reversible there.
	 */
	private function disable_site($scan, $site, $findings, $worst)
	{
		global $app;

		$web = $app->dbmaster->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?',
			intval($scan['parent_domain_id']));

		if (!is_array($web)) {
			$this->log_action($scan, 'error', $worst, count($findings), '',
				'Die Website wurde nicht gefunden und konnte nicht abgeschaltet werden.');
			return;
		}
		if ($web['active'] === 'n') {
			// Already off. Saying so is more useful than a second identical
			// log entry claiming an action that changed nothing.
			$this->log_action($scan, 'disable_site', $worst, count($findings), (string) $web['domain'],
				'Die Website war bereits abgeschaltet.');
			return;
		}

		$app->dbmaster->datalogUpdate('web_domain', array('active' => 'n'), 'domain_id', intval($web['domain_id']));

		$this->log_action($scan, 'disable_site', $worst, count($findings), (string) $web['domain'],
			'Abgeschaltet wegen ' . count($findings) . ' neuer Fund(e), schwerster Fund: ' . $worst
			. '. Das Wiedereinschalten geschieht von Hand.');

		$app->log('malwatch: website ' . $web['domain'] . ' disabled after ' . count($findings)
			. ' new findings (' . $worst . ')', LOGLEVEL_WARN);
	}

	/**
	 * Tells the operator about an upgrade that did not end cleanly - an element
	 * taken back, one that failed, a site still broken after the rollback, a
	 * run that failed, or a run without a readable report ($upgrade_id 0) - and
	 * the customer as well when the website asks for it and an element is
	 * concerned. A run whose elements were all updated, or refused before
	 * anything changed, sends nothing; the page of the website shows it.
	 */
	public function notify_upgrade($job, $upgrade_id)
	{
		global $app;

		$app->uses('malwatch_helper,getconf');
		$helper = $app->malwatch_helper;

		$upgrade = null;
		$elements = array();
		if ($upgrade_id > 0) {
			$upgrade = $app->dbmaster->queryOneRecord(
				'SELECT * FROM malwatch_upgrade WHERE upgrade_id = ?', intval($upgrade_id));
			$elements = (array) $app->dbmaster->queryAllRecords(
				'SELECT * FROM malwatch_upgrade_element WHERE upgrade_id = ? '
				. "AND outcome IN ('rolled_back', 'failed', 'rollback_failed') ORDER BY element_id ASC",
				intval($upgrade_id));
		}
		$run_failed = !is_array($upgrade) || intval($upgrade['exit_code']) === 3;
		if (count($elements) === 0 && !$run_failed) {
			return;
		}

		$broken = false;
		foreach ($elements as $element) {
			if ((string) $element['outcome'] === 'rollback_failed') {
				$broken = true;
			}
		}
		$errors = is_array($upgrade) ? trim((string) $upgrade['errors'])
			: 'Der Lauf hat keinen lesbaren Bericht hinterlassen.';

		$web = $helper->get_web($job['parent_domain_id']);
		$site = $helper->get_site($job['parent_domain_id']);
		$config = $helper->get_config();
		$scan_like = array(
			'sys_groupid' => is_array($web) ? intval($web['sys_groupid']) : 0,
			'parent_domain_id' => intval($job['parent_domain_id']),
			'domain' => (string) $job['domain'],
			'scan_id' => 0,
		);

		$recipient = trim((string) $config['admin_email']);
		if ($recipient === '') {
			$global = $app->getconf->get_global_config('mail');
			$recipient = isset($global['admin_mail']) ? trim((string) $global['admin_mail']) : '';
		}
		if ($recipient === '') {
			$this->log_action($scan_like, 'error', '', count($elements), '',
				'Keine Empfängeradresse hinterlegt, die Meldung zum Update wurde nicht versendet.');
		} else {
			$this->send_upgrade_mail($scan_like, $config, $recipient, 'notify_admin', 'malwatch_upgrade_notification',
				'de', $this->upgrade_replacements($job, $elements, $errors, 'de'), count($elements), $broken);
		}

		if (count($elements) === 0 || !is_array($site) || (string) $site['notify_client'] !== 'y') {
			return;
		}
		$client = $app->dbmaster->queryOneRecord(
			'SELECT client.email, client.language FROM client, sys_group '
			. 'WHERE sys_group.client_id = client.client_id AND sys_group.groupid = ?',
			intval($scan_like['sys_groupid']));
		$client_mail = is_array($client) ? trim((string) $client['email']) : '';
		if ($client_mail === '') {
			$this->log_action($scan_like, 'error', '', count($elements), '',
				'Der Kunde hat keine E-Mail-Adresse, die Meldung zum Update wurde nicht versendet.');
			return;
		}
		$language = (string) $client['language'] !== '' ? (string) $client['language'] : 'de';
		$this->send_upgrade_mail($scan_like, $config, $client_mail, 'notify_client',
			'malwatch_client_upgrade_notification', $language,
			$this->upgrade_replacements($job, $elements, $errors, $language), count($elements), $broken);
	}

	/** The placeholders of an upgrade mail, the element lines in the language of the recipient. */
	private function upgrade_replacements($job, array $elements, $errors, $language)
	{
		$labels = array(
			'de' => array('rolled_back' => 'zurückgeholt', 'failed' => 'gescheitert, alter Stand zurück',
				'rollback_failed' => 'Website nach dem Zurückholen fehlerhaft'),
			'en' => array('rolled_back' => 'taken back', 'failed' => 'failed, previous state back',
				'rollback_failed' => 'website still broken after the rollback'),
		);
		$set = isset($labels[$language]) ? $labels[$language] : $labels['de'];

		$lines = array();
		foreach ($elements as $element) {
			$kind = (string) $element['element_kind'];
			$name = $kind === 'core' ? 'WordPress' : $kind . ' ' . (string) $element['slug'];
			$outcome = (string) $element['outcome'];
			$line = '  ' . $name . ' ' . $element['from_version'] . ' → ' . $element['to_version'] . ': '
				. (isset($set[$outcome]) ? $set[$outcome] : $outcome)
				. "\n      " . $element['install_path'];
			if ((string) $element['message'] !== '') {
				$line .= "\n      " . $element['message'];
			}
			$lines[] = $line;
		}
		return array(
			'{domain}' => (string) $job['domain'],
			'{hostname}' => (string) php_uname('n'),
			'{elements}' => implode("\n", $lines),
			'{errors}' => (string) $errors,
		);
	}

	/** Renders an upgrade template and hands it to the mailer of ISPConfig. */
	private function send_upgrade_mail(array $scan_like, $config, $recipient, $type, $template, $language,
		array $replace, $count, $broken)
	{
		global $app;

		$app->uses('getconf,functions');
		$global = $app->getconf->get_global_config('mail');
		$sender = trim((string) $config['sender_email']);
		if ($sender === '') {
			$sender = isset($global['admin_mail']) && $global['admin_mail'] !== '' ? $global['admin_mail'] : 'root';
		}

		$file = $this->template_file($template, $language);
		if ($file === '') {
			$this->log_action($scan_like, 'error', '', $count, $recipient, 'Die Mailvorlage ' . $template . ' fehlt.');
			return;
		}
		$body = strtr((string) file_get_contents($file), $replace);
		$body = $this->strip_optional_block($body, 'broken', $broken);
		$body = $this->strip_optional_block($body, 'errors', trim($replace['{errors}']) !== '');

		$subject = 'malwatch: Update auf ' . $scan_like['domain'];
		if (strpos($body, "\n\n") !== false) {
			list($headers, $text) = explode("\n\n", $body, 2);
			if (preg_match('/^Subject:\s*(.+)$/mi', $headers, $match)) {
				$subject = trim($match[1]);
			}
			$body = $text;
		}
		$app->functions->mail($recipient, $subject, $body, $sender);
		$this->log_action($scan_like, $type, '', $count, $recipient,
			'Meldung zum Update: ' . $count . ' Element(e) zurückgeholt oder gescheitert.');
	}

	private function log_action($scan, $type, $worst, $count, $recipient, $detail)
	{
		global $app, $conf;

		$app->dbmaster->query(
			'INSERT INTO malwatch_action_log (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, parent_domain_id, domain, scan_id, action_type, trigger_severity, trigger_findings, '
			. 'recipient, detail, created_at) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
			intval($scan['sys_groupid']), intval($conf['server_id']), intval($scan['parent_domain_id']),
			(string) $scan['domain'], intval($scan['scan_id']), $type, (string) $worst, intval($count),
			substr((string) $recipient, 0, 255), (string) $detail);
	}
}
