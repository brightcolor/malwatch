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
		$next = $app->malwatch_helper->next_run($site['schedule']);

		$app->dbmaster->query(
			'UPDATE malwatch_site SET last_scan_id = ?, last_run = ?, next_run = ?, open_findings = ?, '
			. 'worst_severity = ?, last_state = ? WHERE site_id = ?',
			intval($scan['scan_id']), $scan['finished_at'], $next, $count, $worst, $state, intval($site['site_id']));
	}

	/**
	 * Creates the settings row of a website with the defaults from the schema.
	 *
	 * Every column below the identity has a default, so the row is the plain
	 * "not configured, but scanned" state - which is exactly what a website
	 * is after a scan that nobody set up beforehand.
	 */
	private function create_site_row($scan)
	{
		global $app;

		$domain_id = intval($scan['parent_domain_id']);
		if ($domain_id < 1) {
			return null;
		}
		$app->dbmaster->query(
			'INSERT INTO malwatch_site (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
			. 'sys_perm_other, server_id, parent_domain_id, domain) '
			. "VALUES (1, 1, 'riud', 'riud', '', ?, ?, ?)",
			intval($scan['server_id']), $domain_id, (string) $scan['domain']);

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

		$app->uses('functions');
		$app->functions->mail($recipient, $subject, $body, $sender);

		$this->log_action($scan, $type, $worst, count($findings), $recipient, '');
	}

	private function render($template, $language, $scan, $findings, $worst, $auto)
	{
		$file = $this->template_file($template, $language);
		if ($file === '') {
			return '';
		}

		$lines = array();
		foreach (array_slice($findings, 0, 25) as $finding) {
			$lines[] = '  [' . $finding['severity'] . '] ' . $finding['rule_id'] . "\n      " . $finding['file_path'];
		}
		if (count($findings) > 25) {
			$lines[] = '  … und ' . (count($findings) - 25) . ' weitere.';
		}

		$auto_lines = array();
		foreach (array_slice($auto, 0, 50) as $rel) {
			$auto_lines[] = '  ' . $rel;
		}
		if (count($auto) > 50) {
			$auto_lines[] = '  … und ' . (count($auto) - 50) . ' weitere.';
		}

		$replace = array(
			'{domain}' => (string) $scan['domain'],
			'{hostname}' => (string) php_uname('n'),
			'{scan_time}' => (string) $scan['finished_at'],
			'{scan_path}' => (string) $scan['scan_path'],
			'{count}' => (string) count($findings),
			'{worst}' => (string) $worst,
			'{files_scanned}' => (string) $scan['files_scanned'],
			'{outdated}' => (string) $scan['count_outdated'],
			'{findings}' => implode("\n", $lines),
			'{quarantine}' => implode("\n", $auto_lines),
			'{quarantine_count}' => (string) count($auto),
		);

		$body = strtr((string) file_get_contents($file), $replace);

		// The paragraph about moved files applies only when this very run
		// queued something; a template written once for both cases needs a
		// way to leave it out on the others, which a plain strtr() cannot do.
		return $this->strip_optional_block($body, 'quarantine', !empty($auto));
	}

	/** The mail template for a language: custom first, then the shipped one, German as fallback. */
	private function template_file($template, $language)
	{
		global $conf;

		$language = preg_match('/^[a-z]{2}$/', (string) $language) ? $language : 'de';
		$candidates = array(
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_' . $language . '.txt',
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_de.txt',
			$conf['rootpath'] . '/conf/' . $template . '_' . $language . '.txt',
			$conf['rootpath'] . '/conf/' . $template . '_de.txt',
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

		$base = rtrim((string) $scan['scan_path'], '/');
		$paths = array();
		foreach ($new as $finding) {
			if ($mode === 'critical' && $finding['severity'] !== 'critical') {
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
