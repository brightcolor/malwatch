<?php

/**
 * Carries out what a website's settings ask for after a scan: notifications
 * and, if the operator asked for it, disabling the site.
 *
 * Three rules hold everywhere in this class:
 *
 *   - Only findings that are new since the last run can trigger an action.
 *     Otherwise a site would be disabled again on every nightly run for a
 *     problem the operator has already looked at.
 *   - Outdated software never disables anything. It is a maintenance matter,
 *     not a break-in.
 *   - A clean run never re-enables a site. Turning a customer's website back
 *     on is a decision for a person, not for a scanner.
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

		if ($site['notify_admin'] === 'y' && $helper->severity_at_least($worst, $site['notify_admin_severity'])) {
			$this->notify_admin($scan, $site, $config, $new, $worst);
		}
		if ($site['notify_client'] === 'y' && $helper->severity_at_least($worst, $site['notify_client_severity'])) {
			$this->notify_client($scan, $site, $config, $new, $worst);
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
		} elseif (intval($scan['count_outdated']) > 0) {
			$state = 'outdated';
		}

		if (!is_array($site)) {
			return;
		}

		$app->uses('malwatch_helper');
		$next = $app->malwatch_helper->next_run($site['schedule']);

		$app->dbmaster->query(
			'UPDATE malwatch_site SET last_scan_id = ?, last_run = ?, next_run = ?, open_findings = ?, '
			. 'worst_severity = ?, last_state = ? WHERE site_id = ?',
			intval($scan['scan_id']), $scan['finished_at'], $next, $count, $worst, $state, intval($site['site_id']));
	}

	private function notify_admin($scan, $site, $config, $findings, $worst)
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
		$this->send($scan, $site, $config, $findings, $worst, $recipient, 'notify_admin', 'malwatch_notification');
	}

	private function notify_client($scan, $site, $config, $findings, $worst)
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
		$this->send($scan, $site, $config, $findings, $worst, $recipient, 'notify_client',
			'malwatch_client_notification', $language);
	}

	/** Renders a template and hands it to ISPConfig's mailer. */
	private function send($scan, $site, $config, $findings, $worst, $recipient, $type, $template, $language = 'de')
	{
		global $app, $conf;

		$app->uses('getconf');
		$global = $app->getconf->get_global_config('mail');
		$sender = trim((string) $config['sender_email']);
		if ($sender === '') {
			$sender = isset($global['admin_mail']) && $global['admin_mail'] !== '' ? $global['admin_mail'] : 'root';
		}

		$body = $this->render($template, $language, $scan, $findings, $worst);
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

	private function render($template, $language, $scan, $findings, $worst)
	{
		global $conf;

		$language = preg_match('/^[a-z]{2}$/', (string) $language) ? $language : 'de';
		$candidates = array(
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_' . $language . '.txt',
			$conf['rootpath'] . '/conf-custom/mail/' . $template . '_de.txt',
			$conf['rootpath'] . '/conf/' . $template . '_' . $language . '.txt',
			$conf['rootpath'] . '/conf/' . $template . '_de.txt',
		);
		$file = '';
		foreach ($candidates as $candidate) {
			if (is_file($candidate)) {
				$file = $candidate;
				break;
			}
		}
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
		);

		return strtr((string) file_get_contents($file), $replace);
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
