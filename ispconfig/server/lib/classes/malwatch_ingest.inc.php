<?php

/**
 * Reads a finished scan report and turns it into rows.
 */
class malwatch_ingest
{
	/** The report format this class understands. */
	const SCHEMA = 1;

	/**
	 * The two enum columns of malwatch_quarantine whose value arrives from the
	 * scanner's JSON rather than from a literal in this file. Kept here as
	 * lists so install/schema.sql stays the one place that decides what is
	 * allowed - check 38 in tests/check_wiring.sh compares the two.
	 */
	private static $entry_kinds = array('file', 'dir');
	private static $origins = array('manual', 'auto', 'repair');

	/**
	 * Ingests the result of one job. Returns the scan id, or 0 on failure.
	 */
	public function ingest($job)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		if ($file === '' || !is_file($file)) {
			$helper->fail_job($job['job_id'], 'Der Scanner hat keinen Bericht hinterlassen. '
				. $this->tail_log($job) );
			return 0;
		}

		$raw = file_get_contents($file);
		$report = json_decode((string) $raw, true);
		if (!is_array($report) || !isset($report['schema'])) {
			$helper->fail_job($job['job_id'], 'Der Bericht ist unlesbar. ' . $this->tail_log($job));
			return 0;
		}
		if (intval($report['schema']) !== self::SCHEMA) {
			// A newer scanner writing an unknown format must not be parsed by
			// guesswork; half understood findings are worse than none.
			$helper->fail_job($job['job_id'], 'Der Bericht hat Format ' . intval($report['schema'])
				. ', erwartet wird ' . self::SCHEMA . '. Bitte Erweiterung und Scanner auf denselben Stand bringen.');
			return 0;
		}

		$web = $helper->get_web($job['parent_domain_id']);
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;

		$scan_id = $this->store_scan($job, $report, $sys_groupid);
		if ($scan_id === 0) {
			$helper->fail_job($job['job_id'], 'Der Bericht konnte nicht gespeichert werden.');
			return 0;
		}

		$new_findings = $this->store_findings($job, $report, $scan_id, $sys_groupid);
		$this->store_software($job, $report, $scan_id, $sys_groupid);

		$app->dbmaster->query('UPDATE malwatch_scan SET new_findings = ? WHERE scan_id = ?',
			$new_findings, $scan_id);

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW(), job_log = ? WHERE job_id = ?",
			'Bericht eingelesen, Prüflauf ' . $scan_id . '.', $job['job_id']);

		// The report names infected paths of a customer. It is not kept around
		// after it has been read into the database.
		@unlink($file);
		@unlink(preg_replace('/\.json$/', '.log', $file));

		return $scan_id;
	}

	/** Writes the malwatch_scan row and returns its id. */
	/**
	 * Reads the report of a restore into malwatch_repair and its elements.
	 *
	 * Returns the repair_id, or 0 when there was nothing readable to read.
	 */
	public function ingest_repair($job)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		$report = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
		if (!is_array($report) || !isset($report['schema'])) {
			$helper->fail_job($job['job_id'], 'Die Wiederherstellung hat keinen lesbaren Bericht hinterlassen. '
				. $this->tail_log($job));
			return 0;
		}

		$web = $helper->get_web($job['parent_domain_id']);
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;

		$counts = array('replaced' => 0, 'deleted' => 0, 'failed' => 0);
		foreach ((array) (isset($report['elements']) ? $report['elements'] : array()) as $element) {
			$outcome = (string) $element['outcome'];
			if ($outcome === 'replaced') {
				$counts['replaced']++;
			} elseif ($outcome === 'deleted-no-origin') {
				$counts['deleted']++;
			} elseif ($outcome === 'failed') {
				$counts['failed']++;
			}
		}

		$app->dbmaster->query(
			'INSERT INTO malwatch_repair (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
			. 'sys_perm_other, server_id, job_id, parent_domain_id, domain, started_at, finished_at, '
			. 'dry_run, backup_dir, count_replaced, count_deleted, count_failed, exit_code, raw_report) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$sys_groupid, intval($job['server_id']), intval($job['job_id']),
			intval($job['parent_domain_id']), (string) $job['domain'],
			$this->to_datetime(isset($report['started_at']) ? $report['started_at'] : ''),
			$this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : ''),
			!empty($report['dry_run']) ? 'y' : 'n',
			(string) (isset($report['backup_dir']) ? $report['backup_dir'] : ''),
			$counts['replaced'], $counts['deleted'], $counts['failed'],
			intval($job['exit_code']), (string) file_get_contents($file));

		$repair_id = intval($app->dbmaster->insertID());

		foreach ((array) (isset($report['elements']) ? $report['elements'] : array()) as $element) {
			$app->dbmaster->query(
				'INSERT INTO malwatch_repair_element (sys_userid, sys_groupid, sys_perm_user, '
				. 'sys_perm_group, sys_perm_other, server_id, repair_id, parent_domain_id, '
				. 'element_kind, slug, element_version, outcome, files, backup, message) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($job['server_id']), $repair_id, intval($job['parent_domain_id']),
				(string) $element['kind'], (string) (isset($element['slug']) ? $element['slug'] : ''),
				(string) $element['version'], (string) $element['outcome'],
				intval(isset($element['files']) ? $element['files'] : 0),
				(string) (isset($element['backup']) ? $element['backup'] : ''),
				substr((string) (isset($element['message']) ? $element['message'] : ''), 0, 255));
		}

		// A repair alone never runs the quarantine binary, so nothing else
		// would index what it archived. The next quarantine job's full-list
		// sync (sync_quarantine) will find the same entry_id later and leave
		// it alone - but only once such a job actually runs for this server.
		foreach ((array) (isset($report['elements']) ? $report['elements'] : array()) as $element) {
			// Eine Liste, kein einzelner Wert: eine Kernreparatur legt
			// wp-admin, wp-includes und jede geänderte lose Kerndatei je
			// einzeln ab. Aus mehreren Kennungen eine Zeile zu machen hieße,
			// eine Zeile unter einer Kennung anzulegen, die im Speicher
			// nichts benennt - und die restlichen Einträge gar nicht.
			$ids = isset($element['quarantine_ids']) && is_array($element['quarantine_ids'])
				? $element['quarantine_ids'] : array();

			// Nur wenn das Element genau einen Eintrag erzeugt hat, ist der
			// Eintrag das Element - dann stimmen Pfad, Art und Dateizahl. Bei
			// mehreren weiß der Bericht nicht, welche Kennung welchen Teil
			// benennt: eine Kernreparatur legt wp-admin, wp-includes und jede
			// geänderte lose Kerndatei je einzeln ab, und $element['path'] ist
			// für den Kern der Webstamm selbst. Fünf Zeilen, die alle
			// denselben (absoluten, also nicht relativen) Pfad nennen und sich
			// alle 'dir' schimpfen, sind keine Auskunft, sondern eine falsche;
			// leer bleiben ist ehrlicher, bis die Liste des Speichers sie
			// nachträgt.
			$describes_element = count($ids) === 1 && (string) $element['kind'] !== 'core';
			$rel_path = '';
			// Der Vorgabewert der Spalte, solange nichts Genaueres bekannt
			// ist; beide Werte stehen in self::$entry_kinds, das Pruefung 38
			// in tests/check_wiring.sh gegen schema.sql haelt.
			$entry_kind = 'file';
			$files = 0;
			if ($describes_element) {
				$root = rtrim((string) $job['scan_path'], '/');
				$abs = (string) (isset($element['path']) ? $element['path'] : '');
				$rel_path = (strpos($abs, $root . '/') === 0) ? substr($abs, strlen($root) + 1) : '';
				// Ein einzeln abgelegtes Element ist immer sein Verzeichnis -
				// ein Plugin, ein Theme (internal/repair: quarantineElement
				// legt el.Path ab).
				$entry_kind = 'dir';
				$files = intval(isset($element['files']) ? $element['files'] : 0);
			}

			foreach ($ids as $entry_id) {
				$entry_id = (string) $entry_id;
				if ($entry_id === '') {
					continue;
				}
				$existing = $app->dbmaster->queryOneRecord(
					'SELECT quarantine_id FROM malwatch_quarantine WHERE server_id = ? AND entry_id = ?',
					intval($job['server_id']), $entry_id);
				if (is_array($existing)) {
					continue;
				}

				// The exact Reason string Store was called with never reaches
				// this report - only the id it handed back does - but every
				// element the run archived took one of these two sentences,
				// keyed on the run's own mode.
				$reason = ((string) (isset($report['mode']) ? $report['mode'] : '')) === 'overlay'
					? 'Vor dem Darüberschreiben abgelegt'
					: 'Beim Ersetzen durch das Original abgelegt';

				// Größe bleibt hier vorläufig: die kennt nur die Liste des
				// Speichers, und die holt complete_quarantine_index() binnen
				// einer Minute über sync_quarantine nach - archive_bytes = 0
				// findet genau diese Zeilen. Bis dahin ist die Zeile
				// auffindbar, nur nicht vollständig.
				$app->dbmaster->query(
					'INSERT INTO malwatch_quarantine (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
					. 'sys_perm_other, server_id, parent_domain_id, domain, entry_id, entry_kind, rel_path, '
					. "origin, reason, rule_id, severity, files, bytes, created_at) "
					. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, 'repair', ?, '', '', ?, 0, ?)",
					$sys_groupid, intval($job['server_id']), intval($job['parent_domain_id']), (string) $job['domain'],
					$entry_id, $entry_kind, $rel_path, $reason, $files,
					$this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : ''));
			}
		}

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW() WHERE job_id = ?",
			intval($job['job_id']));
		return $repair_id;
	}

	/**
	 * Reads the result of a quarantine job and brings malwatch_quarantine
	 * back in step with the store, then marks any findings it removed.
	 *
	 * The report is always the store's complete list, never a diff of what
	 * this one job did (see sync_quarantine) - that is what lets the index
	 * heal itself run after run, whichever job or operator made an entry
	 * disappear.
	 */
	public function ingest_quarantine($job)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		if ($file === '' || !is_file($file)) {
			$helper->fail_job($job['job_id'], 'Die Quarantäne hat keinen Bericht hinterlassen. '
				. $this->tail_log($job));
			return 0;
		}

		$report = json_decode((string) file_get_contents($file), true);
		if (!is_array($report) || !isset($report['schema']) || intval($report['schema']) !== self::SCHEMA) {
			$helper->fail_job($job['job_id'], 'Der Bericht ist unlesbar. ' . $this->tail_log($job));
			return 0;
		}

		$entries = isset($report['entries']) && is_array($report['entries']) ? $report['entries'] : array();
		$skipped = isset($report['skipped']) ? intval($report['skipped']) : 0;
		$skipped_ids = isset($report['skipped_ids']) && is_array($report['skipped_ids'])
			? $report['skipped_ids'] : array();
		$server_id = intval($job['server_id']);

		$options = json_decode((string) $job['options'], true);
		if (!is_array($options)) {
			$options = array();
		}
		$action = isset($options['action']) ? (string) $options['action'] : 'add';
		$asked_for = isset($options['ids']) && is_array($options['ids']) ? $options['ids'] : array();

		// Read before the sync, because the sync is what removes the rows of
		// everything that has just left the store - and the website and path
		// on those rows are the only way back to the findings they belong to.
		$restoring = $action === 'restore' ? $this->indexed_rows($server_id, $asked_for) : array();

		$this->sync_quarantine($server_id, $entries, $skipped, $skipped_ids);

		if ($action === 'restore') {
			$this->reopen_restored($server_id, $restoring);
		}

		// Marking the finding fixed happens from the job itself, right away
		// - otherwise a finding list left open would still show it until
		// the next scheduled scan runs. Only an 'add' job ever populates
		// options['files'], so this is a no-op for the other actions.
		$base = rtrim((string) $job['scan_path'], '/');
		foreach ((array) (isset($options['files']) ? $options['files'] : array()) as $rel) {
			$full = $base . '/' . ltrim((string) $rel, '/');
			if (is_file($full)) {
				// Still there: the binary refused it or failed on it, and
				// calling the finding fixed would be a lie.
				continue;
			}
			$app->dbmaster->query(
				"UPDATE malwatch_finding SET finding_state = 'fixed' WHERE parent_domain_id = ? "
				. "AND file_path = ? AND finding_state IN ('open','ignored')",
				intval($job['parent_domain_id']), $full);
		}

		// Everything above is worth doing whatever the exit code says: the
		// scanner writes the complete listing before it reports a failure, so
		// the index heals either way. What must not happen is the job standing
		// as 'done' afterwards - an entry that never came back would then sit
		// in the list with nothing anywhere saying why, which is exactly how
		// "Der Eintrag wird zurückgeholt." became a sentence about nothing.
		if (intval($job['exit_code']) !== 0) {
			$helper->fail_job($job['job_id'],
				$this->quarantine_failure($action) . ' ' . $this->tail_log($job));
			return 0;
		}

		if ($action === 'export') {
			$this->finish_export($server_id, $options);
		}

		$app->dbmaster->query(
			"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW() WHERE job_id = ?",
			intval($job['job_id']));
		return count($entries);
	}

	/** What to tell the operator when a quarantine job ended badly. */
	private function quarantine_failure($action)
	{
		if ($action === 'restore') {
			return 'Es konnte nicht alles zurückgeholt werden. Was noch in der Liste steht, liegt weiter in Quarantäne.';
		}
		if ($action === 'delete') {
			return 'Es konnte nicht alles endgültig gelöscht werden. Was noch in der Liste steht, liegt weiter in Quarantäne.';
		}
		if ($action === 'export') {
			return 'Das ZIP konnte nicht gepackt werden. Es steht nichts zum Herunterladen bereit.';
		}
		return 'Es konnte nicht alles in die Quarantäne verschoben werden.';
	}

	/**
	 * The indexed rows behind a list of entry ids.
	 *
	 * Only ever called before sync_quarantine(): afterwards the rows of
	 * everything that actually left the store are gone, and with them the
	 * website and the path that say which findings the entry covered.
	 */
	private function indexed_rows($server_id, array $ids)
	{
		global $app;

		$rows = array();
		foreach ($ids as $entry_id) {
			$entry_id = (string) $entry_id;
			if ($entry_id === '') {
				continue;
			}
			$row = $app->dbmaster->queryOneRecord(
				'SELECT entry_id, entry_kind, parent_domain_id, rel_path FROM malwatch_quarantine '
				. 'WHERE server_id = ? AND entry_id = ?',
				intval($server_id), $entry_id);
			if (is_array($row)) {
				$rows[] = $row;
			}
		}
		return $rows;
	}

	/**
	 * Undoes on the finding list what a restore has just undone on the disk.
	 *
	 * Moving a file to quarantine marks its finding 'fixed' and leaves the
	 * website "sauber" in the overview. Putting the same file back makes both
	 * statements untrue, and nothing else in the extension notices: the state
	 * is only ever recalculated from a scan, so on the monthly schedule the
	 * panel would call an active backdoor a solved problem for up to a month.
	 *
	 * An entry still in the index after the sync was not restored - the binary
	 * refused it or failed on it - so its finding is left exactly as it was.
	 */
	private function reopen_restored($server_id, array $rows)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$domains = array();
		foreach ($rows as $row) {
			$still_held = $app->dbmaster->queryOneRecord(
				'SELECT quarantine_id FROM malwatch_quarantine WHERE server_id = ? AND entry_id = ?',
				intval($server_id), (string) $row['entry_id']);
			if (is_array($still_held)) {
				continue;
			}

			$domain_id = intval($row['parent_domain_id']);
			if ($domain_id < 1) {
				// An entry whose website could not be resolved when it was
				// indexed. The file is back, but there is no finding list it
				// belongs to and no site row to correct.
				continue;
			}
			$domains[$domain_id] = true;

			$web = $helper->get_web($domain_id);
			$base = is_array($web) ? rtrim($helper->scan_path($web), '/') : '';
			if ($base === '') {
				continue;
			}

			$rel_path = ltrim((string) $row['rel_path'], '/');
			if ($rel_path === '') {
				// Eine Zeile, die eine Reparatur angelegt hat und die Liste
				// des Speichers noch nicht vervollständigt hat (ingest_repair:
				// bei mehreren Einträgen je Element ist der Pfad unbekannt).
				// Ohne Pfad gibt es keinen Fund, der dazu gehört - und die
				// Alternative wäre ein LIKE auf den ganzen Webstamm.
				continue;
			}
			$full = $base . '/' . $rel_path;

			// Only 'fixed' is reversed. 'ignored' is a person having decided
			// this file is fine, and a restore is not an argument against it.
			if ((string) $row['entry_kind'] === 'dir') {
				// A directory came back with everything under it, so every
				// finding below that path did too.
				$app->dbmaster->query(
					"UPDATE malwatch_finding SET finding_state = 'open' WHERE parent_domain_id = ? "
					. "AND file_path LIKE ? ESCAPE '!' AND finding_state = 'fixed'",
					$domain_id, $this->like_prefix($full . '/'));
				continue;
			}
			$app->dbmaster->query(
				"UPDATE malwatch_finding SET finding_state = 'open' WHERE parent_domain_id = ? "
				. "AND file_path = ? AND finding_state = 'fixed'",
				$domain_id, $full);
		}

		foreach (array_keys($domains) as $domain_id) {
			$this->refresh_site_state($domain_id);
		}
	}

	/**
	 * A path as the literal beginning of a LIKE pattern.
	 *
	 * A real directory name may hold % or _, which LIKE would otherwise read
	 * as "anything" - a website whose folder is called uploads_2021 would
	 * reopen the findings of uploadsX2021 next to it.
	 */
	private function like_prefix($path)
	{
		return str_replace(array('!', '%', '_'), array('!!', '!%', '!_'), (string) $path) . '%';
	}

	/**
	 * Recalculates what a website's row claims about it after something came
	 * back out of quarantine.
	 *
	 * Deliberately not malwatch_actions::update_site_state(): that one
	 * describes a scan and writes last_scan_id, last_run and next_run along
	 * with the state. A restore is not a scan, and saying one just ran would
	 * put a second untrue statement on the row this method is here to correct.
	 */
	private function refresh_site_state($parent_domain_id)
	{
		global $app;

		$parent_domain_id = intval($parent_domain_id);
		$site = $app->dbmaster->queryOneRecord(
			'SELECT site_id FROM malwatch_site WHERE parent_domain_id = ?', $parent_domain_id);
		if (!is_array($site)) {
			// Without a settings row there is nothing claiming anything: a
			// website nobody ever configured shows as "ungeprüft" anyway.
			return;
		}

		$open = $app->dbmaster->queryOneRecord(
			"SELECT COUNT(*) AS n, MAX(FIELD(severity, 'low', 'medium', 'high', 'critical')) AS worst "
			. "FROM malwatch_finding WHERE parent_domain_id = ? AND finding_state = 'open'",
			$parent_domain_id);

		$count = is_array($open) ? intval($open['n']) : 0;
		$worst = '';
		if (is_array($open) && intval($open['worst']) > 0) {
			$names = malwatch_helper::$severities;
			$index = intval($open['worst']) - 1;
			if (isset($names[$index])) {
				$worst = $names[$index];
			}
		}

		$app->dbmaster->query(
			'UPDATE malwatch_site SET open_findings = ?, worst_severity = ?, last_state = ? WHERE site_id = ?',
			$count, $worst, $this->restored_site_state($count), intval($site['site_id']));
	}

	/**
	 * What malwatch_site.last_state says once a file has been put back onto a
	 * website. Both values are members of that column's enum in
	 * install/schema.sql; check 38 in tests/check_wiring.sh reads them here
	 * and compares them against it.
	 */
	private function restored_site_state($open_findings)
	{
		if ($open_findings > 0) {
			return 'findings';
		}
		// Nothing left to point at - the finding was swept up by the ninety
		// day housekeeping, or the entry never had one. A file this extension
		// had taken off the website is nonetheless back on it and no scan has
		// looked since: 'clean' would be a claim with nothing behind it.
		return 'unknown';
	}

	/**
	 * Brings malwatch_quarantine back in step with what the store actually
	 * holds for one server.
	 *
	 * entries is always the store's complete list (see ingest_quarantine),
	 * so an entry_id missing from it is gone regardless of which job took
	 * it out - restore, delete, or an export that happened to run last. A
	 * row already on file is left untouched: rewriting it here would throw
	 * away an export_token a download link may still be waiting on.
	 *
	 * skipped_ids names the entry directories the listing could not read.
	 * Only the log ever sees them, and that is the point: without a name
	 * there is no way to reach the one directory that is holding the whole
	 * index back (see the branch below).
	 */
	public function sync_quarantine($server_id, $entries, $skipped = 0, $skipped_ids = array())
	{
		global $app;

		$server_id = intval($server_id);
		$skipped = intval($skipped);

		$known = array();
		$rows = $app->dbmaster->queryAllRecords(
			'SELECT entry_id FROM malwatch_quarantine WHERE server_id = ?', $server_id);
		if (is_array($rows)) {
			foreach ($rows as $row) {
				$known[(string) $row['entry_id']] = true;
			}
		}

		$seen = array();
		foreach ((array) $entries as $entry) {
			$entry_id = isset($entry['id']) ? (string) $entry['id'] : '';
			if ($entry_id === '') {
				continue;
			}
			$seen[$entry_id] = true;

			if (isset($known[$entry_id])) {
				// Refreshed, not left alone: a row inserted from a repair
				// report knows only the entry id, so its size and reason stay
				// at zero until a listing fills them in - and those rows are
				// the big ones. What must survive an update is the export
				// state, because a download may be waiting on that token.
				$this->update_quarantine_row($server_id, $entry);
				continue;
			}
			$this->insert_quarantine_row($server_id, $entry);
		}

		// Aufräumen nur, wenn die Liste vollständig ist. Sie ist es nicht,
		// wenn der Scanner Einträge überspringen musste - dann hieße "steht
		// nicht in der Liste" nicht "ist weg", sondern "war gerade nicht
		// lesbar", und die Zeile verschwände aus dem Panel, während der
		// Eintrag samt Schadcode auf der Platte liegen bleibt.
		//
		// Die Kennungen stehen mit in der Zeile, weil dieser Zustand keinen
		// Ausgang von selbst hat: solange das eine kaputte Verzeichnis liegen
		// bleibt, bleibt der Index dauerhaft veraltet, und ohne Namen findet
		// niemand unter Hunderten gleich aussehender Verzeichnisse das eine,
		// um das es geht.
		if ($skipped > 0) {
			$names = array();
			foreach ((array) $skipped_ids as $skipped_id) {
				$skipped_id = (string) $skipped_id;
				if ($skipped_id !== '') {
					$names[] = $skipped_id;
				}
			}
			$app->log('malwatch: ' . $skipped . ' Quarantäneeintrag/-einträge waren nicht lesbar; '
				. 'der Index wird diesmal nur ergänzt, nicht bereinigt.'
				. (count($names) > 0 ? ' Betroffen: ' . implode(', ', $names) . '.' : ''), LOGLEVEL_WARN);
			return;
		}

		// Zweite Bremse, unabhängig von der ersten: eine leere Liste löscht
		// nichts, solange die Datenbank für diesen Server Zeilen kennt. Ein
		// vorhandenes, aber leeres Speicherverzeichnis meldet weder einen
		// Fehler noch übersprungene Einträge - es entsteht genau so, wenn in
		// den Einstellungen ein anderes Arbeitsverzeichnis eingetragen wird
		// und der nächste Auftrag es sich selbst anlegt. Ohne diese Bremse
		// verschwände der ganze Index in einem Lauf, während die Archive
		// unberührt unter dem alten Pfad liegen.
		if (count($seen) === 0 && count($known) > 0) {
			$app->log('malwatch: die Quarantäneliste ist leer, der Index kennt aber '
				. count($known) . ' Eintrag/Einträge für diesen Server; es wird nichts gelöscht. '
				. 'Zeigt "Arbeitsverzeichnis" noch auf den Speicher, in dem sie liegen?', LOGLEVEL_WARN);
			return;
		}

		foreach (array_keys($known) as $entry_id) {
			if (!isset($seen[$entry_id])) {
				$app->dbmaster->query(
					'DELETE FROM malwatch_quarantine WHERE server_id = ? AND entry_id = ?',
					$server_id, $entry_id);
			}
		}
	}

	/**
	 * Brings an indexed row up to date with the store's own listing.
	 *
	 * Everything the store knows is authoritative; export_token, export_bytes
	 * and export_ready_at are not its business and stay where they are.
	 */
	private function update_quarantine_row($server_id, $entry)
	{
		global $app;

		$app->dbmaster->query(
			'UPDATE malwatch_quarantine SET entry_kind = ?, rel_path = ?, origin = ?, reason = ?, '
			. 'rule_id = ?, severity = ?, files = ?, bytes = ?, archive_bytes = ? '
			. 'WHERE server_id = ? AND entry_id = ?',
			$this->enum_value(isset($entry['entry_kind']) ? $entry['entry_kind'] : '', self::$entry_kinds, 'file'),
			substr((string) (isset($entry['rel_path']) ? $entry['rel_path'] : ''), 0, 1024),
			$this->enum_value(isset($entry['origin']) ? $entry['origin'] : '', self::$origins, 'manual'),
			substr((string) (isset($entry['reason']) ? $entry['reason'] : ''), 0, 255),
			(string) (isset($entry['rule_id']) ? $entry['rule_id'] : ''),
			substr((string) (isset($entry['severity']) ? $entry['severity'] : ''), 0, 10),
			intval(isset($entry['files']) ? $entry['files'] : 0),
			intval(isset($entry['bytes']) ? $entry['bytes'] : 0),
			intval(isset($entry['archive_bytes']) ? $entry['archive_bytes'] : 0),
			intval($server_id), (string) $entry['id']);
	}

	/**
	 * An enum value out of the scanner's report, or the column's own default.
	 *
	 * Every other enum this class writes is a literal a few lines above the
	 * query; these two arrive as JSON. A store entry filed by a call from the
	 * command line can carry an origin the column does not know, and MySQL in
	 * strict mode does not write a lenient row for that - it refuses the whole
	 * INSERT, and the entry is then never indexed at all.
	 */
	private function enum_value($value, array $allowed, $default)
	{
		$value = (string) $value;
		return in_array($value, $allowed, true) ? $value : $default;
	}

	/** Inserts one row from a store entry, as the scanner's report describes it. */
	private function insert_quarantine_row($server_id, $entry)
	{
		global $app;

		$domain = isset($entry['domain']) ? (string) $entry['domain'] : '';
		// A miss here is not an error: the entry is still valid with
		// parent_domain_id 0, just not click-through-able to a website.
		$web = $domain !== '' ? $app->dbmaster->queryOneRecord(
			'SELECT domain_id, sys_groupid FROM web_domain WHERE domain = ?', $domain) : null;
		$parent_domain_id = is_array($web) ? intval($web['domain_id']) : 0;
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;

		$app->dbmaster->query(
			'INSERT INTO malwatch_quarantine (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
			. 'sys_perm_other, server_id, parent_domain_id, domain, entry_id, entry_kind, rel_path, '
			. 'origin, reason, rule_id, severity, files, bytes, archive_bytes, created_at) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$sys_groupid, $server_id, $parent_domain_id, $domain,
			(string) (isset($entry['id']) ? $entry['id'] : ''),
			$this->enum_value(isset($entry['entry_kind']) ? $entry['entry_kind'] : '', self::$entry_kinds, 'file'),
			substr((string) (isset($entry['rel_path']) ? $entry['rel_path'] : ''), 0, 1024),
			$this->enum_value(isset($entry['origin']) ? $entry['origin'] : '', self::$origins, 'manual'),
			substr((string) (isset($entry['reason']) ? $entry['reason'] : ''), 0, 255),
			(string) (isset($entry['rule_id']) ? $entry['rule_id'] : ''),
			substr((string) (isset($entry['severity']) ? $entry['severity'] : ''), 0, 10),
			intval(isset($entry['files']) ? $entry['files'] : 0),
			intval(isset($entry['bytes']) ? $entry['bytes'] : 0),
			intval(isset($entry['archive_bytes']) ? $entry['archive_bytes'] : 0),
			$this->to_datetime(isset($entry['created_at']) ? $entry['created_at'] : ''));
	}

	/**
	 * Records that an exported ZIP is ready to download.
	 *
	 * The token is the same one build_arguments() put into the file name -
	 * this is the only place that needs to know the spool layout, so the
	 * download page can work from the token alone and never see a path.
	 */
	private function finish_export($server_id, $options)
	{
		global $app;

		$token = isset($options['token']) ? (string) $options['token'] : '';
		$ids = isset($options['ids']) && is_array($options['ids']) ? $options['ids'] : array();
		if ($token === '' || count($ids) === 0) {
			return;
		}

		$config = $app->malwatch_helper->get_config();
		$zip = rtrim((string) $config['state_dir'], '/') . '/spool/' . $token . '.zip';
		if (!is_file($zip)) {
			// The scanner reported success but left no file behind - do not
			// hand the download page a token nothing backs.
			return;
		}

		// One ZIP holds the whole selection, so every row of that selection
		// carries the same token: whichever row the operator clicks, the same
		// file comes back, and clearing one token after the download clears
		// the offer everywhere it was shown.
		$bytes = filesize($zip);
		foreach ($ids as $entry_id) {
			$entry_id = (string) $entry_id;
			if ($entry_id === '') {
				continue;
			}
			$app->dbmaster->query(
				'UPDATE malwatch_quarantine SET export_token = ?, export_bytes = ?, export_ready_at = NOW() '
				. 'WHERE server_id = ? AND entry_id = ?',
				$token, $bytes, $server_id, $entry_id);
		}
	}

	private function store_scan($job, $report, $sys_groupid)
	{
		global $app, $conf;

		$counts = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0);
		$findings = isset($report['findings']) && is_array($report['findings']) ? $report['findings'] : array();
		foreach ($findings as $finding) {
			$severity = isset($finding['severity']) ? (string) $finding['severity'] : 'medium';
			if (isset($counts[$severity])) {
				$counts[$severity]++;
			}
		}

		$outdated = 0;
		$software = isset($report['software']) && is_array($report['software']) ? $report['software'] : array();
		foreach ($software as $entry) {
			if (!empty($entry['outdated'])) {
				$outdated++;
			}
		}

		$started = $this->to_datetime(isset($report['started_at']) ? $report['started_at'] : '');
		$finished = $this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : '');
		$duration = 0;
		if ($started !== null && $finished !== null) {
			$duration = max(0, strtotime($finished) - strtotime($started));
		}

		$state = 'clean';
		if (array_sum($counts) > 0) {
			$state = 'findings';
		} elseif ($outdated > 0) {
			$state = 'outdated';
		}

		$stats = isset($report['stats']) && is_array($report['stats']) ? $report['stats'] : array();
		$engines = array();
		if (isset($report['engines']) && is_array($report['engines'])) {
			foreach ($report['engines'] as $name => $value) {
				$engines[] = $name . ': ' . $value;
			}
		}
		$notes = array();
		if (isset($report['errors']) && is_array($report['errors'])) {
			$notes = array_slice($report['errors'], 0, 50);
		}

		$insert = array(
			'sys_userid' => 1,
			'sys_groupid' => $sys_groupid,
			'sys_perm_user' => 'riud',
			'sys_perm_group' => 'r',
			'sys_perm_other' => '',
			'server_id' => intval($conf['server_id']),
			'job_id' => intval($job['job_id']),
			'parent_domain_id' => intval($job['parent_domain_id']),
			'domain' => (string) $job['domain'],
			'scan_path' => (string) $job['scan_path'],
			'started_at' => $started,
			'finished_at' => $finished,
			'duration_seconds' => $duration,
			'files_scanned' => isset($stats['files_scanned']) ? intval($stats['files_scanned']) : 0,
			'files_skipped' => isset($stats['files_skipped']) ? intval($stats['files_skipped']) : 0,
			'count_critical' => $counts['critical'],
			'count_high' => $counts['high'],
			'count_medium' => $counts['medium'],
			'count_low' => $counts['low'],
			'count_outdated' => $outdated,
			'exit_code' => intval($job['exit_code']),
			'scan_state' => $state,
			'engines' => substr(implode(', ', $engines), 0, 255),
			'notes' => implode("\n", $notes),
		);

		$app->dbmaster->query(
			'INSERT INTO malwatch_scan (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, job_id, parent_domain_id, domain, scan_path, started_at, finished_at, duration_seconds, '
			. 'files_scanned, files_skipped, count_critical, count_high, count_medium, count_low, count_outdated, '
			. 'exit_code, scan_state, engines, notes) '
			. 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			$insert['sys_userid'], $insert['sys_groupid'], $insert['sys_perm_user'], $insert['sys_perm_group'],
			$insert['sys_perm_other'], $insert['server_id'], $insert['job_id'], $insert['parent_domain_id'],
			$insert['domain'], $insert['scan_path'], $insert['started_at'], $insert['finished_at'],
			$insert['duration_seconds'], $insert['files_scanned'], $insert['files_skipped'],
			$insert['count_critical'], $insert['count_high'], $insert['count_medium'], $insert['count_low'],
			$insert['count_outdated'], $insert['exit_code'], $insert['scan_state'], $insert['engines'], $insert['notes']);

		$row = $app->dbmaster->queryOneRecord('SELECT scan_id FROM malwatch_scan WHERE job_id = ? ORDER BY scan_id DESC',
			intval($job['job_id']));

		return is_array($row) ? intval($row['scan_id']) : 0;
	}

	/**
	 * Merges the findings of this run with what was already recorded.
	 *
	 * A finding keeps its identity across runs, so the extension can tell a
	 * problem that is still there from one that appeared since the last scan.
	 * The actions key on the new ones only - without that a site would be
	 * disabled again on every run for a finding the operator has decided to
	 * leave alone.
	 */
	private function store_findings($job, $report, $scan_id, $sys_groupid)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;
		$domain_id = intval($job['parent_domain_id']);
		$now = date('Y-m-d H:i:s');
		$new = 0;

		$findings = isset($report['findings']) && is_array($report['findings']) ? $report['findings'] : array();
		$seen = array();

		foreach ($findings as $finding) {
			$path = isset($finding['path']) ? (string) $finding['path'] : '';
			$rule = isset($finding['rule']) ? (string) $finding['rule'] : '';
			if ($path === '' || $rule === '') {
				continue;
			}
			$hash = $helper->path_hash($path);
			$key = $hash . '|' . $rule;
			if (isset($seen[$key])) {
				continue;
			}
			$seen[$key] = true;

			$existing = $app->dbmaster->queryOneRecord(
				'SELECT finding_id, finding_state FROM malwatch_finding WHERE parent_domain_id = ? AND path_hash = ? AND rule_id = ?',
				$domain_id, $hash, $rule);

			$severity = isset($finding['severity']) ? (string) $finding['severity'] : 'medium';
			$excerpt = isset($finding['excerpt']) ? substr((string) $finding['excerpt'], 0, 255) : '';
			$mtime = $this->to_datetime(isset($finding['mtime']) ? $finding['mtime'] : '');

			if (is_array($existing)) {
				// A finding the operator released stays released, even when
				// the scanner reports it again.
				$state = $existing['finding_state'] === 'ignored' ? 'ignored' : 'open';
				$app->dbmaster->query(
					'UPDATE malwatch_finding SET scan_id = ?, line_number = ?, severity = ?, engine = ?, '
					. 'file_sha256 = ?, excerpt = ?, file_size = ?, file_mtime = ?, finding_state = ?, last_seen = ? '
					. 'WHERE finding_id = ?',
					$scan_id, intval(isset($finding['line']) ? $finding['line'] : 0), $severity,
					substr((string) (isset($finding['engine']) ? $finding['engine'] : ''), 0, 32),
					(string) (isset($finding['sha256']) ? $finding['sha256'] : ''), $excerpt,
					intval(isset($finding['size']) ? $finding['size'] : 0), $mtime, $state, $now,
					intval($existing['finding_id']));
				continue;
			}

			$app->dbmaster->query(
				'INSERT INTO malwatch_finding (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, parent_domain_id, domain, scan_id, file_path, path_hash, line_number, rule_id, severity, '
				. 'engine, file_sha256, excerpt, file_size, file_mtime, finding_state, first_seen, last_seen) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)",
				$sys_groupid, intval($conf['server_id']), $domain_id, (string) $job['domain'], $scan_id,
				substr($path, 0, 1024), $hash, intval(isset($finding['line']) ? $finding['line'] : 0), $rule,
				$severity, substr((string) (isset($finding['engine']) ? $finding['engine'] : ''), 0, 32),
				(string) (isset($finding['sha256']) ? $finding['sha256'] : ''), $excerpt,
				intval(isset($finding['size']) ? $finding['size'] : 0), $mtime, $now, $now);
			$new++;
		}

		// Anything not seen in this run is gone from disk. It is marked fixed
		// rather than deleted, so the history stays readable.
		$app->dbmaster->query(
			"UPDATE malwatch_finding SET finding_state = 'fixed' "
			. 'WHERE parent_domain_id = ? AND last_seen < ? AND finding_state = ?',
			$domain_id, $now, 'open');

		return $new;
	}

	/** Records the detected web software of this run. */
	private function store_software($job, $report, $scan_id, $sys_groupid)
	{
		global $app, $conf;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;
		$domain_id = intval($job['parent_domain_id']);
		$now = date('Y-m-d H:i:s');

		$software = isset($report['software']) && is_array($report['software']) ? $report['software'] : array();
		foreach ($software as $entry) {
			$path = isset($entry['path']) ? (string) $entry['path'] : '';
			if ($path === '') {
				continue;
			}
			$hash = $helper->path_hash($path);
			$kind = isset($entry['kind']) ? (string) $entry['kind'] : 'core';
			$slug = isset($entry['slug']) ? (string) $entry['slug'] : '';

			$existing = $app->dbmaster->queryOneRecord(
				'SELECT software_id FROM malwatch_software WHERE parent_domain_id = ? AND path_hash = ? AND software_kind = ? AND slug = ?',
				$domain_id, $hash, $kind, $slug);

			$outdated = !empty($entry['outdated']) ? 'y' : 'n';
			$unknown = !empty($entry['unknown']) ? 'y' : 'n';

			if (is_array($existing)) {
				$app->dbmaster->query(
					'UPDATE malwatch_software SET scan_id = ?, installed_version = ?, latest_version = ?, '
					. 'outdated = ?, version_unknown = ?, last_seen = ? WHERE software_id = ?',
					$scan_id, (string) $entry['version'], (string) (isset($entry['latest']) ? $entry['latest'] : ''),
					$outdated, $unknown, $now, intval($existing['software_id']));
				continue;
			}

			$app->dbmaster->query(
				'INSERT INTO malwatch_software (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, parent_domain_id, domain, scan_id, install_path, path_hash, product, software_kind, slug, '
				. 'installed_version, latest_version, outdated, version_unknown, last_seen) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($conf['server_id']), $domain_id, (string) $job['domain'], $scan_id,
				substr($path, 0, 1024), $hash, substr((string) $entry['product'], 0, 64), substr($kind, 0, 16),
				substr($slug, 0, 128), (string) $entry['version'],
				(string) (isset($entry['latest']) ? $entry['latest'] : ''), $outdated, $unknown, $now);
		}

		// Installations that disappeared are removed: unlike a finding, a
		// deleted CMS is not history worth keeping.
		$app->dbmaster->query('DELETE FROM malwatch_software WHERE parent_domain_id = ? AND last_seen < ?',
			$domain_id, $now);
	}

	/** Converts an RFC 3339 timestamp into a MySQL datetime. */
	private function to_datetime($value)
	{
		$value = trim((string) $value);
		if ($value === '') {
			return null;
		}
		$time = strtotime($value);
		if ($time === false || $time <= 0) {
			return null;
		}
		return date('Y-m-d H:i:s', $time);
	}

	/** Returns the last lines the scanner printed, for the job log. */
	private function tail_log($job)
	{
		$log = preg_replace('/\.json$/', '.log', (string) $job['result_file']);
		if ($log === '' || !is_file($log)) {
			return '';
		}
		$content = trim((string) file_get_contents($log));
		if ($content === '') {
			return '';
		}
		$lines = preg_split('/[\r\n]+/', $content);
		$lines = array_slice($lines, -5);
		return 'Ausgabe: ' . substr(implode(' | ', $lines), 0, 400);
	}
}
