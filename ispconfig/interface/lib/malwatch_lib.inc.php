<?php

/**
 * Shared helpers for the malwatch pages in the Security module.
 *
 * Plain functions rather than a class: ISPConfig loads interface pages
 * directly, and a class would have to be registered with $app->uses(), which
 * only looks in the core library directory.
 */

/** Returns the global settings plus whether the scanner is actually there. */
function malwatch_get_config($app)
{
	$row = $app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1');
	if (!is_array($row)) {
		$row = array(
			'binary_path' => '/usr/local/bin/malwatch',
			'state_dir' => '/var/lib/malwatch',
			'default_schedule' => 'weekly',
			'default_excludes' => '',
		);
	}
	// The panel may run on a different machine than the web server, in which
	// case the file is not visible from here. An unreadable path is reported
	// as "unknown", never as "missing" - a false alarm on the settings page
	// would send an operator hunting for a problem that is not there.
	$row['binary_ready'] = true;
	if (php_uname('n') !== '' && is_dir(dirname((string) $row['binary_path']))) {
		$row['binary_ready'] = is_file((string) $row['binary_path']);
	}
	return $row;
}

/**
 * Queues a scan for one website.
 *
 * Returns true, or a German message explaining why nothing was queued.
 */
function malwatch_queue_scan($app, $domain_id)
{
	$domain_id = $app->functions->intval($domain_id);
	if ($domain_id < 1) {
		return 'Ungültige Website.';
	}

	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}

	malwatch_drop_pending_vulncheck($app, $domain_id);
	$running = $app->db->queryOneRecord(
		"SELECT job_id, job_kind FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
		$domain_id);
	if (is_array($running)) {
		// The page hides a running vulnerability check; the refusal names it.
		return $running['job_kind'] === 'vulncheck'
			? 'Für diese Website läuft gerade der Schwachstellenabgleich. Danach lässt sich die Prüfung starten.'
			: 'Für diese Website läuft bereits eine Prüfung.';
	}

	$path = malwatch_scan_path($web);
	if ($path === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

	$site = $app->db->queryOneRecord('SELECT * FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
	$options = array(
		'excludes' => is_array($site) ? (string) $site['excludes'] : '',
		'max_age' => is_array($site) ? $app->functions->intval($site['max_age']) : 0,
		'version_scan' => is_array($site) ? (string) $site['version_scan'] : 'y',
	);

	// The insert goes through the datalog so the server plugin sees it.
	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $_SESSION['s']['user']['userid'],
		'sys_groupid' => $app->functions->intval($web['sys_groupid']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => $app->functions->intval($web['server_id']),
		'parent_domain_id' => $domain_id,
		'domain' => (string) $web['domain'],
		'scan_path' => $path,
		'job_source' => 'manual',
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');

	return true;
}

/**
 * Queues a restore of the vendor files.
 *
 * The website is switched off for the duration by the caller, not here: an
 * installation that is half exchanged has no business being served, and a
 * backdoor that is still reachable would write again while it happens.
 *
 * $mode, $no_original and $only travel straight into options under the exact
 * keys malwatch_runner::build_arguments() reads for a 'repair' job - see
 * that method before renaming any of them. Defaults match its own fallback
 * ("unset or empty means the default"), so a caller that skips them gets the
 * same behaviour a job queued before these options existed would.
 */
function malwatch_queue_repair($app, $domain_id, $dry_run = false, $previous_active = 'y',
	$mode = 'replace', $no_original = 'keep', array $only = array())
{
	// The state before the run travels with the job: switching back has to
	// restore what was, not guess that every website was online.
	return malwatch_queue_job($app, $domain_id, 'repair', array(
		'dry_run' => $dry_run ? 1 : 0,
		'previous_active' => $previous_active === 'y' ? 'y' : 'n',
		'mode' => $mode === 'overlay' ? 'overlay' : 'replace',
		'no_original' => $no_original === 'quarantine' ? 'quarantine' : 'keep',
		'only' => array_values($only),
	));
}

/**
 * Queues the removal of single files.
 *
 * Only paths that stand as a finding of this very website are accepted. The
 * value arrives from a form field, and a path is one unlink away from being
 * anything on the disk; the binary checks the boundary a second time.
 */
function malwatch_queue_quarantine($app, $domain_id, array $paths)
{
	$domain_id = $app->functions->intval($domain_id);
	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}
	$base = malwatch_scan_path($web);
	if ($base === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

	$accepted = array();
	foreach ($paths as $path) {
		$path = (string) $path;
		$row = $app->db->queryOneRecord(
			'SELECT file_path FROM malwatch_finding WHERE parent_domain_id = ? AND file_path = ? '
			. "AND finding_state IN ('open','ignored') LIMIT 1",
			$domain_id, $path);
		if (!is_array($row)) {
			continue;
		}
		if (strpos($path, $base . '/') !== 0) {
			continue;
		}
		$accepted[] = substr($path, strlen($base) + 1);
	}
	if (count($accepted) === 0) {
		return 'Keiner der Pfade steht als Fund dieser Website.';
	}

	// 'action' ausdrücklich, obwohl der Runner ohne sie auf 'add' zurückfällt:
	// die Optionen eines Auftrags sind das Einzige, was hinterher noch sagt,
	// was er tun sollte, und ein Auftrag ohne Aktion sieht in der Datenbank
	// wie ein halb gebauter aus.
	$queued = malwatch_queue_job($app, $domain_id, 'quarantine',
		array('action' => 'add', 'origin' => 'manual', 'files' => $accepted));
	return $queued === true ? count($accepted) : $queued;
}

/**
 * The WHERE fragment and bind params one automatic-action mode filters open
 * findings by, or null for a mode that covers nothing ('none', or 'preset'
 * with no rule to go by).
 *
 * Mirrors malwatch_actions::auto_paths() on the server side exactly - 'safe'
 * goes by malwatch_rule.auto_safe, 'critical' by the finding's own severity,
 * never the rule catalogue's. The two are not one a subset of the other; a
 * measurement against real findings found 767 files under 'safe' and 472
 * under 'critical' out of 1511 open ones, so keeping both queries faithful
 * to auto_paths() rather than approximating one from the other matters.
 */
function malwatch_auto_mode_filter($app, $mode, array $rule_ids = array())
{
	if ($mode === 'critical') {
		return array("severity = 'critical'", array());
	}
	if ($mode === 'safe') {
		return array("rule_id IN (SELECT rule_id FROM malwatch_rule WHERE auto_safe = 'y')", array());
	}
	if ($mode === 'preset' && count($rule_ids) > 0) {
		$placeholders = implode(',', array_fill(0, count($rule_ids), '?'));
		return array("rule_id IN ($placeholders)", array_values($rule_ids));
	}
	return null;
}

/**
 * How many currently open findings - counted as distinct files, the way a
 * human reads "how many files", not as raw rule hits - a mode would cover
 * right now. The only honest preview for a setting that moves files on its
 * own: a rule count from the catalogue says nothing about what is actually
 * sitting on real websites today.
 */
function malwatch_auto_mode_finding_count($app, $mode, array $rule_ids = array())
{
	$filter = malwatch_auto_mode_filter($app, $mode, $rule_ids);
	if ($filter === null) {
		return 0;
	}
	list($where, $params) = $filter;
	$row = call_user_func_array(array($app->db, 'queryOneRecord'), array_merge(
		array('SELECT COUNT(DISTINCT parent_domain_id, file_path) AS n FROM malwatch_finding '
			. "WHERE finding_state = 'open' AND $where"),
		$params));
	return is_array($row) ? $app->functions->intval($row['n']) : 0;
}

/**
 * Open finding paths a mode currently covers, grouped by website - the
 * shape malwatch_queue_quarantine() wants, one call per parent_domain_id.
 *
 * Only 'open' findings qualify, never 'ignored': an ignored finding was a
 * person's own call that this file is not a problem, and a sweep like this
 * has no business overriding that on its own.
 */
function malwatch_auto_mode_paths_by_domain($app, $mode, array $rule_ids = array())
{
	$filter = malwatch_auto_mode_filter($app, $mode, $rule_ids);
	if ($filter === null) {
		return array();
	}
	list($where, $params) = $filter;
	$rows = call_user_func_array(array($app->db, 'queryAllRecords'), array_merge(
		array('SELECT parent_domain_id, file_path FROM malwatch_finding '
			. "WHERE finding_state = 'open' AND $where"),
		$params));

	// Keyed by path first, so a file two different rules both hit (a real
	// case for 'preset', which can name several rule_ids at once) ends up
	// in the job's file list once, not once per matching rule.
	$by_domain = array();
	foreach ((array) $rows as $row) {
		$domain_id = $app->functions->intval($row['parent_domain_id']);
		if ($domain_id < 1) {
			continue;
		}
		if (!isset($by_domain[$domain_id])) {
			$by_domain[$domain_id] = array();
		}
		$by_domain[$domain_id][(string) $row['file_path']] = true;
	}
	foreach ($by_domain as $domain_id => $paths) {
		$by_domain[$domain_id] = array_keys($paths);
	}
	return $by_domain;
}

/**
 * Removes a vulnerability check that is still waiting for this website.
 *
 * Every other job reads the software as well, a scan most of all, so the
 * waiting check has nothing left to do. Kept, it would turn the daily round
 * into a stretch in which every job an operator starts is refused with
 * "läuft bereits". A check that has already started is left to finish.
 */
function malwatch_drop_pending_vulncheck($app, $domain_id)
{
	$app->db->query(
		"DELETE FROM malwatch_job WHERE parent_domain_id = ? AND job_kind = 'vulncheck' AND job_status = 'pending'",
		$app->functions->intval($domain_id));
}

/** Puts one job of any kind into the queue. */
function malwatch_queue_job($app, $domain_id, $kind, array $options)
{
	$domain_id = $app->functions->intval($domain_id);
	if ($domain_id < 1) {
		return 'Ungültige Website.';
	}
	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}
	if ($kind !== 'vulncheck') {
		malwatch_drop_pending_vulncheck($app, $domain_id);
	}
	$running = $app->db->queryOneRecord(
		"SELECT job_id, job_kind FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
		$domain_id);
	if (is_array($running)) {
		return ($running['job_kind'] === 'vulncheck' && $kind !== 'vulncheck')
			? 'Für diese Website läuft gerade der Schwachstellenabgleich. Danach lässt sich der Auftrag starten.'
			: 'Für diese Website läuft bereits ein Auftrag.';
	}
	$path = malwatch_scan_path($web);
	if ($path === '') {
		return 'Für diese Website ist kein Verzeichnis hinterlegt.';
	}

	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $_SESSION['s']['user']['userid'],
		'sys_groupid' => $app->functions->intval($web['sys_groupid']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => $app->functions->intval($web['server_id']),
		'parent_domain_id' => $domain_id,
		'domain' => (string) $web['domain'],
		'scan_path' => $path,
		'job_source' => 'manual',
		'job_kind' => $kind,
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');

	return true;
}

/**
 * Queues a vulnerability check for every active website.
 *
 * Returns array(queued, busy, optout, failed): busy websites already have a
 * job pending or running - a scan looks the flaws up as well -, opted-out
 * ones are set to "Veraltete Software suchen: nein", failed ones have no
 * directory to look into.
 */
function malwatch_queue_vulnchecks($app)
{
	$webs = $app->db->queryAllRecords(
		"SELECT domain_id FROM web_domain WHERE type IN ('vhost','vhostsubdomain','vhostalias') AND active = 'y' "
		. 'ORDER BY domain_id ASC');
	$queued = 0;
	$busy = 0;
	$optout = 0;
	$failed = 0;
	foreach ((array) $webs as $web) {
		$domain_id = $app->functions->intval($web['domain_id']);
		$site = $app->db->queryOneRecord(
			'SELECT excludes, version_scan FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
		if (is_array($site) && $site['version_scan'] === 'n') {
			$optout++;
			continue;
		}
		$running = $app->db->queryOneRecord(
			"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running')",
			$domain_id);
		if (is_array($running)) {
			$busy++;
			continue;
		}
		$result = malwatch_queue_job($app, $domain_id, 'vulncheck',
			array('excludes' => is_array($site) ? (string) $site['excludes'] : ''));
		if ($result === true) {
			$queued++;
		} else {
			$failed++;
		}
	}
	return array($queued, $busy, $optout, $failed);
}

/** The WordPress installation a plugin or theme directory belongs to, '' for anything else. */
function malwatch_install_of($element_path, $kind)
{
	$path = rtrim((string) $element_path, '/');
	$parent = $kind === 'plugin' ? 'plugins' : ($kind === 'theme' ? 'themes' : '');
	if ($parent === '' || basename(dirname($path)) !== $parent) {
		return '';
	}
	return dirname(dirname(dirname($path)));
}

/**
 * The folder of a WordPress installation below the scan path of its website:
 * "blog" or "campus/blog", "." for an installation in the scan path itself and
 * "" for a path outside it. The pages "Updates" and "Reparatur" group by it,
 * and repair --only names it after @.
 */
function malwatch_install_folder($install_path, $scan_base)
{
	$base = rtrim((string) $scan_base, '/');
	$path = rtrim((string) $install_path, '/');
	if ($base === '' || ($path !== $base && strpos($path, $base . '/') !== 0)) {
		return '';
	}
	$rel = trim((string) substr($path, strlen($base)), '/');
	return $rel === '' ? '.' : $rel;
}

/**
 * The --only values of one folder, for the buttons of that folder. An empty
 * folder keeps every value. The folder starts after the first @, where repair
 * --only cuts as well: a slug carries none, a folder name may.
 */
function malwatch_only_in_folder(array $only, $folder)
{
	$folder = (string) $folder;
	if ($folder === '') {
		return array_values($only);
	}
	$kept = array();
	foreach ($only as $value) {
		$value = (string) $value;
		$at = strpos($value, '@');
		if ($at !== false && substr($value, $at + 1) === $folder) {
			$kept[] = $value;
		}
	}
	return $kept;
}

/**
 * What an update to $version does about the known flaws of a software row:
 * "schließt alle 7 Lücken", "schließt 5 von 7, für 2 gibt es keine Korrektur",
 * "behoben erst ab 6.5.2". Empty for a row without known flaws.
 */
function malwatch_upgrade_closes_label(array $row, $version, array $wb)
{
	$count = intval($row['vuln_count']);
	if ($count === 0) {
		return '';
	}
	$nofix = intval($row['vuln_nofix']);
	$fixed_in = (string) $row['vuln_fixed_in'];
	if ($fixed_in !== '' && version_compare((string) $version, $fixed_in, '<')) {
		return sprintf($wb['closes_later_txt'], $fixed_in);
	}
	if ($nofix > 0) {
		return sprintf($wb['closes_some_txt'], $count - $nofix, $count, $nofix);
	}
	return $count === 1 ? $wb['closes_one_txt'] : sprintf($wb['closes_all_txt'], $count);
}

/**
 * The target versions the page "Updates" offers for one software row.
 *
 * latest is the newest release the site can take: for a plugin or theme
 * latest_version, when the site meets latest_requires_wp and
 * latest_requires_php; for the core latest_in_branch. An unknown site version
 * ($core_version or $php empty) checks nothing here - the scanner checks the
 * fetched release in its phase 3. reason says why latest stays out although
 * a newer release exists. minimal is vuln_fixed_in, the lowest release that
 * fixes every known flaw with a fix, offered once when it equals latest.
 *
 * choices are the target versions the select lists, newest first: latest,
 * minimal and every release in versions above the installed one. mark names
 * the two offers. A newest release that needs more PHP stays out, since a run
 * cannot change PHP; one that needs a newer WordPress stays in with that mark,
 * because a core update in the same run can meet it. default is the choice
 * the select starts on: latest, else minimal, else the newest other choice.
 *
 * A function of its arguments alone, so tests/upgrade_offers_test.php can call
 * it without a panel.
 */
function malwatch_upgrade_offers(array $row, $core_version, $php, array $wb)
{
	$installed = (string) $row['installed_version'];
	$kind = (string) $row['software_kind'];
	$out = array('latest' => null, 'minimal' => null, 'reason' => '', 'choices' => array(), 'default' => '');

	// The versions the select lists, before sorting, and the marks some carry.
	$versions = array();
	$marks = array();
	$withheld = '';

	$latest = $kind === 'core' ? (string) $row['latest_in_branch'] : (string) $row['latest_version'];
	if ($latest !== '' && version_compare($latest, $installed, '>')) {
		$needs_php = $kind === 'core' ? '' : (string) $row['latest_requires_php'];
		$needs_wp = $kind === 'core' ? '' : (string) $row['latest_requires_wp'];
		if ($needs_php !== '' && (string) $php !== '' && version_compare((string) $php, $needs_php, '<')) {
			$out['reason'] = sprintf($wb['needs_php_txt'], $latest, $needs_php, $php);
			$withheld = $latest;
		} elseif ($needs_wp !== '' && (string) $core_version !== '' && version_compare((string) $core_version, $needs_wp, '<')) {
			$out['reason'] = sprintf($wb['needs_wp_txt'], $latest, $needs_wp, $core_version);
			$withheld = $latest;
			$versions[] = $latest;
			$marks[$latest] = sprintf($wb['needs_wp_short_txt'], $needs_wp);
		} else {
			$out['latest'] = array('version' => $latest, 'closes' => malwatch_upgrade_closes_label($row, $latest, $wb));
			$versions[] = $latest;
			$marks[$latest] = $wb['offer_latest_txt'];
		}
	}

	$minimal = (string) $row['vuln_fixed_in'];
	if ($minimal !== '' && version_compare($minimal, $installed, '>')
		&& ($out['latest'] === null || $out['latest']['version'] !== $minimal)) {
		$out['minimal'] = array('version' => $minimal, 'closes' => malwatch_upgrade_closes_label($row, $minimal, $wb));
		$versions[] = $minimal;
		if (!isset($marks[$minimal])) {
			$marks[$minimal] = $wb['offer_minimal_txt'];
		}
	}

	$listed = json_decode((string) (isset($row['versions']) ? $row['versions'] : ''), true);
	if (is_array($listed)) {
		foreach ($listed as $version) {
			if (is_string($version) && preg_match('/^[0-9]+(\.[0-9]+)*$/', $version)) {
				$versions[] = $version;
			}
		}
	}

	$seen = array();
	foreach ($versions as $version) {
		$version = (string) $version;
		if (isset($seen[$version]) || !version_compare($version, $installed, '>')) {
			continue;
		}
		// The newest release, when it needs more PHP than the site runs.
		if ($version === $withheld && !isset($marks[$version])) {
			continue;
		}
		$seen[$version] = true;
		$out['choices'][] = array(
			'version' => $version,
			'closes' => malwatch_upgrade_closes_label($row, $version, $wb),
			'mark' => isset($marks[$version]) ? $marks[$version] : '',
		);
	}
	usort($out['choices'], function ($a, $b) {
		return version_compare($b['version'], $a['version']);
	});

	if ($out['latest'] !== null) {
		$out['default'] = $out['latest']['version'];
	} elseif ($out['minimal'] !== null) {
		$out['default'] = $out['minimal']['version'];
	} else {
		foreach ($out['choices'] as $choice) {
			if ($choice['version'] !== $withheld) {
				$out['default'] = $choice['version'];
				break;
			}
		}
		if ($out['default'] === '' && count($out['choices']) > 0) {
			$out['default'] = $out['choices'][0]['version'];
		}
	}

	// The select opens short: the offers above, the default, and the newest
	// release of each of the five newest major versions - x.y for the core,
	// the first number for a plugin or theme. A list of several hundred
	// releases in each of five hundred selects kept the page busy for
	// seconds; short counts what the full list holds beyond it.
	$majors = array();
	foreach ($out['choices'] as $i => $choice) {
		$parts = explode('.', $choice['version']);
		$major = $kind === 'core' ? $parts[0] . '.' . (isset($parts[1]) ? $parts[1] : '0') : $parts[0] . '.x';
		if (isset($majors[$major]) || count($majors) === 5) {
			continue;
		}
		$majors[$major] = true;
		if ($choice['mark'] === '') {
			$out['choices'][$i]['mark'] = sprintf($wb['offer_major_txt'], $major);
		}
		$out['choices'][$i]['newest_of_major'] = true;
	}
	$out['short'] = array();
	foreach ($out['choices'] as $i => $choice) {
		$out['choices'][$i]['label'] = $choice['mark'] !== '' ? $choice['version'] . ' · ' . $choice['mark'] : $choice['version'];
		unset($out['choices'][$i]['newest_of_major']);
		if ($choice['mark'] !== '' || $choice['version'] === $out['default']) {
			$out['short'][] = $out['choices'][$i];
		}
	}
	$out['more'] = count($out['short']) < count($out['choices']);
	return $out;
}

/**
 * The section of the website page a link opens at: show=vulns the software
 * with its vulnerabilities, show=malware the malware findings. The id of that
 * section, '' for the top of the page.
 */
function malwatch_site_jump($param)
{
	if (!is_string($param)) {
		return '';
	}
	$sections = array('vulns' => 'mw-software', 'malware' => 'mw-findings');
	return isset($sections[$param]) ? $sections[$param] : '';
}

/**
 * The rows the page "Updates" lists for one website, grouped by WordPress
 * installation: installations with known flaws first, at most $limit of them.
 *
 * A row appears when it has something to offer, a reason why its newest
 * release stays out, or known flaws while wordpress.org does not list it
 * (manual_only). Within an installation rows with known flaws come first.
 * Returns array($installs, $hidden), $hidden being the installations left out.
 */
function malwatch_upgrade_candidates($app, $domain_id, array $wb, $limit = 50)
{
	$rows = $app->db->queryAllRecords(
		"SELECT * FROM malwatch_software WHERE parent_domain_id = ? AND product = 'wordpress' "
		. "ORDER BY FIELD(software_kind, 'core', 'plugin', 'theme'), slug ASC", $domain_id);
	$site = $app->db->queryOneRecord('SELECT php_version FROM malwatch_site WHERE parent_domain_id = ?', $domain_id);
	$php = is_array($site) ? (string) $site['php_version'] : '';

	$installs = array();
	foreach ((array) $rows as $row) {
		if ((string) $row['software_kind'] === 'core') {
			$path = rtrim((string) $row['install_path'], '/');
			$installs[$path] = array('path' => $path, 'core_version' => (string) $row['installed_version'],
				'flaws' => 0, 'rows' => array());
		}
	}

	foreach ((array) $rows as $row) {
		$kind = (string) $row['software_kind'];
		$path = $kind === 'core' ? rtrim((string) $row['install_path'], '/')
			: malwatch_install_of((string) $row['install_path'], $kind);
		if (!isset($installs[$path])) {
			continue;
		}
		$manual_only = (string) $row['version_unknown'] === 'y' && intval($row['vuln_count']) > 0;
		$offers = malwatch_upgrade_offers($row, $installs[$path]['core_version'], $php, $wb);
		if (count($offers['choices']) === 0 && $offers['reason'] === '' && !$manual_only) {
			continue;
		}
		$installs[$path]['rows'][] = array(
			'software_id' => intval($row['software_id']),
			'kind' => $kind,
			'name' => $kind === 'core' ? 'WordPress' : (string) $row['slug'],
			'installed' => (string) $row['installed_version'],
			'vuln_count' => intval($row['vuln_count']),
			'manual_only' => $manual_only,
			'offers' => $offers,
		);
		$installs[$path]['flaws'] += intval($row['vuln_count']);
	}

	$kept = array();
	foreach ($installs as $install) {
		if (count($install['rows']) === 0) {
			continue;
		}
		usort($install['rows'], function ($a, $b) {
			$flawed = ($b['vuln_count'] > 0 ? 1 : 0) - ($a['vuln_count'] > 0 ? 1 : 0);
			if ($flawed !== 0) {
				return $flawed;
			}
			$order = array('core' => 0, 'plugin' => 1, 'theme' => 2);
			if ($order[$a['kind']] !== $order[$b['kind']]) {
				return $order[$a['kind']] - $order[$b['kind']];
			}
			return strcmp($a['name'], $b['name']);
		});
		$kept[] = $install;
	}
	usort($kept, function ($a, $b) {
		if ($a['flaws'] !== $b['flaws']) {
			return $a['flaws'] > $b['flaws'] ? -1 : 1;
		}
		return strcmp($a['path'], $b['path']);
	});

	return array(array_slice($kept, 0, $limit), max(0, count($kept) - $limit));
}

/**
 * Whether the page "Updates" ticks a row when it opens: only the element whose
 * row link opened the page. Everything else waits for the operator, so
 * "Updates starten" queues what was ticked on purpose.
 */
function malwatch_upgrade_checked(array $row, $can_update, $preselect)
{
	return $can_update && intval($preselect) > 0 && intval($row['software_id']) === intval($preselect);
}

/**
 * Queues an upgrade of the chosen rows of one website.
 *
 * $choices maps software_id to a version. A version counts only when this
 * page offers it for that row right now: the offers are computed again here
 * from the database, so a changed form field cannot slip another version into
 * the plan. $folder (see malwatch_install_folder()) keeps the rows of that one
 * installation, for the buttons of a folder. Returns the number of queued
 * elements, or a German message.
 */
function malwatch_queue_upgrade($app, $domain_id, array $choices, $dry_run, array $wb, $folder = '')
{
	$domain_id = $app->functions->intval($domain_id);
	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return $wb['err_site_not_found_txt'];
	}
	if ((string) $web['php'] === 'no') {
		return $wb['err_no_php_txt'];
	}

	$scan_base = malwatch_scan_path($web);
	list($installs) = malwatch_upgrade_candidates($app, $domain_id, $wb, 100000);
	$offered = array();
	foreach ($installs as $install) {
		if ((string) $folder !== '' && malwatch_install_folder($install['path'], $scan_base) !== (string) $folder) {
			continue;
		}
		foreach ($install['rows'] as $row) {
			foreach ($row['offers']['choices'] as $choice) {
				$offered[$row['software_id']][$choice['version']] = true;
			}
		}
	}

	$elements = array();
	foreach ($choices as $software_id => $version) {
		$software_id = $app->functions->intval($software_id);
		$version = (string) $version;
		if (isset($offered[$software_id][$version])) {
			$elements[] = array('software_id' => $software_id, 'version' => $version);
		}
	}
	if (count($elements) === 0) {
		return $wb['err_no_selection_txt'];
	}

	$queued = malwatch_queue_job($app, $domain_id, 'upgrade',
		array('elements' => $elements, 'dry_run' => $dry_run ? 1 : 0));
	return $queued === true ? count($elements) : $queued;
}

/**
 * "alle behoben ab 5.9.2", or "2 von 3 behoben ab 5.9.2" when some flaws name
 * no fixed version - an update to that version leaves those where they are.
 * Empty when no flaw names one.
 */
function malwatch_update_to_label($wb, $update_to, $count, $nofix)
{
	$update_to = (string) $update_to;
	if ($update_to === '') {
		return '';
	}
	if ($nofix <= 0) {
		return sprintf($wb['vuln_update_to_txt'], $update_to);
	}
	return sprintf($wb['vuln_update_some_txt'], number_format(max(0, $count - $nofix), 0, ',', '.'),
		number_format($count, 0, ',', '.'), $update_to);
}

/**
 * Turns the stored list of known flaws of one install into template rows.
 *
 * Shared by the website page and the vulnerability overview, so both say
 * the same about the same flaw. Returns the rows and how many were left out
 * beyond $limit. $total is the full number of flaws: the stored list is
 * capped (malwatch_ingest::compact_vulns), and counting it would understate
 * what is left out.
 */
function malwatch_vuln_rows($app, $wb, $json, $limit = 25, $total = -1)
{
	$list = json_decode((string) $json, true);
	if (!is_array($list)) {
		return array(array(), 0);
	}
	$rows = array();
	foreach (array_slice($list, 0, $limit) as $vuln) {
		if (!is_array($vuln)) {
			continue;
		}
		$severity = isset($vuln['severity']) ? (string) $vuln['severity'] : '';
		$score = isset($vuln['score']) ? (float) $vuln['score'] : 0.0;
		$rating = $severity !== '' ? malwatch_severity_label($wb, $severity) : $wb['vuln_unrated_txt'];
		if ($score > 0) {
			$rating .= ' ' . number_format($score, 1, ',', '.');
		}

		$fix = '';
		if (!empty($vuln['fixed_in'])) {
			$fix = sprintf($wb['vuln_fixed_in_txt'], (string) $vuln['fixed_in']);
		} elseif (!empty($vuln['last_affected'])) {
			$fix = sprintf($wb['vuln_last_affected_txt'], (string) $vuln['last_affected']);
		} elseif (!empty($vuln['unfixed'])) {
			$fix = $wb['vuln_unfixed_txt'];
		}

		// Checked a third time, here where it becomes an href: the list comes
		// from a database the scanner does not control.
		$link = isset($vuln['link']) ? (string) $vuln['link'] : '';
		if (!preg_match('#^https?://#i', $link)) {
			$link = '';
		}
		$id = isset($vuln['id']) ? (string) $vuln['id'] : '';

		$rows[] = array(
			'vuln_rating' => $app->functions->htmlentities($rating),
			'vuln_class' => $severity !== '' ? malwatch_severity_class($severity) : 'label-default',
			'vuln_id' => $app->functions->htmlentities($id),
			'has_vuln_id' => $id !== '' ? 1 : 0,
			'vuln_title' => $app->functions->htmlentities(isset($vuln['title']) ? (string) $vuln['title'] : ''),
			'vuln_fix' => $app->functions->htmlentities($fix),
			'vuln_link' => $app->functions->htmlentities($link),
			'has_vuln_link' => $link !== '' ? 1 : 0,
		);
	}
	$all = $total >= 0 ? max($total, count($list)) : count($list);
	return array($rows, max(0, $all - count($rows)));
}

/**
 * Queues a restore, download or permanent delete for one or more quarantine
 * entries.
 *
 * The quarantine list spans every website on the server, so a batch of ids
 * can belong to more than one domain at once - unlike malwatch_queue_job,
 * which is always about a single site. What ties a job to one machine is
 * server_id, not parent_domain_id: the store the CLI opens with
 * --quarantine-dir lives on one server's disk, and that is what its cron
 * uses to find its own work.
 *
 * restore and delete both end in a full-list resync of the store
 * (malwatch_ingest::sync_quarantine), so several ids from the same server
 * are safe to queue as one job. So is an export: one job writes one ZIP for
 * the whole selection, and malwatch_ingest::finish_export() files that one
 * token onto every id of the job's list, so whichever row the operator
 * clicks hands back the same archive. A job runs alone per server, so twenty
 * single exports would be nineteen refusals and one download - and the
 * operator asked for twenty files, not for twenty waits.
 *
 * Every id arrives as "<server_id>:<entry_id>", the pair the quarantine list
 * puts into its checkboxes. Not because the panel can act on a second server
 * yet, but because entry_id on its own is not a key: malwatch_quarantine is
 * unique on (server_id, entry_id), since the store lives on one server's
 * disk and the same id can occur once per machine (see schema.sql).
 *
 * Returns the number of ids queued, or the language key of a message
 * explaining why nothing was queued - this file has no $wb of its own, and
 * anything an operator reads belongs in a language file.
 */
function malwatch_queue_quarantine_action($app, array $ids, $action)
{
	if (!in_array($action, array('restore', 'delete', 'export'), true)) {
		return 'err_unknown_action_txt';
	}

	$valid = array();
	foreach ($ids as $id) {
		$id = (string) $id;
		$separator = strpos($id, ':');
		if ($separator === false) {
			continue;
		}
		$server_part = substr($id, 0, $separator);
		$entry_id = substr($id, $separator + 1);
		if ($server_part === '' || !ctype_digit($server_part) || $entry_id === '') {
			continue;
		}
		// Only a pair actually in the store may be queued - it came back from
		// a form field, and a stale or tampered value must not reach the
		// binary as if it named a real entry.
		$row = $app->db->queryOneRecord(
			'SELECT entry_id, server_id FROM malwatch_quarantine WHERE server_id = ? AND entry_id = ?',
			$app->functions->intval($server_part), $entry_id);
		if (!is_array($row)) {
			continue;
		}
		$valid[] = array(
			'entry_id' => (string) $row['entry_id'],
			'server_id' => $app->functions->intval($row['server_id']),
		);
	}
	if (count($valid) === 0) {
		return 'err_none_found_txt';
	}

	$by_server = array();
	foreach ($valid as $entry) {
		if (!isset($by_server[$entry['server_id']])) {
			$by_server[$entry['server_id']] = array();
		}
		$by_server[$entry['server_id']][] = $entry['entry_id'];
	}

	foreach ($by_server as $server_id => $group_ids) {
		$options = array('action' => $action, 'ids' => $group_ids);
		if ($action === 'export') {
			$options['token'] = bin2hex(random_bytes(20));
		}
		malwatch_insert_quarantine_job($app, $server_id, $options);
	}
	return count($valid);
}

/**
 * Inserts one malwatch_job row of kind 'quarantine'.
 *
 * parent_domain_id and domain stay empty on purpose: nothing reads them for
 * this job kind once options['action'] is not 'add' - the runner works
 * entirely from --id, and a job's ids can span more than one website anyway,
 * so neither field could name a single one honestly.
 */
function malwatch_insert_quarantine_job($app, $server_id, array $options)
{
	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $_SESSION['s']['user']['userid'],
		'sys_groupid' => $app->functions->intval($_SESSION['s']['user']['default_group']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => $server_id,
		'parent_domain_id' => 0,
		'domain' => '',
		'scan_path' => '',
		'job_source' => 'manual',
		'job_kind' => 'quarantine',
		'job_status' => 'pending',
		'options' => json_encode($options),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');
}

/** The directory of a website that actually holds the customer's files. */
function malwatch_scan_path($web)
{
	if (!is_array($web) || (string) $web['document_root'] === '') {
		return '';
	}
	$folder = isset($web['web_folder']) ? trim((string) $web['web_folder'], '/') : '';
	if (($web['type'] === 'vhostsubdomain' || $web['type'] === 'vhostalias') && $folder !== '') {
		return rtrim((string) $web['document_root'], '/') . '/' . $folder;
	}
	return rtrim((string) $web['document_root'], '/') . '/web';
}

/** Severity names, weakest first. */
function malwatch_severities()
{
	return array('low', 'medium', 'high', 'critical');
}

function malwatch_severity_label($wb, $severity)
{
	$key = 'severity_' . (string) $severity . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $severity;
}

function malwatch_state_label($wb, $state)
{
	$key = 'state_' . (string) $state . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $state;
}

function malwatch_schedule_label($wb, $schedule)
{
	if ($schedule === null || $schedule === '') {
		$schedule = 'off';
	}
	$key = 'schedule_' . (string) $schedule . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $schedule;
}

/** How a quarantine entry got there: manual, auto or repair. */
function malwatch_origin_label($wb, $origin)
{
	$key = 'origin_' . (string) $origin . '_txt';
	return isset($wb[$key]) ? $wb[$key] : (string) $origin;
}

/** Bootstrap label class for a website state. */
function malwatch_state_class($state)
{
	switch ($state) {
		case 'findings':
		case 'vulnerable':
			return 'label-danger';
		case 'outdated':
			return 'label-warning';
		case 'clean':
			return 'label-success';
		case 'error':
			return 'label-danger';
	}
	return 'label-default';
}

/** Bootstrap label class for a severity. */
function malwatch_severity_class($severity)
{
	switch ($severity) {
		case 'critical':
			return 'label-danger';
		case 'high':
			return 'label-warning';
		case 'medium':
			return 'label-info';
		case 'low':
			return 'label-default';
	}
	return 'label-default';
}

/** The label class of an upgrade outcome. */
function malwatch_upgrade_outcome_class($outcome)
{
	switch ((string) $outcome) {
		case 'updated':
			return 'label-success';
		case 'would_update':
			return 'label-info';
		case 'refused':
		case 'skipped':
			return 'label-default';
		case 'rolled_back':
		case 'failed':
			return 'label-warning';
	}
	return 'label-danger';
}

/** Short text listing which actions a website has switched on. */
function malwatch_action_summary($wb, $row)
{
	$parts = array();
	if (isset($row['notify_admin']) && $row['notify_admin'] === 'y') {
		$parts[] = isset($wb['action_admin_txt']) ? $wb['action_admin_txt'] : 'Betreiber';
	}
	if (isset($row['notify_client']) && $row['notify_client'] === 'y') {
		$parts[] = isset($wb['action_client_txt']) ? $wb['action_client_txt'] : 'Kunde';
	}
	if (isset($row['disable_site']) && $row['disable_site'] === 'y') {
		$parts[] = isset($wb['action_disable_txt']) ? $wb['action_disable_txt'] : 'Abschalten';
	}
	if (empty($parts)) {
		return isset($wb['action_none_txt']) ? $wb['action_none_txt'] : '–';
	}
	return implode(', ', $parts);
}

/**
 * Splits a file path into the part worth reading and the part that is only
 * noise.
 *
 * Every path on the server starts with the same twenty characters of
 * /var/www/clients/clientN/webN/. Printing that in front of each of forty
 * findings hides the one thing the reader is looking for, which is the file
 * name. The base is cut off, the directory is kept for orientation and the
 * file name is returned on its own so the template can lift it out.
 *
 * Returns an array with 'dir', 'file' and 'full'.
 */
function malwatch_split_path($full, $base = '')
{
	$full = (string) $full;
	$rest = $full;

	$base = rtrim((string) $base, '/');
	if ($base !== '' && strpos($full, $base . '/') === 0) {
		$rest = substr($full, strlen($base) + 1);
	}

	$slash = strrpos($rest, '/');
	if ($slash === false) {
		return array('dir' => '', 'file' => $rest, 'full' => $full);
	}

	return array(
		'dir' => substr($rest, 0, $slash + 1),
		'file' => substr($rest, $slash + 1),
		'full' => $full,
	);
}

/**
 * Groups findings by file.
 *
 * One infected file often trips several rules. Listed one row per rule the
 * same path appears four times and the number of affected files is no longer
 * readable at all - which is the first thing anyone wants to know.
 */
function malwatch_group_findings($app, $rows, $wb, $base = '')
{
	$groups = array();

	foreach ($rows as $row) {
		$key = (string) $row['file_path'];
		if (!isset($groups[$key])) {
			$parts = malwatch_split_path($key, $base);
			$groups[$key] = array(
				// Carried on every row on purpose: a template loop must not
				// depend on an outer variable being visible inside it.
				'domain_id' => $app->functions->intval($row['parent_domain_id']),
				'dir' => $app->functions->htmlentities($parts['dir']),
				'file' => $app->functions->htmlentities($parts['file']),
				'full_path' => $app->functions->htmlentities($parts['full']),
				'has_dir' => $parts['dir'] !== '' ? 1 : 0,
				'severity' => '',
				'severity_label' => '',
				'severity_class' => '',
				'first_seen' => $app->functions->htmlentities(malwatch_datetime($row['first_seen'])),
				'is_ignored' => 1,
				'hits' => array(),
				'hit_count' => 0,
			);
		}

		// The block carries the worst severity of its file, so sorting and
		// colouring follow the file rather than whichever rule came first.
		if (malwatch_severity_rank($row['severity']) > malwatch_severity_rank($groups[$key]['severity'])) {
			$groups[$key]['severity'] = (string) $row['severity'];
			$groups[$key]['severity_label'] = $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity']));
			$groups[$key]['severity_class'] = malwatch_severity_class($row['severity']);
		}
		// A file counts as released only when every one of its findings is.
		if ($row['finding_state'] !== 'ignored') {
			$groups[$key]['is_ignored'] = 0;
		}

		$groups[$key]['hits'][] = array(
			'finding_id' => $app->functions->intval($row['finding_id']),
			'rule_id' => $app->functions->htmlentities($row['rule_id']),
			'engine' => $app->functions->htmlentities($row['engine']),
			'line_number' => $app->functions->intval($row['line_number']),
			'has_line' => $app->functions->intval($row['line_number']) > 0 ? 1 : 0,
			'excerpt' => $app->functions->htmlentities($row['excerpt']),
			'severity_label' => $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity'])),
			'severity_class' => malwatch_severity_class($row['severity']),
			'is_ignored' => $row['finding_state'] === 'ignored' ? 1 : 0,
		);
		$groups[$key]['hit_count'] = count($groups[$key]['hits']);
	}

	// Die Stufe steht schon in der ersten Spalte der Zeile. Sie an jeder
	// Regelzeile darunter zu wiederholen sagt nichts dazu - außer wenn eine
	// Datei Treffer verschiedener Stufen hat: dann zeigt die Spalte die
	// schwerste, und erst das Etikett an der Regel sagt, welche Regel welche
	// gefunden hat. Genau dann wird es gezeigt und sonst nicht.
	foreach ($groups as $key => $group) {
		$mixed = false;
		foreach ($group['hits'] as $hit) {
			if ($hit['severity_label'] !== $group['severity_label']) {
				$mixed = true;
				break;
			}
		}
		foreach ($groups[$key]['hits'] as $i => $hit) {
			$groups[$key]['hits'][$i]['show_severity'] = $mixed ? 1 : 0;
		}
	}

	// Worst first, then by path, so the same scan always reads the same way.
	uasort($groups, function ($a, $b) {
		$diff = malwatch_severity_rank($b['severity']) - malwatch_severity_rank($a['severity']);
		if ($diff !== 0) {
			return $diff;
		}
		return strcmp($a['full_path'], $b['full_path']);
	});

	return array_values($groups);
}

/** Numeric weight of a severity, 0 for an unknown value. */
function malwatch_severity_rank($severity)
{
	$rank = array_search((string) $severity, malwatch_severities(), true);
	return $rank === false ? 0 : $rank + 1;
}

/** Formats a database timestamp, or a dash when there is none. */
function malwatch_datetime($value)
{
	$value = (string) $value;
	if ($value === '' || $value === '0000-00-00 00:00:00' || $value === null) {
		return '–';
	}
	$time = strtotime($value);
	if ($time === false || $time <= 0) {
		return '–';
	}
	return date('d.m.Y H:i', $time);
}

/** Formats a duration in seconds as a short human string. */
function malwatch_duration($seconds)
{
	$seconds = (int) $seconds;
	if ($seconds < 60) {
		return $seconds . ' s';
	}
	if ($seconds < 3600) {
		return floor($seconds / 60) . ' min ' . ($seconds % 60) . ' s';
	}
	return floor($seconds / 3600) . ' h ' . floor(($seconds % 3600) / 60) . ' min';
}

/**
 * Language lines for the data-mw-* attributes of a button, escaped for HTML.
 *
 * The dialog in templates/malwatch_modal.htm reads its title, question and
 * button label from those attributes. $app->tpl->setVar($wb) hands a line over
 * exactly as the language file wrote it, and one straight double quote ends
 * the attribute in the middle of the sentence. A key the language file lacks
 * is left out.
 *
 * Pass the result to $app->tpl->setVar() after setVar($wb).
 */
function malwatch_attr_texts(array $wb, array $keys)
{
	$texts = array();
	foreach ($keys as $key) {
		if (isset($wb[$key])) {
			$texts[$key] = htmlspecialchars((string) $wb[$key], ENT_QUOTES, 'UTF-8');
		}
	}
	return $texts;
}

/**
 * The quarantine by website: one row per parent_domain_id, the most entries
 * first, equal counts by name.
 *
 * $groups are the rows of a GROUP BY parent_domain_id over malwatch_quarantine
 * with the columns site, domain, entries, bytes (archive_bytes) and latest
 * (created_at). The entries without a website carry parent_domain_id 0 and
 * share the row "ohne Website".
 */
function malwatch_quarantine_overview(array $groups, array $wb)
{
	$rows = array();
	foreach ($groups as $group) {
		$site = intval($group['site']);
		$rows[] = array(
			'site' => $site,
			'label' => $site === 0 ? $wb['overview_no_site_txt'] : (string) $group['domain'],
			'entries' => intval($group['entries']),
			'bytes' => (float) $group['bytes'],
			'latest' => (string) $group['latest'],
		);
	}
	usort($rows, function ($a, $b) {
		if ($a['entries'] !== $b['entries']) {
			return $a['entries'] > $b['entries'] ? -1 : 1;
		}
		return strcmp($a['label'], $b['label']);
	});
	return $rows;
}

/**
 * The website the parameter site= narrows the quarantine list to.
 *
 * Returns its parent_domain_id when the overview lists it, 0 for the entries
 * without a website. Everything else shows the whole list and returns -1: no
 * parameter, one that is not a plain number, and a website with nothing left
 * in quarantine, which is where a filtered list lands once its last entry is
 * gone.
 */
function malwatch_quarantine_site($param, array $overview)
{
	if (!is_string($param) || !preg_match('/^[0-9]+$/', $param)) {
		return -1;
	}
	$site = intval($param);
	foreach ($overview as $row) {
		if ($row['site'] === $site) {
			return $site;
		}
	}
	return -1;
}

/**
 * Formats a byte count the way a human reads it: "169 B", "5,4 kB",
 * "41,8 MB" - decimal units and a German comma, not the binary kind an
 * administrator's tools would show.
 */
function malwatch_bytes($n)
{
	$n = (float) $n;
	$units = array('B', 'kB', 'MB', 'GB', 'TB');
	$i = 0;
	while ($n >= 1000 && $i < count($units) - 1) {
		$n /= 1000;
		$i++;
	}
	if ($i === 0) {
		return number_format($n, 0, ',', '.') . ' B';
	}
	return number_format($n, 1, ',', '.') . ' ' . $units[$i];
}

/**
 * Liefert die Websites, die etwas brauchen, und die Zahl der uebrigen.
 *
 * Der taegliche Schwachstellenabgleich zaehlt hier nicht als laufende
 * Pruefung: er liest keine Datei, hat keinen Fortschritt zu zeigen und liefe
 * jeden Morgen fuer jede Website gleichzeitig durch diese Liste.
 *
 * Reihenfolge: kritische Funde, dann laufende Pruefungen, dann hohe Funde.
 * Wer morgens hinsieht, soll die dringendste Website oben finden und nicht
 * suchen muessen.
 */
function malwatch_status_rows($app)
{
	$sql = "SELECT w.domain_id, w.domain,
			COALESCE(f.total, 0) AS findings,
			COALESCE(f.urgent, 0) AS urgent,
			s.finished_at, s.files_scanned,
			j.job_id AS running_job
		FROM web_domain w
		LEFT JOIN (
			SELECT parent_domain_id,
				COUNT(*) AS total,
				SUM(severity = 'critical') AS urgent
			FROM malwatch_finding
			WHERE finding_state = 'open'
			GROUP BY parent_domain_id
		) f ON f.parent_domain_id = w.domain_id
		LEFT JOIN malwatch_scan s ON s.scan_id = (
			SELECT scan_id FROM malwatch_scan
			WHERE parent_domain_id = w.domain_id
				AND scan_state IN ('clean','findings','vulnerable','outdated')
			ORDER BY scan_id DESC LIMIT 1
		)
		LEFT JOIN malwatch_job j ON j.job_id = (
			SELECT job_id FROM malwatch_job
			WHERE parent_domain_id = w.domain_id
				AND job_status IN ('pending','running')
				AND job_kind != 'vulncheck'
			ORDER BY job_id DESC LIMIT 1
		)
		WHERE w.type IN ('vhost','vhostsubdomain','vhostalias') AND w.active = 'y'
		ORDER BY COALESCE(f.urgent, 0) DESC, j.job_id DESC,
			COALESCE(f.total, 0) DESC, w.domain ASC";

	$all = $app->db->queryAllRecords($sql);
	if (!is_array($all)) {
		$all = array();
	}

	$attention = array();
	$quiet = 0;
	$newest = 0;

	foreach ($all as $row) {
		if (!empty($row['finished_at'])) {
			$stamp = strtotime($row['finished_at']);
			if ($stamp > $newest) {
				$newest = $stamp;
			}
		}
		$running  = intval($row['running_job']) > 0;
		$findings = intval($row['findings']);
		if (!$running && $findings < 1) {
			$quiet++;
			continue;
		}
		$row['is_running']  = $running ? 'y' : 'n';
		$row['urgent']      = intval($row['urgent']);
		$row['findings']    = $findings;
		$row['state_class'] = $running ? 'busy' : ($row['urgent'] > 0 ? 'bad' : 'warn');
		$attention[] = $row;
	}

	$next = malwatch_next_run($app);

	return array(
		'attention'      => $attention,
		'quiet_count'    => $quiet,
		'as_of'          => $newest ? malwatch_when($newest) : '—',
		'next_run_state' => $next['state'],
		'next_run'       => $next['when'],
	);
}

/**
 * Ein Zeitpunkt so, wie ein Mensch ihn sagt: "heute 03:14 Uhr", "gestern
 * 21:12 Uhr", sonst "6. September, 21:12 Uhr".
 *
 * Gilt fuer Zeitpunkte in der Vergangenheit (as_of - ein Scan-Ende) genauso
 * wie in der Zukunft (next_run - ein geplanter Lauf): "heute" und "gestern"
 * brauchen dafuer beide eine obere Grenze. Ohne sie prueft "heute" nur
 * "$stamp >= Mitternacht heute", was fuer einen ausschliesslich in der
 * Vergangenheit liegenden Zeitpunkt (der nie nach "jetzt" liegen kann)
 * zufaellig richtig war, aber jeden kuenftigen Zeitpunkt - auch naechste
 * Woche oder naechsten Monat - ebenfalls "heute" nennen wuerde.
 *
 * Bleibt absichtlich bei deutschen Wortbestandteilen ("heute", "gestern",
 * den Monatsnamen, "Uhr"), unabhaengig von der Sprache des Bedieners - das
 * ist kein Versehen. Der Rueckgabewert dieser Funktion steckt bereits seit
 * dem vorigen Bündel unveraendert in as_of_txt und erscheint dort auch auf
 * der englischen Oberflaeche; next_run tritt dieser bestehenden Abweichung
 * lediglich bei, statt eine neue zu schaffen. Eine echte Uebersetzung ist
 * kein Ersetzen einzelner Woerter: die Monatsnamen muessten in beide
 * Sprachdateien wandern, "Uhr" hat im Englischen keine Entsprechung
 * ("3:14 PM", nicht "3:14 PM o'clock"), und die dritte Form dreht die
 * Reihenfolge von Tag/Monat auf Monat/Tag um ("6. September" gegenueber
 * "September 6") - das ist ein Umbau der Funktionslogik, nicht nur ihrer
 * Zeichenketten, und damit ausserhalb dessen, was diese Aenderung beheben
 * soll: next_run war falsch (ein erfundenes 03:00 Uhr), nicht unuebersetzt.
 * Wer das fuer die englische Oberflaeche vervollstaendigen will, sollte
 * as_of gleich mit erledigen - beide teilen sich diese Funktion.
 */
function malwatch_when($stamp)
{
	$monate = array('', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
		'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember');
	$heute  = strtotime('today');
	$zeit   = date('H:i', $stamp) . ' Uhr';
	if ($stamp >= $heute && $stamp < $heute + 86400) {
		return 'heute ' . $zeit;
	}
	if ($stamp >= $heute - 86400 && $stamp < $heute) {
		return 'gestern ' . $zeit;
	}
	return intval(date('j', $stamp)) . '. ' . $monate[intval(date('n', $stamp))] . ', ' . $zeit;
}

/**
 * Der naechste anstehende Lauf ueber alle Websites - oder der Grund, warum
 * es keinen gibt.
 *
 * Es gibt keine feste Uhrzeit: next_run gehoert der einzelnen Website
 * (malwatch_site.next_run), jede hat ihren eigenen schedule, und der Cron
 * (server/lib/classes/cron.d/560-malwatch.inc.php, '* * * * *') greift jede
 * Minute auf, was faellig ist. Der richtige Wert ist deshalb das Minimum von
 * next_run ueber alle Websites, deren schedule nicht 'off' ist - aber nur
 * unter denen, die tatsaechlich noch in der Zukunft liegen.
 *
 * Liefert ein Array mit 'state' und 'when':
 *   - 'scheduled': 'when' ist ein mit malwatch_when() formatierter Zeitpunkt.
 *   - 'due': ein Zeitplan ist eingeschaltet, aber sein faelliger Zeitpunkt
 *     liegt nicht (mehr) in der Zukunft. Das deckt zwei Faelle ab, die von
 *     hier aus nicht zu unterscheiden sind: eine Website, die gerade erst
 *     eingeschaltet wurde (next_run steht auf NOW(), siehe scheduleNextRun()
 *     in malwatch_site_edit.php) und binnen einer Minute vom naechsten
 *     Cron-Tick abgeholt wird - der Normalfall - oder ein Cron, der laenger
 *     nicht lief. Eine erfundene Uhrzeit waere in beiden Faellen falsch
 *     ("gestern 03:00 Uhr" fuer etwas, das die Seite als kuenftig
 *     ankuendigt); 'due' behauptet nur, dass eine Pruefung ansteht, nicht
 *     wann - keine Diagnose, nur eine ehrliche Aussage ueber die Tabelle.
 *   - 'none': keine Website hat ueberhaupt einen Zeitplan (alle 'off', oder
 *     die Tabelle ist leer). Anders als 'due' behauptet das nicht, dass
 *     gleich etwas passiert.
 *
 * Gezaehlt werden nur Websites, deren angekuendigter Lauf auch stattfinden
 * kann. Zwei Faelle, in denen er das nicht tut, und beide stehen in
 * queue_due_scans() (server/lib/classes/cron.d/560-malwatch.inc.php):
 *
 *   - Eine abgeschaltete Website (web_domain.active = 'n'). Der Cron liest die
 *     Zeile, sieht active != 'y' und schiebt next_run nur weiter, ohne einen
 *     Auftrag anzulegen. Die Seite haette einen Lauf angekuendigt, der nie
 *     kommt. malwatch_status_rows() blendet abgeschaltete Websites ohnehin
 *     aus - die Kopfzeile darf nicht ueber eine Website sprechen, die
 *     darunter nicht steht.
 *   - Eine Zeile, deren server_id nicht die der Website ist. Der Cron holt
 *     sich seine Zeilen ueber malwatch_site.server_id = eigene ID: der dort
 *     genannte Server findet das Verzeichnis der Website bei sich nicht
 *     (create_job() bricht mit "no scan path" ab), und der Server, auf dem
 *     die Website wirklich liegt, sieht die Zeile nie. Auf einer
 *     Mehrserver-Installation kuendigte die Seite so den Lauf eines fremden
 *     Servers an, den es nicht geben wird.
 *
 * Der Typfilter ist derselbe wie in malwatch_status_rows(): worueber die
 * Kopfzeile spricht, muss darunter auch auftauchen koennen.
 */
function malwatch_next_run($app)
{
	// Beide Abfragen sehen dieselbe Menge an Websites an. Sonst koennte die
	// zweite 'due' melden fuer eine Website, die die erste zu Recht nicht
	// mitzaehlt - und die Seite behauptete, gleich passiere etwas.
	$scope = ' FROM malwatch_site s'
		. ' JOIN web_domain w ON w.domain_id = s.parent_domain_id'
		. " WHERE s.schedule != 'off'"
		. " AND w.active = 'y'"
		. " AND w.type IN ('vhost','vhostsubdomain','vhostalias')"
		. ' AND s.server_id = w.server_id';

	$upcoming = $app->db->queryOneRecord(
		'SELECT MIN(s.next_run) AS next_run' . $scope . ' AND s.next_run > NOW()');
	if (is_array($upcoming) && !empty($upcoming['next_run'])) {
		$stamp = strtotime($upcoming['next_run']);
		if ($stamp !== false && $stamp > 0) {
			return array('state' => 'scheduled', 'when' => malwatch_when($stamp));
		}
	}

	$any = $app->db->queryOneRecord('SELECT s.site_id' . $scope . ' LIMIT 1');
	if (is_array($any)) {
		return array('state' => 'due', 'when' => '');
	}

	return array('state' => 'none', 'when' => '');
}
