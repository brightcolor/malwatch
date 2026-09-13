# WordPress-Updates, Teil B: das Addon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das ISPConfig-Addon bietet je Website eine Seite „Updates“, reiht einen Auftrag `upgrade` ein, startet `malwatch upgrade` mit Plandatei, liest den Bericht ein, meldet Zurückgeholtes an Betreiber und Kunde und zeigt Fortschritt und Verlauf.

**Architecture:** Das Panel rechnet die Angebote je Element aus `malwatch_software` (Teil A liefert die Anforderungen der neuesten Version und die PHP-Version der Website) und nimmt beim Einreihen allein Versionen an, die es selbst angeboten hat. Der Runner löst die Software-IDs zu Pfaden auf, schreibt die Plandatei und setzt Benutzer, PHP und Verbindungsziel aus `web_domain`. Die Cron-Klasse liest den Bericht in `malwatch_upgrade` und `malwatch_upgrade_element`, gleicht Versionen und Quarantäne-Index ab, reiht einen Abgleich ein und verschickt Meldungen.

**Tech Stack:** PHP im Stil der vorhandenen Klassen (PHP-7.0-kompatible Syntax, `array()`), ISPConfig 3 Interface- und Server-Framework, MySQL mit selbstprüfenden Schemaänderungen.

**Spec:** `docs/superpowers/specs/2026-09-13-wordpress-updates-design.md` (Teil 3 und Nachtrag). Voraussetzung ist Teil A: `docs/superpowers/plans/2026-09-14-wordpress-upgrade-teil-a.md`, dessen Abschlussprüfung erfüllt ist.

## Global Constraints

- Kennungen im Addon: `job_kind = 'upgrade'`, Tabellen `malwatch_upgrade` und `malwatch_upgrade_element`, Seite `malwatch_upgrade_start.php`, `malwatch_ingest::ingest_upgrade`, Mailvorlagen `malwatch_upgrade_notification_*` und `malwatch_client_upgrade_notification_*`. Die Beschriftung im Panel heißt „Updates“ und „Aktualisieren“.
- Aufruf des Scanners: `upgrade --path=… --plan=… --run-as=… --php=… --wp-cli=… --connect=… --quarantine-dir=… --staging-dir=… --domain=… --progress=… --json --out=…` und bei Probelauf `--dry-run`. Scan und Abgleich bekommen zusätzlich `--php=…`.
- Bericht (Teil A, Task 3): `elements[]` mit `kind`, `slug`, `install`, `path`, `from`, `to`, `outcome` (`updated`, `would_update`, `refused`, `rolled_back`, `failed`, `rollback_failed`, `skipped`), `message`, `quarantine_ids`, `db_export_id`; dazu `php_version`, `dry_run`, `errors`. Rückgabecodes 0, 2 und 3.
- Fortschritt (Teil A, Task 2 und 10): `kind: "upgrade"`, `phase_index` 1 bis 4, `steps[]` mit `kind`, `slug`, `from`, `to`, `state`.
- Syntax, die PHP 7.0 versteht: keine Pfeilfunktionen, keine typisierten Eigenschaften, kein `match`, kein `?->`.
- Jede neue Datei unter `ispconfig/interface` und `ispconfig/server` steht in `ispconfig/install/file.list`.
- Jeder Sprachschlüssel steht in der deutschen und der englischen Datei.
- Jeder Text in `confirm()` oder `alert()` geht durch `malwatch_js_text()`.
- Verweise auf eine Website-Seite nutzen `id=`.
- Jeder Aufzählungswert, den PHP schreibt, steht in `schema.sql`; Spalten an bestehenden Tabellen kommen über die selbstprüfende Hülle mit `information_schema`.
- Texte ohne Negativabgrenzungen und ohne Zeitschätzungen; keine echten Daten in Tests und Doku; die zwei aus der Git-Historie entfernten Produktnamen kommen nicht vor (Prüfung vor jedem Commit wie in Teil A: `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` liefert nichts).
- Prüfungen je Task: `sh ispconfig/tests/check_wiring.sh`, `sh ispconfig/tests/check_constants.sh`; `php -l` für geänderte PHP-Dateien auf dem Server; nach dem Einspielen `php /usr/local/ispconfig/extensions/malwatch/tests/render_pages.php <domain_id>` auf dem Server.
- Jeder Commit endet mit der Zeile `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`; die Schritte nennen nur die erste Zeile.

## Entscheidungen gegenüber der Spezifikation

| # | Entscheidung | Grund | Preis, falls falsch |
|---|---|---|---|
| 1 | Die Angebote rechnet eine reine Funktion `malwatch_upgrade_offers()` ohne `$app` | lässt sich mit `php tests/upgrade_offers_test.php` prüfen, auch in CI | ein zweiter Aufrufweg |
| 2 | Der Kunde bekommt eine eigene Vorlage `malwatch_client_upgrade_notification_*` | der Betreiber braucht Pfade und Kennungen, der Kunde eine verständliche Nachricht | eine Vorlage mehr |
| 3 | Bereitstellung unter `<state_dir>/staging`, allein für root lesbar | Archive eines Kerns passen dort sicher hin, und `/tmp` ist oft knapp bemessen | ein Verzeichnis mehr im Zustandsbaum |
| 4 | Ein Upgrade teilt sich die Plätze von `max_parallel` mit Scan und Reparatur | es verändert Dateien wie eine Reparatur | Warten hinter einem langen Scan |
| 5 | Eine Website mit `web_domain.php = 'no'` bietet keine Updates an; der Runner lehnt einen solchen Auftrag ab | ohne PHP läuft kein WordPress und keine PHP-Abfrage | keine |
| 6 | Die PHP-Version im Panel kommt aus `malwatch_site.php_version`, geschrieben von Scan und Abgleich; fehlt sie, zeigt die Seite „neueste“ ohne PHP-Prüfung, und der Scanner prüft in Phase 3 | ein frisch eingerichtetes Addon kennt die Version erst nach dem ersten Abgleich | ein abgelehntes Element im ersten Lauf |
| 7 | Der Kunde bekommt eine Mail, sobald ein Element `rolled_back`, `failed` oder `rollback_failed` trägt; ein Fehler des Laufs ohne betroffenes Element geht allein an den Betreiber | an der Website hat sich dann nichts geändert, und dem Kunden bliebe eine Nachricht ohne Inhalt | eine Mail an den Kunden fehlt in einem Fall, den der Betreiber ohnehin bekommt |

## File Structure

| Datei | Verantwortung |
|---|---|
| `ispconfig/install/schema.sql`, `ispconfig/install/uninstall-schema.sql` | neue Tabellen, Spalten und Aufzählungswerte |
| `ispconfig/server/lib/classes/malwatch_helper.inc.php` | PHP-Binary, Verbindungsziel und Adresse einer Installation |
| `ispconfig/server/lib/classes/malwatch_runner.inc.php` | `--php` für Scan und Abgleich; Plandatei und Argumente für `upgrade` |
| `ispconfig/server/lib/classes/malwatch_ingest.inc.php` | neue Softwarefelder, PHP-Version je Website, `ingest_upgrade` |
| `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php` | Auftragsart `upgrade` einsammeln, danach Abgleich und Meldungen |
| `ispconfig/server/lib/classes/malwatch_actions.inc.php` | `notify_upgrade` |
| `ispconfig/server/conf/malwatch_upgrade_notification_{de,en}.txt`, `ispconfig/server/conf/malwatch_client_upgrade_notification_{de,en}.txt` | Mailvorlagen |
| `ispconfig/interface/lib/malwatch_lib.inc.php` | `malwatch_upgrade_offers`, `malwatch_upgrade_candidates`, `malwatch_queue_upgrade` |
| `ispconfig/interface/malwatch_upgrade_start.php`, `ispconfig/interface/templates/malwatch_upgrade_start.htm`, `ispconfig/interface/lang/{de,en}_malwatch_upgrade.lng` | Seite „Updates“ |
| `ispconfig/interface/malwatch_site_show.php`, `templates/malwatch_site_show.htm`, `lang/{de,en}_malwatch.lng` | Knopf, Zeilenverweis, Fortschritt, Verlauf |
| `ispconfig/interface/templates/malwatch_vuln_list.htm`, `lang/{de,en}_malwatch_vuln_list.lng` | Verweis „Updates“ je Website |
| `ispconfig/interface/form/malwatch_config.tform.php`, `templates/malwatch_config_edit.htm`, `lang/{de,en}_malwatch_config.lng` | Einstellung „WP-CLI“ |
| `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`, `ispconfig/tests/check_wiring.sh`, `ispconfig/tests/upgrade_offers_test.php`, `.github/workflows/ci.yml` | Verdrahtung und Prüfungen |
| `ispconfig/README.md`, `README.md`, `CHANGELOG.md`, `internal/version/version.go`, `ispconfig/version` | Doku und Freigabe 0.14.0 |

---

### Task 1: Das Schema

**Files:**
- Modify: `ispconfig/install/schema.sql`
- Modify: `ispconfig/install/uninstall-schema.sql`

**Interfaces:**
- Produces:
  - `malwatch_job.job_kind` kennt `upgrade`
  - `malwatch_quarantine.origin` kennt `upgrade`
  - `malwatch_software.latest_requires_wp` varchar(32), `latest_requires_php` varchar(32), `latest_in_branch` varchar(64)
  - `malwatch_site.php_version` varchar(32)
  - `malwatch_config.wp_cli_path` varchar(255), Vorgabe `/usr/local/bin/wp`
  - Tabelle `malwatch_upgrade` (`upgrade_id`, ISPConfig-Spalten, `server_id`, `job_id`, `parent_domain_id`, `domain`, `started_at`, `finished_at`, `dry_run`, `php_version`, `count_updated`, `count_refused`, `count_rolled_back`, `count_failed`, `exit_code`, `errors`, `raw_report`)
  - Tabelle `malwatch_upgrade_element` (`element_id`, ISPConfig-Spalten, `server_id`, `upgrade_id`, `parent_domain_id`, `install_path`, `element_kind`, `slug`, `from_version`, `to_version`, `outcome`, `message`, `quarantine_ids`, `db_export_id`)

- [ ] **Step 1: Take `upgrade` into the quarantine origin**

In `CREATE TABLE IF NOT EXISTS \`malwatch_quarantine\`` die Zeile ersetzen:

```sql
  `origin` enum('manual','auto','repair','upgrade') NOT NULL DEFAULT 'manual',
```

- [ ] **Step 2: Append the changes to `schema.sql`**

Am Ende von `ispconfig/install/schema.sql` anhängen:

```sql
-- --------------------------------------------------------
-- WordPress-Updates aus dem Panel (malwatch upgrade).
-- --------------------------------------------------------

-- upgrade aktualisiert WordPress-Kern, Plugins und Themes; siehe
-- malwatch_runner::build_arguments und malwatch_ingest::ingest_upgrade.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'',''upgrade'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE LIKE '%''upgrade''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Ein Upgrade legt den ersetzten Stand mit dem Ursprung upgrade ab.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_quarantine` MODIFY COLUMN `origin` enum(''manual'',''auto'',''repair'',''upgrade'') NOT NULL DEFAULT ''manual''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_quarantine' AND COLUMN_NAME = 'origin'
    AND COLUMN_TYPE LIKE '%''upgrade''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Was die neueste Version verlangt und, beim Kern, die neueste Version des
-- installierten Zweigs. Daraus rechnet malwatch_upgrade_offers() die Angebote.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `latest_requires_wp` varchar(32) NOT NULL DEFAULT '''' AFTER `latest_version`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'latest_requires_wp');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `latest_requires_php` varchar(32) NOT NULL DEFAULT '''' AFTER `latest_requires_wp`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'latest_requires_php');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `latest_in_branch` varchar(64) NOT NULL DEFAULT '''' AFTER `latest_requires_php`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'latest_in_branch');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Die PHP-Version der Website, wie Scan und Abgleich sie zuletzt gelesen haben.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `php_version` varchar(32) NOT NULL DEFAULT '''' AFTER `last_state`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'php_version');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `wp_cli_path` varchar(255) NOT NULL DEFAULT ''/usr/local/bin/wp'' AFTER `wpscan_token`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'wp_cli_path');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- Ein Upgrade-Lauf und seine Elemente, nach dem Muster der Reparatur.
--
CREATE TABLE IF NOT EXISTS `malwatch_upgrade` (
  `upgrade_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `started_at` datetime DEFAULT NULL,
  `finished_at` datetime DEFAULT NULL,
  `dry_run` enum('n','y') NOT NULL DEFAULT 'n',
  `php_version` varchar(32) NOT NULL DEFAULT '',
  `count_updated` int(11) unsigned NOT NULL DEFAULT '0',
  `count_refused` int(11) unsigned NOT NULL DEFAULT '0',
  `count_rolled_back` int(11) unsigned NOT NULL DEFAULT '0',
  `count_failed` int(11) unsigned NOT NULL DEFAULT '0',
  `exit_code` int(11) NOT NULL DEFAULT '0',
  `errors` text,
  `raw_report` mediumtext,
  PRIMARY KEY (`upgrade_id`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `malwatch_upgrade_element` (
  `element_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `upgrade_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `install_path` varchar(1024) NOT NULL DEFAULT '',
  `element_kind` varchar(16) NOT NULL DEFAULT '',
  `slug` varchar(190) NOT NULL DEFAULT '',
  `from_version` varchar(64) NOT NULL DEFAULT '',
  `to_version` varchar(64) NOT NULL DEFAULT '',
  `outcome` varchar(32) NOT NULL DEFAULT '',
  `message` varchar(255) NOT NULL DEFAULT '',
  `quarantine_ids` varchar(1024) NOT NULL DEFAULT '',
  `db_export_id` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`element_id`),
  KEY `upgrade_id` (`upgrade_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;
```

- [ ] **Step 3: Drop the tables on uninstall**

In `ispconfig/install/uninstall-schema.sql` direkt unter der Kopfzeile einfügen:

```sql
DROP TABLE IF EXISTS `malwatch_upgrade_element`;
DROP TABLE IF EXISTS `malwatch_upgrade`;
```

- [ ] **Step 4: Run the schema twice against a throwaway database**

Die Datei auf den Server bringen und dort gegen eine eigene Wegwerf-Datenbank laufen lassen:

```bash
ssh ispconfig 'mkdir -p /root/mw-schema' && scp ispconfig/install/schema.sql ispconfig:/root/mw-schema/schema.sql
```

Auf dem Server:

```bash
mysql -e 'CREATE DATABASE mw_schema_probe'
mysql mw_schema_probe < /root/mw-schema/schema.sql
mysql mw_schema_probe < /root/mw-schema/schema.sql
mysql -N mw_schema_probe -e "SHOW COLUMNS FROM malwatch_job LIKE 'job_kind'; SHOW COLUMNS FROM malwatch_quarantine LIKE 'origin'; SHOW COLUMNS FROM malwatch_software LIKE 'latest%'; SHOW COLUMNS FROM malwatch_site LIKE 'php_version'; SHOW COLUMNS FROM malwatch_config LIKE 'wp_cli_path'; SHOW TABLES LIKE 'malwatch_upgrade%'"
mysql -e 'DROP DATABASE mw_schema_probe'
```

Expected: beide Durchläufe ohne Fehler; `job_kind` und `origin` nennen `upgrade`; drei `latest…`-Spalten; `php_version`, `wp_cli_path`; zwei Tabellen `malwatch_upgrade…`.

Run lokal: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 5: Commit**

```bash
git add ispconfig/install/schema.sql ispconfig/install/uninstall-schema.sql
git commit -m "feat(ispconfig): schema for upgrades from the panel"
```

---

### Task 2: Runner und Helfer

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_helper.inc.php`
- Modify: `ispconfig/server/lib/classes/malwatch_runner.inc.php`
- Modify: `ispconfig/tests/check_wiring.sh` (Prüfung 16 kennt `upgrade`)
- Modify: `.github/workflows/ci.yml` (Job `php-syntax` ruft das Testskript auf)
- Test: `ispconfig/tests/upgrade_helpers_test.php` (neu)

**Interfaces:**
- Consumes: Tabelle `server_php`, Spalten `web_domain.php`, `server_php_id`, `system_user`, `system_group`, `ip_address`, `ssl`; `malwatch_config.wp_cli_path` (Task 1); Schalter von `malwatch upgrade` (Teil A)
- Produces:
  - `malwatch_helper::cli_php_path($cgi_binary)` (statisch, rein)
  - `malwatch_helper::connect_address($web)` (statisch, rein)
  - `malwatch_helper::install_url($domain, $https, $scan_path, $install_path)` (statisch, rein)
  - `malwatch_helper::install_of($element_path, $kind)` (statisch, rein)
  - `$helper->php_cli_binary($web)`: Pfad oder `''`
  - `$helper->upgrade_installs($job, $web, $scan_path, $options)`: Installationen der Plandatei
  - Auftragsoptionen eines Upgrades: `{"elements":[{"software_id":12,"version":"5.3.3"}],"dry_run":0}` (Task 4 schreibt sie)
  - Plandatei `<state_dir>/runs/job-<id>.plan.json` mit Rechten 0600; Bereitstellung `<state_dir>/staging` mit 0700

- [ ] **Step 1: Write the failing test**

`ispconfig/tests/upgrade_helpers_test.php`:

```php
<?php
/**
 * Checks the pure helpers an upgrade job is built from.
 *
 *   php ispconfig/tests/upgrade_helpers_test.php
 */
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

expect_same('cgi with version', malwatch_helper::cli_php_path('/usr/bin/php-cgi8.2'), '/usr/bin/php8.2');
expect_same('cgi without version', malwatch_helper::cli_php_path('/opt/php-8.1/bin/php-cgi'), '/opt/php-8.1/bin/php');
expect_same('not a cgi binary', malwatch_helper::cli_php_path('/usr/sbin/php-fpm8.2'), '');
expect_same('shell characters', malwatch_helper::cli_php_path('/usr/bin/php-cgi8.2; rm -rf /'), '');

expect_same('any address', malwatch_helper::connect_address(array('ip_address' => '*')), '127.0.0.1');
expect_same('empty address', malwatch_helper::connect_address(array('ip_address' => '')), '127.0.0.1');
expect_same('vhost address', malwatch_helper::connect_address(array('ip_address' => '10.50.0.11')), '10.50.0.11');
expect_same('garbage address', malwatch_helper::connect_address(array('ip_address' => 'localhost;')), '127.0.0.1');

$root = '/var/www/clients/client3/web12/web';
expect_same('install at the root', malwatch_helper::install_url('beispiel.de', true, $root, $root), 'https://beispiel.de/');
expect_same('install in a folder', malwatch_helper::install_url('beispiel.de', false, $root, $root . '/blog'), 'http://beispiel.de/blog/');
expect_same('folder with a space', malwatch_helper::install_url('beispiel.de', true, $root, $root . '/alte seite'), 'https://beispiel.de/alte%20seite/');

expect_same('plugin install', malwatch_helper::install_of($root . '/blog/wp-content/plugins/akismet', 'plugin'), $root . '/blog');
expect_same('theme in a renamed content directory', malwatch_helper::install_of($root . '/inhalt/themes/vier', 'theme'), $root);
expect_same('plugin outside plugins/', malwatch_helper::install_of($root . '/wp-content/akismet', 'plugin'), '');
expect_same('core', malwatch_helper::install_of($root, 'core'), '');

if ($failures > 0) {
	exit(1);
}
echo "upgrade helpers OK\n";
```

- [ ] **Step 2: Run test to verify it fails**

Run (Server oder jeder Rechner mit PHP 7 oder neuer): `php ispconfig/tests/upgrade_helpers_test.php`
Expected: Fatal error, `Call to undefined method malwatch_helper::cli_php_path()`

- [ ] **Step 3: Add the helpers to `malwatch_helper.inc.php`**

Vor der Methode `log` einfügen:

```php
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
```

- [ ] **Step 4: Build the arguments in `malwatch_runner.inc.php`**

In `start()` direkt nach `$args = $this->build_arguments($job, $config, $path, $result_file);`:

```php
		if ($args === null) {
			// build_arguments() failed the job and named the reason.
			return false;
		}
```

In `build_arguments()` vor `if ($kind === 'quarantine') {`:

```php
		if ($kind === 'upgrade') {
			return $this->upgrade_arguments($job, $config, $path, $state_dir, $progress, $result_file, $options);
		}
```

Im Zweig `vulncheck` nach `$this->add_vuln_arguments($check, $state_dir, $config);` und im Scan-Zweig nach `$this->add_vuln_arguments($args, $state_dir, $config);` jeweils:

```php
		$this->add_php_argument($check, $job);
```

bzw.

```php
		$this->add_php_argument($args, $job);
```

Nach `add_vuln_arguments` die neuen Methoden einfügen:

```php
	/** Names the PHP of the website, so the report carries its version. */
	private function add_php_argument(array &$args, $job)
	{
		global $app;

		$web = $app->malwatch_helper->get_web($job['parent_domain_id']);
		if (!is_array($web) || (string) $web['php'] === 'no') {
			return;
		}
		$php = $app->malwatch_helper->php_cli_binary($web);
		if ($php !== '') {
			$args[] = '--php=' . $php;
		}
	}

	/**
	 * Assembles an upgrade: writes the plan file and names the user, the PHP
	 * and the address of the website. Returns null when the job cannot run;
	 * the job is failed with the reason then.
	 */
	private function upgrade_arguments($job, $config, $path, $state_dir, $progress, $result_file, $options)
	{
		global $app;

		$helper = $app->malwatch_helper;
		$web = $helper->get_web($job['parent_domain_id']);
		if (!is_array($web)) {
			return $this->refuse_upgrade($job, 'Die Website wurde nicht gefunden.');
		}
		if ((string) $web['php'] === 'no') {
			return $this->refuse_upgrade($job, 'Die Website läuft ohne PHP, WordPress lässt sich dort nicht aktualisieren.');
		}
		$php = $helper->php_cli_binary($web);
		if ($php === '') {
			return $this->refuse_upgrade($job, 'Zur PHP-Version der Website liegt auf diesem Server kein PHP-Kommandozeilenprogramm.');
		}

		$installs = $helper->upgrade_installs($job, $web, $path, $options);
		if (count($installs) === 0) {
			return $this->refuse_upgrade($job, 'Der Auftrag nennt keine Installation dieser Website.');
		}

		$plan_file = $state_dir . '/runs/job-' . intval($job['job_id']) . '.plan.json';
		$old = umask(0077);
		$written = @file_put_contents($plan_file, json_encode(array('schema' => 1, 'installs' => $installs),
			JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
		umask($old);
		if ($written === false) {
			return $this->refuse_upgrade($job, 'Die Plandatei konnte nicht geschrieben werden.');
		}
		@chmod($plan_file, 0600);

		// Root only: archives of a whole WordPress core sit here before the
		// exchange, and a database export on its way into quarantine.
		$staging = $state_dir . '/staging';
		if (!is_dir($staging)) {
			@mkdir($staging, 0700, true);
		}
		@chmod($staging, 0700);

		$upgrade = array(
			'upgrade',
			'--path=' . $path,
			'--plan=' . $plan_file,
			'--run-as=' . $web['system_user'] . ':' . $web['system_group'],
			'--php=' . $php,
			'--wp-cli=' . $this->wp_cli_path($config),
			'--connect=' . malwatch_helper::connect_address($web),
			'--quarantine-dir=' . $state_dir . '/quarantine',
			'--staging-dir=' . $staging,
			'--domain=' . $job['domain'],
			'--progress=' . $progress,
			'--json',
			'--out=' . $result_file,
		);
		if (!empty($options['dry_run'])) {
			$upgrade[] = '--dry-run';
		}
		return $upgrade;
	}

	/** The WP-CLI path from the settings, the default where it is empty. */
	private function wp_cli_path($config)
	{
		$path = isset($config['wp_cli_path']) ? trim((string) $config['wp_cli_path']) : '';
		return $path !== '' ? $path : '/usr/local/bin/wp';
	}

	/** Fails an upgrade job before the scanner starts; build_arguments() returns this. */
	private function refuse_upgrade($job, $message)
	{
		global $app;

		$app->malwatch_helper->fail_job($job['job_id'], $message);
		return null;
	}
```

- [ ] **Step 5: Wire the checks**

In `ispconfig/tests/check_wiring.sh`, Prüfung 16, die Schleife erweitern:

```sh
for kind in repair quarantine upgrade; do
```

In `.github/workflows/ci.yml`, Job `php-syntax`, nach „Check wiring“:

```yaml
      - name: Upgrade helpers
        run: php ispconfig/tests/upgrade_helpers_test.php
```

- [ ] **Step 6: Run the checks**

Run: `php ispconfig/tests/upgrade_helpers_test.php && php -l ispconfig/server/lib/classes/malwatch_helper.inc.php && php -l ispconfig/server/lib/classes/malwatch_runner.inc.php`
Expected: `upgrade helpers OK`, zweimal `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK` (Prüfung 37 findet `--plan`, `--run-as`, `--php`, `--wp-cli`, `--connect` in `usage.go`; Prüfung 40 findet `malwatch upgrade`)

- [ ] **Step 7: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_helper.inc.php ispconfig/server/lib/classes/malwatch_runner.inc.php ispconfig/tests/upgrade_helpers_test.php ispconfig/tests/check_wiring.sh .github/workflows/ci.yml
git commit -m "feat(ispconfig): the runner writes the plan and starts malwatch upgrade"
```

---

### Task 3: Die neuen Angaben einlesen

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_ingest.inc.php` (`ingest`, `ingest_vulncheck`, `store_software`)

**Interfaces:**
- Consumes: Bericht von Scan und Abgleich mit `php_version` und je Software `latest_requires_wp`, `latest_requires_php`, `latest_in_branch` (Teil A, Task 12); Spalten aus Task 1
- Produces: gefüllte Spalten `malwatch_software.latest_requires_wp`, `latest_requires_php`, `latest_in_branch` und `malwatch_site.php_version`, auf die Task 4 die Angebote baut

- [ ] **Step 1: Read the three fields in `store_software`**

Nach `$latest = (string) (isset($entry['latest']) ? $entry['latest'] : '');` einfügen:

```php
			$requires_wp = substr((string) (isset($entry['latest_requires_wp']) ? $entry['latest_requires_wp'] : ''), 0, 32);
			$requires_php = substr((string) (isset($entry['latest_requires_php']) ? $entry['latest_requires_php'] : ''), 0, 32);
			$in_branch = substr((string) (isset($entry['latest_in_branch']) ? $entry['latest_in_branch'] : ''), 0, 64);
```

- [ ] **Step 2: Write them with every UPDATE and the INSERT**

Den Block `if (is_array($existing)) { … }` samt dem folgenden INSERT ersetzen durch:

```php
			if (is_array($existing)) {
				if (!$vuln_checked && (string) $existing['installed_version'] === $version) {
					// Nobody was asked this time, and the version is the one the
					// stored list was made for: the list stays, marked as not
					// checked in this run. The pages say so next to it.
					$app->dbmaster->query(
						'UPDATE malwatch_software SET scan_id = ?, installed_version = ?, latest_version = ?, '
						. 'latest_requires_wp = ?, latest_requires_php = ?, latest_in_branch = ?, '
						. "outdated = ?, version_unknown = ?, vuln_unchecked = 'y', last_seen = ? WHERE software_id = ?",
						$scan_id, $version, $latest, $requires_wp, $requires_php, $in_branch,
						$outdated, $unknown, $now, intval($existing['software_id']));
					continue;
				}
				$app->dbmaster->query(
					'UPDATE malwatch_software SET scan_id = ?, installed_version = ?, latest_version = ?, '
					. 'latest_requires_wp = ?, latest_requires_php = ?, latest_in_branch = ?, '
					. 'outdated = ?, version_unknown = ?, vuln_count = ?, vuln_nofix = ?, vuln_severity = ?, '
					. 'vuln_fixed_in = ?, vuln_unchecked = ?, vulns = ?, last_seen = ? WHERE software_id = ?',
					$scan_id, $version, $latest, $requires_wp, $requires_php, $in_branch,
					$outdated, $unknown, $vuln_count, $vuln_nofix, $vuln_severity,
					$vuln_fixed_in, $vuln_checked ? 'n' : 'y', $vuln_json, $now, intval($existing['software_id']));
				continue;
			}

			$app->dbmaster->query(
				'INSERT INTO malwatch_software (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, parent_domain_id, domain, scan_id, install_path, path_hash, product, software_kind, slug, '
				. 'installed_version, latest_version, latest_requires_wp, latest_requires_php, latest_in_branch, '
				. 'outdated, version_unknown, vuln_count, vuln_nofix, vuln_severity, '
				. 'vuln_fixed_in, vuln_unchecked, vulns, last_seen) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($conf['server_id']), $domain_id, (string) $job['domain'], $scan_id,
				substr($path, 0, 1024), $hash, substr((string) $entry['product'], 0, 64), substr($kind, 0, 16),
				substr($slug, 0, 128), $version, $latest, $requires_wp, $requires_php, $in_branch, $outdated, $unknown,
				$vuln_count, $vuln_nofix, $vuln_severity, $vuln_fixed_in, $vuln_checked ? 'n' : 'y', $vuln_json, $now);
```

Zählprobe für das INSERT: 28 Spalten, davon 4 Literale (`1`, `'riud'`, `'r'`, `''`), also 24 Platzhalter und 24 Werte.

- [ ] **Step 3: Keep the PHP version of the website**

Vor `/** Converts an RFC 3339 timestamp into a MySQL datetime. */` einfügen:

```php
	/**
	 * Keeps the PHP version the scanner read for the website. A report without
	 * one leaves the stored value where it is: a runner before this version
	 * passes no --php.
	 */
	private function store_php_version($job, $report)
	{
		global $app;

		$php = isset($report['php_version']) ? (string) $report['php_version'] : '';
		if (!preg_match('/^\d+\.\d+(\.\d+)?$/', $php)) {
			return;
		}
		$app->dbmaster->query('UPDATE malwatch_site SET php_version = ? WHERE parent_domain_id = ?',
			$php, intval($job['parent_domain_id']));
	}
```

In `ingest()` nach `$this->store_software($job, $report, $scan_id, $sys_groupid);` und in `ingest_vulncheck()` nach derselben Zeile:

```php
		$this->store_php_version($job, $report);
```

- [ ] **Step 4: Run the checks**

Run: `php -l ispconfig/server/lib/classes/malwatch_ingest.inc.php && sh ispconfig/tests/check_wiring.sh`
Expected: `No syntax errors detected`, `Wiring OK`

Die Wirkung auf die Datenbank prüft Task 10 nach dem Einspielen: der nächste Abgleich füllt die vier Spalten.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_ingest.inc.php
git commit -m "feat(ispconfig): keep the requirements of the newest release and the PHP of each website"
```

---

### Task 4: Angebote und Einreihen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_lib.inc.php`
- Create: `ispconfig/interface/lang/de_malwatch_upgrade.lng`, `ispconfig/interface/lang/en_malwatch_upgrade.lng`
- Modify: `ispconfig/install/file.list`, `.github/workflows/ci.yml`
- Test: `ispconfig/tests/upgrade_offers_test.php` (neu)

**Interfaces:**
- Consumes: `malwatch_queue_job($app, $domain_id, $kind, array $options)`; Spalten aus Task 1 und 3
- Produces:
  - `malwatch_upgrade_offers(array $row, $core_version, $php, array $wb)` → `array('latest' => array('version','closes')|null, 'minimal' => …|null, 'reason' => string)`
  - `malwatch_upgrade_closes_label(array $row, $version, array $wb)` → Text
  - `malwatch_install_of($element_path, $kind)` → Installationspfad oder `''`
  - `malwatch_upgrade_candidates($app, $domain_id, array $wb, $limit = 50)` → `array($installs, $hidden)`; jede Installation `array('path', 'core_version', 'flaws', 'rows')`, jede Zeile `array('software_id', 'kind', 'name', 'installed', 'vuln_count', 'manual_only', 'offers')`
  - `malwatch_queue_upgrade($app, $domain_id, array $choices, $dry_run, array $wb)` → Zahl der eingereihten Elemente oder Meldung; Optionen wie in Task 2 beschrieben
  - Sprachschlüssel `closes_all_txt`, `closes_one_txt`, `closes_some_txt`, `closes_later_txt`, `needs_php_txt`, `needs_wp_txt`, `err_site_not_found_txt`, `err_no_php_txt`, `err_no_selection_txt`

- [ ] **Step 1: Write the failing test**

`ispconfig/tests/upgrade_offers_test.php`:

```php
<?php
/**
 * Checks the target versions the page "Updates" offers.
 *
 *   php ispconfig/tests/upgrade_offers_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_lib.inc.php';

$wb = array(
	'closes_all_txt' => 'schließt alle %s Lücken',
	'closes_one_txt' => 'schließt die bekannte Lücke',
	'closes_some_txt' => 'schließt %s von %s, für %s gibt es keine Korrektur',
	'closes_later_txt' => 'behoben erst ab %s',
	'needs_php_txt' => '%s braucht PHP %s, die Website läuft mit %s',
	'needs_wp_txt' => '%s braucht WordPress %s, installiert ist %s',
);

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function software_row(array $fields)
{
	return array_merge(array(
		'software_kind' => 'plugin', 'installed_version' => '5.3.0', 'latest_version' => '',
		'latest_in_branch' => '', 'latest_requires_wp' => '', 'latest_requires_php' => '',
		'vuln_count' => 0, 'vuln_nofix' => 0, 'vuln_fixed_in' => '', 'version_unknown' => 'n',
	), $fields);
}

// The newest release fits the site and fixes both flaws.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'latest_requires_php' => '7.2',
	'vuln_count' => 2, 'vuln_fixed_in' => '5.3.1')), '6.6.2', '8.2.10', $wb);
expect_same('latest offered', $o['latest']['version'], '5.3.7');
expect_same('latest closes all', $o['latest']['closes'], 'schließt alle 2 Lücken');
expect_same('minimal offered', $o['minimal']['version'], '5.3.1');

// The newest release asks for more PHP than the site runs.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '3.18.0', 'latest_version' => '3.25.1',
	'latest_requires_php' => '8.1', 'vuln_count' => 7, 'vuln_fixed_in' => '3.18.2')), '6.6.2', '7.4.33', $wb);
expect_same('latest withheld', $o['latest'], null);
expect_same('php reason', $o['reason'], '3.25.1 braucht PHP 8.1, die Website läuft mit 7.4.33');
expect_same('minimal remains', $o['minimal']['version'], '3.18.2');

// The newest release asks for a newer WordPress.
$o = malwatch_upgrade_offers(software_row(array('installed_version' => '1.0', 'latest_version' => '2.0',
	'latest_requires_wp' => '6.6')), '6.4.5', '8.2.10', $wb);
expect_same('wordpress reason', $o['reason'], '2.0 braucht WordPress 6.6, installiert ist 6.4.5');

// The core stays on its branch; a fix that only a newer branch carries is named.
$o = malwatch_upgrade_offers(software_row(array('software_kind' => 'core', 'installed_version' => '6.4.2',
	'latest_version' => '7.1', 'latest_in_branch' => '6.4.5', 'vuln_count' => 3, 'vuln_fixed_in' => '6.5.2')),
	'6.4.2', '8.2.10', $wb);
expect_same('core latest is the branch', $o['latest']['version'], '6.4.5');
expect_same('branch fixes later', $o['latest']['closes'], 'behoben erst ab 6.5.2');
expect_same('core minimal', $o['minimal']['version'], '6.5.2');

// Flaws without a fix are counted apart, and one version is offered once.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'vuln_count' => 3, 'vuln_nofix' => 1,
	'vuln_fixed_in' => '5.3.7')), '6.6.2', '8.2.10', $wb);
expect_same('one offer when both agree', $o['minimal'], null);
expect_same('some closed', $o['latest']['closes'], 'schließt 2 von 3, für 1 gibt es keine Korrektur');

// A single flaw reads as one.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'vuln_count' => 1,
	'vuln_fixed_in' => '5.3.7')), '6.6.2', '8.2.10', $wb);
expect_same('one flaw', $o['latest']['closes'], 'schließt die bekannte Lücke');

// Nothing newer: nothing to offer.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.0')), '6.6.2', '8.2.10', $wb);
expect_same('current: latest', $o['latest'], null);
expect_same('current: minimal', $o['minimal'], null);
expect_same('current: reason', $o['reason'], '');

// An unknown PHP version checks nothing here; the scanner checks in phase 3.
$o = malwatch_upgrade_offers(software_row(array('latest_version' => '5.3.7', 'latest_requires_php' => '8.1')),
	'6.6.2', '', $wb);
expect_same('unknown php', $o['latest']['version'], '5.3.7');

expect_same('plugin install', malwatch_install_of('/w/blog/wp-content/plugins/akismet', 'plugin'), '/w/blog');
expect_same('theme install', malwatch_install_of('/w/inhalt/themes/vier', 'theme'), '/w');
expect_same('stray plugin path', malwatch_install_of('/w/wp-content/akismet', 'plugin'), '');

if ($failures > 0) {
	exit(1);
}
echo "upgrade offers OK\n";
```

- [ ] **Step 2: Run test to verify it fails**

Run: `php ispconfig/tests/upgrade_offers_test.php`
Expected: Fatal error, `Call to undefined function malwatch_upgrade_offers()`

- [ ] **Step 3: Add the functions to `malwatch_lib.inc.php`**

Nach `malwatch_queue_vulnchecks` einfügen:

```php
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
 * A function of its arguments alone, so tests/upgrade_offers_test.php can call
 * it without a panel.
 */
function malwatch_upgrade_offers(array $row, $core_version, $php, array $wb)
{
	$installed = (string) $row['installed_version'];
	$kind = (string) $row['software_kind'];
	$out = array('latest' => null, 'minimal' => null, 'reason' => '');

	$latest = $kind === 'core' ? (string) $row['latest_in_branch'] : (string) $row['latest_version'];
	if ($latest !== '' && version_compare($latest, $installed, '>')) {
		$needs_php = $kind === 'core' ? '' : (string) $row['latest_requires_php'];
		$needs_wp = $kind === 'core' ? '' : (string) $row['latest_requires_wp'];
		if ($needs_php !== '' && (string) $php !== '' && version_compare((string) $php, $needs_php, '<')) {
			$out['reason'] = sprintf($wb['needs_php_txt'], $latest, $needs_php, $php);
		} elseif ($needs_wp !== '' && (string) $core_version !== '' && version_compare((string) $core_version, $needs_wp, '<')) {
			$out['reason'] = sprintf($wb['needs_wp_txt'], $latest, $needs_wp, $core_version);
		} else {
			$out['latest'] = array('version' => $latest, 'closes' => malwatch_upgrade_closes_label($row, $latest, $wb));
		}
	}

	$minimal = (string) $row['vuln_fixed_in'];
	if ($minimal !== '' && version_compare($minimal, $installed, '>')
		&& ($out['latest'] === null || $out['latest']['version'] !== $minimal)) {
		$out['minimal'] = array('version' => $minimal, 'closes' => malwatch_upgrade_closes_label($row, $minimal, $wb));
	}
	return $out;
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
		if ($offers['latest'] === null && $offers['minimal'] === null && $offers['reason'] === '' && !$manual_only) {
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
 * Queues an upgrade of the chosen rows of one website.
 *
 * $choices maps software_id to a version. A version counts only when this
 * page offers it for that row right now: the offers are computed again here
 * from the database, so a changed form field cannot slip another version into
 * the plan. Returns the number of queued elements, or a German message.
 */
function malwatch_queue_upgrade($app, $domain_id, array $choices, $dry_run, array $wb)
{
	$domain_id = $app->functions->intval($domain_id);
	$web = $app->db->queryOneRecord('SELECT php FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return $wb['err_site_not_found_txt'];
	}
	if ((string) $web['php'] === 'no') {
		return $wb['err_no_php_txt'];
	}

	list($installs) = malwatch_upgrade_candidates($app, $domain_id, $wb, 100000);
	$offered = array();
	foreach ($installs as $install) {
		foreach ($install['rows'] as $row) {
			foreach (array('latest', 'minimal') as $which) {
				if ($row['offers'][$which] !== null) {
					$offered[$row['software_id']][$row['offers'][$which]['version']] = true;
				}
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
```

- [ ] **Step 4: Create the language files**

`ispconfig/interface/lang/de_malwatch_upgrade.lng`:

```php
<?php
$wb['closes_all_txt'] = 'schließt alle %s Lücken';
$wb['closes_one_txt'] = 'schließt die bekannte Lücke';
$wb['closes_some_txt'] = 'schließt %s von %s, für %s gibt es keine Korrektur';
$wb['closes_later_txt'] = 'behoben erst ab %s';
$wb['needs_php_txt'] = '%s braucht PHP %s, die Website läuft mit %s';
$wb['needs_wp_txt'] = '%s braucht WordPress %s, installiert ist %s';
$wb['err_site_not_found_txt'] = 'Die Website wurde nicht gefunden.';
$wb['err_no_php_txt'] = 'Die Website läuft ohne PHP; WordPress lässt sich dort nicht aktualisieren.';
$wb['err_no_selection_txt'] = 'Es wurde keine Version ausgewählt, die diese Seite anbietet.';
```

`ispconfig/interface/lang/en_malwatch_upgrade.lng`:

```php
<?php
$wb['closes_all_txt'] = 'fixes all %s vulnerabilities';
$wb['closes_one_txt'] = 'fixes the known vulnerability';
$wb['closes_some_txt'] = 'fixes %s of %s, %s have no fix yet';
$wb['closes_later_txt'] = 'fixed from %s on';
$wb['needs_php_txt'] = '%s needs PHP %s, the website runs %s';
$wb['needs_wp_txt'] = '%s needs WordPress %s, %s is installed';
$wb['err_site_not_found_txt'] = 'The website was not found.';
$wb['err_no_php_txt'] = 'The website runs without PHP; WordPress cannot be updated there.';
$wb['err_no_selection_txt'] = 'No version this page offers was selected.';
```

In `ispconfig/install/file.list` nach den Zeilen von `malwatch_vuln_list.lng`:

```
c:interface/lang/de_malwatch_upgrade.lng:interface/web/security/lib/lang/de_malwatch_upgrade.lng
c:interface/lang/en_malwatch_upgrade.lng:interface/web/security/lib/lang/en_malwatch_upgrade.lng
```

In `.github/workflows/ci.yml`, Job `php-syntax`, nach „Upgrade helpers“:

```yaml
      - name: Upgrade offers
        run: php ispconfig/tests/upgrade_offers_test.php
```

- [ ] **Step 5: Run the checks**

Run: `php ispconfig/tests/upgrade_offers_test.php && php -l ispconfig/interface/lib/malwatch_lib.inc.php && sh ispconfig/tests/check_wiring.sh`
Expected: `upgrade offers OK`, `No syntax errors detected`, `Wiring OK` (Prüfung 39 findet die neuen Schlüssel in beiden Sprachen)

- [ ] **Step 6: Commit**

```bash
git add ispconfig/interface/lib/malwatch_lib.inc.php ispconfig/interface/lang/de_malwatch_upgrade.lng ispconfig/interface/lang/en_malwatch_upgrade.lng ispconfig/install/file.list ispconfig/tests/upgrade_offers_test.php .github/workflows/ci.yml
git commit -m "feat(ispconfig): offer target versions and queue an upgrade only for what was offered"
```

---

### Task 5: Die Seite „Updates“

**Files:**
- Create: `ispconfig/interface/malwatch_upgrade_start.php`
- Create: `ispconfig/interface/templates/malwatch_upgrade_start.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_upgrade.lng`, `ispconfig/interface/lang/en_malwatch_upgrade.lng`
- Modify: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`, `ispconfig/tests/check_wiring.sh` (Prüfung 34)

**Interfaces:**
- Consumes: `malwatch_upgrade_candidates`, `malwatch_queue_upgrade` (Task 4); `malwatch_js_text`, `malwatch_scan_path`
- Produces: Seite `security/malwatch_upgrade_start.php?id=<domain_id>[&software_id=<id>]`; Formularfelder `selected[]` (Software-IDs), `version[<software_id>]`, `malwatch_action` (`upgrade`, `upgrade_dry`)

- [ ] **Step 1: Write `ispconfig/interface/malwatch_upgrade_start.php`**

```php
<?php

/**
 * The page "Updates" of one website: every WordPress core, plugin and theme
 * with a newer release at wordpress.org, a target version per row, a dry run
 * and the start.
 *
 * Reached as malwatch_upgrade_start.php?id=<domain_id>, optionally with
 * &software_id=<id> to preselect one row. id=, the name malwatch_site_show.php
 * reads as well (check_wiring.sh, check 34).
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Included, see malwatch_repair_start.php for why load_language_file() would
// leave $wb empty here.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_upgrade.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_upgrade.lng';
}
include $lng_file;

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
if ($domain_id < 1) {
	die($wb['err_invalid_site_txt']);
}
$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
if (!is_array($web)) {
	die($wb['err_site_not_found_txt']);
}
$preselect = $app->functions->intval(isset($_REQUEST['software_id']) ? $_REQUEST['software_id'] : 0);

$message = '';
$error = '';

// --- Actions -----------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';
	if ($action === 'upgrade' || $action === 'upgrade_dry') {
		$choices = array();
		$selected = isset($_POST['selected']) && is_array($_POST['selected']) ? $_POST['selected'] : array();
		$versions = isset($_POST['version']) && is_array($_POST['version']) ? $_POST['version'] : array();
		foreach ($selected as $software_id) {
			$software_id = $app->functions->intval($software_id);
			if ($software_id > 0 && isset($versions[$software_id])) {
				$choices[$software_id] = (string) $versions[$software_id];
			}
		}
		// malwatch_queue_upgrade() accepts only versions this page offers.
		$result = malwatch_queue_upgrade($app, $domain_id, $choices, $action === 'upgrade_dry', $wb);
		if (is_int($result)) {
			$message = sprintf($action === 'upgrade_dry' ? $wb['msg_dry_txt'] : $wb['msg_queued_txt'], $result);
		} else {
			$error = $result;
		}
	}
}

// --- Rows --------------------------------------------------------------------
list($installs, $hidden) = malwatch_upgrade_candidates($app, $domain_id, $wb);
$scan_base = rtrim(malwatch_scan_path($web), '/');
$labels = array('latest' => $wb['offer_latest_txt'], 'minimal' => $wb['offer_minimal_txt']);

$blocks = array();
$selected_count = 0;
$row_count = 0;
foreach ($installs as $install) {
	$rows = array();
	foreach ($install['rows'] as $row) {
		// The options go out as one escaped string: the template loops over
		// installations and rows already, and every value in it is escaped
		// here.
		$options_html = '';
		$default = '';
		$default_closes = '';
		foreach ($labels as $which => $label) {
			$offer = $row['offers'][$which];
			if ($offer === null) {
				continue;
			}
			if ($default === '') {
				$default = $offer['version'];
				$default_closes = $offer['closes'];
			}
			$options_html .= '<option value="' . $app->functions->htmlentities($offer['version']) . '"'
				. ' data-closes="' . $app->functions->htmlentities($offer['closes']) . '"'
				. ($default === $offer['version'] ? ' selected' : '') . '>'
				. $app->functions->htmlentities($offer['version'] . ' · ' . $label) . '</option>';
		}

		$can_update = $default !== '';
		$checked = $can_update && ($preselect > 0 ? $row['software_id'] === $preselect : $row['vuln_count'] > 0);
		if ($can_update) {
			$row_count++;
		}
		if ($checked) {
			$selected_count++;
		}
		$note = $row['manual_only'] ? $wb['manual_only_txt'] : $row['offers']['reason'];

		$rows[] = array(
			'software_id' => $row['software_id'],
			'kind_label' => $app->functions->htmlentities(
				isset($wb['kind_' . $row['kind'] . '_txt']) ? $wb['kind_' . $row['kind'] . '_txt'] : $row['kind']),
			'name' => $app->functions->htmlentities($row['name']),
			'installed' => $app->functions->htmlentities($row['installed']),
			'has_vulns' => $row['vuln_count'] > 0 ? 1 : 0,
			'vuln_label' => $app->functions->htmlentities($row['vuln_count'] === 1
				? $wb['vuln_one_txt'] : sprintf($wb['vuln_many_txt'], number_format($row['vuln_count'], 0, ',', '.'))),
			'can_update' => $can_update ? 1 : 0,
			'is_checked' => $checked ? 1 : 0,
			'options_html' => $options_html,
			'closes' => $app->functions->htmlentities($default_closes),
			'has_note' => $note !== '' ? 1 : 0,
			'note' => $app->functions->htmlentities($note),
		);
	}
	$rel = trim((string) substr($install['path'], strlen($scan_base)), '/');
	$blocks[] = array(
		'install_label' => $app->functions->htmlentities($rel === '' ? $wb['install_root_txt'] : '/' . $rel),
		'core_version' => $app->functions->htmlentities($install['core_version']),
		'rows' => $rows,
	);
}

// --- Page --------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_upgrade_start.htm');
$app->tpl->setVar($wb);

// Both end up inside alert('…') and confirm('…') in an onclick attribute.
foreach (array('err_no_selection_txt', 'confirm_start_txt') as $js_key) {
	if (isset($wb[$js_key])) {
		$app->tpl->setVar($js_key, malwatch_js_text($app, $wb[$js_key]));
	}
}

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('back_label', sprintf($wb['back_txt'], $app->functions->htmlentities($web['domain'])));
$app->tpl->setVar('has_blocks', count($blocks) > 0 ? 1 : 0);
$app->tpl->setLoop('blocks', $blocks);
$app->tpl->setVar('has_hidden', $hidden > 0 ? 1 : 0);
$app->tpl->setVar('hidden_line', $app->functions->htmlentities(
	sprintf($wb['hidden_txt'], number_format($hidden, 0, ',', '.'))));

$selected_template = sprintf($wb['selected_template_txt'], number_format($row_count, 0, ',', '.'));
$app->tpl->setVar('selected_template', $app->functions->htmlentities($selected_template));
$app->tpl->setVar('selected_line',
	$app->functions->htmlentities(str_replace('{n}', (string) $selected_count, $selected_template)));

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_upgrade_start');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
```

- [ ] **Step 2: Write `ispconfig/interface/templates/malwatch_upgrade_start.htm`**

```html
<div class='page-header'>
	<h1>{tmpl_var name='lede_txt'}</h1>
</div>
<p class="mw-back"><a href="#" data-load-content="security/malwatch_site_show.php?id={tmpl_var name='domain_id'}">{tmpl_var name='back_label'}</a></p>

<tmpl_if name="message">
	<div class="alert alert-success">{tmpl_var name='message'}</div>
</tmpl_if>
<tmpl_if name="error">
	<div class="alert alert-danger">{tmpl_var name='error'}</div>
</tmpl_if>

<style>
/* Dieselben Regeln wie malwatch_repair_start.htm: gedaempfte Schrift ueber
   Deckkraft, Linien und Flaechen als durchscheinendes Grau, damit beide
   Themes lesbar bleiben. Ein Block je WordPress-Installation. */
#mw-upgrade .mw-back{margin:0 0 10px}
#mw-upgrade .mw-sub{margin:6px 0 16px;opacity:.72;font-size:13px;max-width:76ch}
#mw-upgrade .mw-install{margin:18px 0 6px;font-size:14px;font-weight:600;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
#mw-upgrade .mw-install small{font-weight:400;opacity:.72}
#mw-upgrade .table{table-layout:auto}
#mw-upgrade .table > thead > tr > th,
#mw-upgrade .table > tbody > tr > td{padding:6px 10px;vertical-align:middle}
#mw-upgrade .mw-kind{
	font-size:9.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;margin-right:6px;
	padding:1px 5px;border-radius:3px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.4));opacity:.75;
}
#mw-upgrade .mw-mono{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:12px}
#mw-upgrade .mw-closes{margin-top:3px;font-size:12.5px;opacity:.8}
#mw-upgrade .mw-note{margin-top:3px;font-size:12.5px;color:var(--cic-warn-lift,#b25f00)}
#mw-upgrade tr.mw-disabled td{opacity:.6}
#mw-upgrade select.form-control{min-width:16ch;max-width:100%}
#mw-upgrade .table-wrapper{overflow-x:auto}
#mw-upgrade .mw-quiet{
	margin-top:16px;padding:12px 15px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-radius:3px;opacity:.85;font-size:13px;background:var(--cic-head,rgba(128,128,128,.07));
}
#mw-upgrade .mw-savebar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:14px}
#mw-upgrade .mw-selcount{font-size:13px;opacity:.72;font-variant-numeric:tabular-nums;white-space:nowrap}
#mw-upgrade input[type=checkbox]{accent-color:var(--cic-accent,#dd630d)}
</style>

<div id="mw-upgrade">

<p class="mw-sub">{tmpl_var name='intro_txt'}</p>

<!--
	No form of our own: the panel wraps the whole content area in pageForm and
	posts it by AJAX (see malwatch_repair_start.htm). selected[] and
	version[<software_id>] are read by name.
-->
<input type="hidden" name="id" value="{tmpl_var name='domain_id'}" />
<input type="hidden" name="malwatch_action" id="mw-action" value="" />

<tmpl_if name="has_blocks">
<tmpl_loop name="blocks">
<p class="mw-install">{tmpl_var name='install_label'} <small>WordPress {tmpl_var name='core_version'}</small></p>
<div class="table-wrapper">
<table class="table">
	<thead class="dark">
		<tr>
			<th style="width:28px">&nbsp;</th>
			<th>{tmpl_var name='col_element_txt'}</th>
			<th>{tmpl_var name='col_installed_txt'}</th>
			<th>{tmpl_var name='col_target_txt'}</th>
		</tr>
	</thead>
	<tbody>
		<tmpl_loop name="rows">
		<tr<tmpl_unless name="can_update"> class="mw-disabled"</tmpl_unless>>
			<td><tmpl_if name="can_update"><input type="checkbox" class="mw-up-check" name="selected[]" value="{tmpl_var name='software_id'}" <tmpl_if name="is_checked">checked</tmpl_if> /></tmpl_if></td>
			<td><span class="mw-kind">{tmpl_var name='kind_label'}</span><b>{tmpl_var name='name'}</b>
				<tmpl_if name="has_vulns"><span class="label label-danger">{tmpl_var name='vuln_label'}</span></tmpl_if></td>
			<td><span class="mw-mono">{tmpl_var name='installed'}</span></td>
			<td>
				<tmpl_if name="can_update">
				<select class="form-control mw-up-version" name="version[{tmpl_var name='software_id'}]">{tmpl_var name='options_html'}</select>
				<div class="mw-closes">{tmpl_var name='closes'}</div>
				</tmpl_if>
				<tmpl_if name="has_note"><div class="mw-note">{tmpl_var name='note'}</div></tmpl_if>
			</td>
		</tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
</tmpl_loop>
<tmpl_if name="has_hidden"><p class="mw-sub">{tmpl_var name='hidden_line'}</p></tmpl_if>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='no_candidates_txt'}</p>
</tmpl_if>

<div class="mw-quiet"><strong>{tmpl_var name='quiet_head_txt'}</strong> {tmpl_var name='quiet_body_txt'}</div>

<tmpl_if name="has_blocks">
<div class="mw-savebar">
	<button class="btn btn-default formbutton-default" type="button"
		onclick="if(!mwUpgradeSelected()){alert('{tmpl_var name='err_no_selection_txt'}');event.stopPropagation();return false;} document.getElementById('mw-action').value='upgrade_dry';"
		data-submit-form="pageForm" data-form-action="security/malwatch_upgrade_start.php?id={tmpl_var name='domain_id'}">{tmpl_var name='btn_dry_run_txt'}</button>
	<button class="btn btn-danger" type="button"
		onclick="if(!mwUpgradeSelected()){alert('{tmpl_var name='err_no_selection_txt'}');event.stopPropagation();return false;} if(!confirm('{tmpl_var name='confirm_start_txt'}')){event.stopPropagation();return false;} document.getElementById('mw-action').value='upgrade';"
		data-submit-form="pageForm" data-form-action="security/malwatch_upgrade_start.php?id={tmpl_var name='domain_id'}">{tmpl_var name='btn_start_txt'}</button>
	<span class="mw-selcount" id="mw-up-count" data-template="{tmpl_var name='selected_template'}">{tmpl_var name='selected_line'}</span>
</div>
</tmpl_if>

</div>

<script>
(function () {
	var root = document.getElementById('mw-upgrade');
	if (!root) { return; }
	var count = document.getElementById('mw-up-count');
	var template = count ? (count.getAttribute('data-template') || '') : '';

	// The guard of both buttons: a click with nothing selected is caught
	// before the request goes out.
	window.mwUpgradeSelected = function () {
		return root.querySelectorAll('.mw-up-check:checked').length;
	};

	function refresh() {
		if (count) {
			count.textContent = template.replace('{n}', String(window.mwUpgradeSelected()));
		}
	}

	// What a target version fixes travels on its option; the line below the
	// select follows the choice.
	var selects = root.querySelectorAll('.mw-up-version');
	for (var i = 0; i < selects.length; i++) {
		selects[i].addEventListener('change', function () {
			var option = this.options[this.selectedIndex];
			var hint = this.parentNode.querySelector('.mw-closes');
			if (hint && option) { hint.textContent = option.getAttribute('data-closes') || ''; }
		});
	}
	var checks = root.querySelectorAll('.mw-up-check');
	for (var j = 0; j < checks.length; j++) {
		checks[j].addEventListener('change', refresh);
	}
	refresh();
})();
</script>
```

- [ ] **Step 3: Add the page texts**

An `ispconfig/interface/lang/de_malwatch_upgrade.lng` anhängen:

```php
$wb['back_txt'] = '← %s';
$wb['lede_txt'] = 'Updates';
$wb['intro_txt'] = 'WordPress, Plugins und Themes bekommen die gewählte Version von wordpress.org. Vorher prüft malwatch Prüfsummen und Anforderungen, danach die Startseite und die Anmeldeseite. Antwortet eine davon mit einem Fehler, kommt der alte Stand zurück.';
$wb['col_element_txt'] = 'Element';
$wb['col_installed_txt'] = 'Installiert';
$wb['col_target_txt'] = 'Zielversion';
$wb['offer_latest_txt'] = 'neueste passende';
$wb['offer_minimal_txt'] = 'kleinste, die alle Lücken schließt';
$wb['manual_only_txt'] = 'nur von Hand: nicht bei wordpress.org';
$wb['install_root_txt'] = 'Webstamm';
$wb['kind_core_txt'] = 'Kern';
$wb['kind_plugin_txt'] = 'Plugin';
$wb['kind_theme_txt'] = 'Theme';
$wb['vuln_one_txt'] = '1 Lücke';
$wb['vuln_many_txt'] = '%s Lücken';
$wb['no_candidates_txt'] = 'Für die WordPress-Installationen dieser Website nennt der letzte Abgleich keine neuere Version.';
$wb['hidden_txt'] = '%s weitere Installationen folgen, sobald die ersten 50 aktualisiert sind.';
$wb['quiet_head_txt'] = 'Der alte Stand bleibt erhalten.';
$wb['quiet_body_txt'] = 'Jeder ersetzte Ordner liegt danach in der Quarantäne. Während des Tauschs zeigt WordPress kurz den Wartungsmodus. Hebt ein Kern-Update die Datenbank an, wird sie vorher exportiert.';
$wb['selected_template_txt'] = '{n} von %s Elementen ausgewählt';
$wb['btn_dry_run_txt'] = 'Probelauf';
$wb['btn_start_txt'] = 'Updates starten';
$wb['confirm_start_txt'] = 'Die ausgewählten Elemente jetzt aktualisieren? Die alten Ordner gehen in die Quarantäne, die Website zeigt kurz den Wartungsmodus, und bei einem Fehler danach kommt der alte Stand automatisch zurück.';
$wb['msg_queued_txt'] = 'Das Update von %s Element(en) ist eingereiht. Der Fortschritt steht auf der Seite der Website.';
$wb['msg_dry_txt'] = 'Der Probelauf für %s Element(e) ist eingereiht. Die Website bleibt dabei unverändert.';
$wb['err_invalid_site_txt'] = 'Ungültige Website.';
```

An `ispconfig/interface/lang/en_malwatch_upgrade.lng` anhängen:

```php
$wb['back_txt'] = '← %s';
$wb['lede_txt'] = 'Updates';
$wb['intro_txt'] = 'WordPress, plugins and themes get the chosen release from wordpress.org. malwatch checks checksums and requirements first, and the front page and the login page afterwards. If either answers with an error, the previous state comes back.';
$wb['col_element_txt'] = 'Element';
$wb['col_installed_txt'] = 'Installed';
$wb['col_target_txt'] = 'Target version';
$wb['offer_latest_txt'] = 'newest that fits';
$wb['offer_minimal_txt'] = 'lowest that fixes all vulnerabilities';
$wb['manual_only_txt'] = 'manual only: not on wordpress.org';
$wb['install_root_txt'] = 'Web root';
$wb['kind_core_txt'] = 'core';
$wb['kind_plugin_txt'] = 'plugin';
$wb['kind_theme_txt'] = 'theme';
$wb['vuln_one_txt'] = '1 vulnerability';
$wb['vuln_many_txt'] = '%s vulnerabilities';
$wb['no_candidates_txt'] = 'The last check names no newer release for the WordPress installations of this website.';
$wb['hidden_txt'] = '%s more installations follow once the first 50 are up to date.';
$wb['quiet_head_txt'] = 'The previous state is kept.';
$wb['quiet_body_txt'] = 'Every replaced folder ends up in quarantine. WordPress briefly shows its maintenance mode during the exchange. When a core update raises the database, the database is exported first.';
$wb['selected_template_txt'] = '{n} of %s elements selected';
$wb['btn_dry_run_txt'] = 'Dry run';
$wb['btn_start_txt'] = 'Start updates';
$wb['confirm_start_txt'] = 'Update the selected elements now? The old folders go to quarantine, the website briefly shows maintenance mode, and if an error follows, the previous state comes back automatically.';
$wb['msg_queued_txt'] = 'The update of %s element(s) is queued. Its progress shows on the page of the website.';
$wb['msg_dry_txt'] = 'The dry run for %s element(s) is queued. The website stays as it is.';
$wb['err_invalid_site_txt'] = 'Invalid website.';
```

- [ ] **Step 4: Wire the page**

In `ispconfig/install/file.list` nach der Zeile von `malwatch_repair_start.php` und nach der Zeile von `templates/malwatch_repair_start.htm`:

```
c:interface/malwatch_upgrade_start.php:interface/web/security/malwatch_upgrade_start.php
```

```
c:interface/templates/malwatch_upgrade_start.htm:interface/web/security/templates/malwatch_upgrade_start.htm
```

In `ispconfig/tests/render_pages.php` die Liste `$pages` um `'malwatch_upgrade_start.php',` ergänzen.

In `ispconfig/tests/check_wiring.sh`, Prüfung 34, in der Schleife nach der Abfrage für `malwatch_repair_start`:

```sh
	if grep -q 'malwatch_upgrade_start\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt upgrade_start mit domain_id=, die Seite liest id="
	fi
```

- [ ] **Step 5: Run the checks**

Run: `php -l ispconfig/interface/malwatch_upgrade_start.php && php ispconfig/tests/upgrade_offers_test.php && sh ispconfig/tests/check_wiring.sh`
Expected: `No syntax errors detected`, `upgrade offers OK`, `Wiring OK` (Prüfungen 6, 7, 8, 9, 10, 11, 32, 36, 39 und 41 betreffen diese Seite)

Das Rendern mit `render_pages.php` folgt in Task 10, sobald das Schema auf dem Server liegt.

- [ ] **Step 6: Commit**

```bash
git add ispconfig/interface/malwatch_upgrade_start.php ispconfig/interface/templates/malwatch_upgrade_start.htm ispconfig/interface/lang/de_malwatch_upgrade.lng ispconfig/interface/lang/en_malwatch_upgrade.lng ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh
git commit -m "feat(ispconfig): the page Updates"
```

---

### Task 6: Den Bericht einlesen

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_ingest.inc.php` (`$origins`, `ingest_upgrade`, `index_upgrade_entries`)
- Modify: `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php` (`collect_finished`, `finish_upgrade`)

**Interfaces:**
- Consumes: Bericht aus Teil A, Task 3; Tabellen aus Task 1; `malwatch_helper::path_hash`, `get_web`, `get_site`, `fail_job`; `cronjob_malwatch::create_job($site, $web, $source, $kind)`
- Produces:
  - `malwatch_ingest::ingest_upgrade($job)` → `upgrade_id` oder 0
  - `malwatch_actions::notify_upgrade($job, $upgrade_id)` wird hier aufgerufen und in Task 7 geschrieben; bis dahin fehlt die Methode, deshalb gehören Task 6 und Task 7 in denselben Stand, bevor das Addon auf einen Server geht
  - Nach einem echten Lauf ein Auftrag `vulncheck` für die Website

- [ ] **Step 1: Take `upgrade` into the origins in `malwatch_ingest.inc.php`**

```php
	private static $origins = array('manual', 'auto', 'repair', 'upgrade');
```

- [ ] **Step 2: Add `ingest_upgrade` and its index helper**

Nach `ingest_repair` einfügen:

```php
	/**
	 * Reads the report of an upgrade into malwatch_upgrade and its elements,
	 * brings malwatch_software to the new versions and indexes what the run
	 * filed into quarantine.
	 *
	 * Returns the upgrade_id, or 0 when there was no readable report.
	 */
	public function ingest_upgrade($job)
	{
		global $app;

		$app->uses('malwatch_helper');
		$helper = $app->malwatch_helper;

		$file = (string) $job['result_file'];
		$report = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
		if (!is_array($report) || !isset($report['schema'])) {
			$helper->fail_job($job['job_id'], 'Das Update hat keinen lesbaren Bericht hinterlassen. '
				. $this->tail_log($job));
			return 0;
		}
		if (intval($report['schema']) !== self::SCHEMA) {
			$helper->fail_job($job['job_id'], 'Der Bericht hat Format ' . intval($report['schema'])
				. ', erwartet wird ' . self::SCHEMA . '. Bitte Erweiterung und Scanner auf denselben Stand bringen.');
			return 0;
		}

		$web = $helper->get_web($job['parent_domain_id']);
		$sys_groupid = is_array($web) ? intval($web['sys_groupid']) : 0;
		$elements = isset($report['elements']) && is_array($report['elements']) ? $report['elements'] : array();
		$errors = isset($report['errors']) && is_array($report['errors']) ? $report['errors'] : array();
		$dry_run = !empty($report['dry_run']);

		$counts = array('updated' => 0, 'refused' => 0, 'rolled_back' => 0, 'failed' => 0);
		foreach ($elements as $element) {
			$outcome = (string) (isset($element['outcome']) ? $element['outcome'] : '');
			if ($outcome === 'updated' || $outcome === 'refused' || $outcome === 'rolled_back') {
				$counts[$outcome]++;
			} elseif ($outcome === 'failed' || $outcome === 'rollback_failed') {
				$counts['failed']++;
			}
		}

		$app->dbmaster->query(
			'INSERT INTO malwatch_upgrade (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
			. 'server_id, job_id, parent_domain_id, domain, started_at, finished_at, dry_run, php_version, '
			. 'count_updated, count_refused, count_rolled_back, count_failed, exit_code, errors, raw_report) '
			. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			$sys_groupid, intval($job['server_id']), intval($job['job_id']), intval($job['parent_domain_id']),
			(string) $job['domain'],
			$this->to_datetime(isset($report['started_at']) ? $report['started_at'] : ''),
			$this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : ''),
			$dry_run ? 'y' : 'n',
			substr((string) (isset($report['php_version']) ? $report['php_version'] : ''), 0, 32),
			$counts['updated'], $counts['refused'], $counts['rolled_back'], $counts['failed'],
			intval($job['exit_code']), implode("\n", array_slice($errors, 0, 20)), (string) file_get_contents($file));
		$upgrade_id = intval($app->dbmaster->insertID());

		foreach ($elements as $element) {
			$ids = isset($element['quarantine_ids']) && is_array($element['quarantine_ids'])
				? $element['quarantine_ids'] : array();
			$app->dbmaster->query(
				'INSERT INTO malwatch_upgrade_element (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
				. 'sys_perm_other, server_id, upgrade_id, parent_domain_id, install_path, element_kind, slug, '
				. 'from_version, to_version, outcome, message, quarantine_ids, db_export_id) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				$sys_groupid, intval($job['server_id']), $upgrade_id, intval($job['parent_domain_id']),
				substr((string) (isset($element['install']) ? $element['install'] : ''), 0, 1024),
				substr((string) (isset($element['kind']) ? $element['kind'] : ''), 0, 16),
				substr((string) (isset($element['slug']) ? $element['slug'] : ''), 0, 190),
				substr((string) (isset($element['from']) ? $element['from'] : ''), 0, 64),
				substr((string) (isset($element['to']) ? $element['to'] : ''), 0, 64),
				substr((string) (isset($element['outcome']) ? $element['outcome'] : ''), 0, 32),
				mb_substr((string) (isset($element['message']) ? $element['message'] : ''), 0, 255, 'UTF-8'),
				substr(implode(',', $ids), 0, 1024),
				substr((string) (isset($element['db_export_id']) ? $element['db_export_id'] : ''), 0, 64));

			// The daily check afterwards confirms it; until then the page shows
			// the version that is installed now.
			if (!$dry_run && (string) (isset($element['outcome']) ? $element['outcome'] : '') === 'updated') {
				$app->dbmaster->query(
					'UPDATE malwatch_software SET installed_version = ? WHERE parent_domain_id = ? '
					. 'AND path_hash = ? AND software_kind = ? AND slug = ?',
					substr((string) $element['to'], 0, 64), intval($job['parent_domain_id']),
					$helper->path_hash((string) (isset($element['path']) ? $element['path'] : '')),
					(string) $element['kind'], (string) (isset($element['slug']) ? $element['slug'] : ''));
			}

			$this->index_upgrade_entries($job, $report, $element, $ids, $sys_groupid);
		}

		$summary = sprintf('Update: %d aktualisiert, %d abgelehnt, %d zurückgeholt, %d gescheitert.',
			$counts['updated'], $counts['refused'], $counts['rolled_back'], $counts['failed']);
		$code = intval($job['exit_code']);
		if ($code === 0 || $code === 2) {
			$app->dbmaster->query(
				"UPDATE malwatch_job SET job_status = 'done', finished_at = NOW(), job_log = ? WHERE job_id = ?",
				$summary, intval($job['job_id']));
		} else {
			$helper->fail_job($job['job_id'], trim($summary . ' ' . implode(' ', array_slice($errors, 0, 3))
				. ' ' . $this->tail_log($job)));
		}

		// The report names paths of a customer; it is not kept once it is read.
		@unlink($file);
		@unlink(preg_replace('/\.json$/', '.log', $file));
		return $upgrade_id;
	}

	/**
	 * Indexes the quarantine entries of one upgrade element, the way
	 * ingest_repair does for a repair: complete_quarantine_index() fills in
	 * size and path from the listing of the store afterwards. A database export
	 * gets a row of its own.
	 */
	private function index_upgrade_entries($job, $report, $element, array $ids, $sys_groupid)
	{
		global $app;

		$export = (string) (isset($element['db_export_id']) ? $element['db_export_id'] : '');
		if ($export !== '') {
			$ids[] = $export;
		}
		$to = (string) (isset($element['to']) ? $element['to'] : '');
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
			$reason = $entry_id === $export
				? 'Datenbank vor dem Kern-Update auf ' . $to
				: 'Vor dem Update auf ' . $to . ' abgelegt';
			$app->dbmaster->query(
				'INSERT INTO malwatch_quarantine (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, '
				. 'sys_perm_other, server_id, parent_domain_id, domain, entry_id, entry_kind, rel_path, '
				. 'origin, reason, rule_id, severity, files, bytes, created_at) '
				. "VALUES (1, ?, 'riud', 'r', '', ?, ?, ?, ?, 'file', '', 'upgrade', ?, '', '', 0, 0, ?)",
				$sys_groupid, intval($job['server_id']), intval($job['parent_domain_id']), (string) $job['domain'],
				$entry_id, $reason, $this->to_datetime(isset($report['finished_at']) ? $report['finished_at'] : ''));
		}
	}
```

Zählprobe: `malwatch_upgrade` 20 Spalten, 4 Literale, 16 Platzhalter, 16 Werte; `malwatch_upgrade_element` 17 Spalten, 4 Literale, 13 Platzhalter, 13 Werte; `malwatch_quarantine` 18 Spalten, 11 Literale, 7 Platzhalter, 7 Werte.

- [ ] **Step 3: Collect upgrade jobs in the cron class**

In `collect_finished()` vor `if ($kind === 'quarantine') {`:

```php
			if ($kind === 'upgrade') {
				$upgrade_id = $app->malwatch_ingest->ingest_upgrade($job);
				$app->malwatch_runner->clear_marker($job);
				@unlink(preg_replace('/\.json$/', '.plan.json', (string) $job['result_file']));
				$this->finish_upgrade($job, $upgrade_id);
				continue;
			}
```

Nach `finish_repair()` einfügen:

```php
	/**
	 * After an upgrade: the notifications about whatever came back or failed,
	 * and a check of the website, so versions, flaws and state describe what
	 * is installed now. A dry run changed nothing and needs neither.
	 */
	private function finish_upgrade($job, $upgrade_id)
	{
		global $app;

		$options = json_decode((string) $job['options'], true);
		if (is_array($options) && !empty($options['dry_run'])) {
			return;
		}

		// A missing report is a run nobody can vouch for: notify_upgrade()
		// tells the operator with upgrade_id 0 as well.
		$app->malwatch_actions->notify_upgrade($job, $upgrade_id);

		$web = $app->malwatch_helper->get_web($job['parent_domain_id']);
		if (!is_array($web)) {
			return;
		}
		$site = $app->malwatch_helper->get_site($job['parent_domain_id']);
		if (!is_array($site)) {
			$site = array('excludes' => '', 'max_age' => 0, 'version_scan' => 'y');
		}
		$this->create_job($site, $web, 'schedule', 'vulncheck');
	}
```

- [ ] **Step 4: Run the checks**

Run: `php -l ispconfig/server/lib/classes/malwatch_ingest.inc.php && php -l ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php && sh ispconfig/tests/check_wiring.sh`
Expected: zweimal `No syntax errors detected`, `Wiring OK` (Prüfung 38 findet `upgrade` in `$origins` und in `malwatch_quarantine.origin`)

- [ ] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_ingest.inc.php ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php
git commit -m "feat(ispconfig): read an upgrade report, index its quarantine entries, check the site afterwards"
```

---

### Task 7: Meldungen an Betreiber und Kunde

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_actions.inc.php` (`template_file`, `render`, `notify_upgrade` und Helfer)
- Create: `ispconfig/server/conf/malwatch_upgrade_notification_de.txt`, `ispconfig/server/conf/malwatch_upgrade_notification_en.txt`, `ispconfig/server/conf/malwatch_client_upgrade_notification_de.txt`, `ispconfig/server/conf/malwatch_client_upgrade_notification_en.txt`
- Modify: `ispconfig/install/file.list`

**Interfaces:**
- Consumes: Tabellen `malwatch_upgrade`, `malwatch_upgrade_element` (Task 1, gefüllt in Task 6); `log_action`, `strip_optional_block`, `malwatch_helper::get_config`, `get_web`, `get_site`
- Produces: `public function notify_upgrade($job, $upgrade_id)`; aufgerufen aus `finish_upgrade` (Task 6)

Entscheidung in diesem Task: Der Kunde bekommt eine Mail, sobald ein Element `rolled_back`, `failed` oder `rollback_failed` trägt. Ein Fehler des Laufs ohne betroffenes Element, etwa eine abweichende Prüfsumme vor jedem Tausch, geht allein an den Betreiber: an der Website hat sich dann nichts geändert, und dem Kunden bliebe eine Nachricht ohne Inhalt.

- [ ] **Step 1: Share the template lookup**

In `malwatch_actions.inc.php` nach `render()` einfügen:

```php
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
```

In `render()` den Block von `$language = preg_match(…)` bis zum Ende von `if ($file === '') { return ''; }` ersetzen durch:

```php
		$file = $this->template_file($template, $language);
		if ($file === '') {
			return '';
		}
```

In `render()` bleibt `global $conf;` stehen, falls die Methode `$conf` weiter nutzt; sonst entfällt die Zeile.

- [ ] **Step 2: Add the upgrade notification**

Vor `log_action()` einfügen:

```php
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
```

- [ ] **Step 3: Write the templates**

`ispconfig/server/conf/malwatch_upgrade_notification_de.txt`:

```
MIME-Version: 1.0
Content-type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Subject: malwatch: Das Update auf {domain} braucht Aufmerksamkeit

Das Update von WordPress auf der Website {domain} braucht Ihre Aufmerksamkeit.

{broken_block}
ACHTUNG: Die Website antwortet auch nach dem Zurückholen fehlerhaft und braucht
jetzt Hilfe. Die übrigen Elemente dieses Laufs wurden nicht mehr begonnen.

{/broken_block}
Betroffene Elemente:

{elements}

{errors_block}
Fehler des Laufs:

{errors}

{/errors_block}
Ersetzte Ordner und Datenbank-Exporte liegen in der Quarantäne dieser Website.
Die Einzelheiten stehen im ISPConfig-Panel unter Security auf der Seite der
Website.

Server: {hostname}
```

`ispconfig/server/conf/malwatch_upgrade_notification_en.txt`:

```
MIME-Version: 1.0
Content-type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Subject: malwatch: the update on {domain} needs attention

The WordPress update on the website {domain} needs your attention.

{broken_block}
IMPORTANT: The website still answers with errors after the rollback and needs
help now. The remaining elements of this run were left unstarted.

{/broken_block}
Elements concerned:

{elements}

{errors_block}
Errors of the run:

{errors}

{/errors_block}
Replaced folders and database exports are kept in the quarantine of this
website. The details are in the ISPConfig panel under Security, on the page of
the website.

Server: {hostname}
```

`ispconfig/server/conf/malwatch_client_upgrade_notification_de.txt`:

```
MIME-Version: 1.0
Content-type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Subject: Hinweis zum Update Ihrer Website {domain}

Guten Tag,

wir haben WordPress auf Ihrer Website {domain} aktualisiert. Bei einigen
Bestandteilen hat die Prüfung danach einen Fehler gezeigt; für diese haben wir
den vorherigen Stand wiederhergestellt.

{broken_block}
Ihre Website zeigt derzeit einen Fehler. Wir kümmern uns darum und melden uns
bei Ihnen.

{/broken_block}
Betroffen:

{elements}

Diese Bestandteile bleiben vorerst auf dem bisherigen Stand. Wir planen das
Update neu, sobald die Ursache geklärt ist.

Bei Fragen melden Sie sich gern.
```

`ispconfig/server/conf/malwatch_client_upgrade_notification_en.txt`:

```
MIME-Version: 1.0
Content-type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Subject: Notice about the update of your website {domain}

Hello,

we updated WordPress on your website {domain}. For some of its parts the check
afterwards showed an error, and for those we restored the previous state.

{broken_block}
Your website currently shows an error. We are looking into it and will get
back to you.

{/broken_block}
Concerned:

{elements}

These parts stay on their previous release for now. We will schedule the
update again once the cause is clear.

Please get in touch if you have any questions.
```

In `ispconfig/install/file.list` nach den Zeilen der vorhandenen Vorlagen:

```
c:server/conf/malwatch_upgrade_notification_de.txt:server/conf/malwatch_upgrade_notification_de.txt
c:server/conf/malwatch_upgrade_notification_en.txt:server/conf/malwatch_upgrade_notification_en.txt
c:server/conf/malwatch_client_upgrade_notification_de.txt:server/conf/malwatch_client_upgrade_notification_de.txt
c:server/conf/malwatch_client_upgrade_notification_en.txt:server/conf/malwatch_client_upgrade_notification_en.txt
```

- [ ] **Step 4: Run the checks**

Run: `php -l ispconfig/server/lib/classes/malwatch_actions.inc.php && sh ispconfig/tests/check_wiring.sh`
Expected: `No syntax errors detected`, `Wiring OK` (Prüfung 6 findet die vier Vorlagen in `file.list`; Prüfung 22 findet nur `error` als wörtlichen `action_type`)

- [ ] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_actions.inc.php ispconfig/server/conf/malwatch_upgrade_notification_de.txt ispconfig/server/conf/malwatch_upgrade_notification_en.txt ispconfig/server/conf/malwatch_client_upgrade_notification_de.txt ispconfig/server/conf/malwatch_client_upgrade_notification_en.txt ispconfig/install/file.list
git commit -m "feat(ispconfig): tell the operator and the customer about an upgrade that was taken back"
```

---

### Task 8: Seite der Website und Schwachstellen-Übersicht

**Files:**
- Modify: `ispconfig/interface/malwatch_site_show.php`
- Modify: `ispconfig/interface/templates/malwatch_site_show.htm`
- Modify: `ispconfig/interface/lib/malwatch_lib.inc.php` (`malwatch_upgrade_outcome_class`)
- Modify: `ispconfig/interface/lang/de_malwatch.lng`, `ispconfig/interface/lang/en_malwatch.lng`
- Modify: `ispconfig/interface/templates/malwatch_vuln_list.htm`, `ispconfig/interface/lang/de_malwatch_vuln_list.lng`, `ispconfig/interface/lang/en_malwatch_vuln_list.lng`

**Interfaces:**
- Consumes: Seite aus Task 5; Tabellen aus Task 1; Fortschrittsdatei aus Teil A (`kind: "upgrade"`, `steps[].state`)
- Produces: Knopf „Updates“, Verweis „Aktualisieren“ je Softwarezeile, Fortschritt mit vier Phasen und einer Zeile je Schritt, Abschnitt „Updates“ mit den letzten zehn Läufen, Verweis „Updates für diese Website“ in der Übersicht

- [ ] **Step 1: Label class of an outcome in `malwatch_lib.inc.php`**

Nach `malwatch_severity_class` einfügen:

```php
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
```

- [ ] **Step 2: Feed the page in `malwatch_site_show.php`**

Vor der Schleife über `$software` einfügen:

```php
$has_upgrades = false;
```

In der Schleife vor `$software_rows[] = array(`:

```php
		// A newer release or known flaws, on something wordpress.org publishes.
		$can_upgrade = (string) $row['product'] === 'wordpress' && $row['version_unknown'] !== 'y'
			&& ($row['outdated'] === 'y' || $vuln_count > 0);
		if ($can_upgrade) {
			$has_upgrades = true;
		}
```

Im Array `$software_rows[]` ergänzen:

```php
			'software_id' => $app->functions->intval($row['software_id']),
			'can_upgrade' => $can_upgrade ? 1 : 0,
```

Nach `$app->tpl->setVar('has_software', count($software_rows) > 0);`:

```php
$app->tpl->setVar('has_upgrades', $has_upgrades ? 1 : 0);
```

Vor `// --- History ---` einfügen:

```php
// --- Updates -------------------------------------------------------------------
$upgrades = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_upgrade WHERE parent_domain_id = ? ORDER BY upgrade_id DESC LIMIT 10', $domain_id);
$upgrade_rows = array();
foreach ((array) $upgrades as $run) {
	$elements = $app->db->queryAllRecords(
		'SELECT * FROM malwatch_upgrade_element WHERE upgrade_id = ? ORDER BY element_id ASC LIMIT 100',
		$app->functions->intval($run['upgrade_id']));
	$lines = array();
	foreach ((array) $elements as $element) {
		$kind = (string) $element['element_kind'];
		$outcome = (string) $element['outcome'];
		$lines[] = array(
			'name' => $app->functions->htmlentities($kind === 'core' ? 'WordPress' : $kind . ' ' . $element['slug']),
			'versions' => $app->functions->htmlentities($element['from_version'] . ' → ' . $element['to_version']),
			'outcome_label' => $app->functions->htmlentities(isset($wb['upgrade_outcome_' . $outcome . '_txt'])
				? $wb['upgrade_outcome_' . $outcome . '_txt'] : $outcome),
			'outcome_class' => malwatch_upgrade_outcome_class($outcome),
			'message' => $app->functions->htmlentities((string) $element['message']),
		);
	}
	$upgrade_rows[] = array(
		'finished_at' => $app->functions->htmlentities(malwatch_datetime($run['finished_at'])),
		'run_label' => $app->functions->htmlentities($run['dry_run'] === 'y' ? $wb['upgrade_dry_txt'] : $wb['upgrade_real_txt']),
		'elements' => $lines,
	);
}
$app->tpl->setLoop('upgrades', $upgrade_rows);
$app->tpl->setVar('has_upgrade_history', count($upgrade_rows) > 0 ? 1 : 0);
```

- [ ] **Step 3: Button and row link in `malwatch_site_show.htm`**

Nach dem Verweis auf `malwatch_repair_start.php` im Block `#mw-actions`:

```html
	<tmpl_if name="has_upgrades">
	<a class="btn btn-default formbutton-default" href="#"
		data-load-content="security/malwatch_upgrade_start.php?id={tmpl_var name='domain_id'}">{tmpl_var name='upgrades_txt'}</a>
	</tmpl_if>
```

In der Softwaretabelle in der Produktzelle nach dem Etikett mit `vuln_count_label`:

```html
				<tmpl_if name="can_upgrade"><a class="mw-uplink" href="#" data-load-content="security/malwatch_upgrade_start.php?id={tmpl_var name='domain_id'}&amp;software_id={tmpl_var name='software_id'}">{tmpl_var name='upgrade_row_txt'}</a></tmpl_if>
```

Im zweiten `<style>`-Block (Softwaretabelle) ergänzen:

```css
#mw-site .mw-uplink{margin-left:6px;font-size:12px;white-space:nowrap}
.mw-upline{margin:2px 0;font-size:12.5px;line-height:1.5}
#mw-run .mw-steps{margin:0 0 8px;font-size:12.5px;display:flex;flex-direction:column;gap:2px}
#mw-run .mw-step-rolled_back,#mw-run .mw-step-failed{color:var(--cic-warn-lift,#b25f00)}
#mw-run .mw-step-rollback_failed{color:var(--cic-danger,#c9302c);font-weight:600}
```

- [ ] **Step 4: Progress of an upgrade**

Im Block `#mw-run` nach `<div class="mw-phases" id="mw-phases"></div>`:

```html
	<div class="mw-steps" id="mw-steps" style="display:none"></div>
```

Im Skript nach der Definition von `repairPhases`:

```js
	var upgradePhases = ['{tmpl_var name="phase_detect_txt"}', '{tmpl_var name="phase_fetch_txt"}',
		'{tmpl_var name="phase_verify_txt"}', '{tmpl_var name="phase_upgrade_txt"}'];
	var stepLabels = {
		waiting: '{tmpl_var name="step_waiting_txt"}', fetched: '{tmpl_var name="step_fetched_txt"}',
		verified: '{tmpl_var name="step_verified_txt"}', refused: '{tmpl_var name="step_refused_txt"}',
		swapped: '{tmpl_var name="step_swapped_txt"}', database: '{tmpl_var name="step_database_txt"}',
		updated: '{tmpl_var name="step_updated_txt"}', would_update: '{tmpl_var name="step_would_update_txt"}',
		rolled_back: '{tmpl_var name="step_rolled_back_txt"}', failed: '{tmpl_var name="step_failed_txt"}',
		rollback_failed: '{tmpl_var name="step_rollback_failed_txt"}', skipped: '{tmpl_var name="step_skipped_txt"}'
	};
	var finalStates = ['updated', 'would_update', 'refused', 'rolled_back', 'failed', 'rollback_failed', 'skipped'];
```

In `draw(d)` den Anfang bis einschließlich der Phasenanzeige ersetzen durch:

```js
		var p = d.progress || {};
		var isRepair = (d.kind === 'repair');
		var isUpgrade = (d.kind === 'upgrade');
		var steps = p.steps || [];
		var bar = document.getElementById('mw-bar');
		var pct = null;

		if (isRepair && p.elements_total) {
			pct = Math.round((p.elements_done || 0) * 100 / p.elements_total);
		} else if (isUpgrade && steps.length) {
			var finished = steps.filter(function (s) { return finalStates.indexOf(s.state) >= 0; }).length;
			pct = Math.round(finished * 100 / steps.length);
		} else if (!isRepair && !isUpgrade && p.files_total) {
			pct = Math.round((p.files_done || 0) * 100 / p.files_total);
		}
		if (pct !== null) {
			// Der Erwartungswert ist eine Schaetzung aus dem letzten Lauf; eine
			// Website waechst dazwischen. Bei 99 deckeln, bis der Lauf fertig
			// meldet - ein Balken bei 140 Prozent ist schlimmer als keiner.
			if (pct > 99) { pct = 99; }
			if (pct < 0) { pct = 0; }
			if (d.state === 'done') { pct = 100; }
			bar.className = 'mw-fill';
			bar.style.width = pct + '%';
			document.getElementById('mw-pct').textContent = pct + ' %';
		} else {
			bar.className = 'mw-fill mw-idle';
			document.getElementById('mw-pct').textContent = '';
		}

		var ph = document.getElementById('mw-phases');
		var phases = isRepair ? repairPhases : (isUpgrade ? upgradePhases : null);
		if (phases) {
			ph.innerHTML = phases.map(function (n, i) {
				var c = (i + 1) < (p.phase_index || 0) ? 'done'
					: (i + 1) === (p.phase_index || 0) ? 'now' : '';
				return '<span class="mw-ph ' + c + '">' + n + '</span>';
			}).join('');
			document.getElementById('mw-what').textContent =
				phases[(p.phase_index || 1) - 1] || phases[0];
		} else {
			ph.innerHTML = '';
			document.getElementById('mw-what').textContent = scanningTxt;
		}

		// One line per element. Built from text nodes: slugs come off the
		// customer's disk and may carry markup.
		var list = document.getElementById('mw-steps');
		list.textContent = '';
		steps.forEach(function (s) {
			var line = document.createElement('div');
			line.className = 'mw-step mw-step-' + s.state;
			var name = s.kind === 'core' ? 'WordPress' : s.kind + ' ' + (s.slug || '');
			line.textContent = name + ' ' + (s.from || '') + ' → ' + (s.to || '') + ' · ' + (stepLabels[s.state] || s.state);
			list.appendChild(line);
		});
		list.style.display = steps.length ? '' : 'none';
```

- [ ] **Step 5: History of upgrades**

Vor `<p class="fieldset-legend">{tmpl_var name='history_txt'}</p>` einfügen:

```html
<tmpl_if name="has_upgrade_history">
<p class="fieldset-legend">{tmpl_var name='upgrades_history_txt'}</p>
<div class="table-wrapper marginTop15">
<table class="table">
	<thead class="dark">
		<tr>
			<th class="mw-tight">{tmpl_var name='finished_txt'}</th>
			<th class="mw-tight">{tmpl_var name='upgrade_run_txt'}</th>
			<th>{tmpl_var name='upgrade_elements_txt'}</th>
		</tr>
	</thead>
	<tbody>
		<tmpl_loop name="upgrades">
		<tr>
			<td class="num mw-tight">{tmpl_var name='finished_at'}</td>
			<td class="mw-tight">{tmpl_var name='run_label'}</td>
			<td>
				<tmpl_loop name="elements">
				<div class="mw-upline"><span class="label {tmpl_var name='outcome_class'}">{tmpl_var name='outcome_label'}</span> {tmpl_var name='name'} <span class="mw-mono">{tmpl_var name='versions'}</span><tmpl_if name="message"> <small class="mw-flaw-dim">{tmpl_var name='message'}</small></tmpl_if></div>
				</tmpl_loop>
			</td>
		</tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
</tmpl_if>
```

- [ ] **Step 6: Texts of the website page**

An `ispconfig/interface/lang/de_malwatch.lng` anhängen:

```php
$wb['upgrades_txt'] = 'Updates';
$wb['upgrade_row_txt'] = 'Aktualisieren';
$wb['phase_upgrade_txt'] = 'Aktualisieren';
$wb['step_waiting_txt'] = 'wartet';
$wb['step_fetched_txt'] = 'geholt';
$wb['step_verified_txt'] = 'geprüft';
$wb['step_refused_txt'] = 'abgelehnt';
$wb['step_swapped_txt'] = 'getauscht';
$wb['step_database_txt'] = 'Datenbank';
$wb['step_updated_txt'] = 'aktualisiert';
$wb['step_would_update_txt'] = 'würde aktualisiert';
$wb['step_rolled_back_txt'] = 'zurückgeholt';
$wb['step_failed_txt'] = 'gescheitert, alter Stand zurück';
$wb['step_rollback_failed_txt'] = 'Website fehlerhaft';
$wb['step_skipped_txt'] = 'übersprungen';
$wb['upgrades_history_txt'] = 'Updates';
$wb['upgrade_run_txt'] = 'Lauf';
$wb['upgrade_elements_txt'] = 'Elemente';
$wb['upgrade_dry_txt'] = 'Probelauf';
$wb['upgrade_real_txt'] = 'Update';
$wb['upgrade_outcome_updated_txt'] = 'aktualisiert';
$wb['upgrade_outcome_would_update_txt'] = 'würde aktualisiert';
$wb['upgrade_outcome_refused_txt'] = 'abgelehnt';
$wb['upgrade_outcome_rolled_back_txt'] = 'zurückgeholt';
$wb['upgrade_outcome_failed_txt'] = 'gescheitert';
$wb['upgrade_outcome_rollback_failed_txt'] = 'Website fehlerhaft';
$wb['upgrade_outcome_skipped_txt'] = 'übersprungen';
```

An `ispconfig/interface/lang/en_malwatch.lng` anhängen:

```php
$wb['upgrades_txt'] = 'Updates';
$wb['upgrade_row_txt'] = 'Update';
$wb['phase_upgrade_txt'] = 'Update';
$wb['step_waiting_txt'] = 'waiting';
$wb['step_fetched_txt'] = 'fetched';
$wb['step_verified_txt'] = 'verified';
$wb['step_refused_txt'] = 'refused';
$wb['step_swapped_txt'] = 'exchanged';
$wb['step_database_txt'] = 'database';
$wb['step_updated_txt'] = 'updated';
$wb['step_would_update_txt'] = 'would be updated';
$wb['step_rolled_back_txt'] = 'taken back';
$wb['step_failed_txt'] = 'failed, previous state back';
$wb['step_rollback_failed_txt'] = 'website broken';
$wb['step_skipped_txt'] = 'skipped';
$wb['upgrades_history_txt'] = 'Updates';
$wb['upgrade_run_txt'] = 'Run';
$wb['upgrade_elements_txt'] = 'Elements';
$wb['upgrade_dry_txt'] = 'Dry run';
$wb['upgrade_real_txt'] = 'Update';
$wb['upgrade_outcome_updated_txt'] = 'updated';
$wb['upgrade_outcome_would_update_txt'] = 'would be updated';
$wb['upgrade_outcome_refused_txt'] = 'refused';
$wb['upgrade_outcome_rolled_back_txt'] = 'taken back';
$wb['upgrade_outcome_failed_txt'] = 'failed';
$wb['upgrade_outcome_rollback_failed_txt'] = 'website broken';
$wb['upgrade_outcome_skipped_txt'] = 'skipped';
```

- [ ] **Step 7: Link from the vulnerability overview**

In `ispconfig/interface/templates/malwatch_vuln_list.htm` die Zeile mit `class="mw-sitelink"` ersetzen durch:

```html
				<p class="mw-sitelink"><a href="#" data-load-content="security/malwatch_site_show.php?id={tmpl_var name='domain_id'}">{tmpl_var name='open_site_txt'}</a> · <a href="#" data-load-content="security/malwatch_upgrade_start.php?id={tmpl_var name='domain_id'}">{tmpl_var name='open_upgrades_txt'}</a></p>
```

An `de_malwatch_vuln_list.lng` anhängen: `$wb['open_upgrades_txt'] = 'Updates für diese Website';`
An `en_malwatch_vuln_list.lng` anhängen: `$wb['open_upgrades_txt'] = 'Updates for this website';`

- [ ] **Step 8: Run the checks**

Run: `php -l ispconfig/interface/malwatch_site_show.php && php -l ispconfig/interface/lib/malwatch_lib.inc.php && sh ispconfig/tests/check_wiring.sh`
Expected: zweimal `No syntax errors detected`, `Wiring OK` (Prüfungen 9 und 36 finden alle neuen Schlüssel, Prüfung 34 findet `id=` in beiden Verweisen, Prüfung 29 findet kein Neuladen im Takt)

- [ ] **Step 9: Commit**

```bash
git add ispconfig/interface/malwatch_site_show.php ispconfig/interface/templates/malwatch_site_show.htm ispconfig/interface/lib/malwatch_lib.inc.php ispconfig/interface/lang/de_malwatch.lng ispconfig/interface/lang/en_malwatch.lng ispconfig/interface/templates/malwatch_vuln_list.htm ispconfig/interface/lang/de_malwatch_vuln_list.lng ispconfig/interface/lang/en_malwatch_vuln_list.lng
git commit -m "feat(ispconfig): updates on the website page - button, row link, progress and history"
```

---

### Task 9: Einstellung „WP-CLI“

**Files:**
- Modify: `ispconfig/interface/form/malwatch_config.tform.php`
- Modify: `ispconfig/interface/templates/malwatch_config_edit.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_config.lng`, `ispconfig/interface/lang/en_malwatch_config.lng`

**Interfaces:**
- Consumes: Spalte `malwatch_config.wp_cli_path` (Task 1)
- Produces: Feld `wp_cli_path` in den Einstellungen; der Runner liest es (Task 2)

- [ ] **Step 1: Add the field to the form definition**

In `malwatch_config.tform.php` nach dem Feld `'wpscan_token' => array(…),`:

```php
		// The command line of WP-CLI. The runner hands it to malwatch upgrade;
		// a core update that raises the database needs it. Empty means the
		// default, /usr/local/bin/wp.
		'wp_cli_path' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'default' => '/usr/local/bin/wp',
			'validators' => array(
				array(
					'type' => 'REGEX',
					'regex' => '/^(\/[a-zA-Z0-9\/_.-]{2,250})?$/',
					'errmsg' => 'wp_cli_path_error_regex'
				)
			),
			'value' => '',
			'width' => '40',
			'maxlength' => '255'
		),
```

- [ ] **Step 2: Show it**

In `malwatch_config_edit.htm` nach dem `form-group` des WPScan-Schlüssels:

```html
<div class="form-group">
	<label for="wp_cli_path" class="col-sm-3 control-label">{tmpl_var name='wp_cli_path_txt'}</label>
	<div class="col-sm-9">
		<input type="text" name="wp_cli_path" id="wp_cli_path" value="{tmpl_var name='wp_cli_path'}" class="form-control" />
		<span class="help-block">{tmpl_var name='wp_cli_path_hint_txt'}</span>
	</div>
</div>
```

An `de_malwatch_config.lng` anhängen:

```php
$wb['wp_cli_path_txt'] = 'WP-CLI';
$wb['wp_cli_path_hint_txt'] = 'Pfad zu WP-CLI auf dem Server. Updates exportieren und heben damit die Datenbank an, wenn ein Kern-Update das verlangt. Ein leeres Feld steht für /usr/local/bin/wp.';
$wb['wp_cli_path_error_regex'] = 'Der Pfad zu WP-CLI muss ein absoluter Pfad sein.';
```

An `en_malwatch_config.lng` anhängen:

```php
$wb['wp_cli_path_txt'] = 'WP-CLI';
$wb['wp_cli_path_hint_txt'] = 'Path to WP-CLI on the server. Updates use it to export and raise the database when a core update asks for it. An empty field stands for /usr/local/bin/wp.';
$wb['wp_cli_path_error_regex'] = 'The path to WP-CLI must be an absolute path.';
```

- [ ] **Step 3: Run the checks**

Run: `php -l ispconfig/interface/form/malwatch_config.tform.php && sh ispconfig/tests/check_wiring.sh`
Expected: `No syntax errors detected`, `Wiring OK` (Prüfungen 5, 9 und 36)

- [ ] **Step 4: Commit**

```bash
git add ispconfig/interface/form/malwatch_config.tform.php ispconfig/interface/templates/malwatch_config_edit.htm ispconfig/interface/lang/de_malwatch_config.lng ispconfig/interface/lang/en_malwatch_config.lng
git commit -m "feat(ispconfig): the path to WP-CLI in the settings"
```

---

### Task 10: Doku, Gesamtprüfung und Freigabe 0.14.0

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`, `CHANGELOG.md`, `README.md`, `ispconfig/README.md`

**Interfaces:**
- Consumes: alle Tasks aus Teil A und Teil B
- Produces: Version 0.14.0, getaggt und auf dem Server eingespielt

Der Ablauf folgt dem Release-Skill des Nutzers: Version zuerst, dann Doku, dann Prüfungen, dann Commit, Push und Tag, dann Prüfung am laufenden System, zum Schluss „Fertig“ mit Versionsnummer. Das Zusammenführen des Zweigs `wordpress-updates` in `main` entscheidet der Nutzer über `superpowers:finishing-a-development-branch`, bevor der Tag gesetzt wird.

- [ ] **Step 1: Bump the version**

`internal/version/version.go`: `var Version = "0.14.0"`; `ispconfig/version`: `0.14.0`.

- [ ] **Step 2: Write the changelog**

In `CHANGELOG.md` über dem Eintrag 0.13.2 einfügen, mit dem Datum des Tages, an dem der Tag gesetzt wird:

~~~markdown
## [0.14.0] – JJJJ-MM-TT

### Neu

**WordPress-Updates aus dem Panel.** Die Seite „Updates“ einer Website bietet
für den WordPress-Kern und für Plugins und Themes mit neuerer Version bei
wordpress.org je zwei Zielversionen an: die neueste, deren Anforderungen an
WordPress- und PHP-Version die Website erfüllt, und die kleinste, die alle
bekannten Lücken schließt. Beim Kern ist die neueste die jüngste Version seines
Zweigs. Jede Angabe nennt, welche Lücken sie schließt.

**Der Befehl `malwatch upgrade`.** Er liest eine Plandatei, lädt die
Zielversionen, prüft Prüfsummen und Anforderungen, legt den alten Stand in die
Quarantäne und tauscht ihn, während WordPress kurz den Wartungsmodus zeigt.
Hebt ein Kern-Update die Datenbank an, exportiert WP-CLI sie vorher als
Benutzer der Website und hebt sie danach an. Anschließend ruft malwatch
Startseite und Anmeldeseite ab; antwortet eine davon mit einem Serverfehler,
ohne Antwort oder mit leerer Seite, kommt der alte Stand zurück, die Datenbank
eingeschlossen.

**Meldungen.** Zurückholen und Fehler gehen per Mail an den Betreiber und, wenn
für die Website „Kunde benachrichtigen“ eingeschaltet ist, an den Kunden. Die
Seite der Website zeigt den Fortschritt je Element und die letzten zehn Läufe.

**Scan und Abgleich** nennen die PHP-Version der Website (`--php`), je Software
die Anforderungen der neuesten Version und beim Kern die neueste Version des
Zweigs.

**Einstellungen:** Pfad zu WP-CLI.
~~~

`JJJJ-MM-TT` durch das Datum ersetzen, bevor der Commit entsteht.

- [ ] **Step 3: Document the command and the page**

In `README.md` vor `## Quarantäne verwalten` einfügen:

~~~markdown
## Aktualisieren

`upgrade` bringt WordPress-Kern, Plugins und Themes auf eine Zielversion von
wordpress.org. Welche Elemente auf welche Version gehen, steht in einer
Plandatei:

```json
{"schema":1,"installs":[{"path":"/var/www/web1/web","url":"https://beispiel.de/",
  "elements":[{"kind":"core","version":"6.4.5"},{"kind":"plugin","slug":"akismet","version":"5.3.3"}]}]}
```

```
malwatch upgrade --path=/var/www/web1/web --plan=plan.json --run-as=web1:client1 \
                 --php=/usr/bin/php8.2 --quarantine-dir=/var/lib/malwatch/quarantine
```

Je Element:

1. Archiv laden, Prüfsummen und Anforderungen prüfen
2. die Datenbank exportieren, wenn ein Kern-Update sie anhebt
3. den alten Ordner in die Quarantäne legen, den neuen einsetzen, die Datenbank anheben
4. Startseite und Anmeldeseite abrufen und bei einem Fehler den alten Stand zurückholen

WP-CLI läuft als `--run-as`; root wird abgewiesen. `--dry-run` hält vor dem
Tausch an. Die Rückgabecodes stehen in `malwatch --help`.
~~~

In `ispconfig/README.md` vor `## Aktionen` einfügen:

~~~markdown
## Updates

Die Seite **Updates** einer Website listet je WordPress-Installation Kern,
Plugins und Themes mit neuerer Version bei wordpress.org. Jede Zeile bietet die
neueste passende Version und die kleinste, die alle bekannten Lücken schließt.
Der Runner schreibt eine Plandatei und startet `malwatch upgrade` als Benutzer
der Website mit ihrer PHP-Version; die Nachprüfung verbindet sich mit der IP des
Vhosts.

Scheitert die Nachprüfung, holt malwatch den alten Stand zurück und meldet es
dem Betreiber, bei eingeschaltetem „Kunde benachrichtigen“ auch dem Kunden. Den
Pfad zu WP-CLI trägt **Security > Einstellungen**.
~~~

- [ ] **Step 4: Run every check**

Run lokal: `gofmt -l . && go vet ./... && go build ./... && sh ispconfig/tests/check_wiring.sh && sh ispconfig/tests/check_constants.sh`
Expected: keine Ausgabe von gofmt und vet, `Wiring OK`, `Constants OK: …`

Auf dem Server (Stand des Zweigs unter `/root/mw-test`, Testbinaries unter `/root/mw-test/bin`, wie im Speicher `malwatch-server-testing` beschrieben):

```bash
cd /root/mw-test && for f in $(git ls-files 2>/dev/null || find ispconfig -name '*.php'); do case "$f" in *.php) php -l "$f" > /dev/null || echo "LINT $f";; esac; done
php ispconfig/tests/upgrade_helpers_test.php && php ispconfig/tests/upgrade_offers_test.php
```

Expected: keine Zeile `LINT`, `upgrade helpers OK`, `upgrade offers OK`, jedes Go-Testbinary `ok`.

- [ ] **Step 5: Commit on the branch**

```bash
git add -A
git commit -m "docs: WordPress updates from the panel (0.14.0)"
```

- [ ] **Step 6: Finish the branch**

`superpowers:finishing-a-development-branch` aufrufen. Der Nutzer wählt, wie `wordpress-updates` nach `main` kommt. Die folgenden Schritte laufen auf `main`.

- [ ] **Step 7: Push and tag**

```bash
git push
git tag v0.14.0 && git push origin v0.14.0
```

Die CI-Jobs `test`, `php-syntax`, `clean-cms`, `repair-roundtrip` und `upgrade-roundtrip` sowie der Release-Lauf müssen grün werden (`gh run watch`).

- [ ] **Step 8: Deploy and verify on the server**

```bash
cd /usr/local/ispconfig/extensions
curl -fsSLo malwatch.pkg https://github.com/brightcolor/malwatch/releases/download/v0.14.0/malwatch.pkg
mkdir -p malwatch && cd malwatch && unzip -o -q ../malwatch.pkg && rm -f ../malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php
/usr/local/bin/malwatch version
cat /usr/local/ispconfig/extensions/malwatch/version
mysql -N dbispconfig -e "SHOW TABLES LIKE 'malwatch_upgrade%'; SHOW COLUMNS FROM malwatch_software LIKE 'latest%'; SHOW COLUMNS FROM malwatch_site LIKE 'php_version'"
domain_id=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND outdated = 'y' LIMIT 1")
php /usr/local/ispconfig/extensions/malwatch/tests/render_pages.php "$domain_id"
```

Expected: `v0.14.0` und `0.14.0`; zwei Tabellen, drei Spalten `latest…`, eine Spalte `php_version`; `All pages render.` mit `malwatch_upgrade_start.php`.

Nach dem nächsten Abgleich (oder „Alle Websites jetzt abgleichen“ in der Schwachstellen-Übersicht):

```bash
mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_site WHERE php_version != ''; SELECT COUNT(*) FROM malwatch_software WHERE latest_requires_php != '' OR latest_in_branch != ''"
```

Expected: beide Zahlen größer als 0.

- [ ] **Step 9: A dry run from the panel**

Auf der Seite **Updates** einer Website mit veraltetem Plugin den Probelauf starten. Erwartet: der Auftrag endet mit `done`, die Seite der Website zeigt im Abschnitt „Updates“ einen Probelauf mit `würde aktualisiert` oder `abgelehnt` samt Grund, die Dateien der Website sind unverändert.

- [ ] **Step 10: The first real update**

Vor dem ersten echten Update beim Nutzer nachfragen, auf welcher Website es laufen soll: es verändert eine Kundenwebsite. Danach auf dieser Website ein Plugin aktualisieren und prüfen: Ausgang `aktualisiert`, Quarantäne-Eintrag mit Ursprung `upgrade`, der folgende Abgleich zeigt die neue Version.

- [ ] **Step 11: Close**

Dem Nutzer knapp berichten und mit „Fertig“ und `0.14.0` enden.
