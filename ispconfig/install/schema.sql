-- --------------------------------------------------------
-- ISPConfig extension: malwatch
-- Database schema
--
-- Naming follows the ISPConfig conventions: sys_userid /
-- sys_groupid / sys_perm_* for the permission framework,
-- server_id for the server assignment, enum('n','y') for flags.
-- --------------------------------------------------------

--
-- Global settings. Exactly one row, config_id = 1.
--
CREATE TABLE IF NOT EXISTS `malwatch_config` (
  `config_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `binary_path` varchar(255) NOT NULL DEFAULT '/usr/local/bin/malwatch',
  `state_dir` varchar(255) NOT NULL DEFAULT '/var/lib/malwatch',
  `admin_email` varchar(255) NOT NULL DEFAULT '',
  `sender_email` varchar(255) NOT NULL DEFAULT '',
  `default_schedule` enum('off','daily','weekly','monthly') NOT NULL DEFAULT 'weekly',
  `default_excludes` text,
  `max_parallel` int(11) unsigned NOT NULL DEFAULT '1',
  `job_timeout_hours` int(11) unsigned NOT NULL DEFAULT '6',
  `keep_scans` int(11) unsigned NOT NULL DEFAULT '30',
  `scan_max_age` int(11) unsigned NOT NULL DEFAULT '0',
  `use_clamav` enum('n','y') NOT NULL DEFAULT 'y',
  `auto_update_signatures` enum('n','y') NOT NULL DEFAULT 'y',
  `last_signature_update` datetime DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Per website settings. A website without a row here uses the
-- global defaults and is never acted upon automatically.
--
CREATE TABLE IF NOT EXISTS `malwatch_site` (
  `site_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `schedule` enum('off','daily','weekly','monthly') NOT NULL DEFAULT 'off',
  `excludes` text,
  `max_age` int(11) unsigned NOT NULL DEFAULT '0',
  `notify_admin` enum('n','y') NOT NULL DEFAULT 'y',
  `notify_admin_severity` enum('low','medium','high','critical') NOT NULL DEFAULT 'high',
  `notify_client` enum('n','y') NOT NULL DEFAULT 'n',
  `notify_client_severity` enum('low','medium','high','critical') NOT NULL DEFAULT 'critical',
  `disable_site` enum('n','y') NOT NULL DEFAULT 'n',
  `disable_severity` enum('low','medium','high','critical') NOT NULL DEFAULT 'critical',
  `version_scan` enum('n','y') NOT NULL DEFAULT 'y',
  `last_scan_id` int(11) unsigned NOT NULL DEFAULT '0',
  `last_run` datetime DEFAULT NULL,
  `next_run` datetime DEFAULT NULL,
  `open_findings` int(11) unsigned NOT NULL DEFAULT '0',
  `worst_severity` varchar(10) NOT NULL DEFAULT '',
  `last_state` enum('unknown','clean','findings','vulnerable','outdated','error') NOT NULL DEFAULT 'unknown',
  PRIMARY KEY (`site_id`),
  UNIQUE KEY `parent_domain_id` (`parent_domain_id`),
  KEY `server_id` (`server_id`),
  KEY `next_run` (`next_run`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Job queue. The interface inserts through the datalog, the
-- server plugin claims a row and starts the scanner detached.
--
CREATE TABLE IF NOT EXISTS `malwatch_job` (
  `job_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `scan_path` varchar(255) NOT NULL DEFAULT '',
  `job_source` enum('manual','schedule') NOT NULL DEFAULT 'manual',
  `job_status` enum('pending','running','done','error') NOT NULL DEFAULT 'pending',
  `options` text,
  `result_file` varchar(255) NOT NULL DEFAULT '',
  `pid` int(11) unsigned NOT NULL DEFAULT '0',
  `exit_code` int(11) DEFAULT NULL,
  `job_log` text,
  `created_at` datetime DEFAULT NULL,
  `started_at` datetime DEFAULT NULL,
  `finished_at` datetime DEFAULT NULL,
  PRIMARY KEY (`job_id`),
  KEY `server_status` (`server_id`,`job_status`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- One finished scan.
--
CREATE TABLE IF NOT EXISTS `malwatch_scan` (
  `scan_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `scan_path` varchar(255) NOT NULL DEFAULT '',
  `started_at` datetime DEFAULT NULL,
  `finished_at` datetime DEFAULT NULL,
  `duration_seconds` int(11) unsigned NOT NULL DEFAULT '0',
  `files_scanned` int(11) unsigned NOT NULL DEFAULT '0',
  `files_skipped` int(11) unsigned NOT NULL DEFAULT '0',
  `count_critical` int(11) unsigned NOT NULL DEFAULT '0',
  `count_high` int(11) unsigned NOT NULL DEFAULT '0',
  `count_medium` int(11) unsigned NOT NULL DEFAULT '0',
  `count_low` int(11) unsigned NOT NULL DEFAULT '0',
  `count_outdated` int(11) unsigned NOT NULL DEFAULT '0',
  `new_findings` int(11) unsigned NOT NULL DEFAULT '0',
  `exit_code` int(11) NOT NULL DEFAULT '0',
  `scan_state` enum('clean','findings','vulnerable','outdated','error') NOT NULL DEFAULT 'clean',
  `engines` varchar(255) NOT NULL DEFAULT '',
  `notes` text,
  PRIMARY KEY (`scan_id`),
  KEY `parent_domain_id` (`parent_domain_id`),
  KEY `started_at` (`started_at`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- One finding. A finding survives across scans: it keeps its
-- first_seen while it is still there, and turns to 'fixed' once
-- it is gone. That is what makes "new since the last run"
-- answerable, which is what the actions key on.
--
CREATE TABLE IF NOT EXISTS `malwatch_finding` (
  `finding_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `scan_id` int(11) unsigned NOT NULL DEFAULT '0',
  `file_path` varchar(1024) NOT NULL DEFAULT '',
  `path_hash` varchar(64) NOT NULL DEFAULT '',
  `line_number` int(11) unsigned NOT NULL DEFAULT '0',
  `rule_id` varchar(128) NOT NULL DEFAULT '',
  `severity` enum('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  `engine` varchar(32) NOT NULL DEFAULT '',
  `file_sha256` varchar(64) NOT NULL DEFAULT '',
  `excerpt` varchar(255) NOT NULL DEFAULT '',
  `file_size` bigint(20) unsigned NOT NULL DEFAULT '0',
  `file_mtime` datetime DEFAULT NULL,
  `finding_state` enum('open','ignored','fixed') NOT NULL DEFAULT 'open',
  `first_seen` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  PRIMARY KEY (`finding_id`),
  UNIQUE KEY `identity` (`parent_domain_id`,`path_hash`,`rule_id`),
  KEY `state` (`finding_state`,`severity`),
  KEY `scan_id` (`scan_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Detected web software per scan.
--
CREATE TABLE IF NOT EXISTS `malwatch_software` (
  `software_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `scan_id` int(11) unsigned NOT NULL DEFAULT '0',
  `install_path` varchar(1024) NOT NULL DEFAULT '',
  `path_hash` varchar(64) NOT NULL DEFAULT '',
  `product` varchar(64) NOT NULL DEFAULT '',
  `software_kind` varchar(16) NOT NULL DEFAULT 'core',
  `slug` varchar(128) NOT NULL DEFAULT '',
  `installed_version` varchar(64) NOT NULL DEFAULT '',
  `latest_version` varchar(64) NOT NULL DEFAULT '',
  `outdated` enum('n','y') NOT NULL DEFAULT 'n',
  `version_unknown` enum('n','y') NOT NULL DEFAULT 'n',
  `last_seen` datetime DEFAULT NULL,
  PRIMARY KEY (`software_id`),
  UNIQUE KEY `identity` (`parent_domain_id`,`path_hash`,`software_kind`,`slug`),
  KEY `outdated` (`outdated`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Log of what the extension did on its own: mails sent, sites
-- disabled. Every automatic action must be traceable back to
-- the finding that caused it.
--
CREATE TABLE IF NOT EXISTS `malwatch_action_log` (
  `action_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `scan_id` int(11) unsigned NOT NULL DEFAULT '0',
  `action_type` enum('notify_admin','notify_client','disable_site','error') NOT NULL DEFAULT 'notify_admin',
  `trigger_severity` varchar(10) NOT NULL DEFAULT '',
  `trigger_findings` int(11) unsigned NOT NULL DEFAULT '0',
  `recipient` varchar(255) NOT NULL DEFAULT '',
  `detail` text,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`action_id`),
  KEY `parent_domain_id` (`parent_domain_id`),
  KEY `created_at` (`created_at`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- The single settings row. INSERT IGNORE so re-running the
-- installer never resets an operator's configuration.
--
INSERT IGNORE INTO `malwatch_config`
  (`config_id`, `sys_userid`, `sys_groupid`, `sys_perm_user`, `sys_perm_group`, `sys_perm_other`, `default_excludes`)
VALUES
  (1, 1, 1, 'riud', 'riud', '', '**/cache/**\n**/*.log\n**/node_modules/**');

-- --------------------------------------------------------
-- Änderungen an bestehenden Tabellen.
--
-- CREATE TABLE IF NOT EXISTS oben lässt eine vorhandene Tabelle unberührt, also
-- erreicht eine neue Spalte damit keine Installation, die es schon gibt. Die
-- folgenden Anweisungen prüfen sich selbst in information_schema und laufen bei
-- jeder Installation und jedem Update mit; eine Versionszählung braucht es
-- dafür nicht.
-- --------------------------------------------------------

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` ADD COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'') NOT NULL DEFAULT ''scan'' AFTER `job_source`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `malwatch_repair` (
  `repair_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
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
  `backup_dir` varchar(255) NOT NULL DEFAULT '',
  `count_replaced` int(11) unsigned NOT NULL DEFAULT '0',
  `count_deleted` int(11) unsigned NOT NULL DEFAULT '0',
  `count_failed` int(11) unsigned NOT NULL DEFAULT '0',
  `exit_code` int(11) NOT NULL DEFAULT '0',
  `raw_report` mediumtext,
  PRIMARY KEY (`repair_id`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `malwatch_repair_element` (
  `element_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `repair_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `element_kind` varchar(16) NOT NULL DEFAULT '',
  `slug` varchar(190) NOT NULL DEFAULT '',
  `element_version` varchar(64) NOT NULL DEFAULT '',
  `outcome` varchar(32) NOT NULL DEFAULT '',
  `files` int(11) unsigned NOT NULL DEFAULT '0',
  `backup` varchar(255) NOT NULL DEFAULT '',
  `message` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`element_id`),
  KEY `repair_id` (`repair_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `auto_action` enum(''none'',''safe'',''critical'',''preset'') NOT NULL DEFAULT ''none'' AFTER `last_signature_update`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'auto_action');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `auto_preset_id` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `auto_action`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'auto_preset_id');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- malwatch_site kennt zusaetzlich 'inherit': eine einzelne Website kann damit
-- von der globalen Vorgabe abweichen, ohne dass 'none' ueberladen werden
-- muesste, das schon "nichts automatisch tun" bedeutet.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `auto_action` enum(''inherit'',''none'',''safe'',''critical'',''preset'') NOT NULL DEFAULT ''inherit'' AFTER `last_state`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'auto_action');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `auto_preset_id` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `auto_action`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'auto_preset_id');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- action_type bekommt quarantine als weiteren Wert: die automatische Massnahme
-- reiht denselben quarantine-Auftrag ein wie ein manueller Klick und muss das
-- im Protokoll ebenso festhalten koennen. Die Spalte selbst gibt es schon,
-- gefragt ist nur ein zusaetzlicher Enum-Wert - deshalb prueft die Huelle hier
-- COLUMN_TYPE statt COUNT(*): ein reiner Existenztest der Spalte waere immer
-- erfuellt und das MODIFY liefe bei jedem Update erneut.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_action_log` MODIFY COLUMN `action_type` enum(''notify_admin'',''notify_client'',''disable_site'',''error'',''quarantine'') NOT NULL DEFAULT ''notify_admin''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_action_log' AND COLUMN_NAME = 'action_type'
    AND COLUMN_TYPE LIKE '%''quarantine''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- One held file or directory. entry_id is the key the store uses on disk;
-- rel_path is for display only. server_id is part of the uniqueness because
-- the store lives on one server's disk, not centrally - the same entry_id
-- can occur once per server. export_* stays empty until an operator asks
-- for a download; the ZIP is built on demand, not kept for every entry.
--
CREATE TABLE IF NOT EXISTS `malwatch_quarantine` (
  `quarantine_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `entry_id` varchar(64) NOT NULL DEFAULT '',
  `entry_kind` enum('file','dir') NOT NULL DEFAULT 'file',
  `rel_path` varchar(1024) NOT NULL DEFAULT '',
  `origin` enum('manual','auto','repair','upgrade') NOT NULL DEFAULT 'manual',
  `reason` varchar(255) NOT NULL DEFAULT '',
  `rule_id` varchar(128) NOT NULL DEFAULT '',
  `severity` varchar(10) NOT NULL DEFAULT '',
  `files` int(11) unsigned NOT NULL DEFAULT '0',
  `bytes` bigint(20) unsigned NOT NULL DEFAULT '0',
  -- Zwei Größen, weil zwei Fragen: `bytes` ist, was der Eintrag im
  -- Webverzeichnis gewogen hat - die Zahl, die ein Mensch wiedererkennt -,
  -- `archive_bytes` ist, was er gepackt auf der Platte belegt. Wer aufräumt,
  -- braucht die zweite; wer entscheidet, ob er etwas zurückholt, die erste.
  `archive_bytes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `created_at` datetime DEFAULT NULL,
  `export_token` varchar(64) NOT NULL DEFAULT '',
  `export_bytes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `export_ready_at` datetime DEFAULT NULL,
  PRIMARY KEY (`quarantine_id`),
  UNIQUE KEY `identity` (`server_id`,`entry_id`),
  KEY `parent_domain_id` (`parent_domain_id`),
  -- Der Downloadweg sucht ausschliesslich hierueber
  -- (malwatch_quarantine_download.php): ein Token, eine Zeile, waehrend der
  -- Bediener wartet. Ohne Index ist das ein voller Tabellendurchlauf je Klick.
  KEY `export_token` (`export_token`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

-- Der Index oben erreicht keine bestehende Installation: CREATE TABLE IF NOT
-- EXISTS laesst eine vorhandene Tabelle unberuehrt (siehe den Hinweis weiter
-- oben). Deshalb dieselbe selbstpruefende Huelle wie fuer die Spalten, nur
-- gegen information_schema.STATISTICS statt COLUMNS.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_quarantine` ADD INDEX `export_token` (`export_token`)',
  'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_quarantine' AND INDEX_NAME = 'export_token');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- Mirror of the scanner's rule catalogue, refreshed once a day by cron from
-- `malwatch rules --json`. The interface reads this instead of shelling out,
-- to show a rule's title next to its bare id and to count how many rules
-- fall under each automatic-action choice. auto_safe is not something an
-- operator sets here: it comes from the scanner's own catalogue
-- (internal/rules) and marks a rule where a hit alone justifies moving the
-- file, because the file cannot have a legitimate purpose.
--
CREATE TABLE IF NOT EXISTS `malwatch_rule` (
  `rule_id` varchar(128) NOT NULL,
  `title` varchar(255) NOT NULL DEFAULT '',
  `severity` varchar(10) NOT NULL DEFAULT '',
  `auto_safe` enum('n','y') NOT NULL DEFAULT 'n',
  `last_seen` datetime DEFAULT NULL,
  PRIMARY KEY (`rule_id`)
) DEFAULT CHARSET=utf8mb4 ;

-- --------------------------------------------------------
-- Bekannte Schwachstellen (0.13.0)
--
-- Je erkannter Software: wie viele bekannte Luecken, die schwerste Stufe,
-- ab welcher Version alle behoben sind, und die Liste selbst als JSON, so
-- wie der Scanner sie liefert (gekappt in malwatch_ingest::store_software).
-- Die drei Spalten vor der Liste gibt es, damit die Seiten danach sortieren
-- und zaehlen koennen, ohne JSON zu lesen.
-- --------------------------------------------------------

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vuln_count` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `version_unknown`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vuln_count');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vuln_severity` varchar(10) NOT NULL DEFAULT '''' AFTER `vuln_count`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vuln_severity');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vuln_fixed_in` varchar(64) NOT NULL DEFAULT '''' AFTER `vuln_severity`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vuln_fixed_in');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 'y', wenn keine Quelle geantwortet hat: eine leere Liste heisst dann
-- "nicht gefragt" und darf nicht als "nichts bekannt" erscheinen.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vuln_unchecked` enum(''n'',''y'') NOT NULL DEFAULT ''n'' AFTER `vuln_fixed_in`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vuln_unchecked');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vulns` mediumtext AFTER `vuln_unchecked`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vulns');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Wie viele der Luecken keine behebende Version nennen. Ohne die Zahl
-- schriebe die Seite "alle behoben ab 5.9.2", obwohl nach dem Update eine
-- Luecke bleibt.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `vuln_nofix` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `vuln_count`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'vuln_nofix');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_scan` ADD COLUMN `count_vulnerable` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `count_outdated`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_scan' AND COLUMN_NAME = 'count_vulnerable');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 'vulnerable' steht zwischen 'findings' und 'outdated': eine bekannte Luecke
-- wiegt schwerer als eine bloss alte Version und leichter als ein Fund.
-- Geprueft wird wie bei action_type der Spaltentyp, nicht die Existenz.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_scan` MODIFY COLUMN `scan_state` enum(''clean'',''findings'',''vulnerable'',''outdated'',''error'') NOT NULL DEFAULT ''clean''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_scan' AND COLUMN_NAME = 'scan_state'
    AND COLUMN_TYPE LIKE '%''vulnerable''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` MODIFY COLUMN `last_state` enum(''unknown'',''clean'',''findings'',''vulnerable'',''outdated'',''error'') NOT NULL DEFAULT ''unknown''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'last_state'
    AND COLUMN_TYPE LIKE '%''vulnerable''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- vulncheck ist der taegliche Abgleich allein: Software erkennen, Versionen
-- und bekannte Luecken nachschlagen, keine Datei auf Schadcode lesen. Er
-- schreibt nur malwatch_software (siehe malwatch_ingest::ingest_vulncheck).
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE LIKE '%''vulncheck''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- vuln_scan schaltet den Abgleich fuer alle Websites ab. wpscan_token ist
-- der API-Schluessel fuer WPScan; leer heisst: WPScan wird nicht gefragt.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `vuln_scan` enum(''n'',''y'') NOT NULL DEFAULT ''y'' AFTER `use_clamav`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'vuln_scan');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `wpscan_token` varchar(255) NOT NULL DEFAULT '''' AFTER `vuln_scan`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'wpscan_token');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- Named rule selections for the "eigene Auswahl" auto action. Not tied to a
-- server or a site: malwatch_config.auto_preset_id and
-- malwatch_site.auto_preset_id both point in here. rule_ids is a
-- comma-separated list of malwatch_rule.rule_id kept as text, since a join
-- table would be overkill for what is at most a few dozen ids.
--
CREATE TABLE IF NOT EXISTS `malwatch_auto_preset` (
  `preset_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `preset_name` varchar(64) NOT NULL DEFAULT '',
  `rule_ids` mediumtext,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`preset_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

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

-- Die veröffentlichten Versionen über der installierten, neueste zuerst, als
-- JSON. Die Seite „Updates" bietet sie als Zielversionen an.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_software` ADD COLUMN `versions` mediumtext AFTER `latest_in_branch`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_software' AND COLUMN_NAME = 'versions');
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

--
-- Ein Dump einer Website: das gepackte Archiv, sein Token und wie lange es
-- liegt. Eine Zeile je Lauf, nach dem Muster von malwatch_upgrade. Der Token
-- steht auch im Dateinamen unter <state_dir>/dumps.
--
CREATE TABLE IF NOT EXISTS `malwatch_dump` (
  `dump_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `dump_state` enum('pending','running','done','error') NOT NULL DEFAULT 'pending',
  `token` varchar(64) NOT NULL DEFAULT '',
  `archive_path` varchar(255) NOT NULL DEFAULT '',
  `archive_bytes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `file_count` int(11) unsigned NOT NULL DEFAULT '0',
  `database_count` int(11) unsigned NOT NULL DEFAULT '0',
  `with_logs` enum('n','y') NOT NULL DEFAULT 'n',
  `error_reason` varchar(32) NOT NULL DEFAULT '',
  `job_log` text,
  `created_at` datetime DEFAULT NULL,
  `ready_at` datetime DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  -- Die oeffentliche Freigabe eines einzelnen Dumps: ein zweiter Schluessel,
  -- getrennt vom Weg durch das Panel, damit ein Widerruf genau ihn trifft.
  -- public_mode sagt, woran die Freigabe endet; public_password haelt nur den
  -- Hash.
  `public_token` varchar(64) NOT NULL DEFAULT '',
  `public_mode` enum('none','expiry','day','once') NOT NULL DEFAULT 'none',
  `public_until` datetime DEFAULT NULL,
  `public_password` varchar(255) NOT NULL DEFAULT '',
  `public_hits` int(11) unsigned NOT NULL DEFAULT '0',
  `public_last_at` datetime DEFAULT NULL,
  `public_last_ip` varchar(45) NOT NULL DEFAULT '',
  PRIMARY KEY (`dump_id`),
  KEY `token` (`token`),
  KEY `public_token` (`public_token`),
  KEY `server_state` (`server_id`,`dump_state`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

-- Dieselben Spalten fuer eine Installation, die malwatch_dump schon hat.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_token` varchar(64) NOT NULL DEFAULT '''' AFTER `expires_at`, ADD KEY `public_token` (`public_token`)',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_token');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_mode` enum(''none'',''expiry'',''day'',''once'') NOT NULL DEFAULT ''none'' AFTER `public_token`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_mode');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_until` datetime DEFAULT NULL AFTER `public_mode`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_until');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_password` varchar(255) NOT NULL DEFAULT '''' AFTER `public_until`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_password');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_hits` int(11) unsigned NOT NULL DEFAULT ''0'' AFTER `public_password`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_hits');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_last_at` datetime DEFAULT NULL AFTER `public_hits`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_last_at');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_dump` ADD COLUMN `public_last_ip` varchar(45) NOT NULL DEFAULT '''' AFTER `public_last_at`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_dump' AND COLUMN_NAME = 'public_last_ip');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- Was ueber die Datenbanken einer Website bekannt ist: Groesse, Zahl der
-- Tabellen, letzter Schreibzugriff und die Installation, die sie benutzt.
-- Gefuellt vom stuendlichen Lauf (cron.d/560-malwatch.inc.php,
-- collect_databases); die Seite "Dumps" macht daraus die Markierungen in der
-- Auswahl.
--
CREATE TABLE IF NOT EXISTS `malwatch_database` (
  `database_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  -- Die Sortierfolge steht hier ausdruecklich: ISPConfig fuehrt
  -- web_database mit utf8mb4_unicode_ci, die Tabellen von malwatch stehen
  -- auf utf8mb4_general_ci. Die Auswahl der Datenbanken verbindet beide
  -- Spalten, und MySQL bricht eine Verbindung ueber zwei Sortierfolgen mit
  -- "Illegal mix of collations" ab - die Seite zeigte daraufhin keine
  -- einzige Datenbank.
  `database_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `table_count` int(11) unsigned NOT NULL DEFAULT '0',
  `bytes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `last_write` datetime DEFAULT NULL,
  `used_kind` varchar(16) NOT NULL DEFAULT '',
  `used_by` varchar(255) NOT NULL DEFAULT '',
  `checked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`database_id`),
  UNIQUE KEY `server_database` (`server_id`,`database_name`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

-- Und dieselbe Sortierfolge fuer eine Installation, die die Tabelle schon
-- angelegt hat, bevor sie hier stand.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_database` MODIFY COLUMN `database_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT ''''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_database' AND COLUMN_NAME = 'database_name'
    AND COLLATION_NAME = 'utf8mb4_unicode_ci');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- dump packt das Webverzeichnis einer Website mit ihren Datenbanken; siehe
-- malwatch_runner::build_arguments und malwatch_ingest::ingest_dump.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'',''upgrade'',''dump'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE LIKE '%''dump''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------
-- Abwehr (WAF): hits from the ModSecurity audit log, day figures, exceptions.
-- Filled by malwatch_waf (server/lib/classes/malwatch_waf.inc.php).
-- --------------------------------------------------------

--
-- One hit per transaction. Holds addresses and request bodies and is kept for
-- waf_detail_days. unique_id is ModSecurity's id of the transaction; a second
-- read of the same line finds its row.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_hit` (
  `hit_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `unique_id` varchar(64) NOT NULL DEFAULT '',
  `seen_at` datetime DEFAULT NULL,
  `client_ip` varchar(45) NOT NULL DEFAULT '',
  `method` varchar(10) NOT NULL DEFAULT '',
  `uri` varchar(2048) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `status` smallint(5) unsigned NOT NULL DEFAULT '0',
  `anomaly_score` smallint(5) unsigned NOT NULL DEFAULT '0',
  `would_block` enum('n','y') NOT NULL DEFAULT 'n',
  `logged_in` enum('n','y') NOT NULL DEFAULT 'n',
  `rules` text,
  `request_headers` text,
  `request_body` mediumtext,
  `response_file` varchar(255) NOT NULL DEFAULT '',
  `response_bytes` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`hit_id`),
  UNIQUE KEY `server_unique` (`server_id`,`unique_id`),
  KEY `site_seen` (`parent_domain_id`,`seen_at`),
  KEY `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`),
  KEY `server_seen` (`server_id`,`seen_at`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Day figures per website, without addresses; kept for waf_stats_days.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_site_day` (
  `site_day_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `day` date NOT NULL,
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block` int(11) unsigned NOT NULL DEFAULT '0',
  `logged_in_hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block_logged_in` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`site_day_id`),
  UNIQUE KEY `day_site` (`day`,`parent_domain_id`),
  KEY `site_day` (`parent_domain_id`,`day`),
  KEY `server_day` (`server_id`,`day`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Day figures per website, rule and path, without addresses; kept for
-- waf_stats_days. Scoring rules (949, 959, 980) are not counted here.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_day` (
  `waf_day_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `day` date NOT NULL,
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `rule_id` varchar(16) NOT NULL DEFAULT '',
  `rule_msg` varchar(255) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `path_hash` char(40) NOT NULL DEFAULT '',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `would_block_hits` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`waf_day_id`),
  UNIQUE KEY `day_site_rule_path` (`day`,`parent_domain_id`,`rule_id`,`path_hash`),
  KEY `site_day` (`parent_domain_id`,`day`),
  KEY `server_day` (`server_id`,`day`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

--
-- Exceptions created in the panel. The rule id in the file is
-- 10200 + exception_id; the note never reaches a file.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_exception` (
  `exception_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `scope` enum('site','site_path','site_param','all','all_path') NOT NULL DEFAULT 'site',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `rule_id` varchar(16) NOT NULL DEFAULT '',
  `path` varchar(1024) NOT NULL DEFAULT '',
  `param` varchar(128) NOT NULL DEFAULT '',
  `note` varchar(255) NOT NULL DEFAULT '',
  `exception_state` enum('pending','active','error','removing') NOT NULL DEFAULT 'pending',
  `error_reason` varchar(255) NOT NULL DEFAULT '',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `created_by` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime DEFAULT NULL,
  `activated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`exception_id`),
  KEY `server_state` (`server_id`,`exception_state`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

-- The WAF state per website as the last job confirmed it, since when, and the
-- job that is changing it. The field "nginx directives" stays the truth. One
-- statement for the four columns: it adds all of them or none.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `waf_state` enum(''off'',''detect'',''enforce'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_state_since` datetime DEFAULT NULL, ADD COLUMN `waf_job_id` int(11) unsigned NOT NULL DEFAULT ''0'', ADD COLUMN `waf_pending_state` varchar(16) NOT NULL DEFAULT ''''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'waf_state');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The settings of the page Abwehr; defaults as in waf_settings_defaults().
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_detail_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_stats_days` int(11) unsigned NOT NULL DEFAULT ''90'', ADD COLUMN `waf_log_keep_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_preview_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_min_detect_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_response_body` enum(''full'',''lean'') NOT NULL DEFAULT ''full'', ADD COLUMN `waf_ingest_max_lines` int(11) unsigned NOT NULL DEFAULT ''5000'', ADD COLUMN `waf_job_deadline_minutes` int(11) unsigned NOT NULL DEFAULT ''5'', ADD COLUMN `waf_audit_log` varchar(255) NOT NULL DEFAULT ''/var/log/waf/audit.log'', ADD COLUMN `waf_conf_dir` varchar(255) NOT NULL DEFAULT ''/etc/nginx/waf'', ADD COLUMN `waf_emergency` enum(''n'',''y'') NOT NULL DEFAULT ''n'', ADD COLUMN `waf_emergency_since` datetime DEFAULT NULL',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_detail_days');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- How many of the latest hits of a website the rule cards read; default as in waf_settings_defaults().
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_card_hits` int(11) unsigned NOT NULL DEFAULT ''5000''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_card_hits');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The address filter of the website page reads the stored requests of one
-- address; the index reaches existing installs here.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_waf_hit` ADD INDEX `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)',
  'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_waf_hit' AND INDEX_NAME = 'site_ip');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Where an address comes from: the chosen sources and how often they are checked.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_origin_geo` enum(''off'',''dbip'',''maxmind'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_maxmind_account` varchar(32) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_maxmind_key` varchar(128) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_tor` enum(''off'',''torproject'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_net` enum(''off'',''x4b'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_origin_tor_hours` int(11) unsigned NOT NULL DEFAULT ''1'', ADD COLUMN `waf_origin_list_hours` int(11) unsigned NOT NULL DEFAULT ''24'', ADD COLUMN `waf_origin_db_hours` int(11) unsigned NOT NULL DEFAULT ''24''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_geo');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- One row per server and origin source: which release is in use, when it was
-- last checked and loaded, how many ranges it holds and what went wrong last.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_origin_source` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `source` varchar(32) NOT NULL DEFAULT '',
  `version` varchar(32) NOT NULL DEFAULT '',
  `checked_at` datetime DEFAULT NULL,
  `fetched_at` datetime DEFAULT NULL,
  `entries` int(11) unsigned NOT NULL DEFAULT '0',
  `error` varchar(255) NOT NULL DEFAULT '',
  `error_at` datetime DEFAULT NULL,
  `day` date DEFAULT NULL,
  `queries` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`source`)
) DEFAULT CHARSET=utf8mb4 ;

-- proxycheck.io comes with 0.22.0: its key, its daily limit and the value
-- `proxycheck` for the choice of the network.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_origin_proxycheck_key` varchar(128) NOT NULL DEFAULT '''', ADD COLUMN `waf_origin_proxycheck_daily` int(11) unsigned NOT NULL DEFAULT ''500''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_proxycheck_key');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` MODIFY COLUMN `waf_origin_net` enum(''off'',''x4b'',''proxycheck'') NOT NULL DEFAULT ''off''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_origin_net'
    AND COLUMN_TYPE LIKE '%''proxycheck''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The day and the queries of that day; only proxycheck.io fills them.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_waf_origin_source` ADD COLUMN `day` date DEFAULT NULL, ADD COLUMN `queries` int(11) unsigned NOT NULL DEFAULT ''0''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_waf_origin_source' AND COLUMN_NAME = 'day');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Sperren kommen mit 0.23.0: die Werte der Automatik.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_ban_mode` enum(''off'',''propose'',''block'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_score` int(11) unsigned NOT NULL DEFAULT ''50'', ADD COLUMN `waf_ban_window_minutes` int(11) unsigned NOT NULL DEFAULT ''10'', ADD COLUMN `waf_ban_hours_first` int(11) unsigned NOT NULL DEFAULT ''1'', ADD COLUMN `waf_ban_hours_second` int(11) unsigned NOT NULL DEFAULT ''24'', ADD COLUMN `waf_ban_hours_third` int(11) unsigned NOT NULL DEFAULT ''168'', ADD COLUMN `waf_ban_max` int(11) unsigned NOT NULL DEFAULT ''5000'', ADD COLUMN `waf_ban_keep_days` int(11) unsigned NOT NULL DEFAULT ''30'', ADD COLUMN `waf_ban_bots` enum(''off'',''on'') NOT NULL DEFAULT ''on''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_ban_mode');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Ab 0.25.3: Vorschläge laufen ab, und die Seite zeigt je Abschnitt eine
-- begrenzte Zahl Zeilen.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_ban_proposal_days` int(11) unsigned NOT NULL DEFAULT ''7'', ADD COLUMN `waf_ban_page_rows` int(11) unsigned NOT NULL DEFAULT ''200''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_ban_proposal_days');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Die Herkunft senkt die Schwelle, ab 0.25.0. Alles beginnt ausgeschaltet.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_ban_origin` enum(''off'',''on'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_origin_score` int(11) unsigned NOT NULL DEFAULT ''20'', ADD COLUMN `waf_ban_origin_factor` int(11) unsigned NOT NULL DEFAULT ''200'', ADD COLUMN `waf_ban_origin_now` enum(''off'',''on'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_origin_hosting` enum(''off'',''on'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_origin_vpn` enum(''off'',''on'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_origin_tor` enum(''off'',''on'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_origin_countries` varchar(255) NOT NULL DEFAULT '''', ADD COLUMN `waf_ban_origin_asn` varchar(255) NOT NULL DEFAULT ''''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_ban_origin');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Der Schlüssel der veröffentlichten Sperrliste kommt mit 0.24.0; er entsteht,
-- sobald die Automatik läuft.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_ban_token` varchar(64) NOT NULL DEFAULT ''''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_ban_token');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The threshold of a website; 0 means the value of the server.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `waf_ban_score` int(11) unsigned NOT NULL DEFAULT ''0'', ADD COLUMN `waf_ban_trigger` enum(''y'',''n'') NOT NULL DEFAULT ''y''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'waf_ban_score');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- One row per server and address: why it is blocked, since when, until when and
-- how many attempts were turned away since. cleanup() removes a row once its
-- end lies further back than waf_ban_keep_days.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_ban` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `state` enum('proposed','active','expired','lifted','dismissed') NOT NULL DEFAULT 'proposed',
  `reason` varchar(255) NOT NULL DEFAULT '',
  `rule` varchar(16) NOT NULL DEFAULT '',
  `score` int(11) unsigned NOT NULL DEFAULT '0',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `level` tinyint(3) unsigned NOT NULL DEFAULT '1',
  `source` enum('auto','manual','fail2ban') NOT NULL DEFAULT 'auto',
  `created_at` datetime DEFAULT NULL,
  `blocked_at` datetime DEFAULT NULL,
  `until` datetime DEFAULT NULL,
  `lifted_at` datetime DEFAULT NULL,
  `lifted_by` varchar(64) NOT NULL DEFAULT '',
  `denied` int(11) unsigned NOT NULL DEFAULT '0',
  `denied_at` datetime DEFAULT NULL,
  PRIMARY KEY (`server_id`,`ip`),
  KEY `state_until` (`server_id`,`state`,`until`)
) DEFAULT CHARSET=utf8mb4 ;

--
-- Addresses and ranges that are never blocked. The fixed networks of the server
-- are in the code, not here.
--
--
-- fail2ban im Panel, ab 0.26.0. Der Cron spiegelt die Sperren der Jails hierher;
-- eine Adresse kann in mehreren Jails und zugleich bei malwatch gesperrt sein,
-- deshalb eine eigene Tabelle mit Jail im Schlüssel.
--
CREATE TABLE IF NOT EXISTS `malwatch_f2b_ban` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `jail` varchar(64) NOT NULL DEFAULT '',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `banned_at` datetime DEFAULT NULL,
  `until` datetime DEFAULT NULL,
  `seen_at` datetime DEFAULT NULL,
  PRIMARY KEY (`server_id`,`jail`,`ip`),
  KEY `ip` (`ip`)
) DEFAULT CHARSET=utf8mb4 ;

-- Ob der letzte Blick auf fail2ban gelang, je Server.
CREATE TABLE IF NOT EXISTS `malwatch_f2b_state` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `state` varchar(16) NOT NULL DEFAULT '',
  `error` varchar(255) NOT NULL DEFAULT '',
  `jails` varchar(255) NOT NULL DEFAULT '',
  `read_at` datetime DEFAULT NULL,
  PRIMARY KEY (`server_id`)
) DEFAULT CHARSET=utf8mb4 ;

-- Was „überall sperren" an einer Zeile dieses Jails tut; leer heißt: wie global.
CREATE TABLE IF NOT EXISTS `malwatch_f2b_jail` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `jail` varchar(64) NOT NULL DEFAULT '',
  `everywhere_mode` varchar(20) NOT NULL DEFAULT '',
  PRIMARY KEY (`server_id`,`jail`)
) DEFAULT CHARSET=utf8mb4 ;

-- Regeln der Abwehr, deren automatische Sperren auch in fail2ban landen.
CREATE TABLE IF NOT EXISTS `malwatch_waf_ban_rule` (
  `rule_id` varchar(16) NOT NULL DEFAULT '',
  `everywhere_mode` varchar(20) NOT NULL DEFAULT '',
  `changed_at` datetime DEFAULT NULL,
  `changed_by` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`rule_id`)
) DEFAULT CHARSET=utf8mb4 ;

SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_f2b` enum(''off'',''on'') NOT NULL DEFAULT ''on'', ADD COLUMN `waf_everywhere_mode` varchar(20) NOT NULL DEFAULT ''web_jail'', ADD COLUMN `waf_everywhere_jail` varchar(64) NOT NULL DEFAULT ''recidive''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_f2b');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `malwatch_waf_allow` (
  `allow_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `cidr` varchar(64) NOT NULL DEFAULT '',
  `note` varchar(255) NOT NULL DEFAULT '',
  `created_at` datetime DEFAULT NULL,
  `created_by` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`allow_id`),
  UNIQUE KEY `server_cidr` (`server_id`,`cidr`)
) DEFAULT CHARSET=utf8mb4 ;

--
-- One row per server and address: what the range files said and, later, what
-- an external service added. cleanup() removes a row as soon as no hit names
-- the address any more, so the origin lives no longer than the hit.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_ip` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `country` varchar(2) NOT NULL DEFAULT '',
  `asn` int(11) unsigned NOT NULL DEFAULT '0',
  `as_org` varchar(128) NOT NULL DEFAULT '',
  `is_tor` enum('n','y') NOT NULL DEFAULT 'n',
  `is_vpn` enum('n','y') NOT NULL DEFAULT 'n',
  `is_hosting` enum('n','y') NOT NULL DEFAULT 'n',
  `is_proxy` enum('n','y') NOT NULL DEFAULT 'n',
  `vpn_operator` varchar(64) NOT NULL DEFAULT '',
  `local_at` datetime DEFAULT NULL,
  `external_state` enum('none','pending','done','failed','limit') NOT NULL DEFAULT 'none',
  `external_at` datetime DEFAULT NULL,
  `external_tries` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`ip`),
  KEY `external` (`server_id`,`external_state`)
) DEFAULT CHARSET=utf8mb4 ;

-- waf carries the jobs of the page Abwehr. The malwatch cron works on them
-- itself (malwatch_waf::run_jobs); the runner never starts one.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` MODIFY COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'',''vulncheck'',''upgrade'',''dump'',''waf'') NOT NULL DEFAULT ''scan''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind'
    AND COLUMN_TYPE LIKE '%''waf''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Every WAF job leaves one line in the action log: person, action, result.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_action_log` MODIFY COLUMN `action_type` enum(''notify_admin'',''notify_client'',''disable_site'',''error'',''quarantine'',''waf'') NOT NULL DEFAULT ''notify_admin''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_action_log' AND COLUMN_NAME = 'action_type'
    AND COLUMN_TYPE LIKE '%''waf''%');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;
