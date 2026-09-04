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
  `last_state` enum('unknown','clean','findings','outdated','error') NOT NULL DEFAULT 'unknown',
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
  `scan_state` enum('clean','findings','outdated','error') NOT NULL DEFAULT 'clean',
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
