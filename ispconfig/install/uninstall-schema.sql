-- ISPConfig extension: malwatch - remove the schema.
DROP TABLE IF EXISTS `malwatch_auto_preset`;
DROP TABLE IF EXISTS `malwatch_rule`;
DROP TABLE IF EXISTS `malwatch_quarantine`;
DROP TABLE IF EXISTS `malwatch_repair_element`;
DROP TABLE IF EXISTS `malwatch_repair`;
DROP TABLE IF EXISTS `malwatch_action_log`;
DROP TABLE IF EXISTS `malwatch_software`;
DROP TABLE IF EXISTS `malwatch_finding`;
DROP TABLE IF EXISTS `malwatch_scan`;
DROP TABLE IF EXISTS `malwatch_job`;
DROP TABLE IF EXISTS `malwatch_site`;
DROP TABLE IF EXISTS `malwatch_config`;
