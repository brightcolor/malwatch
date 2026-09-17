<?php
/**
 * Checks what the buttons of the Abwehr pages queue, against a stand-in for
 * the panel's database that answers the few queries of the helpers.
 *
 *   php ispconfig/tests/waf_panel_post_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';
$wb = array();
include __DIR__ . '/../interface/lang/de_malwatch_waf.lng';

class waf_test_db
{
	public $writes = array();
	public $sites = array();
	public $exceptions = array();
	public $hits = array();
	public $days = array();
	private $next_id = 100;

	public function queryOneRecord($sql)
	{
		$args = array_slice(func_get_args(), 1);
		if (strpos($sql, 'FROM malwatch_config') !== false) {
			return array('waf_min_detect_days' => '7', 'waf_preview_days' => '7', 'waf_detail_days' => '7', 'waf_emergency' => 'n');
		}
		if (strpos($sql, 'NOW() AS now_at') !== false) {
			return array('now_at' => '2026-09-16 12:00:00', 'today' => '2026-09-16');
		}
		if (strpos($sql, 'FROM web_domain') !== false) {
			return isset($this->sites[(int) $args[0]]) ? $this->sites[(int) $args[0]] : null;
		}
		if (strpos($sql, 'FROM malwatch_waf_exception') !== false) {
			return isset($this->exceptions[(int) $args[0]]) ? $this->exceptions[(int) $args[0]] : null;
		}
		return null;
	}

	public function queryAllRecords($sql)
	{
		if (strpos($sql, 'FROM server') !== false) {
			return array(array('server_id' => '1'));
		}
		if (strpos($sql, 'FROM malwatch_waf_hit') !== false) {
			return $this->hits;
		}
		if (strpos($sql, 'FROM malwatch_waf_day') !== false) {
			return $this->days;
		}
		return array();
	}

	public function query($sql)
	{
		$this->writes[] = array('query' => $sql, 'args' => array_slice(func_get_args(), 1));
		return true;
	}

	public function insertID()
	{
		return ++$this->next_id;
	}

	public function datalogInsert($table, $data, $index_field)
	{
		$this->writes[] = array('datalog' => $table, 'data' => $data);
		return ++$this->next_id;
	}
}

class waf_test_functions
{
	public function intval($value)
	{
		return (int) $value;
	}
}

$app = new stdClass();
$app->functions = new waf_test_functions();
$_SESSION['s']['user'] = array('userid' => 1, 'default_group' => 1, 'username' => 'admin');

function fresh_db()
{
	global $app;
	$app->db = new waf_test_db();
	$app->db->sites = array(
		11 => array('domain_id' => '11', 'domain' => 'beispiel.test', 'server_id' => '1', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-14 08:00:00'),
		12 => array('domain_id' => '12', 'domain' => 'zweite.test', 'server_id' => '1', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-01 08:00:00'),
	);
	return $app->db;
}

/** The jobs a test queued: server, kind, options. */
function jobs_of($db)
{
	$jobs = array();
	foreach ($db->writes as $write) {
		if (isset($write['datalog'])) {
			$jobs[] = array($write['data']['server_id'], $write['data']['job_kind'], json_decode($write['data']['options'], true));
		}
	}
	return $jobs;
}

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$db = fresh_db();
expect_same('nothing pressed', waf_panel_handle_post($app, $wb, array()), array('', ''));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'an', 'waf_site' => '11'));
expect_same('odd state', array($result, jobs_of($db)), array(array('', $wb['err_state_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'detect'));
expect_same('no website', $result, array('', $wb['err_no_site_txt']));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'detect', 'waf_pick' => array('11', '12', '11', '99')));
expect_same('detect queued', jobs_of($db), array(array(1, 'waf', array('domain_ids' => array(11, 12), 'state' => 'detect', 'action' => 'set_state', 'user' => 'admin'))));
expect_same('detect message', $result, array('Wechsel auf „mitschreiben“ eingereiht, Websites: 2. Übersprungen: 1 (nicht gefunden oder für „scharf“ noch nicht bereit).', ''));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'enforce', 'waf_pick' => array('11', '12')));
expect_same('enforce only where ready', jobs_of($db), array(array(1, 'waf', array('domain_ids' => array(12), 'state' => 'enforce', 'action' => 'set_state', 'user' => 'admin'))));

$db = fresh_db();
$db->sites[12]['waf_state_since'] = '2026-09-15 08:00:00';
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'enforce', 'waf_pick' => array('11', '12')));
expect_same('enforce nowhere ready', array($result, jobs_of($db)), array(array('', $wb['err_nothing_to_switch_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'emergency_on'));
expect_same('emergency queued', array($result, jobs_of($db)), array(array($wb['msg_emergency_on_txt'], ''),
	array(array(1, 'waf', array('on' => true, 'hard' => false, 'action' => 'emergency', 'user' => 'admin')))));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'response_body', 'waf_mode' => 'lean'));
expect_same('lean queued', jobs_of($db), array(array(1, 'waf', array('mode' => 'lean', 'action' => 'response_body', 'user' => 'admin'))));
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'response_body', 'waf_mode' => 'halb'));
expect_same('odd mode', $result, array('', $wb['err_mode_txt']));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '11', 'exc_scope' => 'site_path',
	'exc_rule' => '942100', 'exc_path' => '/wp-admin/admin-ajax.php', 'exc_note' => 'Formular'));
$insert = $db->writes[0];
expect_same('exception stored', array(strpos($insert['query'], 'INSERT INTO malwatch_waf_exception') === 0, array_slice($insert['args'], 2, 8)),
	array(true, array(1, 'site_path', 11, 'beispiel.test', '942100', '/wp-admin/admin-ajax.php', '', 'Formular')));
expect_same('exception job', jobs_of($db), array(array(1, 'waf', array('exception_id' => 101, 'action' => 'exception_add', 'user' => 'admin'))));
expect_same('exception message', $result, array($wb['msg_exception_added_txt'], ''));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '11', 'exc_scope' => 'site', 'exc_rule' => '10010'));
expect_same('own rule refused', array($result, $db->writes), array(array('', $wb['reason_rule_id_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '77', 'exc_scope' => 'site', 'exc_rule' => '942100'));
expect_same('exception for a missing website', array($result, $db->writes), array(array('', $wb['err_no_site_txt']), array()));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_scope' => 'all', 'exc_rule' => '941160'));
expect_same('exception for every website', jobs_of($db), array(array(1, 'waf', array('exception_id' => 101, 'action' => 'exception_add', 'user' => 'admin'))));

$db = fresh_db();
$db->exceptions[5] = array('exception_id' => '5', 'server_id' => '1', 'exception_state' => 'active');
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_remove', 'waf_exception' => '5'));
expect_same('exception removal', array($result, strpos($db->writes[0]['query'], "SET exception_state = 'removing'") !== false, jobs_of($db)),
	array(array($wb['msg_exception_removing_txt'], ''), true,
	array(array(1, 'waf', array('exception_id' => 5, 'action' => 'exception_remove', 'user' => 'admin')))));
$db = fresh_db();
$db->exceptions[6] = array('exception_id' => '6', 'server_id' => '1', 'exception_state' => 'pending');
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_remove', 'waf_exception' => '6'));
expect_same('pending exception stays', array($result, $db->writes), array(array('', $wb['err_exception_txt']), array()));

$db = fresh_db();
expect_same('unknown button', waf_panel_handle_post($app, $wb, array('waf_action' => 'launch')), array('', $wb['err_unknown_action_txt']));

$db = fresh_db();
$db->days = array(
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => '18'),
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'path' => '/kontakt', 'hits' => '3'),
);
expect_same('preview of a path', waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site_path', 'exc_rule' => '942100', 'exc_path' => '/wp-admin/')),
	array('valid' => true, 'preview' => array('covered' => 18, 'total' => 21), 'text' => 'Diese Ausnahme hätte 18 von 21 Treffern der letzten 7 Tage verhindert.'));
$db->hits = array(
	array('parent_domain_id' => '11', 'path' => '/suche', 'rules' => '[{"id":"942100","param":"q"}]'),
	array('parent_domain_id' => '11', 'path' => '/suche', 'rules' => '[{"id":"942100","param":"s"},{"id":"949110","param":""}]'),
);
$preview = waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site_param', 'exc_rule' => '942100', 'exc_param' => 'q'));
expect_same('preview of a parameter', $preview['preview'], array('covered' => 1, 'total' => 2));
expect_same('preview of bad input', waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site', 'exc_rule' => 'x')),
	array('valid' => false, 'preview' => array('covered' => 0, 'total' => 0), 'text' => $wb['reason_rule_id_txt']));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel_post: alle Prüfungen bestanden\n";
