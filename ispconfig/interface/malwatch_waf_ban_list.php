<?php

/**
 * Abwehr: who is blocked, who is proposed and what is never blocked. Every
 * button queues a job like the other pages of the Abwehr; the malwatch cron
 * writes the deny file of nginx and reloads it, and the page follows the job.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';
require_once 'lib/malwatch_waf_ban.inc.php';

$language = $app->functions->check_language($_SESSION['s']['language']);
$lng_file = 'lib/lang/' . $language . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

$settings = waf_panel_settings($app);
$clock = waf_panel_clock($app);

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_ban_list.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('ban_lift_all_txt', 'ban_lift_all_confirm_txt', 'ban_lift_txt',
	'ban_add_txt', 'ban_allow_remove_txt', 'ban_url_new_txt', 'ban_url_new_confirm_txt',
	'ban_origin_save_txt')));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

// Running jobs are followed like on the overview.
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	$first_job = $first_job === 0 ? $job['job_id'] : $first_job;
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);

$all = waf_panel_rows($app->db->queryAllRecords(
	"SELECT * FROM malwatch_waf_ban ORDER BY FIELD(state, 'active', 'proposed', 'expired', 'lifted', 'dismissed'), "
	. 'until IS NULL DESC, until, ip'));
$origins = waf_panel_origin_lookup($app, array_column($all, 'ip'));
$view = waf_panel_ban_rows($wb, $all, $origins, $clock['now'], $language);

$active = array();
$proposed = array();
$past = array();
foreach ($view as $row) {
	$line = array(
		'ban_ip' => $app->functions->htmlentities($row['ip']),
		'ban_state' => $app->functions->htmlentities($row['state_label']),
		'ban_reason' => $app->functions->htmlentities($row['reason']),
		'ban_since' => $app->functions->htmlentities($row['since']),
		'ban_until' => $app->functions->htmlentities($row['until_label']),
		'ban_denied' => $app->functions->htmlentities(number_format((int) $row['denied'], 0, ',', '.')),
		'ban_source' => $app->functions->htmlentities($row['source_label']),
		'ban_country' => $app->functions->htmlentities($row['origin']['country']),
		'ban_country_title' => $app->functions->htmlentities($row['origin']['country_name']),
		'ban_provider' => $app->functions->htmlentities($row['origin']['provider']),
		'ban_provider_title' => $app->functions->htmlentities($row['origin']['provider_full']),
		'ban_chips' => $app->functions->htmlentities(implode(', ', $row['origin']['chips'])),
		'ban_has_chips' => count($row['origin']['chips']) > 0 ? 1 : 0,
	);
	if ($row['state'] === 'active') {
		$active[] = $line;
	} elseif ($row['state'] === 'proposed') {
		$proposed[] = $line;
	} else {
		$past[] = $line;
	}
}
$app->tpl->setLoop('ban_active', $active);
$app->tpl->setLoop('ban_proposed', $proposed);
$app->tpl->setLoop('ban_past', $past);
$app->tpl->setVar('has_active', count($active) > 0 ? 1 : 0);
$app->tpl->setVar('has_proposed', count($proposed) > 0 ? 1 : 0);
$app->tpl->setVar('has_past', count($past) > 0 ? 1 : 0);
$app->tpl->setVar('ban_count', $app->functions->htmlentities(sprintf($wb['ban_count_txt'],
	number_format(count($active), 0, ',', '.'))));

$allow_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_allow ORDER BY cidr')) as $row) {
	$allow_rows[] = array(
		'allow_id' => (int) $row['allow_id'],
		'allow_cidr' => $app->functions->htmlentities((string) $row['cidr']),
		'allow_note' => $app->functions->htmlentities((string) $row['note']),
		'allow_created' => $app->functions->htmlentities((string) $row['created_by'] . ', '
			. malwatch_datetime($row['created_at'])),
	);
}
$app->tpl->setLoop('ban_allow', $allow_rows);
$app->tpl->setVar('has_allow', count($allow_rows) > 0 ? 1 : 0);

$mode = (string) $settings['waf_ban_mode'];
$modes = array();
foreach (waf_ban_modes() as $one) {
	$modes[] = array(
		'mode_value' => $app->functions->htmlentities($one),
		'mode_label' => $app->functions->htmlentities(waf_panel_text($wb, 'ban_mode_' . $one . '_txt', $one)),
		'mode_current' => $one === $mode ? 1 : 0,
	);
}
$app->tpl->setLoop('ban_modes', $modes);
$app->tpl->setVar('ban_mode_now', $app->functions->htmlentities(waf_panel_text($wb, 'ban_mode_' . $mode . '_txt', $mode)));
$app->tpl->setVar('ban_score_now', $app->functions->htmlentities(number_format((int) $settings['waf_ban_score'], 0, ',', '.')));
$app->tpl->setVar('ban_window_now', $app->functions->htmlentities(number_format((int) $settings['waf_ban_window_minutes'], 0, ',', '.')));
// Herkunft: Länder und Anbieter aus den gespeicherten Treffern, die Häufigsten
// zuerst. Treffer leben waf_detail_days lang; weiter zurück reicht keine Zahl.
$days = (int) $settings['waf_detail_days'];
$countries = waf_panel_ban_origin_rows(waf_panel_rows($app->db->queryAllRecords(
	'SELECT i.country AS value, i.country AS label, COUNT(*) AS hits, COUNT(DISTINCT h.client_ip) AS addresses '
	. 'FROM malwatch_waf_hit h JOIN malwatch_waf_ip i ON i.ip = h.client_ip '
	. "WHERE h.seen_at > DATE_SUB(NOW(), INTERVAL ? DAY) AND i.country != '' "
	. 'GROUP BY i.country ORDER BY hits DESC', $days)),
	waf_ban_origin_countries($settings['waf_ban_origin_countries']));
$providers = waf_panel_ban_origin_rows(waf_panel_rows($app->db->queryAllRecords(
	'SELECT i.asn AS value, i.as_org AS label, COUNT(*) AS hits, COUNT(DISTINCT h.client_ip) AS addresses '
	. 'FROM malwatch_waf_hit h JOIN malwatch_waf_ip i ON i.ip = h.client_ip '
	. 'WHERE h.seen_at > DATE_SUB(NOW(), INTERVAL ? DAY) AND i.asn > 0 '
	. 'GROUP BY i.asn, i.as_org ORDER BY hits DESC', $days)),
	waf_ban_origin_asns($settings['waf_ban_origin_asn']));
foreach (array('country' => $countries, 'asn' => $providers) as $kind => $list) {
	$loop = array();
	foreach ($list as $one) {
		$loop[] = array(
			'origin_value' => $app->functions->htmlentities($one['value']),
			'origin_label' => $app->functions->htmlentities($one['label']),
			'origin_hits' => $app->functions->htmlentities($one['hits']),
			'origin_addresses' => $app->functions->htmlentities($one['addresses']),
			'origin_chosen' => $one['chosen'],
		);
	}
	$app->tpl->setLoop('origin_' . $kind, $loop);
	$app->tpl->setVar('has_origin_' . $kind, count($loop) > 0 ? 1 : 0);
}
$app->tpl->setVar('has_origin_any', count($countries) + count($providers) > 0 ? 1 : 0);
$app->tpl->setVar('origin_mode_on', (string) $settings['waf_ban_origin'] === 'on' ? 1 : 0);
$app->tpl->setVar('origin_days', $app->functions->htmlentities(sprintf(
	waf_panel_text($wb, 'ban_origin_days_txt', '%s'), number_format($days, 0, ',', '.'))));

// Die veröffentlichte Liste: dieselbe Auswahl, die auch in die Datei für nginx geht.
// Der Name, unter dem das Panel gerade aufgerufen wurde; die Form prüft
// waf_ban_list_url(). Ohne Anfrage (Probelauf auf der Kommandozeile) der Name
// des Rechners.
$host = isset($_SERVER['HTTP_HOST']) && (string) $_SERVER['HTTP_HOST'] !== ''
	? (string) $_SERVER['HTTP_HOST'] : (string) php_uname('n');
$url = waf_panel_ban_url($wb, $settings, $host, count($active));
$app->tpl->setVar('ban_url', $app->functions->htmlentities($url['url']));
$app->tpl->setVar('has_ban_url', $url['has_url']);
$app->tpl->setVar('ban_url_count', $app->functions->htmlentities($url['count']));
$app->tpl->setVar('ban_url_hint', $app->functions->htmlentities($url['hint']));
$app->tpl->setVar('self_href', 'security/malwatch_waf_ban_list.php');

$csrf = $app->auth->csrf_token_get('malwatch_waf_ban_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
