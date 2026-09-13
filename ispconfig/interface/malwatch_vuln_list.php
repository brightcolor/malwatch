<?php

/**
 * Bekannte Schwachstellen ueber alle Websites.
 *
 * Die Fundliste beantwortet, was auf einer Website liegt. Diese Seite
 * beantwortet, welche installierte Version ein Update braucht, weil fuer sie
 * eine Luecke veroeffentlicht ist. Die Zeilen stammen aus malwatch_software;
 * gefuellt wird die Tabelle von jeder regulaeren Pruefung und vom taeglichen
 * Abgleich (job_kind 'vulncheck', siehe 560-malwatch.inc.php).
 *
 * Gegliedert nach Websites, mit ihren Installationen darunter. Die einzelnen
 * Luecken stehen auf der Seite der Website: mit ihnen wog diese Seite auf dem
 * Livesystem 1,7 MB, bei 458 Installationen und 3.513 aufgelisteten Luecken.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

// Eingebunden statt ueber $app->load_language_file() geholt - siehe
// status.php: die Methode behaelt das Ergebnis fuer sich, $wb bliebe leer.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_vuln_list.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_vuln_list.lng';
}
include $lng_file;

$message = '';
$error = '';

// --- Aktion -----------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';
	if ($action === 'check_all') {
		list($queued, $busy, $optout, $failed) = malwatch_queue_vulnchecks($app);
		$details = array();
		if ($busy > 0) {
			$details[] = sprintf($wb['msg_skipped_txt'], number_format($busy, 0, ',', '.'));
		}
		if ($optout > 0) {
			$details[] = sprintf($wb['msg_optout_txt'], number_format($optout, 0, ',', '.'));
		}
		if ($failed > 0) {
			$details[] = sprintf($wb['msg_failed_txt'], number_format($failed, 0, ',', '.'));
		}
		if ($queued === 0) {
			$error = trim($wb['err_nothing_queued_txt'] . ' ' . implode(' ', $details));
		} else {
			$message = $queued === 1 ? $wb['msg_queued_one_txt']
				: sprintf($wb['msg_queued_txt'], number_format($queued, 0, ',', '.'));
			if (count($details) > 0) {
				$message .= ' ' . implode(' ', $details);
			}
		}
	}
}

// --- Seite ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_vuln_list.htm');
$app->tpl->setVar($wb);

$config = malwatch_get_config($app);
$app->tpl->setVar('is_disabled', (isset($config['vuln_scan']) && $config['vuln_scan'] === 'n') ? 1 : 0);

$summary = $app->db->queryOneRecord(
	'SELECT COUNT(*) AS installs, COUNT(DISTINCT parent_domain_id) AS sites, '
	. "COALESCE(SUM(vuln_severity = 'critical'), 0) AS critical, COALESCE(SUM(vuln_severity = 'high'), 0) AS high, "
	. "COALESCE(SUM(vuln_severity = 'medium'), 0) AS medium, COALESCE(SUM(vuln_severity = 'low'), 0) AS low, "
	. "COALESCE(SUM(vuln_severity = ''), 0) AS unrated "
	. 'FROM malwatch_software WHERE vuln_count > 0');
$installs = is_array($summary) ? $app->functions->intval($summary['installs']) : 0;
$sites = is_array($summary) ? $app->functions->intval($summary['sites']) : 0;

if ($installs === 0) {
	$lede = $wb['lede_none_txt'];
} elseif ($installs === 1) {
	$lede = $wb['lede_one_txt'];
} elseif ($sites === 1) {
	$lede = sprintf($wb['lede_many_one_site_txt'], number_format($installs, 0, ',', '.'));
} else {
	$lede = sprintf($wb['lede_many_txt'], number_format($installs, 0, ',', '.'), number_format($sites, 0, ',', '.'));
}
$app->tpl->setVar('lede', $app->functions->htmlentities($lede));

// Eine Marke je Stufe, die vorkommt - die schwerste zuerst, wie die Liste.
$chips = array();
if (is_array($summary)) {
	foreach (array('critical', 'high', 'medium', 'low') as $severity) {
		$n = $app->functions->intval($summary[$severity]);
		if ($n > 0) {
			$chips[] = array(
				'chip_class' => malwatch_severity_class($severity),
				'chip_label' => $app->functions->htmlentities(number_format($n, 0, ',', '.') . ' '
					. malwatch_severity_label($wb, $severity)),
			);
		}
	}
	$unrated = $app->functions->intval($summary['unrated']);
	if ($unrated > 0) {
		$chips[] = array(
			'chip_class' => 'label-default',
			'chip_label' => $app->functions->htmlentities(number_format($unrated, 0, ',', '.') . ' ' . $wb['vuln_unrated_txt']),
		);
	}
}
$app->tpl->setLoop('chips', $chips);
$app->tpl->setVar('has_chips', count($chips) > 0 ? 1 : 0);

$seen = $app->db->queryOneRecord('SELECT MAX(last_seen) AS seen FROM malwatch_software');
$seen_stamp = is_array($seen) && !empty($seen['seen']) ? strtotime((string) $seen['seen']) : false;
$as_of = ($seen_stamp !== false && $seen_stamp > 0)
	? sprintf($wb['as_of_txt'], malwatch_when($seen_stamp)) : $wb['never_checked_txt'];

$running = $app->db->queryOneRecord(
	"SELECT COUNT(*) AS n FROM malwatch_job WHERE job_kind = 'vulncheck' AND job_status IN ('pending','running')");
$running_count = is_array($running) ? $app->functions->intval($running['n']) : 0;
if ($running_count === 1) {
	$as_of .= ' ' . $wb['running_one_txt'];
} elseif ($running_count > 1) {
	$as_of .= ' ' . sprintf($wb['running_many_txt'], number_format($running_count, 0, ',', '.'));
}
$app->tpl->setVar('as_of', $app->functions->htmlentities($as_of));

$unchecked = $app->db->queryOneRecord("SELECT COUNT(*) AS n FROM malwatch_software WHERE vuln_unchecked = 'y'");
$unchecked_count = is_array($unchecked) ? $app->functions->intval($unchecked['n']) : 0;
$app->tpl->setVar('has_unchecked', $unchecked_count > 0 ? 1 : 0);
$app->tpl->setVar('unchecked_line', $app->functions->htmlentities($unchecked_count === 1
	? $wb['unchecked_one_txt']
	: sprintf($wb['unchecked_many_txt'], number_format($unchecked_count, 0, ',', '.'))));

// --- Websites und ihre Installationen ----------------------------------------
// Die schwerste Stufe zuerst, bei gleicher Stufe die meisten Luecken. FIELD()
// liefert 0 fuer eine nicht eingestufte Zeile, die damit ans Ende rueckt.
// Die Luecken selbst (Spalte vulns) werden hier nicht gelesen.
$site_rows = $app->db->queryAllRecords(
	'SELECT parent_domain_id, domain, COUNT(*) AS installs, SUM(vuln_count) AS flaws, '
	. "MAX(FIELD(vuln_severity, 'low', 'medium', 'high', 'critical')) AS worst "
	. 'FROM malwatch_software WHERE vuln_count > 0 GROUP BY parent_domain_id, domain '
	. 'ORDER BY worst DESC, flaws DESC, domain ASC');
$install_rows = $app->db->queryAllRecords(
	'SELECT parent_domain_id, product, software_kind, slug, install_path, installed_version, latest_version, '
	. 'outdated, vuln_count, vuln_nofix, vuln_severity, vuln_fixed_in FROM malwatch_software WHERE vuln_count > 0 '
	. "ORDER BY parent_domain_id ASC, FIELD(vuln_severity, 'low', 'medium', 'high', 'critical') DESC, "
	. 'vuln_count DESC, product ASC, slug ASC');

// Eine Demo-Website traegt schnell hundert Installationen. Die ersten 40,
// schwerste zuerst, sagen, was zu tun ist; die Seite der Website hat den Rest.
$per_site = 40;
$kinds = array('core' => $wb['kind_core_txt'], 'plugin' => $wb['kind_plugin_txt'], 'theme' => $wb['kind_theme_txt']);
$by_site = array();
foreach ((array) $install_rows as $row) {
	$domain_id = $app->functions->intval($row['parent_domain_id']);
	if (!isset($by_site[$domain_id])) {
		$by_site[$domain_id] = array();
	}
	if (count($by_site[$domain_id]) >= $per_site) {
		continue;
	}
	$name = (string) $row['product'];
	if ((string) $row['slug'] !== '') {
		$name .= ' / ' . $row['slug'];
	}
	$kind = (string) $row['software_kind'];
	$severity = (string) $row['vuln_severity'];
	$count = $app->functions->intval($row['vuln_count']);
	$latest = (string) $row['latest_version'];
	$update_label = malwatch_update_to_label($wb, $row['vuln_fixed_in'], $count,
		$app->functions->intval($row['vuln_nofix']));

	$by_site[$domain_id][] = array(
		'name' => $app->functions->htmlentities($name),
		'kind_label' => $app->functions->htmlentities(isset($kinds[$kind]) ? $kinds[$kind] : $kind),
		'path' => $app->functions->htmlentities((string) $row['install_path']),
		'installed_line' => $app->functions->htmlentities(sprintf($wb['installed_line_txt'], (string) $row['installed_version'])),
		'has_latest' => ($latest !== '' && $row['outdated'] === 'y') ? 1 : 0,
		'latest_line' => $app->functions->htmlentities(sprintf($wb['latest_line_txt'], $latest)),
		'severity_label' => $app->functions->htmlentities($severity !== ''
			? malwatch_severity_label($wb, $severity) : $wb['vuln_unrated_txt']),
		'severity_class' => $severity !== '' ? malwatch_severity_class($severity) : 'label-default',
		'count_label' => $app->functions->htmlentities($count === 1
			? $wb['vuln_count_one_txt'] : sprintf($wb['vuln_count_many_txt'], number_format($count, 0, ',', '.'))),
		'has_update_to' => $update_label !== '' ? 1 : 0,
		'update_to' => $app->functions->htmlentities($update_label),
	);
}

$severities = array('low', 'medium', 'high', 'critical');
$list = array();
foreach ((array) $site_rows as $site) {
	$domain_id = $app->functions->intval($site['parent_domain_id']);
	$worst_index = $app->functions->intval($site['worst']) - 1;
	$worst = isset($severities[$worst_index]) ? $severities[$worst_index] : '';
	$installs_n = $app->functions->intval($site['installs']);
	$flaws_n = $app->functions->intval($site['flaws']);
	$shown = isset($by_site[$domain_id]) ? $by_site[$domain_id] : array();

	$list[] = array(
		'domain' => $app->functions->htmlentities((string) $site['domain']),
		'domain_id' => $domain_id,
		'site_severity_label' => $app->functions->htmlentities($worst !== ''
			? malwatch_severity_label($wb, $worst) : $wb['vuln_unrated_txt']),
		'site_severity_class' => $worst !== '' ? malwatch_severity_class($worst) : 'label-default',
		'installs_label' => $app->functions->htmlentities($installs_n === 1
			? $wb['site_installs_one_txt']
			: sprintf($wb['site_installs_many_txt'], number_format($installs_n, 0, ',', '.'))),
		'flaws_label' => $app->functions->htmlentities($flaws_n === 1
			? $wb['vuln_count_one_txt'] : sprintf($wb['vuln_count_many_txt'], number_format($flaws_n, 0, ',', '.'))),
		'installs' => $shown,
		'has_more_installs' => $installs_n > count($shown) ? 1 : 0,
		'more_installs_label' => $app->functions->htmlentities(
			sprintf($wb['more_installs_txt'], number_format(max(0, $installs_n - count($shown)), 0, ',', '.'))),
	);
}
$app->tpl->setLoop('sites', $list);
$app->tpl->setVar('has_sites', count($list) > 0 ? 1 : 0);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_vuln_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
