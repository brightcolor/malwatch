<?php

/**
 * Bekannte Schwachstellen ueber alle Websites.
 *
 * Die Fundliste beantwortet, was auf einer Website liegt. Diese Seite
 * beantwortet, welche installierte Version ein Update braucht, weil fuer sie
 * eine Luecke veroeffentlicht ist. Die Zeilen stammen aus malwatch_software;
 * gefuellt wird die Tabelle von jeder regulaeren Pruefung und vom taeglichen
 * Abgleich (job_kind 'vulncheck', siehe 560-malwatch.inc.php).
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

// Eine Zeile je Stufe, die vorkommt - die schwerste zuerst, wie die Tabelle.
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

// --- Tabelle ------------------------------------------------------------------
// Schwerste Stufe zuerst, innerhalb einer Stufe die meisten Luecken. FIELD()
// liefert 0 fuer eine nicht eingestufte Zeile, die damit ans Ende rueckt.
$rows = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_software WHERE vuln_count > 0 '
	. "ORDER BY FIELD(vuln_severity, 'low', 'medium', 'high', 'critical') DESC, vuln_count DESC, "
	. 'domain ASC, product ASC, slug ASC LIMIT 500');

$kinds = array('core' => $wb['kind_core_txt'], 'plugin' => $wb['kind_plugin_txt'], 'theme' => $wb['kind_theme_txt']);
$list = array();
foreach ((array) $rows as $row) {
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
	list($vulns, $more) = malwatch_vuln_rows($app, $wb, $row['vulns'], 25, $count);

	$list[] = array(
		'domain' => $app->functions->htmlentities((string) $row['domain']),
		'domain_id' => $app->functions->intval($row['parent_domain_id']),
		'name' => $app->functions->htmlentities($name),
		'kind_label' => $app->functions->htmlentities(isset($kinds[$kind]) ? $kinds[$kind] : $kind),
		'path' => $app->functions->htmlentities((string) $row['install_path']),
		'installed_version' => $app->functions->htmlentities((string) $row['installed_version']),
		'has_latest' => $latest !== '' ? 1 : 0,
		'latest_line' => $app->functions->htmlentities(sprintf($wb['latest_line_txt'], $latest)),
		'severity_label' => $app->functions->htmlentities($severity !== ''
			? malwatch_severity_label($wb, $severity) : $wb['vuln_unrated_txt']),
		'severity_class' => $severity !== '' ? malwatch_severity_class($severity) : 'label-default',
		'count_label' => $app->functions->htmlentities($count === 1
			? $wb['vuln_count_one_txt'] : sprintf($wb['vuln_count_many_txt'], number_format($count, 0, ',', '.'))),
		'has_update_to' => $update_label !== '' ? 1 : 0,
		'update_to' => $app->functions->htmlentities($update_label),
		'vulns' => $vulns,
		'has_more' => $more > 0 ? 1 : 0,
		'more_label' => $app->functions->htmlentities(sprintf($wb['vuln_more_txt'], number_format($more, 0, ',', '.'))),
	);
}
$app->tpl->setLoop('rows', $list);
$app->tpl->setVar('has_rows', count($list) > 0 ? 1 : 0);

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_vuln_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
