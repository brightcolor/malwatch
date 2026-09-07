<?php

/**
 * Serves the progress of one job as JSON.
 *
 * No template: the panel's form.tpl.htm would append its own markup and the
 * caller would not get valid JSON back.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

// Eingebunden statt ueber $app->load_language_file() geholt: die Methode
// inkludiert die Datei in ihrem eigenen Geltungsbereich und behaelt das
// Ergebnis fuer sich - $wb bliebe hier ungesetzt, und 'label' im JSON waere
// eine leere Zeichenkette. Der Zaehler im Panel haette dann keine
// Beschriftung. check_language() haelt den Wert aus der Sitzung von der
// Pfadangabe fern, der en_-Rueckfall gilt fuer jede Sprache ohne eigene
// Datei. Derselbe Weg wie in status.php und malwatch_site_show.php.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_status.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_status.lng';
}
include $lng_file;

$job_id = $app->functions->intval(isset($_GET['job_id']) ? $_GET['job_id'] : 0);
$domain_id = $app->functions->intval(isset($_GET['domain_id']) ? $_GET['domain_id'] : 0);

// Without a job the caller asks about a website, and gets the job that is
// currently running there - which is what a page has after a reload.
if ($job_id < 1 && $domain_id > 0) {
	$row = $app->db->queryOneRecord(
		"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running') "
		. 'ORDER BY job_id DESC LIMIT 1', $domain_id);
	if (is_array($row)) {
		$job_id = $app->functions->intval($row['job_id']);
	}
}

if ($job_id < 1) {
	echo json_encode(array('state' => 'none'));
	exit;
}

$job = $app->db->queryOneRecord(
	'SELECT job_id, job_kind, job_status, parent_domain_id, exit_code FROM malwatch_job WHERE job_id = ?',
	$job_id);
if (!is_array($job)) {
	echo json_encode(array('state' => 'none'));
	exit;
}

$state = (string) $job['job_status'];

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/runs/job-' . $app->functions->intval($job['job_id']) . '.progress';
$raw = @file_get_contents($file);
$progress = array();
if ($raw !== false) {
	$doc = json_decode($raw, true);
	if (is_array($doc)) {
		$progress = $doc;
	}
}

// Der Erwartungswert ist die Dateizahl des letzten Laufs derselben Website.
// Eine Website waechst zwischen zwei Laeufen, also kann der Zaehler den
// Erwartungswert ueberholen. Bis der Lauf "done" meldet, wird deshalb bei
// 99 Prozent gedeckelt - ein Balken bei 140 Prozent ist schlimmer als einer
// ohne Prozentangabe.
$files_done  = isset($progress['files_done'])  ? intval($progress['files_done'])  : 0;
$files_total = isset($progress['files_total']) ? intval($progress['files_total']) : 0;

$percent = null;
if ($files_total > 0) {
	$percent = intval(floor($files_done * 100 / $files_total));
	if ($percent > 99) {
		$percent = 99;
	}
	if ($percent < 0) {
		$percent = 0;
	}
}
if ($state === 'done') {
	$percent = 100;
}

// Ohne Nenner zaehlt die Anzeige nur - "71.240 Dateien geprueft" ist eine
// ehrliche Aussage, eine erfundene Prozentzahl waere keine. Die Formulierung
// kommt aus der Sprachdatei des angemeldeten Bedieners, nicht fest aus dem
// Code - status.htm zeigt d.label unveraendert an.
$label = ($percent === null)
	? sprintf($wb['progress_scanned_txt'], number_format($files_done, 0, ',', '.'))
	: sprintf($wb['progress_of_total_txt'],
		number_format($files_done, 0, ',', '.'),
		number_format($files_total, 0, ',', '.'));

$out = array(
	'state' => $state,
	'kind' => (string) $job['job_kind'],
	'job_id' => $app->functions->intval($job['job_id']),
	'domain_id' => $app->functions->intval($job['parent_domain_id']),
	'percent'     => $percent,
	'files_done'  => $files_done,
	'files_total' => $files_total,
	'label'       => $label,
);
if (isset($doc) && is_array($doc)) {
	$out['progress'] = $doc;
}

echo json_encode($out);
