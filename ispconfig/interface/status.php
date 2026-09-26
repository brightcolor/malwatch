<?php

/**
 * Die Startseite des Security-Moduls.
 *
 * Sie beantwortet eine Frage - brennt etwas? - statt Daten auszubreiten.
 * Deshalb stehen hier nur die Websites, die etwas brauchen; die
 * unauffaelligen sind eine ruhige Zeile darunter und kein Standardinhalt.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	// Die Modulzugehoerigkeit allein ist keine Rechtepruefung.
	die('');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/status.htm');

// Die Sprachdatei wird hier eingebunden und nicht ueber
// $app->load_language_file() geholt: die Methode inkludiert die Datei in
// ihrem eigenen Geltungsbereich und legt das Ergebnis in ihrer privaten
// Eigenschaft ab. $wb erreicht den Aufrufer dabei nie - setVar(null) setzt
// nichts, und die Seite rendert ohne einen einzigen Text: keine Ueberschrift,
// kein Zustandsschild, kein "Ansehen". check_language() haelt den Wert aus
// der Sitzung von der Pfadangabe fern, und wer eine Sprache ohne eigene Datei
// eingestellt hat, bekommt die englische statt gar keiner. Denselben Weg geht
// malwatch_site_show.php.
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_status.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_status.lng';
}
include $lng_file;
$app->tpl->setVar($wb);

$rows = malwatch_status_rows($app);

// Die Sprachdatei traegt "%s" als Platzhalter fuer die Zahlen; erst hier
// werden sie eingesetzt - die Vorlage darf keinen rohen "%s" anzeigen.
foreach ($rows['attention'] as &$row) {
	$row['findings_line'] = $row['findings'] === 1
		? $wb['findings_one_txt']
		: sprintf($wb['findings_txt'],
			number_format($row['findings'], 0, ',', '.'),
			number_format($row['urgent'], 0, ',', '.'));
}
unset($row);

$app->tpl->setLoop('sites', $rows['attention']);
$app->tpl->setVar('poll_ms', malwatch_poll_ms(malwatch_get_config($app)));
$app->tpl->setVar('attention_count', count($rows['attention']));
$app->tpl->setVar('quiet_count', $rows['quiet_count']);

// Dieselbe Regel wie fuer die Fundzeile: der Platzhalter wird erst hier
// gefuellt, und die Kopfzeile unterscheidet - wie oben im Titel - zwischen
// einer und mehreren Websites.
if (count($rows['attention']) > 1) {
	$app->tpl->setVar('attention_many_txt',
		sprintf($wb['attention_many_txt'], number_format(count($rows['attention']), 0, ',', '.')));
}
if ($rows['quiet_count'] === 1) {
	$app->tpl->setVar('quiet_txt', $wb['quiet_one_txt']);
} elseif ($rows['quiet_count'] > 1) {
	$app->tpl->setVar('quiet_txt', sprintf($wb['quiet_txt'], number_format($rows['quiet_count'], 0, ',', '.')));
}

// Bekannte Luecken haben ihre eigene Seite. Hier steht nur eine ruhige Zeile
// mit dem Weg dorthin: die Startseite behaelt ihre eine Frage - brennt etwas? -,
// und wer morgens nur sie ansieht, erfaehrt trotzdem, dass Updates anstehen.
$vulns = $app->db->queryOneRecord(
	'SELECT COUNT(*) AS installs, COUNT(DISTINCT parent_domain_id) AS sites FROM malwatch_software WHERE vuln_count > 0');
$vuln_installs = is_array($vulns) ? $app->functions->intval($vulns['installs']) : 0;
$vuln_sites = is_array($vulns) ? $app->functions->intval($vulns['sites']) : 0;
$app->tpl->setVar('has_vulns', $vuln_installs > 0 ? 1 : 0);
if ($vuln_installs === 1) {
	$app->tpl->setVar('vulns_line', $wb['vulns_one_txt']);
} elseif ($vuln_installs > 1) {
	$app->tpl->setVar('vulns_line', $vuln_sites === 1
		? sprintf($wb['vulns_many_one_site_txt'], number_format($vuln_installs, 0, ',', '.'))
		: sprintf($wb['vulns_many_txt'], number_format($vuln_installs, 0, ',', '.'), number_format($vuln_sites, 0, ',', '.')));
}

// as_of_txt hat drei Fassungen, je nachdem, was malwatch_next_run() (in
// malwatch_lib.inc.php) als next_run_state ermittelt hat. 'scheduled' ist
// der Normalfall: as_of_txt traegt zwei Platzhalter, Stand und naechster
// Lauf, wie bei findings_line oben per sprintf gefuellt. 'due' und 'none'
// haben keine Uhrzeit zum Einsetzen - eine Website kann faellig sein, ohne
// dass die Seite weiss, wann sie tatsaechlich laeuft, und wenn ueberhaupt
// nichts geplant ist, gibt es keinen Zeitpunkt zu nennen. Beide haben
// deshalb ihren eigenen, vollstaendigen Satz mit nur einem Platzhalter
// (as_of_due_txt / as_of_none_txt) statt eines erfundenen oder leeren
// zweiten Werts fuer as_of_txt.
if ($rows['next_run_state'] === 'scheduled') {
	$as_of_txt = sprintf($wb['as_of_txt'], $rows['as_of'], $rows['next_run']);
} elseif ($rows['next_run_state'] === 'due') {
	$as_of_txt = sprintf($wb['as_of_due_txt'], $rows['as_of']);
} else {
	$as_of_txt = sprintf($wb['as_of_none_txt'], $rows['as_of']);
}
$app->tpl->setVar('as_of_txt', $as_of_txt);

$app->tpl_defaults();
$app->tpl->pparse();
