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
$app->load_language_file('web/security/lib/lang/' . $_SESSION['s']['language'] . '_status.lng');

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
$app->tpl->setVar('attention_count', count($rows['attention']));
$app->tpl->setVar('quiet_count', $rows['quiet_count']);
$app->tpl->setVar('as_of', $rows['as_of']);
$app->tpl->setVar('next_run', $rows['next_run']);
$app->tpl->setVar($wb);

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

$app->tpl_defaults();
$app->tpl->pparse();
