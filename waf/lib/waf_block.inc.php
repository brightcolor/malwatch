<?php
/**
 * Reine Funktionen für den markierten WAF-Block im Feld „nginx-Direktiven".
 * Text hinein, Text heraus: keine Datenbank, kein ISPConfig.
 *
 * Zustände: aus, mitschreiben, scharf.
 */

define('WAF_ANFANG', '# WAF-Anfang');
define('WAF_ENDE', '# WAF-Ende');

function waf_zustand_gueltig($zustand)
{
	return in_array($zustand, array('aus', 'mitschreiben', 'scharf'), true);
}

function waf_block_text($zustand)
{
	if ($zustand === 'aus') {
		return '';
	}
	$zeilen = array(
		WAF_ANFANG . ' (' . $zustand . ') – verwaltet von waf-schalter',
		'modsecurity on;',
	);
	if ($zustand === 'scharf') {
		$zeilen[] = "modsecurity_rules 'SecRuleEngine On';";
	}
	$zeilen[] = WAF_ENDE;
	return implode("\n", $zeilen) . "\n";
}

function waf_block_entfernen($text)
{
	// Entfernt genau den Block samt seinem eigenen Zeilenumbruch. Was davor steht,
	// bleibt Zeichen für Zeichen erhalten, auch der Umbruch der Zeile davor.
	$muster = '/' . preg_quote(WAF_ANFANG, '/') . '.*?' . preg_quote(WAF_ENDE, '/') . '[^\r\n]*(?:\R)?/s';
	return preg_replace($muster, '', $text);
}

function waf_block_setzen($text, $zustand)
{
	$rest = waf_block_entfernen($text);
	if ($zustand === 'aus') {
		return $rest;
	}
	$block = waf_block_text($zustand);
	if (trim($rest) === '') {
		return $block;
	}
	// Endet der Text ohne Umbruch, kommt einer dazu. Sonst bleibt er, wie er ist.
	if (!preg_match('/\R$/', $rest)) {
		$rest .= "\n";
	}
	return $rest . $block;
}

function waf_block_zustand($text)
{
	if (preg_match('/' . preg_quote(WAF_ANFANG, '/') . '\s*\(([a-z]+)\)/', $text, $treffer)) {
		return $treffer[1];
	}
	return 'aus';
}

/**
 * Liest den Zustand aus einer erzeugten vhost-Datei.
 *
 * ISPConfig übernimmt die Direktiven aus dem Feld „nginx-Direktiven", wirft dabei
 * aber Kommentarzeilen heraus. Die Markierung steht deshalb nur in der Datenbank.
 * Im vhost zählt allein die Direktive selbst.
 */
function waf_vhost_zustand($vhost)
{
	$zeilen = preg_split("/\R/", (string)$vhost);
	$an = false;
	$scharf = false;
	foreach ($zeilen as $zeile) {
		$zeile = trim($zeile);
		if ($zeile === '' || $zeile[0] === '#') {
			continue;
		}
		if (preg_match('/^modsecurity\s+on\s*;/i', $zeile)) {
			$an = true;
		}
		if (preg_match('/^modsecurity_rules\s+.*SecRuleEngine\s+On/i', $zeile)) {
			$scharf = true;
		}
	}
	if ($scharf && $an) {
		return 'scharf';
	}
	if ($an) {
		return 'mitschreiben';
	}
	return 'aus';
}

function waf_antwortrumpf_gueltig($modus)
{
	return in_array($modus, array('voll', 'schlank'), true);
}

/**
 * Inhalt von /etc/nginx/waf/antwortrumpf.conf.
 *
 * 110 CRS-Regeln setzen ctl:auditLogParts=+E und schreiben damit die ganze
 * Seitenantwort in den Eintrag. „schlank" nimmt sie in Phase 5 wieder heraus,
 * nachdem alle CRS-Regeln gelaufen sind; „voll" lässt sie stehen.
 */
function waf_antwortrumpf_text($modus)
{
	$zeilen = array(
		'# Antwortrumpf im Audit-Log: ' . $modus,
		'# Verwaltet von waf-schalter, nicht von Hand ändern.',
		'#',
		'# voll:    Die CRS-Regeln dürfen die Seitenantwort in den Eintrag schreiben.',
		'#          110 Regeln setzen dafür ctl:auditLogParts=+E, darunter 27 der',
		'#          XSS-Gruppe. Ein Treffer wiegt damit rund 125 KB statt rund 4 KB.',
		'#          Für die Untersuchung von Fehlalarmen ist das der vollständige Blick.',
		'# schlank: Eine Regel in Phase 5 nimmt die Seitenantwort wieder heraus, nachdem',
		'#          alle CRS-Regeln gelaufen sind. Treffer, Kopfzeilen und Anfrageinhalt',
		'#          bleiben vollständig.',
		'#',
		'# Umschalten: waf-schalter antwortrumpf voll|schlank',
	);
	if ($modus === 'schlank') {
		$zeilen[] = 'SecAction "id:10200,phase:5,pass,nolog,ctl:auditLogParts=-E"';
	}
	return implode("\n", $zeilen) . "\n";
}

/**
 * Liest den Modus aus dem Inhalt von antwortrumpf.conf. Kommentarzeilen zählen nicht.
 */
function waf_antwortrumpf_modus($text)
{
	foreach (preg_split("/\R/", (string)$text) as $zeile) {
		$zeile = trim($zeile);
		if ($zeile === '' || $zeile[0] === '#') {
			continue;
		}
		if (strpos($zeile, 'ctl:auditLogParts=-E') !== false) {
			return 'schlank';
		}
	}
	return 'voll';
}
