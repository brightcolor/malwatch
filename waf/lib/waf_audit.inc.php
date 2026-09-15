<?php
/**
 * Reine Funktionen zum Auswerten des Audit-Logs im JSON-Format.
 * Zeilen hinein, Zusammenfassung heraus: keine Datei-Eigenlogik, kein Zustand.
 */

/**
 * Liest eine Zeile des Audit-Logs und gibt ihre Treffer zurück.
 * Ergebnis ist eine Liste von Treffern oder null, wenn die Zeile unbrauchbar ist.
 */
function waf_audit_zeile($zeile)
{
	$zeile = trim((string)$zeile);
	if ($zeile === '') {
		return null;
	}
	$daten = json_decode($zeile, true);
	if (!is_array($daten) || !isset($daten['transaction'])) {
		return null;
	}
	$t = $daten['transaction'];
	$pfad = isset($t['request']['uri']) ? $t['request']['uri'] : '';
	$frage = strpos($pfad, '?');
	if ($frage !== false) {
		$pfad = substr($pfad, 0, $frage);
	}
	$treffer = array();
	$meldungen = isset($t['messages']) && is_array($t['messages']) ? $t['messages'] : array();
	foreach ($meldungen as $meldung) {
		$treffer[] = array(
			'host' => isset($t['request']['headers']['Host']) ? $t['request']['headers']['Host'] : '?',
			'regel' => isset($meldung['details']['ruleId']) ? (string)$meldung['details']['ruleId'] : '?',
			'meldung' => isset($meldung['message']) ? $meldung['message'] : '',
			'pfad' => $pfad,
			'adresse' => isset($t['client_ip']) ? $t['client_ip'] : '',
			'zeit' => isset($t['time_stamp']) ? $t['time_stamp'] : '',
		);
	}
	return $treffer;
}

/**
 * Fasst Zeilen zu Gruppen aus Website und Regel zusammen, häufigste zuerst.
 */
function waf_audit_auswerten($zeilen)
{
	$gruppen = array();
	foreach ($zeilen as $zeile) {
		$treffer = waf_audit_zeile($zeile);
		if ($treffer === null) {
			continue;
		}
		foreach ($treffer as $t) {
			$schluessel = $t['host'] . '|' . $t['regel'];
			if (!isset($gruppen[$schluessel])) {
				$gruppen[$schluessel] = array(
					'host' => $t['host'],
					'regel' => $t['regel'],
					'meldung' => $t['meldung'],
					'treffer' => 0,
					'beispiel' => $t['pfad'],
				);
			}
			$gruppen[$schluessel]['treffer']++;
		}
	}
	$bericht = array_values($gruppen);
	usort($bericht, function ($a, $b) {
		if ($a['treffer'] === $b['treffer']) {
			return strcmp($a['host'] . $a['regel'], $b['host'] . $b['regel']);
		}
		return $b['treffer'] - $a['treffer'];
	});
	return $bericht;
}
