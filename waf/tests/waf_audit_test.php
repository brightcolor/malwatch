<?php
/**
 * Prüft die Auswertung des Audit-Logs.
 *
 *   php waf/tests/waf_audit_test.php
 */
require __DIR__ . '/../lib/waf_audit.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$zeilen = file(__DIR__ . '/beispiel-audit.log', FILE_IGNORE_NEW_LINES);
$zeilen_ok = array_filter(array_map('waf_audit_zeile', $zeilen));
expect_same('drei gültige Zeilen', count($zeilen_ok), 3);
expect_same('kaputte Zeile fällt weg', waf_audit_zeile('kaputte zeile ohne json'), null);
expect_same('leere Zeile fällt weg', waf_audit_zeile(''), null);

$bericht = waf_audit_auswerten($zeilen);
expect_same('zwei Gruppen', count($bericht), 2);

// Häufigste Gruppe zuerst
expect_same('erste Gruppe Host', $bericht[0]['host'], 'beispiel.test');
expect_same('erste Gruppe Regel', $bericht[0]['regel'], '942100');
expect_same('erste Gruppe Treffer', $bericht[0]['treffer'], 2);
expect_same('erste Gruppe Meldung', $bericht[0]['meldung'], 'SQL Injection Attack Detected');
expect_same('erste Gruppe Beispielpfad', $bericht[0]['beispiel'], '/suche');

expect_same('zweite Gruppe Host', $bericht[1]['host'], 'zweite.test');
expect_same('zweite Gruppe Regel', $bericht[1]['regel'], '941100');
expect_same('zweite Gruppe Treffer', $bericht[1]['treffer'], 1);
expect_same('zweite Gruppe Beispielpfad', $bericht[1]['beispiel'], '/seite');

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_audit: alle Prüfungen bestanden\n";
