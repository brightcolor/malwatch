<?php
/**
 * Prüft die reinen Funktionen für den markierten WAF-Block.
 *
 *   php waf/tests/waf_block_test.php
 */
require __DIR__ . '/../lib/waf_block.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$block_mit = "# WAF-Anfang (mitschreiben) – verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n";
$block_scharf = "# WAF-Anfang (scharf) – verwaltet von waf-schalter\nmodsecurity on;\nmodsecurity_rules 'SecRuleEngine On';\n# WAF-Ende\n";

// Leeres Feld
expect_same('leer, mitschreiben', waf_block_setzen('', 'mitschreiben'), $block_mit);
expect_same('leer, scharf', waf_block_setzen('', 'scharf'), $block_scharf);
expect_same('leer, aus', waf_block_setzen('', 'aus'), '');

// Vorhandene Direktiven bleiben erhalten
$eigene = "location = /xmlrpc.php {\n    deny all;\n}\n";
$gesetzt = waf_block_setzen($eigene, 'mitschreiben');
expect_same('eigene Direktiven bleiben', substr($gesetzt, 0, strlen($eigene)), $eigene);
expect_same('Block hängt hinten an', substr($gesetzt, -strlen($block_mit)), $block_mit);

// Hin und zurück ergibt den Ausgangstext
expect_same('Rundlauf', waf_block_setzen($gesetzt, 'aus'), $eigene);

// Zustand wechseln erzeugt keinen zweiten Block
$scharf = waf_block_setzen($gesetzt, 'scharf');
expect_same('nur ein Anfang', substr_count($scharf, '# WAF-Anfang'), 1);
expect_same('nur ein Ende', substr_count($scharf, '# WAF-Ende'), 1);
expect_same('scharf enthält Engine-Zeile', strpos($scharf, "modsecurity_rules 'SecRuleEngine On';") !== false, true);
expect_same('Rundlauf nach Wechsel', waf_block_setzen($scharf, 'aus'), $eigene);

// Zustand ablesen
expect_same('Zustand mitschreiben', waf_block_zustand($gesetzt), 'mitschreiben');
expect_same('Zustand scharf', waf_block_zustand($scharf), 'scharf');
expect_same('Zustand aus', waf_block_zustand($eigene), 'aus');

// Zeilenenden außerhalb des Blocks bleiben unangetastet
$crlf = "location / {\r\n    try_files \$uri =404;\r\n}\r\n";
$crlf_gesetzt = waf_block_setzen($crlf, 'mitschreiben');
expect_same('CRLF bleibt', substr($crlf_gesetzt, 0, strlen($crlf)), $crlf);
expect_same('CRLF Rundlauf', waf_block_setzen($crlf_gesetzt, 'aus'), $crlf);

// Text ohne abschließenden Umbruch bekommt einen
$ohne_umbruch = "client_max_body_size 64M;";
$mit_block = waf_block_setzen($ohne_umbruch, 'mitschreiben');
expect_same('Umbruch ergänzt', $mit_block, $ohne_umbruch . "\n" . $block_mit);

// Zustand aus dem erzeugten vhost lesen.
// ISPConfig übernimmt die Direktiven, wirft dabei aber Kommentarzeilen heraus.
// Im vhost fehlt die Markierung deshalb, dort zählt allein die Direktive.
$vhost_aus = "server {\n    listen 443 ssl;\n    server_name beispiel.test;\n}\n";
$vhost_mit = "server {\n    listen 443 ssl;\n    modsecurity on;\n}\n";
$vhost_scharf = "server {\n    listen 443 ssl;\n    modsecurity on;\n    modsecurity_rules 'SecRuleEngine On';\n}\n";
expect_same('vhost ohne WAF', waf_vhost_zustand($vhost_aus), 'aus');
expect_same('vhost mitschreiben', waf_vhost_zustand($vhost_mit), 'mitschreiben');
expect_same('vhost scharf', waf_vhost_zustand($vhost_scharf), 'scharf');
expect_same('vhost mit auskommentierter Direktive', waf_vhost_zustand("server {\n    # modsecurity on;\n}\n"), 'aus');
expect_same('vhost mit abgeschalteter Direktive', waf_vhost_zustand("server {\n    modsecurity off;\n}\n"), 'aus');
expect_same('leerer vhost', waf_vhost_zustand(''), 'aus');

// Gültige Zustände
expect_same('gültig: aus', waf_zustand_gueltig('aus'), true);
expect_same('gültig: mitschreiben', waf_zustand_gueltig('mitschreiben'), true);
expect_same('gültig: scharf', waf_zustand_gueltig('scharf'), true);
expect_same('ungültig: an', waf_zustand_gueltig('an'), false);

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_block: alle Prüfungen bestanden\n";
