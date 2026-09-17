<?php
/**
 * Checks how an answer of proxycheck.io becomes the facts of an address and
 * how the queries of a day are counted.
 *
 *   php ispconfig/tests/waf_proxycheck_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_origin.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . PHP_EOL);
	}
}

$fixtures = __DIR__ . '/fixtures/proxycheck';

// --- The choice ---------------------------------------------------------------

expect_same('proxycheck is the external source', waf_origin_external(array('waf_origin_net' => 'proxycheck')), 'proxycheck');
expect_same('the lists are no external source', waf_origin_external(array('waf_origin_net' => 'x4b')), '');
expect_same('nothing chosen, no external source', waf_origin_external(array()), '');
expect_same('proxycheck has no range file', in_array('proxycheck', array_keys(waf_origin_sources()), true), false);

// --- The request --------------------------------------------------------------

expect_same('the body carries the addresses',
	waf_origin_proxycheck_body(array('192.0.2.10', '2001:db8::5')), 'ips=192.0.2.10,2001:db8::5');
expect_same('what is no address is left out',
	waf_origin_proxycheck_body(array('192.0.2.10', 'kein-ip', '', '192.0.2.10')), 'ips=192.0.2.10');
expect_same('nothing to ask', waf_origin_proxycheck_body(array()), '');

// --- The answer ---------------------------------------------------------------

$read = waf_origin_proxycheck_read(file_get_contents($fixtures . '/answer.json'));
expect_same('the answer is read', $read['ok'], true);
expect_same('three addresses, no other key', array_keys($read['ips']), array('192.0.2.10', '198.51.100.7', '2001:db8::5'));
expect_same('a VPN with its operator', array($read['ips']['192.0.2.10']['is_vpn'], $read['ips']['192.0.2.10']['is_proxy'],
	$read['ips']['192.0.2.10']['vpn_operator']), array('y', 'y', 'Beispiel VPN'));
expect_same('country and provider of the first address', array($read['ips']['192.0.2.10']['country'],
	$read['ips']['192.0.2.10']['asn'], $read['ips']['192.0.2.10']['as_org']), array('DE', 64496, 'Beispiel Netz GmbH'));
expect_same('the organisation stands in for a missing provider', $read['ips']['198.51.100.7']['as_org'], 'Zweites Netz');
expect_same('a lower case country becomes upper case', $read['ips']['198.51.100.7']['country'], 'NL');
expect_same('Tor and data centre of the second address', array($read['ips']['198.51.100.7']['is_tor'],
	$read['ips']['198.51.100.7']['is_hosting'], $read['ips']['198.51.100.7']['is_vpn']), array('y', 'y', 'n'));
expect_same('an address without fields stays empty', $read['ips']['2001:db8::5'],
	array('country' => '', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n',
		'is_proxy' => 'n', 'vpn_operator' => ''));

$denied = waf_origin_proxycheck_read(file_get_contents($fixtures . '/denied.json'));
expect_same('a refused key fails', $denied['ok'], false);
expect_same('the text says what to do',
	strpos($denied['error'], 'Bitte den Schlüssel in den Einstellungen der Abwehr prüfen.') !== false, true);
expect_same('no address from a refused answer', $denied['ips'], array());

$empty = waf_origin_proxycheck_read(file_get_contents($fixtures . '/empty.json'));
expect_same('an answer without an address fails', array($empty['ok'],
	strpos($empty['error'], 'keine Adresse') !== false), array(false, true));
$broken = waf_origin_proxycheck_read('<html>kaputt</html>');
expect_same('an answer that is no JSON fails', array($broken['ok'],
	strpos($broken['error'], 'JSON') !== false), array(false, true));

// --- The daily quota ----------------------------------------------------------

expect_same('a new day starts at zero', waf_origin_quota(array('day' => '2026-09-17', 'queries' => 480), '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 0, 'daily' => 500, 'left' => 500));
expect_same('the same day keeps its count', waf_origin_quota(array('day' => '2026-09-18', 'queries' => 480), '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 480, 'daily' => 500, 'left' => 20));
expect_same('the limit is reached',
	waf_origin_quota(array('day' => '2026-09-18', 'queries' => 500), '2026-09-18', 500)['left'], 0);
expect_same('without a row nothing was asked yet', waf_origin_quota(null, '2026-09-18', 500),
	array('day' => '2026-09-18', 'queries' => 0, 'daily' => 500, 'left' => 500));

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_proxycheck: alle Prüfungen bestanden' . PHP_EOL;
