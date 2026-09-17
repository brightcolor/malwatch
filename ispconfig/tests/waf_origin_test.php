<?php
/**
 * Checks the range files of the origin sources: writing, looking up and what
 * a broken file does.
 *
 *   php ispconfig/tests/waf_origin_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_origin.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$dir = sys_get_temp_dir() . '/waf_origin_test_' . getmypid();
@mkdir($dir, 0700, true);

// --- Addresses ----------------------------------------------------------------

expect_same('bytes of an IPv4 address', bin2hex(waf_origin_bytes('192.0.2.7')), '00000000000000000000ffffc0000207');
expect_same('bytes of an IPv6 address', bin2hex(waf_origin_bytes('2001:db8::7')), '20010db8000000000000000000000007');
expect_same('bytes of something else', waf_origin_bytes('192.0.2.300'), '');
expect_same('bytes of a name', waf_origin_bytes('example.test'), '');
expect_same('address as text again', waf_origin_text(waf_origin_bytes('192.0.2.7')), '192.0.2.7');
expect_same('IPv6 as text again', waf_origin_text(waf_origin_bytes('2001:db8::7')), '2001:db8::7');
expect_same('text of too few bytes', waf_origin_text('abc'), '');
expect_same('the next address', waf_origin_text(waf_origin_next(waf_origin_bytes('192.0.2.255'))), '192.0.3.0');
expect_same('the address before', waf_origin_text(waf_origin_previous(waf_origin_bytes('192.0.3.0'))), '192.0.2.255');
expect_same('after the last address', waf_origin_next(str_repeat("\xff", 16)), '');
expect_same('before the first address', waf_origin_previous(str_repeat("\0", 16)), '');

// --- Blocks -------------------------------------------------------------------

$block = waf_origin_cidr('192.0.2.0/24');
expect_same('block of IPv4', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('192.0.2.0', '192.0.2.255'));
$block = waf_origin_cidr('2001:db8::/32');
expect_same('block of IPv6', array(waf_origin_text($block[0]), waf_origin_text($block[1])),
	array('2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'));
$block = waf_origin_cidr('192.0.2.7/32');
expect_same('block of one address', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('192.0.2.7', '192.0.2.7'));
$block = waf_origin_cidr('198.51.100.9');
expect_same('block without a slash', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('198.51.100.9', '198.51.100.9'));
$block = waf_origin_cidr('10.0.0.0/8');
expect_same('block of a whole eight', array(waf_origin_text($block[0]), waf_origin_text($block[1])), array('10.0.0.0', '10.255.255.255'));
expect_same('block with too many bits', waf_origin_cidr('192.0.2.0/33'), null);
expect_same('block of something else', waf_origin_cidr('kein-block/24'), null);
expect_same('block without bits', waf_origin_cidr('192.0.2.0/'), null);

// --- Writing and looking up ---------------------------------------------------

$file = $dir . '/country.bin';
$writer = waf_origin_writer($file);
expect_same('writer opens', is_array($writer), true);
$rows = array(
	array('1.0.0.0', '1.255.255.255', 'AU'),
	array('192.0.2.0', '192.0.2.127', 'DE'),
	// Continues the range before with the same value: both become one range.
	array('192.0.2.128', '192.0.2.255', 'DE'),
	array('198.51.100.0', '198.51.100.255', 'FR'),
	array('2001:db8::', '2001:db8::ffff', 'DE'),
);
foreach ($rows as $row) {
	waf_origin_write($writer, waf_origin_bytes($row[0]), waf_origin_bytes($row[1]), $row[2]);
}
$written = waf_origin_finish($writer);
expect_same('written ranges and values', $written, array('ranges' => 4, 'values' => 3));

$reader = waf_origin_open($file);
expect_same('reader opens', is_array($reader), true);
expect_same('ranges of the file', waf_origin_ranges($reader), 4);
expect_same('address in the first range', waf_origin_find($reader, '1.2.3.4'), 'AU');
expect_same('first address of a range', waf_origin_find($reader, '192.0.2.0'), 'DE');
expect_same('address across the joined ranges', waf_origin_find($reader, '192.0.2.200'), 'DE');
expect_same('last address of a range', waf_origin_find($reader, '192.0.2.255'), 'DE');
expect_same('address after a range', waf_origin_find($reader, '192.0.3.0'), '');
expect_same('address before every range', waf_origin_find($reader, '0.0.0.1'), '');
expect_same('address after every range', waf_origin_find($reader, '2001:db9::1'), '');
expect_same('address in the middle range', waf_origin_find($reader, '198.51.100.9'), 'FR');
expect_same('IPv6 address in its range', waf_origin_find($reader, '2001:db8::7'), 'DE');
expect_same('something that is no address', waf_origin_find($reader, 'kein-ip'), '');
waf_origin_close($reader);
expect_same('reader closes', $reader, null);

// --- Order and overlap --------------------------------------------------------

$file2 = $dir . '/overlap.bin';
$writer = waf_origin_writer($file2);
waf_origin_write($writer, waf_origin_bytes('10.0.0.0'), waf_origin_bytes('10.0.0.255'), 'A');
// Starts inside the range before: only the free part counts.
expect_same('overlapping range is cut', waf_origin_write($writer, waf_origin_bytes('10.0.0.200'), waf_origin_bytes('10.0.1.255'), 'B'), true);
// Lies completely inside what was written: left out.
expect_same('range inside the one before', waf_origin_write($writer, waf_origin_bytes('10.0.0.10'), waf_origin_bytes('10.0.0.20'), 'C'), false);
// End before start: left out.
expect_same('range the wrong way round', waf_origin_write($writer, waf_origin_bytes('10.0.9.0'), waf_origin_bytes('10.0.2.0'), 'D'), false);
$written = waf_origin_finish($writer);
expect_same('ranges after the overlap', $written['ranges'], 2);
$reader = waf_origin_open($file2);
expect_same('value before the overlap', waf_origin_find($reader, '10.0.0.199'), 'A');
expect_same('value in the cut range', waf_origin_find($reader, '10.0.1.0'), 'B');
expect_same('value at the cut', waf_origin_find($reader, '10.0.1.255'), 'B');
waf_origin_close($reader);

// --- Empty and broken files ---------------------------------------------------

$empty = $dir . '/empty.bin';
$writer = waf_origin_writer($empty);
expect_same('empty file', waf_origin_finish($writer), array('ranges' => 0, 'values' => 0));
$reader = waf_origin_open($empty);
expect_same('lookup in an empty file', waf_origin_find($reader, '192.0.2.7'), '');
waf_origin_close($reader);

expect_same('file that is missing', waf_origin_open($dir . '/fehlt.bin'), null);
file_put_contents($dir . '/kaputt.bin', 'kein Bereich');
expect_same('file without the magic', waf_origin_open($dir . '/kaputt.bin'), null);
$cut = substr((string) file_get_contents($file), 0, WAF_ORIGIN_HEAD + WAF_ORIGIN_ROW);
file_put_contents($dir . '/kurz.bin', $cut);
expect_same('file that ends too early', waf_origin_open($dir . '/kurz.bin'), null);

// --- A larger file ------------------------------------------------------------

$many = $dir . '/many.bin';
$writer = waf_origin_writer($many);
for ($i = 0; $i < 2000; $i++) {
	$first = waf_origin_bytes('10.' . (int) ($i / 256) . '.' . ($i % 256) . '.0');
	waf_origin_write($writer, $first, waf_origin_next(waf_origin_next($first)), 'AS' . $i);
}
$written = waf_origin_finish($writer);
expect_same('ranges of the larger file', $written, array('ranges' => 2000, 'values' => 2000));
$reader = waf_origin_open($many);
expect_same('first range of the larger file', waf_origin_find($reader, '10.0.0.1'), 'AS0');
expect_same('range in the middle', waf_origin_find($reader, '10.3.232.2'), 'AS1000');
expect_same('last range', waf_origin_find($reader, '10.7.207.0'), 'AS1999');
expect_same('gap between two ranges', waf_origin_find($reader, '10.3.232.9'), '');
waf_origin_close($reader);

foreach (glob($dir . '/*.bin') as $name) {
	@unlink($name);
}
@rmdir($dir);

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_origin: alle Prüfungen bestanden\n";
