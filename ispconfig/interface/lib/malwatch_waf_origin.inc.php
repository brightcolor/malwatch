<?php

/**
 * Where an address comes from: the range files of the origin sources and the
 * lookup in them. The panel and the server class share these functions; they
 * run from PHP 7.0 without extra extensions.
 *
 * A range file holds sorted, non-overlapping ranges and a table of values:
 *
 *   header  16 bytes: "MWORIG1" and a zero byte, the number of ranges
 *           (uint32) and the offset of the value table (uint32)
 *   ranges  36 bytes each: first address (16), last address (16), the index
 *           of its value (uint32)
 *   values  the number of values (uint32), then each value as its length
 *           (uint16) and its bytes
 *
 * Addresses are the 16 bytes of inet_pton(); an IPv4 address sits in the
 * mapped range ::ffff:a.b.c.d, so one file holds both families. Everything is
 * big-endian, so comparing the bytes orders the addresses.
 */

/** The bytes of the file header, before the first range. */
define('WAF_ORIGIN_HEAD', 16);

/** The bytes of one range: two addresses and the index of its value. */
define('WAF_ORIGIN_ROW', 36);

/** The first bytes of every range file. */
define('WAF_ORIGIN_MAGIC', "MWORIG1\0");

/** The 16 bytes of an address, IPv4 mapped to ::ffff:a.b.c.d; '' when it is none. */
function waf_origin_bytes($ip)
{
	$packed = @inet_pton(trim((string) $ip));
	if ($packed === false) {
		return '';
	}
	if (strlen($packed) === 4) {
		return str_repeat("\0", 10) . "\xff\xff" . $packed;
	}
	return strlen($packed) === 16 ? $packed : '';
}

/** An address of waf_origin_bytes() as text again; '' when the bytes are none. */
function waf_origin_text($bytes)
{
	if (!is_string($bytes) || strlen($bytes) !== 16) {
		return '';
	}
	if (substr($bytes, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
		$bytes = substr($bytes, 12);
	}
	$text = @inet_ntop($bytes);
	return $text === false ? '' : $text;
}

/** The address one step after $bytes; '' after the last address there is. */
function waf_origin_next($bytes)
{
	for ($i = 15; $i >= 0; $i--) {
		$value = ord($bytes[$i]) + 1;
		$bytes[$i] = chr($value & 0xff);
		if ($value < 256) {
			return $bytes;
		}
	}
	return '';
}

/** The address one step before $bytes; '' before the first address there is. */
function waf_origin_previous($bytes)
{
	for ($i = 15; $i >= 0; $i--) {
		$value = ord($bytes[$i]) - 1;
		$bytes[$i] = chr($value & 0xff);
		if ($value >= 0) {
			return $bytes;
		}
	}
	return '';
}

/**
 * The first and last address of a CIDR block as array(first, last), both 16
 * bytes; null when the block is none. A plain address without a slash covers
 * itself.
 */
function waf_origin_cidr($cidr)
{
	$cidr = trim((string) $cidr);
	$slash = strpos($cidr, '/');
	$address = $slash === false ? $cidr : substr($cidr, 0, $slash);
	$first = waf_origin_bytes($address);
	if ($first === '') {
		return null;
	}
	$v4 = strpos($address, ':') === false;
	$bits = $slash === false ? ($v4 ? 32 : 128) : (int) substr($cidr, $slash + 1);
	if ($slash !== false && (!preg_match('/^\d{1,3}$/', substr($cidr, $slash + 1)) || $bits > ($v4 ? 32 : 128))) {
		return null;
	}
	$bits += $v4 ? 96 : 0;
	$last = $first;
	for ($i = 0; $i < 128; $i++) {
		if ($i < $bits) {
			continue;
		}
		$byte = (int) ($i / 8);
		$mask = 1 << (7 - ($i % 8));
		$first[$byte] = chr(ord($first[$byte]) & ~$mask);
		$last[$byte] = chr(ord($last[$byte]) | $mask);
	}
	return array($first, $last);
}

/**
 * Starts a range file. Ranges are written in order with waf_origin_write(),
 * waf_origin_finish() closes it. Returns the writer or null.
 */
function waf_origin_writer($file)
{
	$handle = @fopen($file, 'wb');
	if ($handle === false) {
		return null;
	}
	if (@fwrite($handle, str_repeat("\0", WAF_ORIGIN_HEAD)) !== WAF_ORIGIN_HEAD) {
		fclose($handle);
		return null;
	}
	return array('handle' => $handle, 'values' => array(), 'texts' => array(), 'ranges' => 0,
		'last_end' => '', 'last_value' => -1, 'failed' => false);
}

/**
 * Adds one range. Ranges come in ascending order; a range that overlaps the
 * one before is cut to the free part, and one that continues it with the same
 * value grows it. Returns false when the range is none or the file fails.
 */
function waf_origin_write(&$writer, $first, $last, $value)
{
	if (!is_array($writer) || $writer['failed'] || strlen($first) !== 16 || strlen($last) !== 16 || strcmp($first, $last) > 0) {
		return false;
	}
	if ($writer['last_end'] !== '') {
		if (strcmp($last, $writer['last_end']) <= 0) {
			return false;
		}
		if (strcmp($first, $writer['last_end']) <= 0) {
			$first = waf_origin_next($writer['last_end']);
			if ($first === '') {
				return false;
			}
		}
	}
	$value = (string) $value;
	if (!isset($writer['values'][$value])) {
		$writer['values'][$value] = count($writer['texts']);
		$writer['texts'][] = $value;
	}
	$index = $writer['values'][$value];
	// A range that continues the one before with the same value grows it.
	if ($writer['ranges'] > 0 && $index === $writer['last_value'] && waf_origin_next($writer['last_end']) === $first) {
		if (@fseek($writer['handle'], -(WAF_ORIGIN_ROW - 16), SEEK_END) !== 0
			|| @fwrite($writer['handle'], $last . pack('N', $index)) !== WAF_ORIGIN_ROW - 16) {
			$writer['failed'] = true;
			return false;
		}
		$writer['last_end'] = $last;
		return true;
	}
	if (@fwrite($writer['handle'], $first . $last . pack('N', $index)) !== WAF_ORIGIN_ROW) {
		$writer['failed'] = true;
		return false;
	}
	$writer['ranges']++;
	$writer['last_end'] = $last;
	$writer['last_value'] = $index;
	return true;
}

/**
 * Writes the value table and the header and closes the file. Returns
 * array('ranges' => n, 'values' => n) or null when something failed.
 */
function waf_origin_finish(&$writer)
{
	if (!is_array($writer)) {
		return null;
	}
	$handle = $writer['handle'];
	$ok = !$writer['failed'];
	$offset = WAF_ORIGIN_HEAD + $writer['ranges'] * WAF_ORIGIN_ROW;
	if ($ok) {
		$table = pack('N', count($writer['texts']));
		foreach ($writer['texts'] as $text) {
			$text = substr($text, 0, 65535);
			$table .= pack('n', strlen($text)) . $text;
		}
		$ok = @fseek($handle, $offset) === 0 && @fwrite($handle, $table) === strlen($table)
			&& @fseek($handle, 0) === 0
			&& @fwrite($handle, WAF_ORIGIN_MAGIC . pack('NN', $writer['ranges'], $offset)) === WAF_ORIGIN_HEAD;
	}
	@fclose($handle);
	$result = array('ranges' => $writer['ranges'], 'values' => count($writer['texts']));
	$writer = null;
	return $ok ? $result : null;
}

/**
 * Opens a range file for lookups. Returns the handle with its number of
 * ranges, or null when the file is missing or its header is broken.
 */
function waf_origin_open($file)
{
	if (!is_file($file) || filesize($file) < WAF_ORIGIN_HEAD) {
		return null;
	}
	$handle = @fopen($file, 'rb');
	if ($handle === false) {
		return null;
	}
	$head = (string) @fread($handle, WAF_ORIGIN_HEAD);
	$size = (int) filesize($file);
	if (strlen($head) !== WAF_ORIGIN_HEAD || substr($head, 0, 8) !== WAF_ORIGIN_MAGIC) {
		fclose($handle);
		return null;
	}
	$parts = unpack('Nranges/Noffset', substr($head, 8));
	$ranges = (int) $parts['ranges'];
	$offset = (int) $parts['offset'];
	if ($offset !== WAF_ORIGIN_HEAD + $ranges * WAF_ORIGIN_ROW || $offset + 4 > $size) {
		fclose($handle);
		return null;
	}
	$values = waf_origin_table($handle, $offset);
	if ($values === null) {
		fclose($handle);
		return null;
	}
	return array('handle' => $handle, 'ranges' => $ranges, 'offset' => $offset, 'values' => $values);
}

/** The value table at $offset as a list; null when it is broken. */
function waf_origin_table($handle, $offset)
{
	if (@fseek($handle, $offset) !== 0) {
		return null;
	}
	$count = (string) @fread($handle, 4);
	if (strlen($count) !== 4) {
		return null;
	}
	$count = unpack('N', $count);
	$count = (int) $count[1];
	$values = array();
	for ($i = 0; $i < $count; $i++) {
		$length = (string) @fread($handle, 2);
		if (strlen($length) !== 2) {
			return null;
		}
		$length = unpack('n', $length);
		$length = (int) $length[1];
		$text = $length === 0 ? '' : (string) @fread($handle, $length);
		if (strlen($text) !== $length) {
			return null;
		}
		$values[] = $text;
	}
	return $values;
}

/** How many ranges the open file holds. */
function waf_origin_ranges($reader)
{
	return is_array($reader) ? (int) $reader['ranges'] : 0;
}

/** Closes a reader of waf_origin_open(). */
function waf_origin_close(&$reader)
{
	if (is_array($reader) && isset($reader['handle'])) {
		@fclose($reader['handle']);
	}
	$reader = null;
}

/** The value of the range that holds $ip, '' when no range does. */
function waf_origin_find($reader, $ip)
{
	if (!is_array($reader) || $reader['ranges'] === 0) {
		return '';
	}
	$needle = waf_origin_bytes($ip);
	if ($needle === '') {
		return '';
	}
	$low = 0;
	$high = $reader['ranges'] - 1;
	while ($low <= $high) {
		$middle = (int) (($low + $high) / 2);
		if (@fseek($reader['handle'], WAF_ORIGIN_HEAD + $middle * WAF_ORIGIN_ROW) !== 0) {
			return '';
		}
		$row = (string) @fread($reader['handle'], WAF_ORIGIN_ROW);
		if (strlen($row) !== WAF_ORIGIN_ROW) {
			return '';
		}
		if (strcmp($needle, substr($row, 0, 16)) < 0) {
			$high = $middle - 1;
			continue;
		}
		if (strcmp($needle, substr($row, 16, 16)) > 0) {
			$low = $middle + 1;
			continue;
		}
		$index = unpack('N', substr($row, 32, 4));
		$index = (int) $index[1];
		return isset($reader['values'][$index]) ? $reader['values'][$index] : '';
	}
	return '';
}
// --- Sources ------------------------------------------------------------------

/**
 * The sources this server can load, keyed by their name in
 * malwatch_waf_origin_source. Each one names the setting that turns it on and
 * its value, how its file is read, the smallest plausible number of ranges and
 * the largest download in bytes.
 */
function waf_origin_sources()
{
	return array(
		'dbip_country' => array('setting' => 'waf_origin_geo', 'value' => 'dbip', 'kind' => 'country',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'dbip_asn' => array('setting' => 'waf_origin_geo', 'value' => 'dbip', 'kind' => 'asn',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'maxmind_country' => array('setting' => 'waf_origin_geo', 'value' => 'maxmind', 'kind' => 'country',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'maxmind_asn' => array('setting' => 'waf_origin_geo', 'value' => 'maxmind', 'kind' => 'asn',
			'min' => 100000, 'bytes' => 80 * 1024 * 1024, 'hours' => 'waf_origin_db_hours'),
		'tor' => array('setting' => 'waf_origin_tor', 'value' => 'torproject', 'kind' => 'list',
			'min' => 100, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_tor_hours'),
		'x4b_vpn' => array('setting' => 'waf_origin_net', 'value' => 'x4b', 'kind' => 'list',
			'min' => 1000, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_list_hours'),
		'x4b_datacenter' => array('setting' => 'waf_origin_net', 'value' => 'x4b', 'kind' => 'list',
			'min' => 1000, 'bytes' => 20 * 1024 * 1024, 'hours' => 'waf_origin_list_hours'),
	);
}

/** The sources the settings turn on, in the order of waf_origin_sources(). */
function waf_origin_chosen($settings)
{
	$chosen = array();
	foreach (waf_origin_sources() as $name => $source) {
		$setting = isset($settings[$source['setting']]) ? (string) $settings[$source['setting']] : 'off';
		if ($setting === $source['value']) {
			$chosen[] = $name;
		}
	}
	return $chosen;
}

/** The addresses the source is loaded from, one download per entry. */
function waf_origin_urls($name, $month)
{
	$month = preg_match('/^\d{4}-\d{2}$/', (string) $month) ? (string) $month : gmdate('Y-m');
	switch ($name) {
		case 'dbip_country':
			return array('https://download.db-ip.com/free/dbip-country-lite-' . $month . '.csv.gz');
		case 'dbip_asn':
			return array('https://download.db-ip.com/free/dbip-asn-lite-' . $month . '.csv.gz');
		case 'maxmind_country':
			return array('https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip');
		case 'maxmind_asn':
			return array('https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip');
		case 'tor':
			return array('https://check.torproject.org/torbulkexitlist');
		case 'x4b_vpn':
			return array('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
				'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt');
		case 'x4b_datacenter':
			return array('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt',
				'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt');
	}
	return array();
}

/** An empty result of a reader; the readers count their lines into it. */
function waf_origin_result()
{
	return array('ranges' => 0, 'values' => 0, 'lines' => 0, 'bad' => 0, 'skipped' => 0);
}

/**
 * Opens a text file for reading line by line. gzopen() also reads a file that
 * is not packed, so one function covers both. Returns the handle or null.
 */
function waf_origin_lines($file)
{
	$handle = @gzopen($file, 'rb');
	return $handle === false ? null : $handle;
}

/**
 * The CSV of DB-IP Lite: first address, last address, country. Writes the
 * range file and returns the counts, or null when a file fails.
 */
function waf_origin_read_dbip_country($in, $out)
{
	return waf_origin_read_pairs($in, $out, 3, function ($row) {
		$country = strtoupper(trim($row[2]));
		return preg_match('/^[A-Z]{2}$/', $country) ? array($row[0], $row[1], $country) : null;
	});
}

/**
 * The CSV of DB-IP Lite with the networks: first address, last address, AS
 * number, organisation.
 */
function waf_origin_read_dbip_asn($in, $out)
{
	return waf_origin_read_pairs($in, $out, 4, function ($row) {
		$number = trim($row[2]);
		return preg_match('/^\d{1,10}$/', $number) ? array($row[0], $row[1], waf_origin_as_value($number, $row[3])) : null;
	});
}

/**
 * A CSV whose lines carry the first and the last address. $in is one file or
 * a list of files, read one after the other into one range file. $fields is
 * how many columns a line needs, $pick turns a line into array(first, last,
 * value) or null. The files come sorted; a line out of order is left out.
 */
function waf_origin_read_pairs($in, $out, $fields, $pick)
{
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	$counts = waf_origin_result();
	foreach (is_array($in) ? $in : array($in) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			waf_origin_finish($writer);
			return null;
		}
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$counts['lines']++;
			$row = str_getcsv($line, ",", chr(34), chr(92));
			if (count($row) < $fields) {
				$counts['bad']++;
				continue;
			}
			$picked = call_user_func($pick, $row);
			$first = $picked === null ? '' : waf_origin_bytes($picked[0]);
			$last = $picked === null ? '' : waf_origin_bytes($picked[1]);
			if ($first === '' || $last === '') {
				$counts['bad']++;
				continue;
			}
			if (!waf_origin_write($writer, $first, $last, $picked[2])) {
				$counts['skipped']++;
			}
		}
		gzclose($handle);
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/**
 * The blocks CSV of GeoLite2 with the countries. $locations is the CSV that
 * holds a country for every geoname_id.
 */
function waf_origin_read_maxmind_country($in, $locations, $out)
{
	$countries = waf_origin_maxmind_countries($locations);
	if ($countries === null) {
		return null;
	}
	return waf_origin_read_networks($in, $out, function ($row) use ($countries) {
		$id = trim($row[1]) !== '' ? trim($row[1]) : trim($row[2]);
		return isset($countries[$id]) ? $countries[$id] : null;
	});
}

/** The blocks CSV of GeoLite2 with the networks. */
function waf_origin_read_maxmind_asn($in, $out)
{
	return waf_origin_read_networks($in, $out, function ($row) {
		$number = trim($row[1]);
		return preg_match('/^\d{1,10}$/', $number) ? waf_origin_as_value($number, isset($row[2]) ? $row[2] : '') : null;
	});
}

/** geoname_id to country code from the locations CSV of GeoLite2; null when the file fails. */
function waf_origin_maxmind_countries($file)
{
	$handle = waf_origin_lines($file);
	if ($handle === null) {
		return null;
	}
	$countries = array();
	$head = array();
	while (($line = gzgets($handle)) !== false) {
		$line = trim($line);
		if ($line === '') {
			continue;
		}
		$row = str_getcsv($line, ",", chr(34), chr(92));
		if (count($head) === 0) {
			$head = array_flip($row);
			continue;
		}
		if (!isset($head['geoname_id']) || !isset($head['country_iso_code']) || count($row) <= $head['country_iso_code']) {
			continue;
		}
		$code = strtoupper(trim($row[$head['country_iso_code']]));
		if (preg_match('/^[A-Z]{2}$/', $code)) {
			$countries[trim($row[$head['geoname_id']])] = $code;
		}
	}
	gzclose($handle);
	return $countries;
}

/**
 * A blocks CSV of GeoLite2: the first column is the network as CIDR, $pick
 * turns a line into its value or null. The first line of every file names the
 * columns. $in is one file or the list of files of one source; GeoLite2 ships
 * IPv4 and IPv6 apart, and in that order they stay sorted.
 */
function waf_origin_read_networks($in, $out, $pick)
{
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	$counts = waf_origin_result();
	foreach (is_array($in) ? $in : array($in) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			waf_origin_finish($writer);
			return null;
		}
		$first_line = true;
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '') {
				continue;
			}
			if ($first_line) {
				$first_line = false;
				if (strpos($line, 'network') === 0) {
					continue;
				}
			}
			$counts['lines']++;
			$row = str_getcsv($line, ",", chr(34), chr(92));
			$block = waf_origin_cidr(isset($row[0]) ? $row[0] : '');
			$value = count($row) < 2 ? null : call_user_func($pick, $row);
			if ($block === null || $value === null) {
				$counts['bad']++;
				continue;
			}
			if (!waf_origin_write($writer, $block[0], $block[1], $value)) {
				$counts['skipped']++;
			}
		}
		gzclose($handle);
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/**
 * A list with one address or block per line, as the Tor and X4BNet lists come.
 * The lines are unsorted, so they are sorted here before they are written; the
 * ranges carry no value. $files are read one after the other into one file.
 */
function waf_origin_read_list($files, $out)
{
	$counts = waf_origin_result();
	$rows = array();
	foreach (is_array($files) ? $files : array($files) as $file) {
		$handle = waf_origin_lines($file);
		if ($handle === null) {
			return null;
		}
		while (($line = gzgets($handle)) !== false) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$counts['lines']++;
			$block = waf_origin_cidr($line);
			if ($block === null) {
				$counts['bad']++;
				continue;
			}
			$rows[] = $block[0] . $block[1];
		}
		gzclose($handle);
	}
	sort($rows, SORT_STRING);
	$writer = waf_origin_writer($out);
	if ($writer === null) {
		return null;
	}
	foreach ($rows as $row) {
		// The value marks a hit; an address outside every range answers with ''.
		if (!waf_origin_write($writer, substr($row, 0, 16), substr($row, 16, 16), 'y')) {
			$counts['skipped']++;
		}
	}
	$written = waf_origin_finish($writer);
	if ($written === null) {
		return null;
	}
	$counts['ranges'] = $written['ranges'];
	$counts['values'] = $written['values'];
	return $counts;
}

/** The value of a network range: its number and its name, kept apart by a unit separator. */
function waf_origin_as_value($number, $name)
{
	$name = trim(preg_replace('/\s+/', ' ', (string) $name));
	return (string) (int) $number . "\x1f" . waf_origin_cut($name, 120);
}

/** A value of a range file as array('asn' => n, 'as_org' => text) or, for a country, array('country' => 'DE'). */
function waf_origin_parts($value)
{
	$value = (string) $value;
	if ($value === '') {
		return array();
	}
	$cut = strpos($value, "\x1f");
	if ($cut === false) {
		return preg_match('/^[A-Z]{2}$/', $value) ? array('country' => $value) : array();
	}
	return array('asn' => (int) substr($value, 0, $cut), 'as_org' => substr($value, $cut + 1));
}

/** Cuts a text to $bytes without breaking a character. */
function waf_origin_cut($text, $bytes)
{
	$text = (string) $text;
	if (strlen($text) <= $bytes) {
		return $text;
	}
	if (function_exists('mb_strcut')) {
		return mb_strcut($text, 0, $bytes, 'UTF-8');
	}
	return preg_replace('/[\x80-\xFF]+$/', '', substr($text, 0, $bytes));
}

/**
 * Whether a freshly built range file may replace the one in use. $previous is
 * how many ranges the file in use holds, 0 when there is none. Returns '' when
 * it may, else the reason with what happens next.
 */
function waf_origin_check($name, $counts, $previous)
{
	$sources = waf_origin_sources();
	if (!isset($sources[$name]) || !is_array($counts)) {
		return 'Die Quelle ' . $name . ' ist unbekannt. Bitte die Einstellungen der Abwehr prüfen.';
	}
	$keep = ' Der bisherige Stand bleibt aktiv, der nächste Abruf versucht es erneut.';
	if ($counts['lines'] > 0 && $counts['bad'] > $counts['lines'] / 100) {
		return 'Die Datei der Quelle ' . $name . ' ist unlesbar: ' . $counts['bad'] . ' von '
			. $counts['lines'] . ' Zeilen ergeben keinen Adressbereich.' . $keep;
	}
	$min = (int) $sources[$name]['min'];
	if ($counts['ranges'] < $min) {
		return 'Die Quelle ' . $name . ' liefert nur ' . $counts['ranges'] . ' Bereiche, erwartet sind mindestens '
			. $min . '.' . $keep;
	}
	$previous = (int) $previous;
	if ($previous > 0 && $counts['ranges'] < $previous / 2) {
		return 'Die Quelle ' . $name . ' liefert nur noch ' . $counts['ranges'] . ' Bereiche, vorher waren es '
			. $previous . '.' . $keep;
	}
	return '';
}

/**
 * Whether a source has to be looked at again. A source the settings leave off
 * is never due; one without a row or without a time always is. $row is its row
 * of malwatch_waf_origin_source, $now the time of the database.
 */
function waf_origin_due($name, $row, $settings, $now)
{
	$sources = waf_origin_sources();
	if (!isset($sources[$name]) || !in_array($name, waf_origin_chosen($settings), true)) {
		return false;
	}
	$checked = is_array($row) && isset($row['checked_at']) ? (string) $row['checked_at'] : '';
	if ($checked === '' || $checked === '0000-00-00 00:00:00') {
		return true;
	}
	$hours = isset($settings[$sources[$name]['hours']]) ? (int) $settings[$sources[$name]['hours']] : 24;
	$hours = $hours < 1 ? 1 : $hours;
	$then = strtotime($checked);
	$point = strtotime((string) $now);
	if ($then === false || $point === false) {
		return true;
	}
	return $point - $then >= $hours * 3600;
}

// --- Looking up an address ----------------------------------------------------

/**
 * Opens the range files of $names below $dir. A source without a file is left
 * out, so a lookup answers with what is there. waf_origin_readers_close()
 * closes them again.
 */
function waf_origin_readers($dir, $names)
{
	$readers = array();
	foreach ($names as $name) {
		$reader = waf_origin_open(rtrim((string) $dir, '/') . '/' . $name . '.bin');
		if ($reader !== null) {
			$readers[$name] = $reader;
		}
	}
	return $readers;
}

/** Closes the readers of waf_origin_readers(). */
function waf_origin_readers_close(&$readers)
{
	foreach ($readers as $name => $reader) {
		waf_origin_close($reader);
		unset($readers[$name]);
	}
	$readers = array();
}

/**
 * What the open range files say about one address: country, network and the
 * marks of the lists. A field no source answers stays empty, so the caller can
 * store the result as it is.
 */
function waf_origin_facts($readers, $ip)
{
	$facts = array('country' => '', 'asn' => 0, 'as_org' => '', 'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'n');
	foreach ($readers as $name => $reader) {
		$value = waf_origin_find($reader, $ip);
		if ($value === '') {
			continue;
		}
		if ($name === 'tor') {
			$facts['is_tor'] = 'y';
			continue;
		}
		if ($name === 'x4b_vpn') {
			$facts['is_vpn'] = 'y';
			continue;
		}
		if ($name === 'x4b_datacenter') {
			$facts['is_hosting'] = 'y';
			continue;
		}
		$parts = waf_origin_parts($value);
		if (isset($parts['country'])) {
			$facts['country'] = $parts['country'];
		}
		if (isset($parts['asn'])) {
			$facts['asn'] = $parts['asn'];
			$facts['as_org'] = $parts['as_org'];
		}
	}
	return $facts;
}

/**
 * Whether the row of an address has to be looked up again: it has none, or a
 * source was loaded after the last look. $newest is the newest fetched_at of
 * the chosen sources.
 */
function waf_origin_stale($row, $newest)
{
	$looked = is_array($row) && isset($row['local_at']) ? (string) $row['local_at'] : '';
	if ($looked === '' || $looked === '0000-00-00 00:00:00') {
		return true;
	}
	$newest = (string) $newest;
	if ($newest === '') {
		return false;
	}
	return strtotime($newest) > strtotime($looked);
}

// --- proxycheck.io ------------------------------------------------------------

/**
 * The external source the settings chose, '' when there is none. proxycheck.io
 * answers per address, so it is no entry of waf_origin_sources() and never
 * gets a range file.
 */
function waf_origin_external($settings)
{
	$net = isset($settings['waf_origin_net']) ? (string) $settings['waf_origin_net'] : 'off';
	return $net === 'proxycheck' ? 'proxycheck' : '';
}

/** 'y' when the answer marked the address, 'n' otherwise. */
function waf_origin_mark($value)
{
	if ($value === true || $value === 1 || $value === '1') {
		return 'y';
	}
	return is_string($value) && strtolower($value) === 'yes' ? 'y' : 'n';
}

/**
 * The body of one v3 request: the addresses as the field `ips`. Anything that
 * is no address is left out, and '' means there is nothing to ask.
 */
function waf_origin_proxycheck_body($ips)
{
	$clean = array();
	foreach ($ips as $ip) {
		$ip = trim((string) $ip);
		if ($ip !== '' && waf_origin_bytes($ip) !== '' && !in_array($ip, $clean, true)) {
			$clean[] = $ip;
		}
	}
	return count($clean) === 0 ? '' : 'ips=' . implode(',', $clean);
}

/** The facts of one address from its part of a v3 answer. */
function waf_origin_proxycheck_facts($entry)
{
	$detections = isset($entry['detections']) && is_array($entry['detections']) ? $entry['detections'] : array();
	$network = isset($entry['network']) && is_array($entry['network']) ? $entry['network'] : array();
	$location = isset($entry['location']) && is_array($entry['location']) ? $entry['location'] : array();
	$operator = isset($entry['operator']) && is_array($entry['operator']) ? $entry['operator'] : array();
	$provider = isset($network['provider']) ? trim((string) $network['provider']) : '';
	if ($provider === '' && isset($network['organisation'])) {
		$provider = trim((string) $network['organisation']);
	}
	$country = isset($location['country_code']) ? strtoupper(trim((string) $location['country_code'])) : '';
	return array(
		'country' => preg_match('/^[A-Z]{2}$/', $country) ? $country : '',
		'asn' => isset($network['asn']) ? (int) preg_replace('/[^0-9]/', '', (string) $network['asn']) : 0,
		'as_org' => waf_origin_cut($provider, 128),
		'is_tor' => waf_origin_mark(isset($detections['tor']) ? $detections['tor'] : false),
		'is_vpn' => waf_origin_mark(isset($detections['vpn']) ? $detections['vpn'] : false),
		'is_hosting' => waf_origin_mark(isset($detections['hosting']) ? $detections['hosting'] : false),
		'is_proxy' => waf_origin_mark(isset($detections['proxy']) ? $detections['proxy'] : false),
		'vpn_operator' => waf_origin_cut(isset($operator['name']) ? trim((string) $operator['name']) : '', 64),
	);
}

/**
 * Reads one v3 answer. Returns array('ok' => bool, 'error' => text,
 * 'ips' => array(address => facts)). The text names the cause and the next
 * step; it comes from the answer alone and never carries the key.
 */
function waf_origin_proxycheck_read($text)
{
	$data = json_decode((string) $text, true);
	if (!is_array($data)) {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io antwortete nicht in JSON. Der nächste Durchgang fragt erneut.');
	}
	$status = isset($data['status']) ? strtolower((string) $data['status']) : '';
	$message = isset($data['message'])
		? waf_origin_cut(preg_replace('/\s+/', ' ', trim((string) $data['message'])), 150) : '';
	if ($status === 'denied') {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io hat die Anfrage abgelehnt' . ($message === '' ? '.' : ': ' . $message)
				. ' Bitte den Schlüssel in den Einstellungen der Abwehr prüfen.');
	}
	if ($status === 'error') {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io meldet einen Fehler' . ($message === '' ? '.' : ': ' . $message)
				. ' Der nächste Durchgang fragt erneut.');
	}
	$ips = array();
	foreach ($data as $key => $entry) {
		if (is_array($entry) && waf_origin_bytes((string) $key) !== '') {
			$ips[(string) $key] = waf_origin_proxycheck_facts($entry);
		}
	}
	if (count($ips) === 0) {
		return array('ok' => false, 'ips' => array(),
			'error' => 'proxycheck.io nannte in seiner Antwort keine Adresse. Der nächste Durchgang fragt erneut.');
	}
	return array('ok' => true, 'error' => '', 'ips' => $ips);
}

/**
 * The day and the number of queries of the external source, reset when the day
 * turned. $row is the row of malwatch_waf_origin_source, $today a date as
 * Y-m-d and $daily the limit from the settings.
 */
function waf_origin_quota($row, $today, $daily)
{
	$today = (string) $today;
	$day = is_array($row) && isset($row['day']) ? substr((string) $row['day'], 0, 10) : '';
	$queries = is_array($row) && isset($row['queries']) ? (int) $row['queries'] : 0;
	if ($day !== $today) {
		$day = $today;
		$queries = 0;
	}
	$daily = max(1, (int) $daily);
	return array('day' => $day, 'queries' => $queries, 'daily' => $daily, 'left' => max(0, $daily - $queries));
}
