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
