<?php
/**
 * A raw line break inside a double-quoted string works only while the file keeps
 * LF line endings. Saved with CRLF, the string carries CR LF: a separator given
 * to explode() then no longer matches, and in 0.25.2 that would have brought
 * back a reload of nginx every minute. Line breaks in strings are written as
 * the escape sequence. Multi-line SQL is the one exception: its breaks are
 * layout, not data.
 */

$root = dirname(__DIR__);
$files = array_merge(
	glob($root . '/interface/*.php'), glob($root . '/interface/lib/*.php'),
	glob($root . '/server/lib/classes/*.php'), glob($root . '/tests/*.php'));
if (is_file(dirname($root) . '/waf/waf-switch')) {
	$files[] = dirname($root) . '/waf/waf-switch';
}

$failures = 0;
foreach ($files as $file) {
	foreach (token_get_all((string) file_get_contents($file)) as $tok) {
		if (!is_array($tok)) {
			continue;
		}
		list($id, $text, $line) = $tok;
		$quoted = ($id === T_CONSTANT_ENCAPSED_STRING && $text[0] === '"') || $id === T_ENCAPSED_AND_WHITESPACE;
		if (!$quoted || strpos($text, chr(10)) === false || preg_match('/^"?\s*(SELECT|INSERT|UPDATE|DELETE)\b/i', $text)) {
			continue;
		}
		fwrite(STDERR, 'FAIL ' . substr($file, strlen(dirname($root)) + 1) . ':' . $line
			. ' hat einen echten Zeilenumbruch in einer Zeichenkette; bitte als Escape-Folge schreiben.' . PHP_EOL);
		$failures++;
	}
}

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'string_breaks: alle Prüfungen bestanden' . PHP_EOL;
