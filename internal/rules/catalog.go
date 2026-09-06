package rules

import (
	"regexp"

	"github.com/brightcolor/malwatch/internal/report"
)

// rx compiles a pattern at start-up. A broken rule is a programming error,
// so it fails loudly instead of silently never matching.
func rx(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

// catalog is the heuristic rule set.
//
// Two principles keep the false positive rate down:
//   - A capability alone is never a finding. base64_decode, exec and eval all
//     appear in honest code; only their combination with request data or with
//     each other is reported.
//   - Rules that cannot avoid firing on legitimate code get a lower severity,
//     so an operator can raise the threshold instead of turning them off.
var catalog = []*Rule{
	// ---------------------------------------------------------------- eval
	{
		ID:          "php.eval.encoded",
		Severity:    report.SeverityCritical,
		Description: "eval auf entschlüsseltem Inhalt",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|rawurldecode|urldecode|strrev|pack)\s*\(`),
	},
	{
		ID:          "php.eval.request",
		Severity:    report.SeverityCritical,
		Description: "eval auf Daten aus der Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER|_FILES|GLOBALS)\b`),
	},
	{
		ID:          "php.eval.hexname",
		Severity:    report.SeverityCritical,
		Description: "Funktionsname in Hex-Schreibweise verschleiert",
		Exts:        phpExts,
		// \x65\x76\x61\x6c spells "eval"; the same trick hides system and assert.
		Match: rx(`(?i)\\x6[15]\\x7[03]\\x7[03]\\x6[05]|\\x65\\x76\\x61\\x6c|\\x73\\x79\\x73\\x74\\x65\\x6d`),
	},
	{
		ID:          "php.preg_replace.eval",
		Severity:    report.SeverityCritical,
		Description: "preg_replace mit dem Modifikator e führt Code aus",
		Exts:        phpExts,
		Match:       rx(`(?is)preg_replace\s*\(\s*(?:'[^'\n]{0,200}[/#~|!%][imsxuADSUXJ]*e[imsxuADSUXJ]*'|"[^"\n]{0,200}[/#~|!%][imsxuADSUXJ]*e[imsxuADSUXJ]*")`),
	},
	{
		ID:          "php.callback.request",
		Severity:    report.SeverityCritical,
		Description: "Rückruffunktion direkt aus der Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\bcall_user_func(?:_array)?\s*\(\s*(?:@\s*)?\$(?:_GET|_POST|_REQUEST|_COOKIE)\b`),
	},
	{
		ID:          "php.dynamic.request_call",
		Severity:    report.SeverityCritical,
		Description: "Funktionsname kommt aus der Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[\s*(?:'[^'\n]{0,60}'|"[^"\n]{0,60}"|\$[a-zA-Z_]\w{0,40})\s*\]\s*\(`),
	},
	{
		ID:          "php.eval.variable",
		Severity:    report.SeverityMedium,
		Description: "eval auf einer Variablen",
		Exts:        phpExts,
		Match:       rx(`(?is)\beval\s*\(\s*(?:@\s*)?\$[a-zA-Z_]\w{0,40}\s*[;)]`),
	},
	{
		ID:          "php.eval.variable_call",
		Severity:    report.SeverityCritical,
		Description: "eval auf dem Ergebnis eines Variablenaufrufs",
		// Every dropped payload on the first real infection looked like
		// eval($a($b('...'))): the function names sit in variables, so no rule
		// that spells out base64_decode ever gets to see them. Honest code has
		// no reason to call a variable from inside eval.
		Exts:  phpExts,
		Match: rx(`(?is)\beval\s*\(\s*(?:@\s*)?\$[a-zA-Z_]\w{0,40}\s*\(`),
	},
	{
		ID:          "php.silence.preamble",
		Severity:    report.SeverityHigh,
		Description: "Fehlerausgabe und Fehlerprotokoll zusammen abgeschaltet",
		// Silencing the output happens in honest code often enough. Silencing
		// the error log as well means nobody is supposed to see what this file
		// does - and it stood at the top of every payload of that infection.
		Exts:     phpExts,
		Match:    rx(`(?i)error_reporting\s*\(\s*0\s*\)`),
		Requires: rx(`(?i)ini_set\s*\(\s*['"](?:log_errors|error_log)`),
	},

	// -------------------------------------------------------- obfuscation
	{
		ID:          "php.obfuscation.base64_blob",
		Severity:    report.SeverityHigh,
		Description: "langer kodierter Block, der anschließend dekodiert wird",
		// PHP only. In JavaScript a long base64 blob next to atob() is
		// everyday work - fonts, images and WebAssembly all look like this,
		// and WordPress ships several of them.
		Exts:     phpExts,
		RawOnly:  true,
		Match:    rx(`[A-Za-z0-9+/]{260,}={0,2}`),
		Requires: rx(`(?i)base64_decode|gzinflate|gzuncompress|str_rot13`),
	},
	{
		ID:          "php.obfuscation.name_in_variable",
		Severity:    report.SeverityHigh,
		Description: "gewöhnliche Funktionsnamen in Variablen geparkt",
		Exts:        phpExts,
		// The family that spells its names with chr() calls them through
		// variables afterwards:
		//
		//	$d = 'strlen'; if ($d($k) == 16) { ... }
		//
		// so that no rule naming a function ever sees one. The second view
		// spells the names out again; this rule is what makes that pay.
		//
		// The list holds everyday functions on purpose. A decoder in a
		// variable is honest work - guzzle writes $decoder = 'rawurldecode'
		// and ships inside WordPress plugins by the thousand.
		//
		// The variable has to carry a capital letter, and that is the whole
		// rule. Honest code that puts a function name in a variable names the
		// variable after it, in lower case:
		//
		//	if (function_exists('mb_stripos')) { $strlen = 'mb_strlen'; }
		//	else                               { $strlen = 'strlen'; }
		//
		// That is jetpack, on millions of sites, and the first version of this
		// rule reported it. The obfuscator has no such reason and takes what
		// its generator produced: $DfgSFXZ, $IoaaIh, $MyEtfywT.
		//
		// Measured over the same sets: written loosely the shape appears in 5
		// files of a 193.888 file installation, all of them honest; asking for
		// the capital letter leaves none of them and none in a fresh WordPress
		// or Joomla either.
		//
		// Two of them, because a single $myCallback = 'trim' next to an
		// array_map is a style, not a disguise.
		Match: rx(`(?s)\$[a-zA-Z_]*[A-Z]\w*\s*=\s*["']?(?:strlen|str_split|array_keys|array_values|str_replace|in_array|is_array|implode|explode|substr|strpos|strtolower|strrev|ord|chr|trim|count|sprintf)["']?\s*;.{0,400}?\$[a-zA-Z_]*[A-Z]\w*\s*=\s*["']?(?:strlen|str_split|array_keys|array_values|str_replace|in_array|is_array|implode|explode|substr|strpos|strtolower|strrev|ord|chr|trim|count|sprintf)["']?\s*;`),
	},
	{
		ID:          "php.obfuscation.chr_arithmetic",
		Severity:    report.SeverityHigh,
		Description: "Zeichencodes als Rechnung geschrieben",
		Exts:        phpExts,
		// chr(187-73) is the letter r. There is one reason to write it that
		// way and it is to keep the letter out of the file, so that the name
		// the letters spell cannot be searched for.
		//
		// The second view folds these calls, which lets every rule that names
		// a function read the word again. This one is the net underneath: a
		// chain that spells nothing the catalog knows still says plainly what
		// it is.
		//
		// RawOnly, because the second view resolves exactly this away - asked
		// there, the rule could never match.
		//
		// Two of them, close together. A name spelled this way needs one call
		// per letter, so they arrive in a run. Measured: a fresh WordPress and
		// Joomla hold 7.605 PHP files, 110 of which call chr, and none writes
		// the argument as a sum. Across 194.000 files of customer code exactly
		// one did - a single odd constant in a plugin - and never twice.
		RawOnly: true,
		Match:   rx(`(?is)chr\s*\(\s*\d+\s*[-+*]\s*\d+\s*\).{0,200}?chr\s*\(\s*\d+\s*[-+*]\s*\d+\s*\)`),
	},
	{
		ID:          "php.obfuscation.base64_marker",
		Severity:    report.SeverityHigh,
		Description: "kodierter Aufruf einer Ausführungsfunktion",
		Exts:        webExts,
		// base64 encodes three bytes at a time, so the same word yields three
		// different strings depending on where in the blob it starts. Matching
		// only the pad-0 form would miss two thirds of real payloads, so every
		// alignment is listed. Only the part unaffected by the surrounding
		// bytes is used - the first and last quartet of a run depend on their
		// neighbours and would not match inside a longer blob.
		//
		// Every marker is at least eight characters. A seven character marker
		// hit by chance inside a minified WordPress bundle, which is how the
		// short forms of "eval(" and "system(" were dropped: the payload
		// phrases below cover the same calls without the noise.
		Match: rx(`(?:ZXZhbChiYXNlNjRfZGVj|YWwoYmFzZTY0X2RlY29k|dmFsKGJhc2U2NF9kZWNv` + // eval(base64_decode
			`|ZXZhbCgkX1BP|YWwoJF9Q|dmFsKCRfUE9T` + // eval($_POST
			`|ZXZhbCgkX1JFUVVF|YWwoJF9SRVFV|dmFsKCRfUkVRVUVT` + // eval($_REQUEST
			`|c3lzdGVtKCRf|c3RlbSgkX0dF|eXN0ZW0oJF9H` + // system($_GET
			`|c2hlbGxfZXhlYygk|ZWxsX2V4ZWMo|aGVsbF9leGVj` + // shell_exec($_
			`|cGFzc3Ro|c3N0aHJ1|YXNzdGhy` + // passthru(
			`|YmFzZTY0X2RlY29k|c2U2NF9kZWNv|YXNlNjRfZGVj)`), // base64_decode
	},
	{
		ID:          "php.obfuscation.goto_spaghetti",
		Severity:    report.SeverityHigh,
		Description: "Ablauf in Sprungmarken zerlegt",
		// goto exists in PHP and is rare, but it is not unused: the WordPress
		// HTML parser jumps out of nested loops with it, and so do the AWS SDK
		// and Guzzle. Counting jumps therefore reports all three.
		//
		// What separates them is the layout. An obfuscator packs the jump and
		// the label it lands on into one line - goto IC_4Q; gkxBA: @ini_set(...)
		// - because the file is machine written and meant to be unreadable.
		// Honest code puts a label on a line of its own.
		// One line is the whole tell, and one pattern is cheap enough for a run
		// over two hundred thousand files. Asking only for a label after any
		// semicolon was not: a doc comment reading "; keys: ..." satisfied it.
		Exts:  phpExts,
		Match: rx(`(?i)\bgoto\s+[A-Za-z_]\w{0,40}\s*;[ \t]*[A-Za-z_]\w{0,40}:[ \t]*\S`),
	},
	{
		ID:          "php.obfuscation.split_open_tag",
		Severity:    report.SeverityCritical,
		Description: "PHP-Eröffnungstag aus Bruchstücken zusammengesetzt",
		// '<' . '?' . 'php' is written by somebody who does not want the tag to
		// be found in their own file. On its own that says nothing: TCPDF
		// generates PHP font files and avoids the tag in its source for the
		// same mechanical reason, and it ships inside countless plugins.
		//
		// The loader fetches over the network and then searches what came back
		// for the tag, to see whether it is code. The generator writes the tag
		// and searches for nothing. All three conditions together are the
		// difference.
		Exts:         phpExts,
		Match:        rx(`(?is)['"]<[?]?['"]\s*\.\s*['"](?:[?]\s*['"]\s*\.\s*['"])?php['"]`),
		Requires:     rx(`(?i)\b(?:curl_exec|fsockopen)\s*\(`),
		AlsoRequires: rx(`(?i)\b(?:strpos|stripos|str_contains)\s*\(`),
	},
	{
		ID:          "php.obfuscation.chr_chain",
		Severity:    report.SeverityHigh,
		Description: "Zeichenkette aus aneinandergehängten chr()-Aufrufen",
		Exts:        webExts,
		// Only codes 32 to 126 count, so the chain spells readable text -
		// which is what hiding a function name looks like. Character tables
		// in honest libraries work with the high bytes above 127.
		Match: rx(`(?:chr\s*\(\s*(?:3[2-9]|[4-9][0-9]|1[01][0-9]|12[0-6])\s*\)\s*\.\s*){6,}`),
	},
	{
		ID:          "php.obfuscation.hex_call",
		Severity:    report.SeverityHigh,
		Description: "Funktionsname in Hex-Schreibweise wird aufgerufen",
		Exts:        phpExts,
		// A plain hex string says nothing: crypto constants and character
		// tables are written that way in WordPress and Joomla alike. Only a
		// hex string that is immediately called is a hidden function name.
		Match: rx(`(?:\\x[0-9a-fA-F]{2}){4,}["']\s*\(`),
	},
	{
		ID:          "php.obfuscation.variable_function",
		Severity:    report.SeverityHigh,
		Description: "Funktionsaufruf über eine zusammengesetzte Variable",
		Exts:        phpExts,
		Match:       rx(`(?is)\$\{\s*(?:'|")(?:\\x[0-9a-fA-F]{2}|[A-Za-z0-9_]){1,60}(?:'|")\s*\}\s*\[`),
	},
	{
		ID:          "php.stream.archive_url",
		Severity:    report.SeverityCritical,
		Description: "Adresse, die in ein Archiv hineinzeigt",
		// zip://payload.zip#inner.tmp names a file inside an archive. That is
		// what a loader reads its body from, whether it includes the address
		// or hands it to file_get_contents - the second form is why naming
		// only require and include was not enough. A path built from variables
		// is left alone: Roundcube reads an uploaded archive that way.
		Exts:  phpExts,
		Match: rx(`(?is)['"](?:zip|compress\.[a-z0-9]+)://[^"'$\s]{1,200}#[^"'$\s]{1,120}`),
	},
	{
		ID:          "php.globals.extract_request",
		Severity:    report.SeverityHigh,
		Description: "extract() auf Anfragedaten überschreibt beliebige Variablen",
		Exts:        phpExts,
		Match:       rx(`(?is)\bextract\s*\(\s*(?:@\s*)?\$(?:_GET|_POST|_REQUEST|_COOKIE|GLOBALS)\b`),
	},

	// ---------------------------------------------------------- execution
	{
		ID:          "php.exec.request",
		Severity:    report.SeverityCritical,
		Description: "Systembefehl mit Anteilen aus der Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*[^;)]{0,160}\$(?:_GET|_POST|_REQUEST|_COOKIE)\b`),
	},
	{
		ID:          "php.backtick.request",
		Severity:    report.SeverityCritical,
		Description: "Shell-Aufruf in Backticks mit Anfragedaten",
		Exts:        phpExts,
		// The content must begin with something that looks like a command
		// followed by whitespace. Without that the rule fires on every
		// docblock that puts a superglobal in backticks for formatting - on
		// a clean WordPress that alone was seventeen false alarms.
		Match: rx("(?m)`[/a-zA-Z][\\w./-]{1,40}[ \\t][^`\\n]{0,160}\\$(?:_GET|_POST|_REQUEST|_COOKIE)[^`\\n]{0,160}`"),
	},
	{
		ID:          "php.dropper.write_code",
		Severity:    report.SeverityHigh,
		Description: "schreibt dekodierten oder übermittelten Inhalt in eine Datei",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:file_put_contents|fwrite|fputs)\s*\(\s*[^;)]{0,160}(?:base64_decode|gzinflate|\$(?:_GET|_POST|_REQUEST|_COOKIE))`),
	},
	{
		ID:          "php.include.assembled_path",
		Severity:    report.SeverityCritical,
		Description: "Pfad einer Einbindung aus Array-Zugriffen zusammengesetzt",
		// require_once $T[9+1].$T[43+2].$T[7] spells a filename one character at
		// a time out of an array the file built itself, so the name appears
		// nowhere. At least one subscript has to be arithmetic: joining two
		// plain subscripts - $paths['base'] . $paths['file'] - is how array
		// driven loaders and older procedural code build a path every day.
		Exts:  phpExts,
		Match: rx(`(?is)\b(?:require|include)(?:_once)?\s*\$[A-Za-z_]\w{0,40}\s*\[[ \t]*[0-9][0-9+\-*/ \t]{0,22}\]\s*\.\s*\$[A-Za-z_]\w{0,40}\s*\[`),
	},
	{
		ID:          "php.include.stream_wrapper",
		Severity:    report.SeverityCritical,
		Description: "Code wird aus einem Archiv oder Datenstrom nachgeladen",
		// require "zip://payload.zip#file" is how a loader keeps its body out
		// of the file that gets scanned. Honest code includes files, not
		// archives and not request bodies. phar:// is deliberately absent: a
		// phar stub does exactly this, and guzzle ships one.
		Exts:  phpExts,
		Match: rx(`(?is)\b(?:require|include)(?:_once)?\s*(?:\(\s*)?["']\s*(?:(?:zip|data|compress\.[a-z0-9]+)://|php://(?:input|filter))`),
	},
	{
		ID:          "php.tool.leaf_mailer",
		Severity:    report.SeverityCritical,
		Description: "Leaf PHP Mailer, ein Werkzeug für den Massenversand",
		// A named tool rather than a shape. It comes in variants that share no
		// obfuscation and no gate, so nothing structural covers them all - but
		// every one of them carries its own name. Matching $leaf['version']
		// as well looked structural but was not: $leaf is an ordinary name in
		// tree, menu and taxonomy code.
		Exts:  phpExts,
		Match: rx(`(?is)leafmailer|orvx\.pw`),
	},
	{
		ID:          "php.include.remote",
		Severity:    report.SeverityHigh,
		Description: "bindet eine Datei von einer fremden Adresse ein",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:include|require)(?:_once)?\s*\(?\s*(?:'https?://|"https?://)`),
	},
	{
		ID:          "php.remote.fetch_eval",
		Severity:    report.SeverityHigh,
		Description: "führt aus, was von einer fremden Adresse geladen wurde",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:file_get_contents|curl_exec|fopen)\s*\(`),
	},

	// ----------------------------------------------------- webshell marks
	{
		ID:          "php.webshell.known",
		Severity:    report.SeverityCritical,
		Description: "Kennzeichen einer bekannten Webshell",
		Exts:        webExts,
		Match:       rx(`(?i)(?:c99shell|r57shell|wso\s?shell|b374k|weevely|IndoXploit|AnonymousFox|SyRiAn\s?Sh3ll|MiniShell|Mini\s?Shell|priv8\s?shell|FilesMan|by\s+Orb|IndoSec|Alfa\s?Team\s?Shell|Sh3ll\s?Uploader)`),
	},
	{
		ID:          "php.webshell.password_gate",
		Severity:    report.SeverityCritical,
		Description: "Kennwortabfrage, die anschließend Code ausführt",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:md5|sha1|crypt|password_verify)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]{0,40}\]\s*\)\s*(?:==|===|!=|!==)`),
		Requires:    rx(`(?is)\b(?:eval|assert|system|shell_exec|passthru|proc_open)\s*\(`),
	},
	{
		ID:          "php.webshell.hardcoded_gate",
		Severity:    report.SeverityCritical,
		Description: "Kennwortabfrage gegen einen fest eingetragenen Hash",
		// The same gate as above, but the hash it compares against stands in
		// the file itself. That is the difference between a tool that carries
		// its own key and a plugin that looks one up: NinjaFirewall compares a
		// request hash too, and holds not one hardcoded hash anywhere.
		//
		// It exists as its own rule because two conditions cannot be written
		// A hardcoded hash on its own is not enough either: a small admin gate
		// compares one and does nothing else. The file also has to be able to
		// use the access it grants.
		// that firewall as a webshell.
		Exts:     phpExts,
		Match:    rx(`(?is)\b(?:md5|sha1|crypt)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]{0,40}\]\s*\)\s*(?:==|===|!=|!==)`),
		Requires: rx(`(?i)=\s*['"][0-9a-f]{32,40}['"]`),
		AlsoRequires: rx(`(?is)\b(?:eval|assert|system|shell_exec|passthru|proc_open|popen|` +
			`file_put_contents|move_uploaded_file|curl_exec|fsockopen|fwrite)\s*\(`),
	},
	{
		ID:          "php.webshell.file_manager",
		Severity:    report.SeverityHigh,
		Description: "Dateiverwaltung über die Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\b(?:unlink|rename|copy|chmod|mkdir|rmdir)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[`),
		Requires:    rx(`(?is)\b(?:move_uploaded_file|opendir|scandir|readdir|fopen)\s*\(`),
	},
	{
		ID:          "php.upload.unchecked",
		Severity:    report.SeverityMedium,
		Description: "Datei-Upload ohne erkennbare Prüfung des Ziels",
		Exts:        phpExts,
		Match:       rx(`(?is)\bmove_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]{0,60}\]\s*\[\s*['"]tmp_name['"]\s*\]\s*,\s*[^;)]{0,80}\$(?:_GET|_POST|_REQUEST|_FILES)`),
	},
	{
		ID:          "php.upload.traversal",
		Severity:    report.SeverityCritical,
		Description: "Hochgeladene Datei wird in ein übergeordnetes Verzeichnis gelegt",
		// '../' . $_FILES[...]['name'] puts a file the client named wherever the
		// client wants it. The rule above wants the move and the request data in
		// one statement; this one fires when they sit two lines apart, which is
		// how the shortest upload shell on that site was written.
		Exts:     phpExts,
		Match:    rx(`(?is)['"][^'"\n]{0,40}\.\.\/[^'"\n]{0,40}['"]\s*\.\s*\$_FILES\b`),
		Requires: rx(`(?i)move_uploaded_file`),
	},
	{
		ID:          "php.mailer.request",
		Severity:    report.SeverityMedium,
		Description: "Massenversand mit Empfänger und Text aus der Anfrage",
		Exts:        phpExts,
		Match:       rx(`(?is)\bmail\s*\(\s*\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]{0,40}\]\s*,`),
	},

	// ---------------------------------------------------------- injection
	{
		ID:          "web.iframe.hidden",
		Severity:    report.SeverityHigh,
		Description: "unsichtbarer Rahmen auf eine fremde Seite",
		Exts:        webExts,
		// Two guards, both earned on clean CMS code. The word boundary keeps
		// "marginwidth=0" from reading as a zero-width frame, and the source
		// must be an absolute foreign address - an upload widget hiding its
		// own local frame is not an injection.
		Match:    rx(`(?is)<iframe[^>]{0,240}(?:\bwidth\s*=\s*["']?0["' >]|\bheight\s*=\s*["']?0["' >]|style\s*=\s*["'][^"']{0,120}(?:display\s*:\s*none|visibility\s*:\s*hidden))`),
		Requires: rx(`(?is)<iframe[^>]{0,240}src\s*=\s*["']?(?:https?:)?//`),
	},
	{
		ID:          "js.eval.encoded",
		Severity:    report.SeverityHigh,
		Description: "JavaScript führt entschlüsselten Text aus",
		Exts:        webExts,
		Match:       rx(`(?is)\beval\s*\(\s*(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(`),
	},
	{
		ID:          "js.fromcharcode_chain",
		Severity:    report.SeverityMedium,
		Description: "Zeichenkette aus Zahlencodes zusammengesetzt",
		Exts:        webExts,
		Match:       rx(`(?is)String\.fromCharCode\s*\(\s*[\d\s,]{60,}\)`),
	},
	{
		ID:          "js.miner",
		Severity:    report.SeverityHigh,
		Description: "Skript zum Schürfen von Kryptowährung",
		Exts:        webExts,
		Match:       rx(`(?i)(?:coinhive|coin-hive|cryptonight|crypto-loot|cryptoloot|deepminer|webminepool|jsecoin|minero\.cc|coinimp)`),
	},
	{
		ID:          "js.document_write_encoded",
		Severity:    report.SeverityMedium,
		Description: "schreibt entschlüsselten Text in die Seite",
		Exts:        webExts,
		Match:       rx(`(?is)document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(`),
	},

	// ------------------------------------------------------------ by place
	{
		ID:          "php.in_uploads",
		Severity:    report.SeverityHigh,
		Description: "PHP-Datei in einem Verzeichnis für hochgeladene Dateien",
		Exts:        phpExts,
		// Only directories that hold nothing but user uploads. The list once
		// included media, assets, files and cache; Joomla ships thousands of
		// legitimate PHP files below media alone, which drowned every real
		// finding. What stays is where a CMS never puts code of its own.
		// Plural and lower case only. Joomla keeps its own update code under
		// "src/View/Upload" and "tmpl/upload"; the singular form would flag
		// all of it.
		// A welded tag does not execute: this asks what the web server would
		// do with the file as it lies on disk, which is a question about the
		// raw bytes.
		RawOnly: true,
		// A file here needs no PHP in it to be a problem. One carried nothing
		// but an upload form in plain HTML, which is the visible half of a
		// shell and one appended line away from being the whole of it.
		PathMatch: rx(`/(?:uploads|attachments|avatars|thumbs|userfiles|user_uploads|file_uploads)/`),
		Match:     rx(`(?i)<\?(?:php|=|\s)|enctype\s*=\s*["']?multipart/form-data`),
	},
	{
		ID:          "php.disguised_as_image",
		Severity:    report.SeverityCritical,
		Description: "Ausführbare Endung hinter einem Bildnamen versteckt",
		// Group-36-1-300x49.php sat among the thumbnails of a media library and
		// wore their naming exactly. Nothing about the content had to give it
		// away - the name and the extension are the finding, because the
		// extension is what makes the web server run it.
		//
		// svg is deliberately absent from the list: Symfony's error handler
		// ships symfony-ghost.svg.php, a template that draws one.
		RawOnly:   true,
		PathMatch: rx(`(?i)(?:-[0-9]{2,4}x[0-9]{2,4}|\.(?:jpe?g|png|gif|webp|bmp|ico))\.(?:php[0-9]?|phtml|phps)$`),
		Match:     rx(`(?s)^`),
	},
	{
		ID:          "php.in_image",
		Severity:    report.SeverityCritical,
		Description: "Bilddatei enthält PHP-Code",
		Exts:        imageExts,
		// A welded tag does not execute: this asks what the web server would
		// do with the file as it lies on disk, which is a question about the
		// raw bytes.
		RawOnly: true,
		Match:   rx(`(?i)<\?php`),
	},
	{
		ID:          "htaccess.php_handler",
		Severity:    report.SeverityHigh,
		Description: "macht eine fremde Endung zu ausführbarem PHP",
		PathMatch:   rx(`(?:^|/)\.htaccess$`),
		Match:       rx(`(?im)^\s*(?:AddType|AddHandler|SetHandler)\s+[^\n]{0,120}php`),
	},
	{
		ID:          "htaccess.auto_prepend",
		Severity:    report.SeverityHigh,
		Description: "bindet bei jedem Aufruf eine eigene Datei vorab ein",
		PathMatch:   rx(`(?:^|/)\.htaccess$`),
		Match:       rx(`(?i)auto_(?:prepend|append)_file`),
	},
	{
		ID:          "htaccess.redirect_foreign",
		Severity:    report.SeverityMedium,
		Description: "leitet Besucher auf eine fremde Adresse um",
		PathMatch:   rx(`(?:^|/)\.htaccess$`),
		Match:       rx(`(?im)^\s*RewriteRule\s+[^\n]{0,120}https?://[^\n]{0,120}\[[^\]\n]*R=?3?0?[12]?`),
	},
}
