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
		Match: rx(`(?is)(?:zip|compress\.[a-z0-9]+)://[^"'$\s]{1,200}#[^"'$\s]{1,120}`),
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
		// every one of them carries its own name.
		Exts:  phpExts,
		Match: rx(`(?is)\$leaf\s*\[\s*['"](?:version|website)['"]\s*\]|leafmailer|orvx\.pw`),
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
		// into one pattern here, and widening the rule above instead reported
		// that firewall as a webshell.
		Exts:     phpExts,
		Match:    rx(`(?is)\b(?:md5|sha1|crypt)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]{0,40}\]\s*\)\s*(?:==|===|!=|!==)`),
		Requires: rx(`(?i)=\s*['"][0-9a-f]{32,40}['"]`),
	},
	{
		ID:          "php.webshell.session_filehash_gate",
		Severity:    report.SeverityCritical,
		Description: "Türsteher mit Sitzungsschlüssel aus dem Hash der eigenen Datei",
		// A file that keys a session on its own hash and holds a password is a
		// self-contained tool with a door in front of it: a mailer, a shell, a
		// file manager. Nothing that belongs to a website needs to know the
		// hash of its own path. This is the shape of Leafmailer, which carries
		// no obfuscation at all and therefore slipped past every rule above.
		Exts:     phpExts,
		Match:    rx(`(?i)md5\s*\(\s*__FILE__\s*\)`),
		Requires: rx(`(?is)\$_SESSION\s*\[`),
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
		PathMatch: rx(`/(?:uploads|attachments|avatars|thumbs|userfiles|user_uploads|file_uploads)/`),
		Match:     rx(`(?i)<\?(?:php|=|\s)`),
	},
	{
		ID:          "php.in_image",
		Severity:    report.SeverityCritical,
		Description: "Bilddatei enthält PHP-Code",
		Exts:        imageExts,
		Match:       rx(`(?i)<\?php`),
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
