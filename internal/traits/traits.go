// Package traits says what a file does, as far as its source text shows.
//
// A rule answers "why was this reported". The operator's next question is
// "what does this file actually do", and that decides whether it goes to the
// quarantine: a foreign file that checks the login and the user's rights
// before it unpacks an upload is an old tool, one that runs what arrives in
// the request is a shell. The traits list both sides, the dangerous
// capabilities and the protections, each with the lines they stand on.
//
// A trait alone is never a finding. They are computed only for files that
// already have one.
package traits

import (
	"regexp"
	"sort"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/textpos"
)

type detector struct {
	id    string
	label string
	kind  string
	match *regexp.Regexp
}

// notMember keeps method calls and variables out: $pdo->exec(, re.exec(,
// $system( and Foo::exec( are other functions than the PHP built-in.
const notMember = `(?:^|[^\w$>:.\\])`

// Shared with the rule catalog in spirit, written out here so the two can
// change independently: a rule has to be sure, a trait only has to be true.
const (
	crontabChange   = `\|[ \t]*crontab\b|\bcrontab[ \t]+-(?:r\b|[ \t'")]|$)`
	backgroundStart = `\b(?:nohup|setsid)\b|>[ \t]*/dev/null[ \t]+2>&1[ \t]*&(?:[^&]|$)`
)

// detectors in the order a reader should see them within one kind.
var detectors = []detector{
	// ------------------------------------------------------------- risk
	{"exec.shell", "führt Befehle auf dem Server aus (Shell)", report.TraitRisk,
		regexp.MustCompile(`(?i)` + notMember + `(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`)},
	{"eval.code", "führt Text als Programmcode aus (eval)", report.TraitRisk,
		regexp.MustCompile(`(?i)` + notMember + `(?:eval|assert|create_function)\s*\(`)},
	{"include.remote", "bindet Code von einer fremden Adresse ein", report.TraitRisk,
		regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*['"]https?://`)},
	{"exec.crontab", "ändert die Crontab (geplante Aufgaben)", report.TraitRisk,
		regexp.MustCompile(`(?m)` + crontabChange)},
	{"exec.background", "startet Prozesse im Hintergrund", report.TraitRisk,
		regexp.MustCompile(`(?m)` + backgroundStart)},

	// ---------------------------------------------------------- caution
	{"decode.hidden", "entschlüsselt oder entpackt Text (base64, gzinflate …)", report.TraitCaution,
		regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|atob)\s*\(`)},
	{"hide.encoded_names", "versteckt Text in Hex- oder Zeichencodes", report.TraitCaution,
		regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}|(?i:\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\()`)},
	{"net.fetch", "lädt Daten aus dem Netz", report.TraitCaution,
		regexp.MustCompile(`(?i)\b(?:curl_exec|fsockopen|stream_socket_client|wp_remote_(?:get|post|request))\s*\(|\bfile_get_contents\s*\(\s*['"]https?://`)},
	{"include.dynamic", "bindet Dateien über einen berechneten Pfad ein", report.TraitCaution,
		regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$`)},
	{"file.upload", "nimmt hochgeladene Dateien an", report.TraitCaution,
		regexp.MustCompile(`\$_FILES\b|\bmove_uploaded_file\s*\(|\bwp_handle_upload\s*\(`)},
	{"file.write", "schreibt, verschiebt oder löscht Dateien", report.TraitCaution,
		regexp.MustCompile(`(?i)` + notMember + `(?:file_put_contents|fwrite|fputs|unlink|rename|copy|rmdir|mkdir|chmod|touch)\s*\(`)},
	{"archive.extract", "entpackt Archive", report.TraitCaution,
		regexp.MustCompile(`(?i)\bZipArchive\b|->extractTo\s*\(|\bPclZip\b|\bunzip_file\s*\(`)},
	{"mail.send", "verschickt Mails", report.TraitCaution,
		regexp.MustCompile(`(?i)` + notMember + `(?:mail|wp_mail)\s*\(`)},
	{"hide.errors", "schaltet Fehlermeldungen oder das Fehlerprotokoll ab", report.TraitCaution,
		regexp.MustCompile(`(?i)\berror_reporting\s*\(\s*0\s*\)|\bini_set\s*\(\s*['"](?:display_errors|log_errors|error_log)['"]`)},
	{"run.unlimited", "läuft ohne Zeitlimit weiter, auch wenn der Besucher abbricht", report.TraitCaution,
		regexp.MustCompile(`(?i)\bset_time_limit\s*\(\s*0\s*\)|\bignore_user_abort\s*\(\s*(?:true|1)\s*\)`)},

	// ------------------------------------------------------------- info
	{"input.request", "liest Daten aus der Anfrage ($_GET, $_POST, $_COOKIE …)", report.TraitInfo,
		regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|php://input`)},

	// ------------------------------------------------------------ guard
	{"guard.wordpress", "läuft nur innerhalb von WordPress (ABSPATH)", report.TraitGuard,
		regexp.MustCompile(`(?i)defined\s*\(\s*['"]ABSPATH['"]\s*\)\s*(?:or|\|\|)\s*(?:die|exit)|if\s*\(\s*!\s*defined\s*\(\s*['"]ABSPATH['"]\s*\)\s*\)`)},
	{"guard.joomla", "läuft nur innerhalb von Joomla (_JEXEC)", report.TraitGuard,
		regexp.MustCompile(`(?i)defined\s*\(\s*['"]_JEXEC['"]\s*\)\s*(?:or|\|\|)\s*(?:die|exit)`)},
	{"guard.login", "verlangt eine Anmeldung", report.TraitGuard,
		regexp.MustCompile(`(?i)\bauth_redirect\s*\(|\bis_user_logged_in\s*\(|\b(?:require|include)(?:_once)?\s*\(?\s*['"](?:[^'"\n]*/)?admin\.php['"]`)},
	{"guard.capability", "prüft die Rechte des Benutzers", report.TraitGuard,
		regexp.MustCompile(`\b(?:current_user_can|user_can)\s*\(`)},
	{"guard.nonce", "arbeitet mit einem Formular-Token (Nonce)", report.TraitGuard,
		regexp.MustCompile(`\b(?:check_admin_referer|check_ajax_referer|wp_verify_nonce|wp_nonce_field)\s*\(`)},
}

var kindOrder = map[string]int{
	report.TraitRisk:    0,
	report.TraitCaution: 1,
	report.TraitInfo:    2,
	report.TraitGuard:   3,
}

// Detect lists the traits of content with at most maxMarks marks each, in the
// order risk, caution, info, guard. lines is the index of content.
func Detect(content []byte, lines *textpos.Lines, maxMarks int) []report.Trait {
	var out []report.Trait
	for _, d := range detectors {
		locs := d.match.FindAllIndex(content, maxMarks)
		if len(locs) == 0 {
			continue
		}
		t := report.Trait{ID: d.id, Label: d.label, Kind: d.kind}
		for _, loc := range locs {
			start := loc[0]
			// The boundary of notMember is part of the match; the mark starts
			// at the name itself.
			for start < loc[1] && !isNameByte(content[start]) {
				start++
			}
			t.Marks = append(t.Marks, lines.Marks(start, loc[1], 1)...)
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return kindOrder[out[i].Kind] < kindOrder[out[j].Kind] })
	return out
}

// isNameByte is a byte a mark may start with: a name, a sigil, a quote or
// the start of an escape.
func isNameByte(b byte) bool {
	return b == '$' || b == '\\' || b == '|' || b == '>' || b == '\'' || b == '"' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// IDs lists every trait this package knows, for documentation and tests.
func IDs() []string {
	ids := make([]string, 0, len(detectors))
	for _, d := range detectors {
		ids = append(ids, d.id)
	}
	return ids
}
