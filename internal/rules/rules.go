// Package rules holds the heuristic detection rules. A rule looks at the
// content of one file and reports suspicious spots.
package rules

import (
	"regexp"

	"github.com/brightcolor/malwatch/internal/report"
)

// Rule is one heuristic. Match is run over the file content; every match
// produces one finding.
type Rule struct {
	// ID is the stable name of the rule, used in reports and in --ignore.
	ID string
	// Severity is how certain the rule is that this is malicious.
	Severity report.Severity
	// AutoSafe marks a rule whose match by itself is grounds to move the
	// file without a human looking at it first: the pattern only matches
	// code that cannot serve a legitimate purpose, such as a webshell
	// signature or code that runs decoded or remote data. A rule that keys
	// on where a file sits or how it is packaged - an upload directory, an
	// image extension, an .htaccess directive - is never AutoSafe, because
	// a legitimate file can still trigger it. AutoSafe never sits below
	// report.SeverityHigh; see catalog_test.go.
	AutoSafe bool
	// Description is a short German explanation for the report.
	Description string
	// Match is the pattern. Rules are written to work on the raw bytes.
	Match *regexp.Regexp
	// Exts limits the rule to these extensions. Empty means every candidate.
	//
	// A rule for PHP code also reads a file that opens like PHP under another
	// name, and a rule for images one that starts with image bytes; see Looks.
	Exts []string
	// ExtOnly keeps Exts to the name alone. A rule that asks what the web
	// server would run goes by the extension, because that is what the
	// server goes by: PHP code in a .txt file in an upload directory is
	// served as text.
	ExtOnly bool
	// Requires, when set, must also be present in the file. It keeps rules
	// that are only suspicious in combination from firing on their own.
	Requires *regexp.Regexp
	// AlsoRequires is a second supporting condition, and every one of them has
	// to hold. Some shapes need three facts about a file and two of them
	// cannot be written into one pattern: a gate that compares against a hash
	// in its own source is a webshell only if the file can also do something
	// with the access it grants, and a firewall plugin that checks a request
	// hash has the capability but not the hardcoded key.
	AlsoRequires *regexp.Regexp
	// RawOnly keeps a rule off the reassembled view of the file.
	//
	// That view exists to expose split function names. It also glues data
	// back together, and a rule that looks for a long block rather than a
	// name changes meaning when it does: phpseclib writes a Diffie-Hellman
	// prime as concatenated hex, a gallery plugin carries a base64 PNG, and
	// both became findings. Rules that match data look at the file as it is.
	RawOnly bool
	// PathMatch, when set, limits the rule to files whose location matches.
	// It is applied to the path below the scanned root, never to the
	// absolute path - see walk.File.Rel for why.
	PathMatch *regexp.Regexp
	// Where limits the rule to files below one of the upload directories
	// (InUploads) or to files outside of them (OutsideUploads). The engine
	// knows the directories, see Engine.SetUploadDirs.
	Where Place
	// HeadOnly marks a rule that decides from the first HeadSize bytes of a
	// file. The scanner asks such rules about files over its size limit as
	// well, with just their start, so a program padded past the limit still
	// shows up.
	HeadOnly bool
	// SkipInert lets a PHP file pass that can do nothing when it is requested
	// or included: only comments, an unconditional exit first, or nothing but
	// fixed data (phpcode.Inert). For rules that ask whether a file can be a
	// way in by where it lies, not what it contains.
	SkipInert bool
	// Harmless, when set, weighs every match on its own: a match it calls
	// harmless does not count, and the finding goes to the first one that is
	// not. A block that decodes to a picture is data; a picture next to a
	// block that decodes to code hides nothing.
	Harmless func(e *Engine, hay []byte, loc []int) bool
	// CodeOnly counts a match only where PHP can run it: in code or in a
	// quoted string or heredoc, which runs once the file hands it to eval or
	// writes it into a file. A match in a comment or in the text around the
	// PHP tags does not count. For rules whose pattern names a construct -
	// eval, include, preg_replace, a variable called - which in a comment is
	// a word. A file without any PHP tag is code throughout, as a payload
	// passed to eval is.
	CodeOnly bool
	// SupportInCode asks the same of Requires and AlsoRequires: a comment
	// that mentions curl_exec makes no downloader.
	SupportInCode bool
	// SameScope asks Requires and AlsoRequires to sit in the function body
	// of the match, or in the body of a function that body calls: two parts
	// of a library that share a file but not a purpose describe no action.
	SameScope bool
	// DeadFrom is the PHP version from which the construct no longer runs:
	// on a website with that PHP or newer the rule stays silent. The version
	// comes from the PHP of the site (SetPHPVersion); unknown keeps it on.
	DeadFrom string
	// GuardLowers takes a finding down to medium where WordPress only runs
	// the code for a user with the right capability and a valid nonce: an
	// admin action of a plugin, reachable only by someone who is an
	// administrator already. The finding stays, without a mail.
	GuardLowers bool
	// ByPlace marks a rule that judges a file by where it lies - in a place
	// for uploads, under the name of a picture, in the directory of a known
	// toolkit - rather than by what it contains. A file whose content is
	// confirmed as a vendor's keeps such a finding: a genuine file manager
	// copied into the uploads is still a way in.
	ByPlace bool
}

// Place is where below the scanned root a rule looks.
type Place int

const (
	// Anywhere is every location.
	Anywhere Place = iota
	// InUploads is below one of the upload directories.
	InUploads
	// OutsideUploads is every location that is not.
	OutsideUploads
)

// HeadSize is how much of a file over the size limit the scanner reads for
// the HeadOnly rules: the formats they look for say what they are in their
// first bytes.
const HeadSize = 64

// AppliesTo reports whether the rule wants to look at this file. path is the
// location below the scanned root, ext the extension of its name and looks
// what its first bytes show.
func (r *Rule) AppliesTo(path, ext string, looks Looks) bool {
	if len(r.Exts) > 0 && !contains(r.Exts, ext) && (r.ExtOnly || !r.readsContent(looks)) {
		return false
	}
	if r.PathMatch != nil && !r.PathMatch.MatchString(path) {
		return false
	}
	return true
}

// readsContent reports whether the rule reads a file of this kind whatever
// it is called: a rule for PHP reads PHP code, a rule for images reads images,
// a rule for shell scripts reads a file that opens with the line of a shell.
func (r *Rule) readsContent(looks Looks) bool {
	if looks.PHP && contains(r.Exts, "php") {
		return true
	}
	if looks.Shell && contains(r.Exts, "sh") {
		return true
	}
	if looks.Image {
		for _, e := range imageExts {
			if contains(r.Exts, e) {
				return true
			}
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// Extension groups used by several rules.
var (
	phpExts   = []string{"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phps", "inc", "module", "tpl"}
	webExts   = []string{"php", "php3", "php4", "php5", "php7", "php8", "phtml", "inc", "js", "html", "htm", "tpl"}
	imageExts = []string{"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg"}
	shellExts = []string{"sh", "bash"}
)

// All returns every rule in the catalog.
func All() []*Rule {
	out := make([]*Rule, 0, len(catalog))
	out = append(out, catalog...)
	return out
}

// ByID returns the rule with that ID, or nil.
func ByID(id string) *Rule {
	for _, r := range catalog {
		if r.ID == id {
			return r
		}
	}
	return nil
}
