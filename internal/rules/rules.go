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
	// Description is a short German explanation for the report.
	Description string
	// Match is the pattern. Rules are written to work on the raw bytes.
	Match *regexp.Regexp
	// Exts limits the rule to these extensions. Empty means every candidate.
	Exts []string
	// Requires, when set, must also be present in the file. It keeps rules
	// that are only suspicious in combination from firing on their own.
	Requires *regexp.Regexp
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
}

// AppliesTo reports whether the rule wants to look at this file. path is the
// location below the scanned root.
func (r *Rule) AppliesTo(path, ext string) bool {
	if len(r.Exts) > 0 {
		found := false
		for _, e := range r.Exts {
			if e == ext {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.PathMatch != nil && !r.PathMatch.MatchString(path) {
		return false
	}
	return true
}

// Extension groups used by several rules.
var (
	phpExts   = []string{"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phps", "inc", "module", "tpl"}
	webExts   = []string{"php", "php3", "php4", "php5", "php7", "php8", "phtml", "inc", "js", "html", "htm", "tpl"}
	imageExts = []string{"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg"}
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
