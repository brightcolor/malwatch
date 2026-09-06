package rules

import (
	"bytes"
	"strings"

	"github.com/brightcolor/malwatch/internal/report"
)

// Engine applies the rule catalog to file contents.
type Engine struct {
	rules   []*Rule
	ignored map[string]bool
}

// NewEngine returns an engine over the full catalog, minus the rule IDs in
// ignore (case insensitive, as on the command line).
func NewEngine(ignore []string) *Engine {
	ig := make(map[string]bool, len(ignore))
	for _, id := range ignore {
		ig[strings.ToLower(strings.TrimSpace(id))] = true
	}
	e := &Engine{ignored: ig}
	for _, r := range catalog {
		if ig[strings.ToLower(r.ID)] {
			continue
		}
		e.rules = append(e.rules, r)
	}
	return e
}

// RuleCount returns how many rules are active.
func (e *Engine) RuleCount() int { return len(e.rules) }

// maxExcerpt caps how much of a match ends up in the report. A webshell can
// be one very long line; the report must stay readable and the row must fit
// into the database column the addon writes it to.
const maxExcerpt = 160

// Scan applies every applicable rule to content and returns the findings.
// At most one finding per rule and file: a shell that matches the same rule
// forty times is still one problem, and forty rows would bury the rest.
//
// path is what goes into the report; rel is the location below the scanned
// root and is what location rules are matched against.
func (e *Engine) Scan(path, rel, ext string, content []byte) []report.Finding {
	if rel == "" {
		rel = path
	}
	// The second view has string literals glued together, escapes resolved and
	// comments collapsed, so a payload that writes 'base'.'64'.'_dec'.'ode'
	// cannot hide the function name from every rule that spells it out.
	//
	// It is built on first use, not up front. A scan walks every candidate
	// file, most of them match no rule at all, and the view costs a copy of
	// the file plus an index over it - which for a zip or a log that only
	// happens to be a candidate is paid for nothing.
	var joined []byte
	var index []int32
	built := false

	var out []report.Finding
	for _, r := range e.rules {
		if !r.AppliesTo(rel, ext) {
			continue
		}
		if f, ok := e.apply(r, path, content, content, nil); ok {
			out = append(out, f)
			continue
		}
		if r.RawOnly {
			continue
		}
		if !built {
			joined, index = joinConcatenated(content)
			built = true
		}
		if joined != nil {
			if f, ok := e.apply(r, path, joined, content, index); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// apply runs one rule over hay. raw and index translate a position in hay back
// to the file, so a finding names the line someone can actually open; index is
// nil when hay is the file itself.
func (e *Engine) apply(r *Rule, path string, hay, raw []byte, index []int32) (report.Finding, bool) {
	loc := r.Match.FindIndex(hay)
	if loc == nil {
		return report.Finding{}, false
	}
	if r.Requires != nil && !r.Requires.Match(hay) {
		return report.Finding{}, false
	}
	if r.AlsoRequires != nil && !r.AlsoRequires.Match(hay) {
		return report.Finding{}, false
	}
	at := loc[0]
	if index != nil {
		// joinConcatenated only ever drops bytes, so the map covers the whole
		// view. A short map would mean a finding pointing at the wrong line,
		// which is worse than none at all.
		if loc[0] >= len(index) {
			return report.Finding{}, false
		}
		at = int(index[loc[0]])
	}
	return report.Finding{
		Path:     path,
		Line:     lineOf(raw, at),
		Rule:     r.ID,
		Severity: r.Severity,
		Engine:   "heuristic",
		// The excerpt comes from the view that matched: reading the
		// reassembled name is what explains the finding.
		Excerpt: excerpt(hay[loc[0]:loc[1]]),
	}, true
}

// lineOf returns the 1-based line number of a byte offset.
func lineOf(content []byte, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	return 1 + bytes.Count(content[:offset], []byte{'\n'})
}

// excerpt turns a match into a single short printable line.
func excerpt(b []byte) string {
	s := string(b)
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 32 || r == 127:
			return '.'
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxExcerpt {
		// Cut on a rune boundary so the excerpt stays valid UTF-8.
		cut := maxExcerpt
		for cut > 0 && !isRuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + " …"
	}
	return s
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
