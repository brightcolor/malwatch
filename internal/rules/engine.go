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
	var out []report.Finding
	for _, r := range e.rules {
		if !r.AppliesTo(rel, ext) {
			continue
		}
		loc := r.Match.FindIndex(content)
		if loc == nil {
			continue
		}
		if r.Requires != nil && !r.Requires.Match(content) {
			continue
		}
		out = append(out, report.Finding{
			Path:     path,
			Line:     lineOf(content, loc[0]),
			Rule:     r.ID,
			Severity: r.Severity,
			Engine:   "heuristic",
			Excerpt:  excerpt(content[loc[0]:loc[1]]),
		})
	}
	return out
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
