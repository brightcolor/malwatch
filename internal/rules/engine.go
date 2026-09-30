package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/brightcolor/malwatch/internal/phpcode"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/textpos"
)

// Engine applies the rule catalog to file contents.
type Engine struct {
	rules   []*Rule
	ignored map[string]bool
	// uploadDirs are the directories the location rules call upload
	// directories, uploads the pattern built from them.
	uploadDirs []string
	uploads    *regexp.Regexp
	// markLimit is the most marks a finding carries, 0 for none.
	markLimit int
	// scriptHosts are the hosts a script written by document.write may load
	// from, see DefaultScriptHosts; scriptHostList keeps their order for the
	// fingerprint.
	scriptHosts    map[string]bool
	scriptHostList []string
}

// NewEngine returns an engine over the full catalog, minus the rule IDs in
// ignore (case insensitive, as on the command line), with DefaultUploadDirs.
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
	e.uploadDirs = append([]string(nil), DefaultUploadDirs...)
	e.uploads = uploadPattern(e.uploadDirs)
	if err := e.SetScriptHosts(DefaultScriptHosts); err != nil {
		panic("DefaultScriptHosts: " + err.Error())
	}
	return e
}

// SetUploadDirs replaces the directories the rules with Where call upload
// directories. A list CheckUploadDirs refuses leaves the engine as it was.
func (e *Engine) SetUploadDirs(dirs []string) error {
	if err := CheckUploadDirs(dirs); err != nil {
		return err
	}
	e.uploadDirs = append([]string(nil), dirs...)
	e.uploads = uploadPattern(e.uploadDirs)
	return nil
}

// SetMarkLimit sets how many places a finding marks: the matches of its
// pattern first, then one match of each supporting condition. 0 marks none.
func (e *Engine) SetMarkLimit(n int) {
	if n < 0 {
		n = 0
	}
	e.markLimit = n
}

// RuleCount returns how many rules are active.
func (e *Engine) RuleCount() int { return len(e.rules) }

// Fingerprint identifies what the engine reports on a file: the active rules
// and the upload directories. A clean file stays clean only under the same
// fingerprint.
func (e *Engine) Fingerprint() string {
	return fmt.Sprintf("%d|%s|%s", len(e.rules), strings.Join(e.uploadDirs, ","), strings.Join(e.scriptHostList, ","))
}

// fits reports whether rel lies where the rule looks.
func (e *Engine) fits(r *Rule, rel string) bool {
	switch r.Where {
	case InUploads:
		return e.uploads.MatchString(rel)
	case OutsideUploads:
		return !e.uploads.MatchString(rel)
	}
	return true
}

// ScanHead applies the HeadOnly rules to the start of a file the scanner does
// not read as a whole, see HeadSize. path and rel mean what they mean in Scan.
func (e *Engine) ScanHead(path, rel, ext string, head []byte) []report.Finding {
	if rel == "" {
		rel = path
	}
	looks := look(head)
	var out []report.Finding
	for _, r := range e.rules {
		if !r.HeadOnly || !r.AppliesTo(rel, ext, looks) || !e.fits(r, rel) {
			continue
		}
		if f, ok := e.apply(r, path, head, head, nil, nil, everywhereCode); ok {
			out = append(out, f)
		}
	}
	return out
}

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

	looks := look(content)

	// Whether the file can do anything at all, decided once and only for a
	// file a SkipInert rule looks at.
	inertKnown, inert := false, false
	isInert := func() bool {
		if !inertKnown {
			inert, _ = phpcode.Inert(content)
			inertKnown = true
		}
		return inert
	}

	// What of the file is PHP code, read once and only for a file where a
	// rule about code or about its supporting conditions matched at all. A
	// file the reader loses track in counts as code throughout: a construct
	// it does not know must never hide a match.
	var src *phpcode.Source
	codeAt := func(at int) bool {
		if src == nil {
			src = phpcode.Parse(content)
		}
		return src.Broken() || src.IsCode(at)
	}

	// The line index for the marks, built once and only for a file that
	// matches at all.
	var lines *textpos.Lines
	linesOf := func() *textpos.Lines {
		if lines == nil {
			lines = textpos.New(content)
		}
		return lines
	}

	var out []report.Finding
	for _, r := range e.rules {
		if !r.AppliesTo(rel, ext, looks) || !e.fits(r, rel) {
			continue
		}
		if r.SkipInert && isInert() {
			continue
		}
		if f, ok := e.apply(r, path, content, content, nil, linesOf, codeAt); ok {
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
			if f, ok := e.apply(r, path, joined, content, index, linesOf, codeAt); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// apply runs one rule over hay. raw and index translate a position in hay back
// to the file, so a finding names the line someone can actually open; index is
// nil when hay is the file itself. linesOf gives the line index of raw for the
// marks; nil leaves the finding without marks. codeAt says whether an offset of
// raw is PHP code.
func (e *Engine) apply(r *Rule, path string, hay, raw []byte, index []int32, linesOf func() *textpos.Lines,
	codeAt func(int) bool) (report.Finding, bool) {
	inCode := func(loc []int) bool {
		at := loc[0]
		if index != nil {
			if at >= len(index) {
				return false
			}
			at = int(index[at])
		}
		return codeAt(at)
	}
	loc := e.firstMatch(r, hay, inCode)
	if loc == nil {
		return report.Finding{}, false
	}
	if r.Requires != nil && !supported(r, r.Requires, hay, inCode) {
		return report.Finding{}, false
	}
	if r.AlsoRequires != nil && !supported(r, r.AlsoRequires, hay, inCode) {
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
	f := report.Finding{
		Path:     path,
		Line:     lineOf(raw, at),
		Rule:     r.ID,
		Severity: r.Severity,
		Engine:   "heuristic",
		// The excerpt comes from the view that matched: reading the
		// reassembled name is what explains the finding.
		Excerpt: excerpt(hay[loc[0]:loc[1]]),
	}
	if e.markLimit > 0 && linesOf != nil {
		f.Marks = e.marks(r, hay, index, linesOf(), inCode)
	}
	return f, true
}

// everywhereCode takes every offset for code, for the start of a file that is
// not read as a whole.
func everywhereCode(int) bool { return true }

// supported reports whether a supporting condition holds: anywhere in the
// file, or for a rule with SupportInCode somewhere in its code.
func supported(r *Rule, re *regexp.Regexp, hay []byte, inCode func([]int) bool) bool {
	if !r.SupportInCode {
		return re.Match(hay)
	}
	for _, loc := range re.FindAllIndex(hay, maxWeighedMatches) {
		if inCode(loc) {
			return true
		}
	}
	return false
}

// firstMatch returns the first match of the rule's pattern that counts: the
// first one at all, for a rule with CodeOnly the first one in code, and for a
// rule with Harmless the first one it does not excuse. nil means none counts.
func (e *Engine) firstMatch(r *Rule, hay []byte, inCode func([]int) bool) []int {
	if r.Harmless == nil && !r.CodeOnly {
		return r.Match.FindIndex(hay)
	}
	for _, loc := range r.Match.FindAllIndex(hay, maxWeighedMatches) {
		if r.CodeOnly && !inCode(loc) {
			continue
		}
		if r.Harmless != nil && r.Harmless(e, hay, loc) {
			continue
		}
		return loc
	}
	return nil
}

// marks lists the places behind a finding: every match of the pattern up to
// the limit, then the first match of each supporting condition, since those
// are part of the reason as well. Positions in the reassembled view are taken
// back to the file through index.
func (e *Engine) marks(r *Rule, hay []byte, index []int32, lines *textpos.Lines, inCode func([]int) bool) []report.Mark {
	var out []report.Mark
	add := func(re *regexp.Regexp, n int) {
		for _, loc := range re.FindAllIndex(hay, n) {
			if len(out) >= e.markLimit {
				return
			}
			if re == r.Match && r.Harmless != nil && r.Harmless(e, hay, loc) {
				// A picture next to the block of code is no place to look at.
				continue
			}
			if (re == r.Match && r.CodeOnly || re != r.Match && r.SupportInCode) && !inCode(loc) {
				// A comment that mentions the construct is no place either.
				continue
			}
			start, end := loc[0], loc[1]
			if end <= start {
				// A rule that only asks where a file lies matches the empty
				// start of it; there is no place to point at.
				continue
			}
			if index != nil {
				if end-1 >= len(index) {
					continue
				}
				start, end = int(index[start]), int(index[end-1])+1
			}
			out = append(out, lines.Marks(start, end, e.markLimit-len(out))...)
		}
	}
	add(r.Match, e.markLimit)
	if r.Requires != nil {
		add(r.Requires, 1)
	}
	if r.AlsoRequires != nil {
		add(r.AlsoRequires, 1)
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
