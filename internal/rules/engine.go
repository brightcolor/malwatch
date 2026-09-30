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
	// phpVersion is the PHP version of the website, empty when unknown.
	phpVersion string
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
	return fmt.Sprintf("%d|%s|%s|%s", len(e.rules), strings.Join(e.uploadDirs, ","), strings.Join(e.scriptHostList, ","),
		e.phpVersion)
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
		if f, ok := e.apply(r, path, head, head, nil, nil, &codeView{content: head}); ok {
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
	// rule about code matched at all.
	cv := &codeView{content: content}

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
		if r.DeadFrom != "" && e.phpVersion != "" && versionAtLeast(e.phpVersion, r.DeadFrom) {
			continue
		}
		if f, ok := e.apply(r, path, content, content, nil, linesOf, cv); ok {
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
			if f, ok := e.apply(r, path, joined, content, index, linesOf, cv); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// apply runs one rule over hay. raw and index translate a position in hay back
// to the file, so a finding names the line someone can actually open; index is
// nil when hay is the file itself. linesOf gives the line index of raw for the
// marks; nil leaves the finding without marks. cv reads the PHP structure of
// raw.
func (e *Engine) apply(r *Rule, path string, hay, raw []byte, index []int32, linesOf func() *textpos.Lines,
	cv *codeView) (report.Finding, bool) {
	// rawAt takes an offset of hay back to the file.
	rawAt := func(at int) (int, bool) {
		if index == nil {
			return at, true
		}
		if at >= len(index) {
			return 0, false
		}
		return int(index[at]), true
	}
	inCode := func(loc []int) bool {
		at, ok := rawAt(loc[0])
		return ok && cv.code(at)
	}
	var loc []int
	if r.SameScope {
		loc = e.scopedMatch(r, hay, rawAt, inCode, cv)
	} else {
		loc = e.firstMatch(r, hay, inCode)
		if loc != nil && r.Requires != nil && !supported(r, r.Requires, hay, inCode) {
			loc = nil
		}
		if loc != nil && r.AlsoRequires != nil && !supported(r, r.AlsoRequires, hay, inCode) {
			loc = nil
		}
	}
	if loc == nil {
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
	if r.GuardLowers && f.Severity.AtLeast(report.SeverityHigh) && cv.source().GuardedAt(at, wpRights, wpNonces) {
		f.Severity = report.SeverityMedium
		f.Excerpt = guardedNote + f.Excerpt
	}
	if e.markLimit > 0 && linesOf != nil {
		f.Marks = e.marks(r, hay, index, linesOf(), inCode)
	}
	return f, true
}

// The WordPress functions that check a user's rights and a nonce. They are
// the API of WordPress, not a setting.
var (
	wpRights = map[string]bool{"current_user_can": true, "user_can": true, "is_super_admin": true,
		"current_user_can_for_blog": true}
	wpNonces = map[string]bool{"check_admin_referer": true, "check_ajax_referer": true, "wp_verify_nonce": true}
)

// guardedNote opens the excerpt of a finding GuardLowers took down.
const guardedNote = "[hinter Rechte- und Nonce-Prüfung] "

// codeView reads the PHP structure of one file, once and only when a rule
// asks. A file the reader loses track in counts as code throughout: a
// construct it does not know must never hide a match.
type codeView struct {
	content []byte
	src     *phpcode.Source
}

func (c *codeView) source() *phpcode.Source {
	if c.src == nil {
		c.src = phpcode.Parse(c.content)
	}
	return c.src
}

// code reports whether offset at of the file counts as PHP code for a rule
// that weighs code only: the code itself and every string in it. A string runs
// once the file hands it to eval or writes it into a file, and droppers keep
// their loader exactly there: $k = '...'; eval($k). What PHP never runs does
// not count: comments and the text around the tags.
func (c *codeView) code(at int) bool {
	s := c.source()
	if s.Broken() || s.IsCode(at) {
		return true
	}
	return s.KindAt(at) == phpcode.String
}

// scopedMatch returns the first match of a SameScope rule whose supporting
// conditions sit in the same function body, or in the body of a function
// defined in the file that this body calls. nil means none.
func (e *Engine) scopedMatch(r *Rule, hay []byte, rawAt func(int) (int, bool), inCode func([]int) bool,
	cv *codeView) []int {
	positions := func(re *regexp.Regexp) []int {
		var out []int
		for _, loc := range re.FindAllIndex(hay, maxWeighedMatches) {
			if r.SupportInCode && !inCode(loc) {
				continue
			}
			if at, ok := rawAt(loc[0]); ok {
				out = append(out, at)
			}
		}
		return out
	}
	var req, also []int
	if r.Requires != nil {
		if req = positions(r.Requires); len(req) == 0 {
			return nil
		}
	}
	if r.AlsoRequires != nil {
		if also = positions(r.AlsoRequires); len(also) == 0 {
			return nil
		}
	}
	src := cv.source()
	for _, loc := range r.Match.FindAllIndex(hay, maxWeighedMatches) {
		if r.CodeOnly && !inCode(loc) {
			continue
		}
		if r.Harmless != nil && r.Harmless(e, hay, loc) {
			continue
		}
		at, ok := rawAt(loc[0])
		if !ok {
			continue
		}
		if (r.Requires == nil || reaches(src, at, req)) && (r.AlsoRequires == nil || reaches(src, at, also)) {
			return loc
		}
	}
	return nil
}

// reaches reports whether one of the offsets lies in the function body around
// at, or in the body of a function that body calls. One call deep: a helper
// that downloads for the code that runs it is the common shape of a
// downloader; a library whose unrelated parts happen to share a file is not.
func reaches(src *phpcode.Source, at int, offsets []int) bool {
	for _, o := range offsets {
		if src.SameScope(at, o) {
			return true
		}
	}
	for _, name := range src.CallsIn(at) {
		for _, fn := range src.Functions(name) {
			for _, o := range offsets {
				if fn.Start <= o && o <= fn.End {
					return true
				}
			}
		}
	}
	return false
}

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
