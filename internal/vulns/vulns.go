// Package vulns looks up the publicly known flaws of detected web software.
//
// The scanner already knows which product, plugin or theme sits in a
// directory and in which version. This package asks the databases that track
// flaws about exactly that version and folds their answers into one list per
// install:
//
//   - WordPress core, plugins and themes: WPVulnerability, and WPScan when an
//     API token is configured. wordpress.org adds whether a core version
//     counts as insecure.
//   - Joomla core: the feed of the Joomla Security Centre.
//   - Drupal, TYPO3, phpMyAdmin, Contao, Shopware, MediaWiki and Magento 2:
//     the OSV database of Composer packages, downloaded as a whole and
//     searched locally.
//
// What leaves the server is the name and version being asked about, and for
// OSV not even that. Every answer is kept on disk (see diskCache), so a
// nightly pass over many websites asks each question once.
package vulns

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/version"
)

// Names of the sources as they appear in reports and notes.
const (
	srcWPVulnerability = "WPVulnerability"
	srcWPScan          = "WPScan"
	srcWordPressOrg    = "wordpress.org"
	srcJoomla          = "Joomla Security Centre"
	srcOSV             = "OSV"
)

var sourceOrder = []string{srcWPVulnerability, srcWPScan, srcWordPressOrg, srcJoomla, srcOSV}

// maxFailures is how many requests in a row a source may leave unanswered
// before the run stops asking it. A database that is down would otherwise
// cost the full timeout once for every plugin of every website.
const maxFailures = 3

// Options configure a Checker.
type Options struct {
	// CacheDir holds the stored answers. Empty keeps them for this run only.
	CacheDir string
	// WPScanToken switches WPScan on. Empty leaves it out.
	WPScanToken string
	Timeout     time.Duration
	// Base replaces the addresses of the sources, for tests.
	Base BaseURLs
}

// BaseURLs are the addresses the sources are reached under.
type BaseURLs struct {
	WPVulnerability string
	WPScan          string
	WordPressOrg    string
	OSV             string
	Joomla          string
}

// DefaultBaseURLs returns the public addresses.
func DefaultBaseURLs() BaseURLs {
	return BaseURLs{
		WPVulnerability: "https://www.wpvulnerability.net",
		WPScan:          "https://wpscan.com/api/v3",
		WordPressOrg:    "https://api.wordpress.org",
		OSV:             "https://storage.googleapis.com/osv-vulnerabilities",
		Joomla:          "https://developer.joomla.org",
	}
}

// Checker answers "which flaws are known for this install". One Checker
// serves one scan; it is not safe for concurrent use.
type Checker struct {
	client    *http.Client
	bigClient *http.Client
	cache     diskCache
	base      BaseURLs
	token     string

	memo     map[string][]byte
	failures map[string]int
	missed   map[string]int
	stale    map[string]int
	lastErr  map[string]string
	used     map[string]bool
	extra    []string
	noted    map[string]bool

	stableCheck  map[string]string
	stableLoaded bool

	osvIndex  map[string][]osvAdvisory
	osvLoaded bool

	joomlaItems  []joomlaAdvisory
	joomlaLoaded bool

	wpscanOff bool
}

// New returns a Checker.
func New(opts Options) *Checker {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	base, def := opts.Base, DefaultBaseURLs()
	if base.WPVulnerability == "" {
		base.WPVulnerability = def.WPVulnerability
	}
	if base.WPScan == "" {
		base.WPScan = def.WPScan
	}
	if base.WordPressOrg == "" {
		base.WordPressOrg = def.WordPressOrg
	}
	if base.OSV == "" {
		base.OSV = def.OSV
	}
	if base.Joomla == "" {
		base.Joomla = def.Joomla
	}
	return &Checker{
		client: &http.Client{Timeout: timeout},
		// The OSV archive is ten megabytes and more; the timeout for an API
		// answer would cut it off on a slow line.
		bigClient: &http.Client{Timeout: 10 * timeout},
		cache:     diskCache{dir: opts.CacheDir},
		base:      base,
		token:     strings.TrimSpace(opts.WPScanToken),
		memo:      map[string][]byte{},
		failures:  map[string]int{},
		missed:    map[string]int{},
		stale:     map[string]int{},
		lastErr:   map[string]string{},
		used:      map[string]bool{},
		noted:     map[string]bool{},
	}
}

// Check returns the known flaws of one install, worst first, and whether any
// source answered for it. checked is false for a product no source covers
// and for an install every source failed on; an empty list with checked set
// means the sources know of nothing.
func (c *Checker) Check(inst cms.Install) (list []report.Vulnerability, checked bool) {
	if !plausibleVersion(inst.Version) {
		return nil, false
	}
	var found []entry
	switch {
	case inst.Product == "wordpress":
		found, checked = c.checkWordPress(inst)
	case inst.Kind != "core":
		return nil, false
	case inst.Product == "joomla":
		found, checked = c.checkJoomla(inst)
	case osvPackages[inst.Product] != nil:
		found, checked = c.osv(inst)
	default:
		return nil, false
	}
	return finish(merge(found)), checked
}

// checkWordPress asks the vulnerability databases, and only they decide
// whether the install counts as checked. wordpress.org adds its verdict on
// core releases to the list (see wordpressOrg).
func (c *Checker) checkWordPress(inst cms.Install) ([]entry, bool) {
	var found []entry
	checked := false
	if list, ok := c.wpVulnerability(inst); ok {
		found, checked = append(found, list...), true
	}
	if c.token != "" {
		if list, ok := c.wpScan(inst); ok {
			found, checked = append(found, list...), true
		}
	}
	if inst.Kind == "core" {
		found = c.wordpressOrg(inst, found)
	}
	return found, checked
}

// checkJoomla takes "checked" from the Security Centre feed alone. OSV holds
// a few older announcements filed as GitHub advisories: they add to the list
// and meet the feed's entries on the CVE, and on their own they are too few
// to vouch for "nothing known".
func (c *Checker) checkJoomla(inst cms.Install) ([]entry, bool) {
	found, checked := c.joomla(inst)
	if list, ok := c.osv(inst); ok {
		found = append(found, list...)
	}
	return found, checked
}

// Describe names the sources that answered during this run.
func (c *Checker) Describe() string {
	var names []string
	for _, src := range sourceOrder {
		if c.used[src] {
			names = append(names, src)
		}
	}
	return strings.Join(names, ", ")
}

// Notes returns what the report should say about sources that did not answer.
func (c *Checker) Notes() []string {
	var out []string
	for _, src := range sourceOrder {
		if n := c.missed[src]; n > 0 {
			out = append(out, fmt.Sprintf("Schwachstellen: %d Abfrage(n) bei %s ohne Antwort (%s)", n, src, c.lastErr[src]))
		}
		if n := c.stale[src]; n > 0 {
			out = append(out, fmt.Sprintf("Schwachstellen: %s war nicht erreichbar, für %d Anfrage(n) wurden gespeicherte ältere Daten verwendet", src, n))
		}
	}
	return append(out, c.extra...)
}

// note adds a message once per run.
func (c *Checker) note(key, format string, args ...any) {
	if c.noted[key] {
		return
	}
	c.noted[key] = true
	c.extra = append(c.extra, fmt.Sprintf(format, args...))
}

// request performs one GET and reads at most limit bytes of the answer.
func (c *Checker) request(client *http.Client, source, rawURL string, header http.Header, limit int64) (int, []byte, error) {
	if c.failures[source] >= maxFailures {
		return 0, nil, fmt.Errorf("nach %d Fehlversuchen nicht mehr gefragt", maxFailures)
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "malwatch/"+version.Version)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		c.failures[source]++
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		c.failures[source]++
		return resp.StatusCode, nil, err
	}
	if int64(len(body)) > limit {
		return resp.StatusCode, nil, fmt.Errorf("Antwort größer als %d MB", limit>>20)
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		c.failures[source]++
	} else {
		c.failures[source] = 0
	}
	return resp.StatusCode, body, nil
}

// accept inspects an answer. It returns the body to store, which may differ
// from the one received - a "not found" is stored as an empty document so
// the question is not asked again tomorrow.
type accept func(status int, body []byte) ([]byte, error)

// cached returns the answer stored under key while it is younger than ttl
// and fetches a new one otherwise. When the fetch fails an older stored
// answer is used and counted; only without one does the lookup fail.
func (c *Checker) cached(source, key, rawURL string, ttl time.Duration, header http.Header, ok accept) ([]byte, error) {
	if body, hit := c.memo[key]; hit {
		return body, nil
	}
	stored, age, have := c.cache.get(key)
	if have && age < ttl {
		c.memo[key] = stored
		c.used[source] = true
		return stored, nil
	}

	status, body, err := c.request(c.client, source, rawURL, header, 16<<20)
	if err == nil {
		body, err = ok(status, body)
	}
	if err == nil {
		c.cache.put(key, body)
		c.memo[key] = body
		c.used[source] = true
		return body, nil
	}

	c.lastErr[source] = err.Error()
	if have {
		c.stale[source]++
		c.memo[key] = stored
		c.used[source] = true
		return stored, nil
	}
	c.missed[source]++
	return nil, err
}

// onlyOK accepts a 200 and nothing else.
func onlyOK(status int, body []byte) ([]byte, error) {
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	return body, nil
}

// entry is one flaw as one source describes it, before the sources are
// folded together.
type entry struct {
	// ids holds every identifier the source gives: CVE numbers and the
	// source's own ids, which is how two sources recognise the same flaw.
	ids   []string
	title string
	// titleWeak marks a title made up from a description because the source
	// had none. merge replaces it with a proper title from another source.
	titleWeak bool
	severity  report.Severity
	score     float64
	fixedIn   string
	// lastAffected is the newest version known to be affected, for records
	// that give that instead of a fix.
	lastAffected string
	unfixed      bool
	link         string
	source       string
	sources      []string
}

// bound returns what an entry says about where the flaw ends, as a key two
// entries can be compared on.
func (e entry) boundKey() string {
	switch {
	case e.fixedIn != "":
		return "fixed " + e.fixedIn
	case e.lastAffected != "":
		return "last " + e.lastAffected
	}
	return ""
}

func (e entry) cves() []string {
	var out []string
	for _, id := range e.ids {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

// merge folds entries that describe the same flaw into one.
//
// Two entries are the same flaw when they share an identifier: a CVE, or the
// id one database gives a flaw and another lists next to its own record.
//
// Entries of which at least one carries no CVE are also joined when both name
// the same fixed version. One database lists a flaw once with its CVE and a
// second time, as a different researcher reported it, without one - and both
// say "fixed in 5.3.2". Two different flaws fixed in the same release can end
// up as one this way; they ask for the same update, and listing one flaw three
// times would overstate what there is to do.
func merge(in []entry) []entry {
	var out []entry
	for _, e := range in {
		e.sources = []string{e.source}
		if i := partner(out, e); i >= 0 {
			out[i] = combine(out[i], e)
			continue
		}
		out = append(out, e)
	}
	return out
}

func partner(list []entry, e entry) int {
	for i, m := range list {
		if shares(m.ids, e.ids) {
			return i
		}
	}
	key := e.boundKey()
	if key == "" {
		return -1
	}
	for i, m := range list {
		if m.boundKey() != key {
			continue
		}
		if len(m.cves()) == 0 || len(e.cves()) == 0 {
			return i
		}
	}
	return -1
}

func combine(a, b entry) entry {
	a.ids = appendUnique(a.ids, b.ids...)
	a.sources = appendUnique(a.sources, b.sources...)
	if b.severity.Rank() > a.severity.Rank() {
		a.severity = b.severity
	}
	if b.score > a.score {
		a.score = b.score
	}
	if a.title == "" || (a.titleWeak && !b.titleWeak && b.title != "") {
		a.title, a.titleWeak = b.title, b.titleWeak
	}
	a.fixedIn = higherVersion(a.fixedIn, b.fixedIn)
	a.lastAffected = higherVersion(a.lastAffected, b.lastAffected)
	a.unfixed = a.fixedIn == "" && a.lastAffected == "" && (a.unfixed || b.unfixed)
	if a.link == "" {
		a.link = b.link
	}
	return a
}

// finish turns merged entries into report entries, worst first.
func finish(list []entry) []report.Vulnerability {
	out := make([]report.Vulnerability, 0, len(list))
	for _, e := range list {
		v := report.Vulnerability{
			Title:    e.title,
			Severity: e.severity,
			Score:    e.score,
			FixedIn:  e.fixedIn,
			Unfixed:  e.unfixed && e.fixedIn == "" && e.lastAffected == "",
			Link:     e.link,
			Sources:  e.sources,
		}
		if e.fixedIn == "" {
			v.LastAffected = e.lastAffected
		}
		if cves := e.cves(); len(cves) > 0 {
			sort.Strings(cves)
			v.ID = cves[len(cves)-1]
			v.Link = "https://www.cve.org/CVERecord?id=" + v.ID
		}
		// The link ends up in an href on the panel. A database hands out web
		// addresses; whatever else arrives is dropped before it is rendered.
		if !strings.HasPrefix(v.Link, "https://") && !strings.HasPrefix(v.Link, "http://") {
			v.Link = ""
		}
		if v.Severity == "" {
			v.Severity = severityFromScore(v.Score)
		}
		if v.Title == "" {
			v.Title = v.ID
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID > b.ID
	})
	return out
}

// UpdateTo returns the lowest version that fixes every flaw in list for which
// a fix is known.
func UpdateTo(list []report.Vulnerability) string {
	best := ""
	for _, v := range list {
		best = higherVersion(best, v.FixedIn)
	}
	return best
}

func shares(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		seen := false
		for _, have := range list {
			if have == v {
				seen = true
				break
			}
		}
		if !seen {
			list = append(list, v)
		}
	}
	return list
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// normalizeCVE returns "CVE-2024-1234" for "CVE-2024-1234", "cve-2024-1234"
// and the bare "2024-1234" WPScan writes, and "" for anything else.
func normalizeCVE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "CVE-") {
		s = "CVE-" + s
	}
	if cvePattern.MatchString(s) {
		return s
	}
	return ""
}

var tagPattern = regexp.MustCompile(`<[^>]*>`)

// cleanText turns a title or description from a database into one plain
// line: tags removed, entities decoded, whitespace collapsed, cut to max
// characters.
func cleanText(s string, max int) string {
	s = tagPattern.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return strings.TrimSpace(string(runes[:max])) + " …"
}
