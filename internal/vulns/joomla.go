package vulns

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/report"
)

// The Joomla Security Centre publishes its core announcements as a feed of
// the latest 25. The version ranges in them mostly start at 1.0.0, so an old
// install is caught by a recent announcement as well; what the feed no longer
// carries, OSV adds where a GitHub advisory exists (see checkJoomla).
const joomlaTTL = 24 * time.Hour

type joomlaAdvisory struct {
	title    string
	link     string
	cve      string
	severity report.Severity
	spans    []span
	fixes    []string
}

type joomlaFeed struct {
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

// Each announcement is a small HTML list: "<strong>Versions: </strong>
// 1.0.0-5.4.7,6.0.0-6.1.2". The labels have stayed the same for years; a
// changed label makes the announcement unreadable here, and it is skipped
// rather than guessed at.
func joomlaField(label string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)<strong>\s*` + label + `\s*:\s*</strong>\s*([^<]*)`)
}

var (
	joomlaSubProject  = joomlaField("SubProject")
	joomlaSeverity    = joomlaField("Severity")
	joomlaVersions    = joomlaField("Versions")
	joomlaCVEField    = regexp.MustCompile(`(?is)<strong>\s*CVE Number\s*:\s*</strong>(.*?)</li>`)
	joomlaCVE         = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	joomlaSolution    = regexp.MustCompile(`(?is)Upgrade to version\s*([0-9][0-9.,\s]*)`)
	joomlaTitlePrefix = regexp.MustCompile(`^\s*\[\d+\]\s*-\s*(?:Core\s*-\s*)?`)
	joomlaVersionForm = regexp.MustCompile(`^\d+(\.\d+)*$`)
)

func (c *Checker) joomla(inst cms.Install) ([]entry, bool) {
	if !c.joomlaLoaded {
		c.joomlaLoaded = true
		body, err := c.cached(srcJoomla, "joomla-security-centre.rss",
			c.base.Joomla+"/security-centre.feed?type=rss", joomlaTTL, nil, feedOK)
		if err == nil {
			items, perr := parseJoomlaFeed(body)
			if perr != nil {
				c.note("joomla-parse", "Schwachstellen: der Feed des %s ist nicht lesbar (%v)", srcJoomla, perr)
			} else {
				c.joomlaItems = items
			}
		}
	}
	if c.joomlaItems == nil {
		return nil, false
	}

	var out []entry
	for _, a := range c.joomlaItems {
		fix, ok := a.affects(inst.Version)
		if !ok {
			continue
		}
		e := entry{source: srcJoomla, title: a.title, severity: a.severity, fixedIn: fix, link: a.link}
		if a.cve != "" {
			e.ids = []string{a.cve}
		} else {
			e.ids = []string{a.link}
		}
		out = append(out, e)
	}
	return out, true
}

// feedOK accepts a 200 that looks like an RSS document.
func feedOK(status int, body []byte) ([]byte, error) {
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	if !strings.Contains(string(body[:min(len(body), 512)]), "<rss") {
		return nil, fmt.Errorf("kein RSS-Dokument")
	}
	return body, nil
}

// parseJoomlaFeed reads the announcements that concern the CMS. The returned
// slice is never nil on success, which is how joomla() tells "loaded, nothing
// in it" apart from "not loaded".
func parseJoomlaFeed(body []byte) ([]joomlaAdvisory, error) {
	var feed joomlaFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, err
	}

	// The feed writes "Versions:&nbsp;" as the character itself. \s in Go
	// matches ASCII whitespace only, and without this every announcement
	// failed its label match and the whole feed matched nothing.
	nbsp := strings.NewReplacer(string(rune(0x00A0)), " ", "&nbsp;", " ", "&#160;", " ")

	out := []joomlaAdvisory{}
	for _, it := range feed.Channel.Items {
		d := nbsp.Replace(it.Description)
		// Framework announcements name versions of the framework packages,
		// which have their own numbering; measured against a CMS version
		// they would match by accident.
		if m := joomlaSubProject.FindStringSubmatch(d); m != nil && !strings.EqualFold(strings.TrimSpace(m[1]), "CMS") {
			continue
		}
		m := joomlaVersions.FindStringSubmatch(d)
		if m == nil {
			continue
		}
		spans := joomlaSpans(m[1])
		if len(spans) == 0 {
			continue
		}

		a := joomlaAdvisory{
			title: cleanText(joomlaTitlePrefix.ReplaceAllString(nbsp.Replace(it.Title), ""), 160),
			link:  strings.TrimSpace(it.Link),
			spans: spans,
		}
		if sev := joomlaSeverity.FindStringSubmatch(d); sev != nil {
			a.severity = severityFromWord(sev[1])
		}
		if field := joomlaCVEField.FindStringSubmatch(d); field != nil {
			a.cve = joomlaCVE.FindString(field[1])
		}
		if sol := joomlaSolution.FindStringSubmatch(d); sol != nil {
			for _, v := range strings.Split(sol[1], ",") {
				if v = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(v), ".")); joomlaVersionForm.MatchString(v) {
					a.fixes = append(a.fixes, v)
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// joomlaSpans reads "1.0.0-5.4.7,6.0.0-6.1.2". Both ends are affected. A
// trailing "x" stands for the whole branch: 4.4.x runs to the end of 4.4.
func joomlaSpans(field string) []span {
	var out []span
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, found := strings.Cut(part, "-")
		lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
		if !found {
			hi = lo
		}
		lo = strings.ReplaceAll(strings.ToLower(lo), "x", "0")
		hi = strings.ReplaceAll(strings.ToLower(hi), "x", "99999")
		if !joomlaVersionForm.MatchString(lo) || !joomlaVersionForm.MatchString(hi) {
			continue
		}
		out = append(out, span{from: bound{version: lo, inclusive: true}, to: bound{version: hi, inclusive: true}})
	}
	return out
}

// affects returns whether v lies in one of the ranges and, if so, the fix
// for that range: the lowest listed fix above the range on the same major
// version. "Upgrade to version 5.4.8, 6.1.3" means 5.4.8 for a site on 5.x.
func (a joomlaAdvisory) affects(v string) (string, bool) {
	for _, s := range a.spans {
		if !s.contains(v) {
			continue
		}
		best := ""
		for _, f := range a.fixes {
			if cms.Compare(f, v) <= 0 || cms.Compare(f, s.to.version) <= 0 || !cms.SameBranch(f, s.to.version, 1) {
				continue
			}
			if best == "" || cms.Compare(f, best) < 0 {
				best = f
			}
		}
		if best == "" {
			for _, f := range a.fixes {
				if cms.Compare(f, v) > 0 && (best == "" || cms.Compare(f, best) < 0) {
					best = f
				}
			}
		}
		return best, true
	}
	return "", false
}
