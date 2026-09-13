package vulns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// WPScan answers per plugin, per theme and per core version and needs an API
// token. The free plan allows 25 requests a day. Answers are therefore kept
// for a week, and a used-up quota is remembered across runs: every further
// request would be answered with 429 and still count against the plan.
const (
	wpscanTTL      = 7 * 24 * time.Hour
	wpscanQuotaKey = "wpscan-quota-exhausted"
	wpscanPause    = 6 * time.Hour
)

type wpscanVuln struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	FixedIn      *string `json:"fixed_in"`
	IntroducedIn *string `json:"introduced_in"`
	References   struct {
		CVE stringList `json:"cve"`
	} `json:"references"`
	// CVSS is filled on the enterprise plan only.
	CVSS *struct {
		Score    flexString `json:"score"`
		Vector   string     `json:"vector"`
		Severity string     `json:"severity"`
	} `json:"cvss"`
}

type wpscanItem struct {
	Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
}

func (c *Checker) wpScan(inst cms.Install) ([]entry, bool) {
	var path, key string
	switch inst.Kind {
	case "core":
		// The API wants the version without its dots: 6.4.2 becomes 642.
		digits := strings.ReplaceAll(inst.Version, ".", "")
		if digits == "" || strings.Trim(digits, "0123456789") != "" {
			return nil, false
		}
		path, key = "/wordpresses/"+digits, "wpscan-core-"+inst.Version+".json"
	case "plugin", "theme":
		if !plausibleSlug(inst.Slug) {
			return nil, false
		}
		path, key = "/"+inst.Kind+"s/"+inst.Slug, "wpscan-"+inst.Kind+"-"+inst.Slug+".json"
	default:
		return nil, false
	}

	var body []byte
	if c.wpscanPaused() {
		stored, have := c.storedAny(key)
		if !have {
			c.missed[srcWPScan]++
			return nil, false
		}
		c.used[srcWPScan] = true
		body = stored
	} else {
		header := http.Header{"Authorization": []string{"Token token=" + c.token}}
		fetched, err := c.cached(srcWPScan, key, c.base.WPScan+path, wpscanTTL, header, c.wpscanAccept)
		if err != nil {
			return nil, false
		}
		body = fetched
	}

	list, err := parseWPScan(body, inst)
	if err != nil {
		c.note("wpscan-parse", "Schwachstellen: eine gespeicherte Antwort von %s ist nicht lesbar (%v)", srcWPScan, err)
		return nil, false
	}
	return list, true
}

// wpscanPaused reports whether WPScan must not be asked right now: the token
// was refused during this run, or the quota ran out not long ago.
func (c *Checker) wpscanPaused() bool {
	if c.wpscanOff {
		return true
	}
	if _, age, have := c.cache.get(wpscanQuotaKey); have && age < wpscanPause {
		c.lastErr[srcWPScan] = "Tageskontingent aufgebraucht"
		return true
	}
	return false
}

// storedAny returns a stored answer of any age.
func (c *Checker) storedAny(key string) ([]byte, bool) {
	if body, ok := c.memo[key]; ok {
		return body, true
	}
	body, _, ok := c.cache.get(key)
	if ok {
		c.memo[key] = body
	}
	return body, ok
}

func (c *Checker) wpscanAccept(status int, body []byte) ([]byte, error) {
	switch status {
	case http.StatusOK:
		if !json.Valid(body) {
			return nil, fmt.Errorf("unlesbare Antwort")
		}
		return body, nil
	case http.StatusNotFound:
		// A plugin WPScan has never heard of: stored as an empty answer, so
		// the question does not cost a request again tomorrow.
		return []byte("{}"), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		c.wpscanOff = true
		c.note("wpscan-token", "Schwachstellen: WPScan lehnt den API-Schlüssel ab (HTTP %d); für den Rest des Laufs wurde WPScan nicht mehr gefragt", status)
		return nil, fmt.Errorf("API-Schlüssel abgelehnt")
	case http.StatusTooManyRequests:
		c.wpscanOff = true
		c.cache.put(wpscanQuotaKey, []byte(time.Now().UTC().Format(time.RFC3339)))
		c.note("wpscan-quota", "Schwachstellen: das WPScan-Kontingent ist aufgebraucht; bis es sich erneuert, gelten die gespeicherten Antworten")
		return nil, fmt.Errorf("Tageskontingent aufgebraucht")
	}
	return nil, fmt.Errorf("HTTP %d", status)
}

// parseWPScan returns the flaws that affect inst.Version. The answer is an
// object keyed by the slug or the version asked about.
func parseWPScan(body []byte, inst cms.Install) ([]entry, error) {
	var byName map[string]json.RawMessage
	if err := json.Unmarshal(body, &byName); err != nil {
		return nil, err
	}

	var out []entry
	for _, raw := range byName {
		var item wpscanItem
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		for _, v := range item.Vulnerabilities {
			fixed, intro := deref(v.FixedIn), deref(v.IntroducedIn)
			// A core answer already belongs to the version asked about; a
			// plugin answer is the component's whole history.
			if inst.Kind != "core" {
				s := span{}
				if intro != "" {
					s.from = bound{version: intro, inclusive: true}
				}
				if fixed != "" {
					s.to = bound{version: fixed}
				}
				if !s.contains(inst.Version) {
					continue
				}
			}

			e := entry{
				source:  srcWPScan,
				title:   cleanText(v.Title, 160),
				fixedIn: fixed,
				unfixed: fixed == "",
			}
			if id := strings.TrimSpace(v.ID); plausibleSlug(id) {
				e.ids = append(e.ids, id)
				e.link = "https://wpscan.com/vulnerability/" + id
			}
			for _, ref := range v.References.CVE {
				e.ids = appendUnique(e.ids, normalizeCVE(ref))
			}
			if v.CVSS != nil {
				score, _ := strconv.ParseFloat(strings.TrimSpace(string(v.CVSS.Score)), 64)
				if score <= 0 {
					if computed, ok := cvss3Score(v.CVSS.Vector); ok {
						score = computed
					}
				}
				e.score = score
				e.severity = severityFromWord(v.CVSS.Severity)
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// stringList reads a JSON value that is a list in one record and a single
// string in the next.
type stringList []string

func (l *stringList) UnmarshalJSON(raw []byte) error {
	s := strings.TrimSpace(string(raw))
	switch {
	case s == "null":
		*l = nil
	case strings.HasPrefix(s, "["):
		var items []flexString
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		out := make(stringList, 0, len(items))
		for _, it := range items {
			out = append(out, string(it))
		}
		*l = out
	default:
		var one flexString
		if err := json.Unmarshal(raw, &one); err != nil {
			return err
		}
		*l = stringList{string(one)}
	}
	return nil
}
