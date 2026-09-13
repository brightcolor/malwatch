package vulns

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// osvPackage is a Composer package that advisories are filed under, with the
// major versions of the product it speaks for. Zero leaves that side open.
type osvPackage struct {
	name     string
	minMajor int
	maxMajor int
}

// osvPackages maps a product to the Composer packages its advisories are
// filed under. Most products have more than one: the package was split
// (typo3/cms into typo3/cms-core), or the advisories name the project
// template next to the core package. Advisories listed under two names meet
// again in merge through their shared ids.
//
// Two products keep their name across a rewrite, and the packages of one line
// speak only for that line. The GitHub advisories of Shopware 6 read
// "introduced 0, fixed 6.4.20.2"; measured against Shopware 5.7 that range
// matches, and a Shopware 5 shop would be told to update to 6.4. The same
// holds for Magento 2 against Magento 1, for which no usable source exists.
// shopware/shopware, the package of Shopware 5, carries a few such Shopware 6
// ranges as well: a range that reaches back to version 0 and ends above
// maxMajor is left out (see osv).
//
// Left out, because a missing entry would read as "nothing known": Nextcloud,
// whose advisories carry no Composer package, and Matomo, with three
// advisories from its 1.x days.
var osvPackages = map[string][]osvPackage{
	"drupal":     {{name: "drupal/core"}, {name: "drupal/drupal"}},
	"typo3":      {{name: "typo3/cms-core"}, {name: "typo3/cms"}},
	"phpmyadmin": {{name: "phpmyadmin/phpmyadmin"}},
	"contao":     {{name: "contao/core-bundle"}, {name: "contao/contao"}, {name: "contao/core"}},
	"shopware": {
		{name: "shopware/core", minMajor: 6},
		{name: "shopware/platform", minMajor: 6},
		{name: "shopware/shopware", maxMajor: 5},
	},
	"mediawiki": {{name: "mediawiki/core"}},
	"magento": {
		{name: "magento/community-edition", minMajor: 2},
		{name: "magento/project-community-edition", minMajor: 2},
		{name: "magento/product-community-edition", minMajor: 2},
	},
	"joomla": {{name: "joomla/joomla-cms"}},
}

// packagesFor returns the packages whose advisories speak for the major
// version of inst. Empty when the product, or that major version, has none.
func packagesFor(inst cms.Install) []osvPackage {
	major := majorOf(inst.Version)
	var out []osvPackage
	for _, p := range osvPackages[inst.Product] {
		if (p.minMajor > 0 && major < p.minMajor) || (p.maxMajor > 0 && major > p.maxMajor) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// OSV publishes every advisory of an ecosystem as one archive. It is loaded
// once a day, reduced to the packages above and kept as a small index; the
// question which versions run on this server never leaves it.
const (
	osvTTL      = 24 * time.Hour
	osvIndexKey = "osv-packagist-index.json"
	osvZipLimit = 256 << 20
)

// osvAdvisory is the part of an OSV record the index keeps.
type osvAdvisory struct {
	IDs   []string `json:"ids"`
	Title string   `json:"title"`
	// TitleWeak marks a title taken from the first sentence of the details,
	// for a record that has no summary.
	TitleWeak bool         `json:"title_weak,omitempty"`
	Severity  string       `json:"severity,omitempty"`
	Score     float64      `json:"score,omitempty"`
	Link      string       `json:"link,omitempty"`
	Ranges    [][]osvEvent `json:"ranges,omitempty"`
	Versions  []string     `json:"versions,omitempty"`
}

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func (c *Checker) osv(inst cms.Install) ([]entry, bool) {
	packages := packagesFor(inst)
	if len(packages) == 0 {
		return nil, false
	}
	idx := c.loadOSV()
	if idx == nil {
		return nil, false
	}
	var out []entry
	for _, pkg := range packages {
		for _, adv := range idx[pkg.name] {
			affected, intro, fix, last, ranged := adv.affects(inst.Version)
			if !affected {
				continue
			}
			// "From version 0 until 6.3.5.3" in a package that speaks for
			// majors up to 5 describes the next product line.
			if pkg.maxMajor > 0 && intro == "0" {
				if end := higherVersion(fix, last); end != "" && majorOf(end) > pkg.maxMajor {
					continue
				}
			}
			var ids []string
			for _, id := range adv.IDs {
				if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
					id = normalizeCVE(id)
				}
				ids = appendUnique(ids, id)
			}
			out = append(out, entry{
				source:       srcOSV,
				ids:          ids,
				title:        adv.Title,
				titleWeak:    adv.TitleWeak,
				severity:     severityFromWord(adv.Severity),
				score:        adv.Score,
				fixedIn:      fix,
				lastAffected: last,
				// Only a range can say that no fix exists. A record that
				// merely lists affected versions says nothing either way.
				unfixed: ranged && fix == "" && last == "",
				link:    adv.Link,
			})
		}
	}
	return out, true
}

// affects returns whether v is affected, where the stretch it sits in begins
// and how it ends - a fixed version or a last affected one -, and whether the
// answer came from a range or from a plain version list.
func (a osvAdvisory) affects(v string) (affected bool, intro, fix, last string, ranged bool) {
	for _, events := range a.Ranges {
		if ok, i, f, l := osvAffected(v, events); ok {
			return true, i, f, l, true
		}
	}
	for _, listed := range a.Versions {
		if cms.Compare(strings.TrimPrefix(listed, "v"), v) == 0 {
			return true, "", "", "", false
		}
	}
	return false, "", "", "", len(a.Ranges) > 0
}

func (c *Checker) loadOSV() map[string][]osvAdvisory {
	if c.osvLoaded {
		return c.osvIndex
	}
	c.osvLoaded = true

	stored, age, have := c.cache.get(osvIndexKey)
	if have && age < osvTTL {
		if idx, err := decodeOSVIndex(stored); err == nil {
			c.osvIndex = idx
			c.used[srcOSV] = true
			return idx
		}
	}

	idx, err := c.downloadOSV()
	if err == nil {
		if raw, merr := json.Marshal(idx); merr == nil {
			c.cache.put(osvIndexKey, raw)
		}
		c.osvIndex = idx
		c.used[srcOSV] = true
		return idx
	}

	c.lastErr[srcOSV] = err.Error()
	if have {
		if old, derr := decodeOSVIndex(stored); derr == nil {
			c.stale[srcOSV]++
			c.osvIndex = old
			c.used[srcOSV] = true
			return old
		}
	}
	c.missed[srcOSV]++
	return nil
}

func (c *Checker) downloadOSV() (map[string][]osvAdvisory, error) {
	status, body, err := c.request(c.bigClient, srcOSV, c.base.OSV+"/Packagist/all.zip", nil, osvZipLimit)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	return buildOSVIndex(body)
}

func decodeOSVIndex(raw []byte) (map[string][]osvAdvisory, error) {
	var idx map[string][]osvAdvisory
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("leerer Index")
	}
	return idx, nil
}

// buildOSVIndex reduces the archive to the advisories of the packages in
// osvPackages.
func buildOSVIndex(archive []byte) (map[string][]osvAdvisory, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("Archiv nicht lesbar: %v", err)
	}

	wanted := map[string]bool{}
	var needles [][]byte
	for _, pkgs := range osvPackages {
		for _, p := range pkgs {
			wanted[p.name] = true
			needles = append(needles, []byte(`"`+p.name+`"`))
		}
	}

	idx := map[string][]osvAdvisory{}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 8<<20 {
			continue
		}
		raw, err := readZipFile(f)
		if err != nil || !containsAny(raw, needles) {
			continue
		}
		var rec osvRecord
		if json.Unmarshal(raw, &rec) != nil || rec.Withdrawn != "" {
			continue
		}

		// One record may list a package several times, once per branch.
		perPackage := map[string]*osvAdvisory{}
		var order []string
		for _, aff := range rec.Affected {
			name := aff.Package.Name
			if aff.Package.Ecosystem != "Packagist" || !wanted[name] {
				continue
			}
			adv := perPackage[name]
			if adv == nil {
				adv = newOSVAdvisory(rec)
				perPackage[name] = adv
				order = append(order, name)
			}
			ranged := false
			for _, r := range aff.Ranges {
				if (r.Type == "ECOSYSTEM" || r.Type == "SEMVER") && len(r.Events) > 0 {
					adv.Ranges = append(adv.Ranges, r.Events)
					ranged = true
				}
			}
			if !ranged {
				adv.Versions = append(adv.Versions, aff.Versions...)
			}
		}
		for _, name := range order {
			idx[name] = append(idx[name], *perPackage[name])
		}
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("das Archiv enthält keines der gesuchten Pakete")
	}
	return idx, nil
}

func newOSVAdvisory(rec osvRecord) *osvAdvisory {
	adv := &osvAdvisory{IDs: appendUnique([]string{rec.ID}, rec.Aliases...)}
	adv.Title = cleanText(rec.Summary, 160)
	if adv.Title == "" {
		adv.Title = firstSentence(rec.Details, 160)
		adv.TitleWeak = true
	}

	sev := severityFromWord(rec.DatabaseSpecific.Severity)
	for _, s := range rec.Severity {
		if !strings.HasPrefix(s.Type, "CVSS_V3") {
			continue
		}
		if score, ok := cvss3Score(s.Score); ok {
			adv.Score = score
			if sev == "" {
				sev = severityFromScore(score)
			}
		}
	}
	adv.Severity = string(sev)

	for _, want := range []string{"WEB", "ADVISORY"} {
		for _, r := range rec.References {
			if r.Type == want && strings.HasPrefix(r.URL, "https://") {
				adv.Link = r.URL
				break
			}
		}
		if adv.Link != "" {
			break
		}
	}
	if adv.Link == "" {
		adv.Link = "https://osv.dev/vulnerability/" + rec.ID
	}
	return adv
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 8<<20))
}

func containsAny(raw []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(raw, n) {
			return true
		}
	}
	return false
}

// firstSentence returns the first sentence of a description, for records
// that come without a summary.
func firstSentence(s string, max int) string {
	s = cleanText(s, 4*max)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	return cleanText(s, max)
}
