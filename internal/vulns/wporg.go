package vulns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// wordpress.org marks every WordPress release as "latest", "outdated" or
// "insecure". It names no flaw. What it does give is the vendor's own verdict
// on every release there ever was, and from it the security release of a
// branch - which is the version a site on that branch has to reach.
const wporgTTL = 24 * time.Hour

func (c *Checker) loadStableCheck() map[string]string {
	if c.stableLoaded {
		return c.stableCheck
	}
	c.stableLoaded = true

	body, err := c.cached(srcWordPressOrg, "wordpress-stable-check.json",
		c.base.WordPressOrg+"/core/stable-check/1.0/", wporgTTL, nil, jsonOK)
	if err != nil {
		return nil
	}
	var statuses map[string]string
	if json.Unmarshal(body, &statuses) != nil {
		return nil
	}
	c.stableCheck = statuses
	return statuses
}

// wordpressOrg completes the list for a WordPress core install.
//
// For an insecure release every flaw without a known end gets the branch's
// security release as its fix. When the databases returned nothing for a
// release wordpress.org calls insecure, the verdict becomes an entry of its
// own, so a gap in a database still leaves the release marked.
//
// Whether the install counts as checked stays with the databases (see
// checkWordPress). A verdict that names no flaw cannot vouch for "nothing
// known".
func (c *Checker) wordpressOrg(inst cms.Install, found []entry) []entry {
	statuses := c.loadStableCheck()
	if statuses[inst.Version] != "insecure" {
		return found
	}

	fix := branchFix(statuses, inst.Version)
	for i := range found {
		if found[i].fixedIn == "" && found[i].lastAffected == "" && !found[i].unfixed {
			found[i].fixedIn = fix
		}
	}
	if len(found) == 0 {
		found = append(found, entry{
			ids:     []string{"wordpress.org:insecure:" + inst.Version},
			title:   "wordpress.org führt diese WordPress-Version als unsicher",
			fixedIn: fix,
			link:    "https://wordpress.org/documentation/wordpress-version/",
			source:  srcWordPressOrg,
		})
	}
	return found
}

// branchFix returns the lowest release above current on the same major and
// minor branch that is not insecure: the security release of that branch.
// Where a branch never got one, the newest release overall.
func branchFix(statuses map[string]string, current string) string {
	best, latest := "", ""
	for v, status := range statuses {
		if status == "latest" {
			latest = v
		}
		if status == "insecure" || cms.Compare(v, current) <= 0 || !cms.SameBranch(v, current, 2) {
			continue
		}
		if best == "" || cms.Compare(v, best) < 0 {
			best = v
		}
	}
	if best == "" {
		return latest
	}
	return best
}

// jsonOK accepts a 200 that is readable JSON.
func jsonOK(status int, body []byte) ([]byte, error) {
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("unlesbare Antwort")
	}
	return body, nil
}
