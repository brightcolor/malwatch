package cms

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Lookup resolves the newest released version of a product. Results are
// cached for the lifetime of the run and, through Cache, across runs.
type Lookup struct {
	client *http.Client
	cache  *Cache
	// errs collects lookups that failed, so the report can say "unknown"
	// instead of silently treating an install as current.
	errs []string
}

// NewLookup returns a lookup with a bounded timeout.
func NewLookup(cache *Cache, timeout time.Duration) *Lookup {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Lookup{
		client: &http.Client{Timeout: timeout},
		cache:  cache,
	}
}

// Errors returns the lookups that could not be answered.
func (l *Lookup) Errors() []string { return l.errs }

// Latest returns the newest version of a core product, or "" if it could not
// be determined. current is the installed version; it selects the right
// maintenance branch where a vendor supports several.
func (l *Lookup) Latest(product, current string) string {
	key := "core:" + product
	if v, ok := l.cache.Get(key); ok {
		return pickBranch(v, current)
	}
	versions, err := l.fetchCore(product)
	if err != nil {
		l.note("%s: aktuelle Version nicht ermittelbar (%v)", product, err)
		return ""
	}
	if len(versions) == 0 {
		l.note("%s: die Herstellerquelle nannte keine Version", product)
		return ""
	}
	l.cache.Set(key, versions)
	return pickBranch(versions, current)
}

// LatestPlugin returns the newest version of a WordPress plugin or theme.
func (l *Lookup) LatestPlugin(kind, slug string) string {
	key := kind + ":" + slug
	if v, ok := l.cache.Get(key); ok {
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	v, err := l.fetchWordPressExtra(kind, slug)
	if err != nil {
		// A plugin that is not on wordpress.org is the normal case for paid
		// and custom plugins. It is recorded as unknown, not as an error.
		l.cache.Set(key, nil)
		return ""
	}
	l.cache.Set(key, []string{v})
	return v
}

// pickBranch chooses the newest version on the same major branch as current.
// A site on Drupal 10 is measured against the newest Drupal 10, not against
// Drupal 12 - otherwise every supported install would read as outdated.
func pickBranch(versions []string, current string) string {
	if len(versions) == 0 {
		return ""
	}
	sorted := append([]string(nil), versions...)
	sort.Slice(sorted, func(i, j int) bool { return Compare(sorted[i], sorted[j]) > 0 })

	for _, v := range sorted {
		if SameBranch(v, current, 1) {
			return v
		}
	}
	return sorted[0]
}

func (l *Lookup) note(format string, args ...any) {
	l.errs = append(l.errs, fmt.Sprintf(format, args...))
}

func (l *Lookup) fetchCore(product string) ([]string, error) {
	switch product {
	case "wordpress":
		return l.wordpressCore()
	case "joomla":
		return l.joomlaCore()
	case "drupal":
		return l.drupalCore()
	case "typo3":
		return l.typo3Core()
	case "phpmyadmin":
		return l.phpmyadminCore()
	case "matomo":
		return l.matomoCore()
	case "nextcloud":
		return l.githubLatest("nextcloud/server")
	case "magento":
		return l.githubLatest("magento/magento2")
	case "mediawiki":
		return l.mediawikiCore()
	case "contao":
		return l.packagist("contao/core-bundle")
	case "shopware":
		return l.packagist("shopware/core")
	}
	return nil, fmt.Errorf("kein Abgleich für %s hinterlegt", product)
}

func (l *Lookup) getJSON(url string, into any) error {
	body, err := l.get(url)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

func (l *Lookup) get(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "malwatch")
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// A vendor answering with megabytes must not exhaust the scanner's memory.
	return io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
}

func (l *Lookup) wordpressCore() ([]string, error) {
	var payload struct {
		Offers []struct {
			Version string `json:"version"`
			Current string `json:"current"`
		} `json:"offers"`
	}
	if err := l.getJSON("https://api.wordpress.org/core/version-check/1.7/", &payload); err != nil {
		return nil, err
	}
	var out []string
	for _, o := range payload.Offers {
		if o.Current != "" {
			out = append(out, o.Current)
		} else if o.Version != "" {
			out = append(out, o.Version)
		}
	}
	return out, nil
}

func (l *Lookup) joomlaCore() ([]string, error) {
	body, err := l.get("https://update.joomla.org/core/list.xml")
	if err != nil {
		return nil, err
	}
	var set struct {
		Extensions []struct {
			Version string `xml:"version,attr"`
		} `xml:"extension"`
	}
	if err := xml.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	var out []string
	for _, e := range set.Extensions {
		if e.Version != "" {
			out = append(out, e.Version)
		}
	}
	return out, nil
}

func (l *Lookup) drupalCore() ([]string, error) {
	body, err := l.get("https://updates.drupal.org/release-history/drupal/current")
	if err != nil {
		return nil, err
	}
	var project struct {
		Releases struct {
			Release []struct {
				Version string `xml:"version"`
				Status  string `xml:"status"`
			} `xml:"release"`
		} `xml:"releases"`
	}
	if err := xml.Unmarshal(body, &project); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range project.Releases.Release {
		if r.Status != "published" || r.Version == "" {
			continue
		}
		// Skip alphas, betas and release candidates: a production site is
		// not outdated because a preview of the next major exists.
		if isPreRelease(r.Version) {
			continue
		}
		out = append(out, r.Version)
	}
	return out, nil
}

func (l *Lookup) typo3Core() ([]string, error) {
	var majors []struct {
		Version       json.Number `json:"version"`
		LatestRelease string      `json:"latest_release"`
	}
	if err := l.getJSON("https://get.typo3.org/api/v1/major/", &majors); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range majors {
		if m.LatestRelease != "" && !isPreRelease(m.LatestRelease) {
			out = append(out, m.LatestRelease)
		}
	}
	return out, nil
}

func (l *Lookup) phpmyadminCore() ([]string, error) {
	var payload struct {
		Version  string `json:"version"`
		Releases []struct {
			Version string `json:"version"`
		} `json:"releases"`
	}
	if err := l.getJSON("https://www.phpmyadmin.net/home_page/version.json", &payload); err != nil {
		return nil, err
	}
	var out []string
	if payload.Version != "" {
		out = append(out, payload.Version)
	}
	for _, r := range payload.Releases {
		if r.Version != "" {
			out = append(out, r.Version)
		}
	}
	return out, nil
}

func (l *Lookup) matomoCore() ([]string, error) {
	body, err := l.get("https://api.matomo.org/1.0/getLatestVersion/")
	if err != nil {
		return nil, err
	}
	v := strings.TrimSpace(string(body))
	if v == "" {
		return nil, fmt.Errorf("leere Antwort")
	}
	return []string{v}, nil
}

var mediawikiDirRe = regexp.MustCompile(`href="(\d+\.\d+)/"`)
var mediawikiTarRe = regexp.MustCompile(`mediawiki-(\d+\.\d+\.\d+)\.tar\.gz`)

func (l *Lookup) mediawikiCore() ([]string, error) {
	index, err := l.get("https://releases.wikimedia.org/mediawiki/")
	if err != nil {
		return nil, err
	}
	branches := uniqueStrings(mediawikiDirRe, index, 1)
	sort.Slice(branches, func(i, j int) bool { return Compare(branches[i], branches[j]) > 0 })
	if len(branches) > 4 {
		branches = branches[:4]
	}
	var out []string
	for _, b := range branches {
		page, err := l.get("https://releases.wikimedia.org/mediawiki/" + b + "/")
		if err != nil {
			continue
		}
		versions := uniqueStrings(mediawikiTarRe, page, 1)
		sort.Slice(versions, func(i, j int) bool { return Compare(versions[i], versions[j]) > 0 })
		if len(versions) > 0 {
			out = append(out, versions[0])
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("keine Version im Verzeichnis gefunden")
	}
	return out, nil
}

func (l *Lookup) githubLatest(repo string) ([]string, error) {
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := l.getJSON("https://api.github.com/repos/"+repo+"/releases/latest", &payload); err != nil {
		return nil, err
	}
	v := strings.TrimPrefix(strings.TrimSpace(payload.TagName), "v")
	if v == "" {
		return nil, fmt.Errorf("leerer Tag-Name")
	}
	return []string{v}, nil
}

func (l *Lookup) packagist(pkg string) ([]string, error) {
	var payload struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := l.getJSON("https://repo.packagist.org/p2/"+pkg+".json", &payload); err != nil {
		return nil, err
	}
	var out []string
	for _, releases := range payload.Packages {
		for _, r := range releases {
			v := strings.TrimPrefix(r.Version, "v")
			if v == "" || isPreRelease(v) {
				continue
			}
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("keine stabile Version im Paketverzeichnis")
	}
	return out, nil
}

func (l *Lookup) fetchWordPressExtra(kind, slug string) (string, error) {
	base := "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
	if kind == "theme" {
		base = "https://api.wordpress.org/themes/info/1.2/?action=theme_information"
	}
	u := base + "&request[slug]=" + url.QueryEscape(slug) +
		"&request[fields][sections]=0&request[fields][description]=0&request[fields][versions]=0"

	var payload struct {
		Version string          `json:"version"`
		Error   json.RawMessage `json:"error"`
	}
	if err := l.getJSON(u, &payload); err != nil {
		return "", err
	}
	if payload.Version == "" {
		return "", fmt.Errorf("nicht im Verzeichnis")
	}
	return payload.Version, nil
}

func isPreRelease(v string) bool {
	low := strings.ToLower(v)
	for _, marker := range []string{"alpha", "beta", "-rc", "rc1", "rc2", "rc3", "dev", "unstable"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func uniqueStrings(re *regexp.Regexp, body []byte, group int) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllSubmatch(body, -1) {
		if len(m) <= group {
			continue
		}
		s := string(m[group])
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
