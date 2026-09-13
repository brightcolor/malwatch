package vulns

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/report"
)

// Records in the OSV schema, reduced to the fields the index reads. The
// Drupal record and the GitHub advisory describe the same flaw, as they do in
// the real archive: one with the ranges and no rating, the other with a
// rating, both sharing the CVE.
var osvSampleRecords = map[string]string{
	"DRUPAL-CORE-2099-001.json": `{"id":"DRUPAL-CORE-2099-001",
		"details":"The Comment module allows users to reply to comments. In certain cases an attacker could trigger a denial of service.",
		"aliases":["CVE-2099-11941","GHSA-aaaa-bbbb-cccc"],
		"references":[{"type":"WEB","url":"https://www.drupal.org/sa-core-2099-001"}],
		"affected":[{"package":{"name":"drupal/core","ecosystem":"Packagist"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"8.0.0"},{"fixed":"10.1.8"}]},
			          {"type":"ECOSYSTEM","events":[{"introduced":"10.2.0"},{"fixed":"10.2.2"}]}]}]}`,
	"GHSA-aaaa-bbbb-cccc.json": `{"id":"GHSA-aaaa-bbbb-cccc","summary":"Drupal core denial of service in the comment module",
		"aliases":["CVE-2099-11941"],"database_specific":{"severity":"MODERATE"},
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
		"affected":[{"package":{"name":"drupal/core","ecosystem":"Packagist"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"10.2.0"},{"fixed":"10.2.2"}]}]}]}`,
	"GHSA-dddd-eeee-ffff.json": `{"id":"GHSA-dddd-eeee-ffff","summary":"TYPO3 open redirect via parsing differences",
		"aliases":["CVE-2099-55892"],"database_specific":{"severity":"MODERATE"},
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
		"affected":[{"package":{"name":"typo3/cms-core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.5.49"}]}]},
		            {"package":{"name":"typo3/cms-core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"12.0.0"},{"fixed":"12.4.25"}]}]}]}`,
	"GHSA-with-drawn.json": `{"id":"GHSA-with-drawn","summary":"withdrawn","withdrawn":"2099-01-01T00:00:00Z",
		"affected":[{"package":{"name":"drupal/core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	"PMA-listed.json": `{"id":"PMA-listed","summary":"phpMyAdmin flaw known by its version list only",
		"affected":[{"package":{"name":"phpmyadmin/phpmyadmin","ecosystem":"Packagist"},
			"ranges":[{"type":"GIT","repo":"https://example.org/pma.git","events":[{"introduced":"0"}]}],
			"versions":["5.2.0","5.2.1"]}]}`,
	"GHSA-shop-ware-six.json": `{"id":"GHSA-shop-ware-six","summary":"Shopware 6 improper session handling",
		"aliases":["CVE-2099-60001"],"database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"name":"shopware/core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.4.20.2"}]}]}]}`,
	"GHSA-shop-ware-five.json": `{"id":"GHSA-shop-ware-five","summary":"Shopware 5 XSS in the backend",
		"aliases":["CVE-2099-50001"],"database_specific":{"severity":"MODERATE"},
		"affected":[{"package":{"name":"shopware/shopware","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"5.0.0"},{"fixed":"5.7.18"}]}]}]}`,
	"GHSA-shop-ware-tmpl.json": `{"id":"GHSA-shop-ware-tmpl","summary":"Shopware 6 flaw filed under the Shopware 5 package name",
		"aliases":["CVE-2099-60002"],"database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"name":"shopware/shopware","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.3.5.3"}]}]}]}`,
	"GHSA-media-wiki-last.json": `{"id":"GHSA-media-wiki-last","summary":"MediaWiki flaw recorded with its last affected release",
		"affected":[{"package":{"name":"mediawiki/core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.39.4"}]}]}]}`,
	"GHSA-joom-la-old.json": `{"id":"GHSA-joom-la-old","summary":"Joomla 3 flaw from before the feed window",
		"aliases":["CVE-2099-30001"],"database_specific":{"severity":"MODERATE"},
		"affected":[{"package":{"name":"joomla/joomla-cms","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"3.9.28"}]}]}]}`,
	"OTHER-1.json": `{"id":"OTHER-1","summary":"somebody else's package",
		"affected":[{"package":{"name":"vendor/other","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	"README": `not a record`,
}

func osvSampleArchive(t *testing.T) []byte {
	t.Helper()
	// Sorted, so the Drupal record comes first and its stand-in title is the
	// one that has to give way (TestMergePrefersAProperTitle covers both
	// orders directly).
	names := make([]string, 0, len(osvSampleRecords))
	for name := range osvSampleRecords {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(osvSampleRecords[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func osvChecker(t *testing.T) *Checker {
	t.Helper()
	idx, err := buildOSVIndex(osvSampleArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{})
	c.osvLoaded = true
	c.osvIndex = idx
	return c
}

func TestOSVIndexKeepsOnlyTheWatchedPackages(t *testing.T) {
	idx, err := buildOSVIndex(osvSampleArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(idx["drupal/core"]); n != 2 {
		t.Errorf("drupal/core: %d advisories, want 2 (the withdrawn one left out)", n)
	}
	if typo3 := idx["typo3/cms-core"]; len(typo3) != 1 || len(typo3[0].Ranges) != 2 {
		t.Errorf("typo3/cms-core: one advisory with both branch ranges expected, got %+v", typo3)
	}
	if _, ok := idx["vendor/other"]; ok {
		t.Error("a package no product maps to was indexed")
	}

	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeOSVIndex(raw)
	if err != nil || len(back["drupal/core"]) != 2 {
		t.Errorf("the stored index does not read back: %v", err)
	}
}

func TestOSVDrupalRecordsMeetOnTheirAliases(t *testing.T) {
	c := osvChecker(t)
	drupal := cms.Install{Product: "drupal", Kind: "core", Version: "10.2.1"}

	list, checked := c.Check(drupal)
	if !checked {
		t.Fatal("the index answered, the install counts as checked")
	}
	if len(list) != 1 {
		t.Fatalf("got %d flaws, want the one described twice: %+v", len(list), list)
	}
	v := list[0]
	if v.ID != "CVE-2099-11941" || v.FixedIn != "10.2.2" || v.Severity != report.SeverityMedium {
		t.Errorf("merged flaw: %+v", v)
	}
	// The GitHub record has a summary; the Drupal record only details, whose
	// first sentence stands in until a proper title turns up.
	if v.Title != "Drupal core denial of service in the comment module" {
		t.Errorf("title %q: the summary of the GitHub record was expected", v.Title)
	}

	if list, _ := c.Check(cms.Install{Product: "drupal", Kind: "core", Version: "10.1.8"}); len(list) != 0 {
		t.Errorf("10.1.8 carries the fix, got %+v", list)
	}
}

func TestOSVTypo3BranchRanges(t *testing.T) {
	c := osvChecker(t)
	list, _ := c.Check(cms.Install{Product: "typo3", Kind: "core", Version: "12.4.0"})
	if len(list) != 1 || list[0].FixedIn != "12.4.25" || list[0].Score != 4.8 {
		t.Fatalf("TYPO3 12.4.0: %+v", list)
	}
	if list, _ := c.Check(cms.Install{Product: "typo3", Kind: "core", Version: "11.5.0"}); len(list) != 0 {
		t.Errorf("11.5.0 is in neither range, got %+v", list)
	}
}

func TestOSVVersionListSaysNothingAboutAFix(t *testing.T) {
	c := osvChecker(t)
	list, _ := c.Check(cms.Install{Product: "phpmyadmin", Kind: "core", Version: "5.2.1"})
	if len(list) != 1 {
		t.Fatalf("5.2.1 is listed as affected: %+v", list)
	}
	if list[0].Unfixed {
		t.Error("a plain version list was reported as having no fix")
	}
	if list, _ := c.Check(cms.Install{Product: "phpmyadmin", Kind: "core", Version: "5.2.2"}); len(list) != 0 {
		t.Errorf("5.2.2 is not listed, got %+v", list)
	}
}

func TestMergePrefersAProperTitle(t *testing.T) {
	standIn := entry{ids: []string{"CVE-2099-7"}, title: "First sentence of the details.", titleWeak: true, source: srcOSV}
	proper := entry{ids: []string{"CVE-2099-7"}, title: "Proper summary", source: srcOSV}

	for _, order := range [][]entry{{standIn, proper}, {proper, standIn}} {
		list := finish(merge(order))
		if len(list) != 1 || list[0].Title != "Proper summary" {
			t.Errorf("order %q then %q: %+v", order[0].title, order[1].title, list)
		}
	}
}

func TestProductWithoutASource(t *testing.T) {
	c := New(Options{})
	for _, inst := range []cms.Install{
		{Product: "nextcloud", Kind: "core", Version: "29.0.1"},
		{Product: "matomo", Kind: "core", Version: "5.1.0"},
		{Product: "magento", Kind: "core", Version: "1.9.4.5"},
	} {
		if list, checked := c.Check(inst); len(list) != 0 || checked {
			t.Errorf("%s %s has no source: list=%v checked=%v", inst.Product, inst.Version, list, checked)
		}
	}
}

func TestOSVShopware6AdvisoriesStayOffShopware5(t *testing.T) {
	c := osvChecker(t)
	five, _ := c.Check(cms.Install{Product: "shopware", Kind: "core", Version: "5.7.17"})
	if len(five) != 1 || five[0].ID != "CVE-2099-50001" {
		t.Errorf("Shopware 5.7.17 should see its own advisory only: %+v", five)
	}
	six, _ := c.Check(cms.Install{Product: "shopware", Kind: "core", Version: "6.4.0"})
	if len(six) != 1 || six[0].ID != "CVE-2099-60001" || six[0].FixedIn != "6.4.20.2" {
		t.Errorf("Shopware 6.4.0 should see the Shopware 6 advisory only: %+v", six)
	}
}

func TestOSVLastAffectedIsKept(t *testing.T) {
	c := osvChecker(t)
	list, _ := c.Check(cms.Install{Product: "mediawiki", Kind: "core", Version: "1.39.3"})
	if len(list) != 1 || list[0].LastAffected != "1.39.4" || list[0].Unfixed || list[0].FixedIn != "" {
		t.Errorf("MediaWiki 1.39.3: %+v", list)
	}
}

func TestJoomlaCountsAsCheckedThroughItsFeedOnly(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security-centre.feed" {
			w.Write([]byte(joomlaSampleFeed))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer up.Close()

	idx, err := buildOSVIndex(osvSampleArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	joomla := cms.Install{Product: "joomla", Kind: "core", Version: "3.9.27"}

	c := fakeChecker(down, "", "")
	c.osvLoaded, c.osvIndex = true, idx
	list, checked := c.Check(joomla)
	if checked {
		t.Error("the feed is down; the old GitHub advisory alone must leave the install unchecked")
	}
	if len(list) != 1 || list[0].ID != "CVE-2099-30001" {
		t.Errorf("the OSV entry should still be listed: %+v", list)
	}

	c = fakeChecker(up, "", "")
	c.osvLoaded, c.osvIndex = true, idx
	list, checked = c.Check(joomla)
	if !checked || len(list) != 2 {
		t.Errorf("feed up: checked=%v, want the upload announcement and the OSV entry: %+v", checked, list)
	}
}
