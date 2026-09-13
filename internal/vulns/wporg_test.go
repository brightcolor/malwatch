package vulns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brightcolor/malwatch/internal/cms"
)

var sampleStatuses = map[string]string{
	"3.9":    "insecure",
	"3.9.40": "insecure",
	"6.4.2":  "insecure",
	"6.4.3":  "insecure",
	"6.4.10": "outdated",
	"6.9.7":  "outdated",
	"7.0.1":  "latest",
}

func checkerWithStatuses(statuses map[string]string) *Checker {
	c := New(Options{})
	c.stableLoaded = true
	c.stableCheck = statuses
	return c
}

func TestBranchFix(t *testing.T) {
	cases := map[string]string{
		"6.4.2": "6.4.10", // the security release of the 6.4 branch
		"6.4.3": "6.4.10",
		"3.9":   "7.0.1", // a branch without one: the newest release
	}
	for current, want := range cases {
		if got := branchFix(sampleStatuses, current); got != want {
			t.Errorf("%s: %q, want %q", current, got, want)
		}
	}
}

func TestInsecureReleaseWithoutDatabaseEntries(t *testing.T) {
	c := checkerWithStatuses(sampleStatuses)
	core := cms.Install{Product: "wordpress", Kind: "core", Version: "6.4.2"}

	list := finish(merge(c.wordpressOrg(core, nil)))
	if len(list) != 1 || list[0].FixedIn != "6.4.10" || list[0].Sources[0] != srcWordPressOrg {
		t.Fatalf("an insecure release with no database entry must still be listed: %+v", list)
	}
}

func TestInsecureReleaseLendsItsFixToTheEntries(t *testing.T) {
	c := checkerWithStatuses(sampleStatuses)
	core := cms.Install{Product: "wordpress", Kind: "core", Version: "6.4.2"}
	given := []entry{
		{ids: []string{"CVE-2099-20001"}, title: "a", source: srcWPVulnerability},
		{ids: []string{"CVE-2099-20002"}, title: "b", fixedIn: "6.4.3", source: srcWPVulnerability},
		{ids: []string{"CVE-2099-20003"}, title: "c", lastAffected: "6.4.2", source: srcWPVulnerability},
	}

	found := c.wordpressOrg(core, given)
	if len(found) != 3 {
		t.Fatalf("the verdict was added although the databases listed flaws: %+v", found)
	}
	if found[0].fixedIn != "6.4.10" {
		t.Errorf("an entry without a fix got %q, want the branch release 6.4.10", found[0].fixedIn)
	}
	if found[1].fixedIn != "6.4.3" {
		t.Errorf("an entry with its own fix was overwritten: %q", found[1].fixedIn)
	}
	if found[2].fixedIn != "" {
		t.Errorf("an entry with a last affected version was given a fix: %q", found[2].fixedIn)
	}
}

func TestCurrentAndUnknownReleases(t *testing.T) {
	c := checkerWithStatuses(sampleStatuses)
	for _, version := range []string{"7.0.1", "6.9.7", "7.1-alpha-59000"} {
		if found := c.wordpressOrg(cms.Install{Product: "wordpress", Kind: "core", Version: version}, nil); len(found) != 0 {
			t.Errorf("%s: %+v", version, found)
		}
	}
}

func TestTheVerdictAloneLeavesTheInstallUnchecked(t *testing.T) {
	// wordpress.org answers, the vulnerability database is down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/core/stable-check/1.0/" {
			_ = json.NewEncoder(w).Encode(sampleStatuses)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := fakeChecker(srv, t.TempDir(), "")
	list, checked := c.Check(cms.Install{Product: "wordpress", Kind: "core", Version: "6.4.2"})
	if checked {
		t.Error("the install counts as checked although no vulnerability database answered")
	}
	if len(list) != 1 || list[0].FixedIn != "6.4.10" {
		t.Errorf("the verdict of wordpress.org should still be listed: %+v", list)
	}

	list, checked = c.Check(cms.Install{Product: "wordpress", Kind: "core", Version: "7.0.1"})
	if checked || len(list) != 0 {
		t.Errorf("latest release with the database down: checked=%v list=%+v", checked, list)
	}
}
