package vulns

import (
	"testing"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/report"
)

// A WPScan plugin answer. The documentation shows "references.cve" as a list
// in the schema and as a single string in its examples, so both appear.
const wpscanPluginAnswer = `{"sample-forms":{"friendly_name":"Sample Forms","latest_version":"6.2.0","popular":true,"vulnerabilities":[
 {"id":"7391118e-eef5-4ff8-a8ea-f6b65f442c63","title":"Sample Forms < 5.3.2 - Unrestricted File Upload","fixed_in":"5.3.2","introduced_in":null,
  "references":{"cve":["2099-10001"],"url":["https://example.org/a"]},"cvss":null,"verified":true},
 {"id":"a1b2c3d4-0000-4000-8000-000000000001","title":"Sample Forms 5.8.0-5.8.3 - Cross-Site Request Forgery","fixed_in":"5.8.4","introduced_in":"5.8.0",
  "references":{"cve":"2099-10003"},"cvss":{"score":"4.3","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N","severity":"medium"}},
 {"id":"a1b2c3d4-0000-4000-8000-000000000002","title":"Sample Forms <= 6.2.0 - Open Redirect","fixed_in":null,"introduced_in":null,
  "references":{},"cvss":null}
]}}`

const wpscanCoreAnswer = `{"6.4.2":{"release_date":"2023-12-06","changelog_url":"https://example.org/6.4.2","status":"insecure","vulnerabilities":[
 {"id":"b0000000-0000-4000-8000-000000000001","title":"WordPress < 6.4.3 - PHP Object Injection","fixed_in":"6.4.3","introduced_in":"6.4.0","references":{"cve":["2099-20001"]}}
]}}`

func wpscanList(t *testing.T, body string, inst cms.Install) []entry {
	t.Helper()
	found, err := parseWPScan([]byte(body), inst)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return found
}

func TestWPScanRanges(t *testing.T) {
	cases := []struct {
		version string
		want    int
	}{
		{"5.3.1", 2}, // the upload flaw and the unpatched redirect
		{"5.8.1", 2}, // the CSRF from 5.8.0 on, and the redirect
		{"5.8.4", 1},
		// No fix and no lower bound: the redirect affects every version,
		// the newest included. That is what "unpatched" means.
		{"6.2.1", 1},
	}
	for _, c := range cases {
		if got := len(wpscanList(t, wpscanPluginAnswer, plugin("sample-forms", c.version))); got != c.want {
			t.Errorf("%s: %d flaws, want %d", c.version, got, c.want)
		}
	}
}

func TestWPScanReadsBothReferenceShapes(t *testing.T) {
	list := finish(merge(wpscanList(t, wpscanPluginAnswer, plugin("sample-forms", "5.8.1"))))
	var csrf *report.Vulnerability
	for i := range list {
		if list[i].ID == "CVE-2099-10003" {
			csrf = &list[i]
		}
	}
	if csrf == nil {
		t.Fatalf("the CVE given as a bare string was lost: %+v", list)
	}
	if csrf.Severity != report.SeverityMedium || csrf.Score != 4.3 || csrf.FixedIn != "5.8.4" {
		t.Errorf("CSRF flaw: %+v", csrf)
	}
	for _, v := range list {
		if v.ID == "" && (!v.Unfixed || v.Link != "https://wpscan.com/vulnerability/a1b2c3d4-0000-4000-8000-000000000002") {
			t.Errorf("unpatched flaw: %+v", v)
		}
	}
}

func TestWPScanAndWPVulnerabilityMeetOnTheSameFlaw(t *testing.T) {
	inst := plugin("sample-forms", "5.3.1")
	fromWPV, err := parseWPVulnerability([]byte(wpvPluginAnswer), inst)
	if err != nil {
		t.Fatal(err)
	}
	both := finish(merge(append(fromWPV, wpscanList(t, wpscanPluginAnswer, inst)...)))

	// WPVulnerability: the upload flaw (two records), the XSS fixed in 5.9.2,
	// the unfixed stored XSS. WPScan: the upload flaw again, and the open
	// redirect nobody else lists. Four flaws in total.
	if len(both) != 4 {
		t.Fatalf("got %d flaws, want 4: %+v", len(both), both)
	}
	upload := both[0]
	if upload.ID != "CVE-2099-10001" || len(upload.Sources) != 2 {
		t.Errorf("the upload flaw should name both sources: %+v", upload)
	}
}

func TestWPScanCoreAnswer(t *testing.T) {
	core := cms.Install{Product: "wordpress", Kind: "core", Version: "6.4.2"}
	list := finish(merge(wpscanList(t, wpscanCoreAnswer, core)))
	if len(list) != 1 || list[0].ID != "CVE-2099-20001" || list[0].FixedIn != "6.4.3" {
		t.Fatalf("core answer: %+v", list)
	}
}

func TestWPScanEmptyAnswer(t *testing.T) {
	if list := wpscanList(t, `{}`, plugin("anything", "1.0")); len(list) != 0 {
		t.Errorf("the stored not-found answer produced %d flaws", len(list))
	}
}
