package report

import (
	"strings"
	"testing"
)

func vulnerableReport() *Report {
	r := New([]string{"/var/www/example"})
	r.Host = "web01"
	r.Software = []Software{
		{
			Path: "/var/www/example", Product: "wordpress", Kind: "core", Version: "6.4.2",
			Latest: "6.9.7", Outdated: true, UpdateTo: "6.4.3",
			Vulns: []Vulnerability{{ID: "CVE-2099-1", Title: "Object injection", Severity: SeverityHigh,
				Score: 7.2, FixedIn: "6.4.3", Sources: []string{"WPVulnerability"}}},
		},
		{
			Path: "/var/www/example/wp-content/plugins/sample", Product: "wordpress", Kind: "plugin",
			Slug: "sample", Version: "2.0", Latest: "2.0",
			Vulns: []Vulnerability{{Title: "Stored XSS", LastAffected: "2.0", Sources: []string{"WPScan"}}},
		},
		{
			Path: "/var/www/example/wp-content/plugins/other", Product: "wordpress", Kind: "plugin",
			Slug: "other", Version: "1.0", Latest: "1.1", Outdated: true,
		},
	}
	return r
}

func TestExitCodeCountsKnownFlaws(t *testing.T) {
	// Up to date and still vulnerable: the vendor has not fixed it yet.
	r := New(nil)
	r.Software = []Software{{Product: "wordpress", Kind: "plugin", Slug: "x", Version: "1.0", Latest: "1.0",
		Vulns: []Vulnerability{{Title: "unfixed", Unfixed: true}}}}
	if code := r.ExitCode(SeverityMedium); code != ExitOutdated {
		t.Errorf("an up-to-date install with a known flaw exits %d, want %d", code, ExitOutdated)
	}
}

func TestTextListsKnownFlawsFirst(t *testing.T) {
	var b strings.Builder
	if err := vulnerableReport().WriteText(&b, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Web-Software: 3 erkannt, 2 mit bekannten Lücken, 2 veraltet, 0 aktuell",
		"Lücken: wordpress 6.4.2 in /var/www/example (alle behoben ab 6.4.3)",
		"hoch 7.2  CVE-2099-1  Object injection, behoben in 6.4.3",
		"nicht eingestuft  Stored XSS, betroffen bis 2.0",
		"veraltet: wordpress other 1.0 (aktuell ist 1.1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the text report lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Lücken: wordpress 6.4.2") > strings.Index(out, "veraltet: wordpress other") {
		t.Error("the known flaws come after the merely outdated install")
	}
	if strings.Contains(out, "veraltet: wordpress 6.4.2") {
		t.Error("the vulnerable core is listed a second time as outdated")
	}
}

func TestUpdateLineCountsTheFlawsItFixes(t *testing.T) {
	r := New(nil)
	r.Software = []Software{{
		Path: "/p", Product: "wordpress", Kind: "plugin", Slug: "forms", Version: "5.3.1", UpdateTo: "5.9.2",
		Vulns: []Vulnerability{
			{Title: "a", FixedIn: "5.3.2"},
			{Title: "b", FixedIn: "5.9.2"},
			{Title: "c", LastAffected: "6.1.0"},
		},
	}}
	var b strings.Builder
	if err := r.WriteText(&b, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(2 von 3 behoben ab 5.9.2)") {
		t.Errorf("an update that leaves one flaw open was described as fixing all:\n%s", b.String())
	}
}

func TestSubjectNamesKnownFlaws(t *testing.T) {
	if got := vulnerableReport().Subject(); got != "malwatch: 2 Installation(en) mit bekannten Lücken auf web01" {
		t.Errorf("subject %q", got)
	}
}
