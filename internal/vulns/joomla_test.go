package vulns

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// Three announcements in the markup the Security Centre feed uses. The
// framework one carries the misspelt "Framewok" the live feed has, and the
// first label ends in a non-breaking space the way the live feed writes it.
var joomlaSampleFeed = strings.ReplaceAll(joomlaSampleFeedRaw, "{NBSP}", string(rune(0x00A0)))

const joomlaSampleFeedRaw = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
	<channel>
		<title>Security Announcements</title>
		<item>
			<title>[20990810] - Core - Unrestricted uploads of sample files</title>
			<link>https://developer.joomla.org/security-centre/9001-sample.html</link>
			<description><![CDATA[<ul>
<li><strong>Project:</strong> Joomla!</li>
<li><strong>SubProject:</strong> CMS</li>
<li><strong>Impact:</strong> High</li>
<li><strong>Severity:</strong> Low</li>
  <li><strong>Versions:{NBSP}</strong>1.0.0-5.4.7,6.0.0-6.1.2</li>
<li><strong>CVE Number:</strong> <a href="https://www.cve.org/CVERecord?id=CVE-2099-73373">CVE-2099-73373</a></li>
</ul>
<h3>Solution</h3>
<p>Upgrade to version 5.4.8, 6.1.3</p>]]></description>
		</item>
		<item>
			<title>[20990411] - Core - XSS in a sample layout</title>
			<link>https://developer.joomla.org/security-centre/9002-sample.html</link>
			<description><![CDATA[<ul>
<li><strong>SubProject:</strong> CMS</li>
<li><strong>Severity:</strong> Moderate</li>
<li><strong>Versions: </strong>4.0.0-4.4.x</li>
</ul>
<p>Upgrade to version 4.4.14</p>]]></description>
		</item>
		<item>
			<title>[20990520] - Framework - Inadequate content filtering</title>
			<link>https://developer.joomla.org/security-centre/9003-sample.html</link>
			<description><![CDATA[<ul>
<li><strong>SubProject:</strong> Framewok</li>
<li><strong>Severity:</strong> Moderate</li>
<li><strong>Versions: </strong>1.0.0-4.0.0</li>
</ul>
<p>Upgrade to version 4.0.1</p>]]></description>
		</item>
	</channel>
</rss>`

func TestJoomlaFeedReadsTheCMSAnnouncements(t *testing.T) {
	items, err := parseJoomlaFeed([]byte(joomlaSampleFeed))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d announcements, want the 2 for the CMS", len(items))
	}
	first := items[0]
	if first.title != "Unrestricted uploads of sample files" {
		t.Errorf("title %q", first.title)
	}
	if first.cve != "CVE-2099-73373" || first.severity != report.SeverityLow || len(first.fixes) != 2 {
		t.Errorf("first announcement: %+v", first)
	}
}

func TestJoomlaFixFollowsTheBranch(t *testing.T) {
	items, err := parseJoomlaFeed([]byte(joomlaSampleFeed))
	if err != nil {
		t.Fatal(err)
	}
	upload, xss := items[0], items[1]

	cases := []struct {
		name     string
		a        joomlaAdvisory
		version  string
		affected bool
		fix      string
	}{
		{"5.x gets the 5.x fix", upload, "5.4.7", true, "5.4.8"},
		{"6.x gets the 6.x fix", upload, "6.1.2", true, "6.1.3"},
		{"an old major is told the lowest current fix", upload, "3.10.12", true, "5.4.8"},
		{"the fixed release", upload, "5.4.8", false, ""},
		{"a trailing x covers the branch", xss, "4.4.13", true, "4.4.14"},
		{"outside the branch", xss, "5.0.0", false, ""},
	}
	for _, c := range cases {
		fix, affected := c.a.affects(c.version)
		if affected != c.affected || fix != c.fix {
			t.Errorf("%s: affected=%v fix=%q, want %v %q", c.name, affected, fix, c.affected, c.fix)
		}
	}
}

func TestJoomlaSpansSkipWhatTheyCannotRead(t *testing.T) {
	spans := joomlaSpans("1.5.0-1.5.26, all versions, 2.5.x ,3.0.0-")
	if len(spans) != 2 {
		t.Fatalf("got %d ranges, want 2 (1.5.0-1.5.26 and 2.5.x): %+v", len(spans), spans)
	}
}
