package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// scanPage scans one page and returns the rules that reported it.
func scanPage(t *testing.T, page string, extra ...string) []string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "about.html"), []byte(page), 0o640); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	args := append([]string{"--path=" + root, "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--out=" + out, "--json"}, extra...)
	if code := cmdScan(args); code == report.ExitError {
		t.Fatalf("Rückgabewert %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, f := range doc.Findings {
		rules = append(rules, f.Rule)
	}
	return rules
}

// --script-hosts names the hosts a script written by document.write may load
// from, as the setting of the addon passes them; an empty value leaves only
// the site itself.
func TestScanTakesTheScriptHosts(t *testing.T) {
	page := "<script>document." + "write(unescape('%3Cscript src=\"https://cdn.example.org/x.js\"%3E%3C/script%3E'))</script>"
	if got := scanPage(t, page); !strings.Contains(strings.Join(got, ","), "js.document_write_encoded") {
		t.Errorf("mit der Vorgabe: %v, erwartet js.document_write_encoded", got)
	}
	if got := scanPage(t, page, "--script-hosts=cdn.example.org"); len(got) != 0 {
		t.Errorf("mit cdn.example.org: %v, erwartet keinen Fund", got)
	}
	ga := "<script>document." + "write(unescape(\"%3Cscript src='\" + gaJsHost + \"google-analytics.com/ga.js'%3E%3C/script%3E\"))</script>"
	if got := scanPage(t, ga); len(got) != 0 {
		t.Errorf("Google Analytics mit der Vorgabe: %v, erwartet keinen Fund", got)
	}
	if got := scanPage(t, ga, "--script-hosts="); len(got) == 0 {
		t.Error("Google Analytics mit leerer Liste: kein Fund")
	}
}

func TestScanRefusesABadScriptHost(t *testing.T) {
	for _, value := range []string{"https://x.example", "x.example/js", "*"} {
		code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav",
			"--script-hosts=" + value})
		if code != report.ExitError {
			t.Errorf("--script-hosts=%q: Rückgabewert %d, erwartet %d", value, code, report.ExitError)
		}
	}
}

func TestUsageNamesTheScriptHosts(t *testing.T) {
	if !strings.Contains(usageText, "--script-hosts=HOSTS") {
		t.Error("die Hilfe nennt --script-hosts nicht")
	}
}
