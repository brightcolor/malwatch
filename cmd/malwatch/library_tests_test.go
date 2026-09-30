package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// scanRules runs a scan over files with extra arguments and returns the rule
// of every finding and the exit code.
func scanRules(t *testing.T, files map[string]string, extra ...string) ([]string, int) {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "r.json")
	args := append([]string{"--path=" + root, "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--out=" + out, "--json"}, extra...)
	code := cmdScan(args)
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, code
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
	return rules, code
}

// The three lists of the addon's section "Testordner von Bibliotheken" reach
// the scanner as --test-dirs, --library-dirs and --test-rules.
func TestScanTakesTheLibraryTestSettings(t *testing.T) {
	bg := "<?php $pid = shell_exec('nohup ./server.sh > /dev/null 2>&1 &');\n"
	files := map[string]string{"web/lib/acme/spec/run.php": bg}
	if got, _ := scanRules(t, files); len(got) != 1 || got[0] != "php.exec.background" {
		t.Fatalf("ohne Schalter: %v, erwartet php.exec.background", got)
	}
	if got, code := scanRules(t, files, "--test-dirs=spec", "--library-dirs=lib, vendor",
		"--test-rules=php.exec.background"); len(got) != 0 || code != report.ExitClean {
		t.Errorf("mit Schaltern: %v, Rückgabewert %d", got, code)
	}
	vendorTest := map[string]string{"web/vendor/acme/lib/test/run.php": bg}
	if got, _ := scanRules(t, vendorTest); len(got) != 0 {
		t.Errorf("Vorgabe: %v", got)
	}
	if got, _ := scanRules(t, vendorTest, "--test-rules="); len(got) != 1 {
		t.Errorf("--test-rules= leer: %v, erwartet einen Fund", got)
	}
}

func TestScanRefusesBadLibraryTestSettings(t *testing.T) {
	for _, arg := range []string{"--test-dirs=../x", "--library-dirs=", "--test-rules=php.eval.request",
		"--test-rules=php.nope"} {
		if _, code := scanRules(t, nil, arg); code != report.ExitError {
			t.Errorf("%s: Rückgabewert %d, erwartet %d", arg, code, report.ExitError)
		}
	}
}

func TestUsageNamesTheLibraryTestSettings(t *testing.T) {
	for _, flag := range []string{"--test-dirs=NAMEN", "--library-dirs=NAMEN", "--test-rules=REGELN"} {
		if !strings.Contains(usageText, flag) {
			t.Errorf("die Hilfe nennt %s nicht", flag)
		}
	}
}
