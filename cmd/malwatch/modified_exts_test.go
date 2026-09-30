package main

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/scanner"
)

// --modified-exts names the extensions where a vendor file that differs from
// the release counts, as the setting of the addon passes them.
func TestScanRefusesABadModifiedExt(t *testing.T) {
	for _, value := range []string{"p.hp", "", "PHP/js", strings.Repeat("a", scanner.MaxModifiedExtLength+1)} {
		code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav",
			"--modified-exts=" + value})
		if code != report.ExitError {
			t.Errorf("--modified-exts=%q: Rückgabewert %d, erwartet %d", value, code, report.ExitError)
		}
	}
}

func TestScanTakesModifiedExts(t *testing.T) {
	code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--modified-exts=php, .JS,txt"})
	if code != report.ExitClean {
		t.Errorf("Rückgabewert %d, erwartet %d", code, report.ExitClean)
	}
}

func TestCheckModifiedExts(t *testing.T) {
	if err := scanner.CheckModifiedExts(scanner.DefaultModifiedExts); err != nil {
		t.Errorf("die Vorgabe selbst wird abgelehnt: %v", err)
	}
	many := make([]string, scanner.MaxModifiedExts+1)
	for i := range many {
		many[i] = "e"
	}
	for _, list := range [][]string{nil, many, {"ph p"}} {
		if err := scanner.CheckModifiedExts(list); err == nil {
			t.Errorf("%v: angenommen", list)
		}
	}
}

func TestUsageNamesTheModifiedExts(t *testing.T) {
	if !strings.Contains(usageText, "--modified-exts=ENDUNGEN") {
		t.Error("die Hilfe nennt --modified-exts nicht")
	}
}
