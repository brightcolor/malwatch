package main

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// The check against Composer archives is steered by these switches, as the
// settings of the addon pass them; a value outside its limits is refused
// before anything is scanned.
func TestScanRefusesBadVerifyValues(t *testing.T) {
	for _, arg := range []string{
		"--verify-hosts=https://github.com", "--verify-hosts=github.com/x",
		"--verify-max-downloads=0", "--verify-max-downloads=1001",
		"--verify-max-mb=0", "--verify-max-mb=501",
		"--verify-timeout=0", "--verify-timeout=601",
		"--verify-retry-hours=-1", "--verify-retry-hours=721",
	} {
		code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", arg})
		if code != report.ExitError {
			t.Errorf("%s: Rückgabewert %d, erwartet %d", arg, code, report.ExitError)
		}
	}
}

func TestScanTakesVerifyValues(t *testing.T) {
	code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--no-verify-composer", "--no-verify-originals", "--verify-hosts=codeload.github.com", "--verify-max-downloads=3",
		"--verify-max-mb=10", "--verify-timeout=20", "--verify-retry-hours=0"})
	if code != report.ExitClean {
		t.Errorf("Rückgabewert %d, erwartet %d", code, report.ExitClean)
	}
}

func TestUsageNamesTheVerifySwitches(t *testing.T) {
	for _, s := range []string{"--no-verify-composer", "--no-verify-originals", "--verify-hosts=HOSTS", "--verify-max-downloads=N",
		"--verify-max-mb=N", "--verify-timeout=S", "--verify-retry-hours=N"} {
		if !strings.Contains(usageText, s) {
			t.Errorf("die Hilfe nennt %s nicht", s)
		}
	}
}
