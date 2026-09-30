package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// --php-version names the PHP of the website where --php does not; rules about
// constructs that PHP no longer runs stay silent there.
func TestScanTakesThePHPVersion(t *testing.T) {
	src := `<?php $s = preg_replace('/(\w+)/e', "strtoupper('$1')", $x);`
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "old.php"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) int {
		args := append([]string{"--path=" + root, "--quiet", "--offline", "--no-clamav", "--no-version-scan"}, extra...)
		return cmdScan(args)
	}
	if code := run(); code != report.ExitFindings {
		t.Errorf("ohne Version: Rückgabewert %d, erwartet %d", code, report.ExitFindings)
	}
	if code := run("--php-version=7.4.33"); code != report.ExitClean {
		t.Errorf("PHP 7.4.33: Rückgabewert %d, erwartet %d", code, report.ExitClean)
	}
	if code := run("--php-version=5.6"); code != report.ExitFindings {
		t.Errorf("PHP 5.6: Rückgabewert %d, erwartet %d", code, report.ExitFindings)
	}
}

func TestScanRefusesABadPHPVersion(t *testing.T) {
	for _, value := range []string{"php7", "7.4.33.1", "latest"} {
		code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--php-version=" + value})
		if code != report.ExitError {
			t.Errorf("--php-version=%q: Rückgabewert %d, erwartet %d", value, code, report.ExitError)
		}
	}
	if !strings.Contains(usageText, "--php-version=VERSION") {
		t.Error("die Hilfe nennt --php-version nicht")
	}
}
