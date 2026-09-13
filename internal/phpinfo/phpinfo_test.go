package phpinfo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fakePHP makes Version start this test binary, which prints what the test
// asks for instead of running PHP.
func fakePHP(t *testing.T, output string) {
	t.Helper()
	command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperPHP", "--")
		cmd.Env = append(os.Environ(), "MALWATCH_FAKE_PHP=1", "MALWATCH_FAKE_PHP_OUTPUT="+output)
		return cmd
	}
	t.Cleanup(func() { command = exec.CommandContext })
}

// TestHelperPHP is the fake binary itself. Outside fakePHP it does nothing.
func TestHelperPHP(t *testing.T) {
	if os.Getenv("MALWATCH_FAKE_PHP") != "1" {
		return
	}
	fmt.Print(os.Getenv("MALWATCH_FAKE_PHP_OUTPUT"))
	os.Exit(0)
}

func TestVersionReadsWhatPHPPrints(t *testing.T) {
	fakePHP(t, "8.2.10")
	v, err := Version("/usr/bin/php8.2", 5*time.Second)
	if err != nil || v != "8.2.10" {
		t.Fatalf("Version = %q, %v; want 8.2.10", v, err)
	}
}

func TestVersionDropsADistributionSuffix(t *testing.T) {
	fakePHP(t, "8.3.6-1+ubuntu22.04.1+deb.sury.org+1")
	v, err := Version("/usr/bin/php8.3", 5*time.Second)
	if err != nil || v != "8.3.6" {
		t.Fatalf("Version = %q, %v; want 8.3.6", v, err)
	}
}

func TestVersionRefusesOutputWithoutAVersion(t *testing.T) {
	fakePHP(t, "PHP Parse error: syntax error")
	_, err := Version("/usr/bin/php", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "nannte keine PHP-Version") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestVersionNeedsABinary(t *testing.T) {
	if _, err := Version("", 0); err == nil {
		t.Fatal("an empty binary was accepted")
	}
}
