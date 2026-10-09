package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanMailArgs is a scan of an empty folder that mails its report through
// srv, as relay, without TLS (the fake server sits on 127.0.0.1).
func scanMailArgs(t *testing.T, srv *fakeSMTP, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	return append([]string{
		"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--no-version-scan",
		"--sig-dir=" + filepath.Join(dir, "sigs"), "--state-dir=" + filepath.Join(dir, "state"),
		"--whitelist-path=" + filepath.Join(dir, "whitelist"), "--json", "--out=" + filepath.Join(dir, "r.json"),
		"--email=admin@example.com", "--email-from=malwatch@example.com", "--email-empty",
		"--smtp=" + srv.addr, "--smtp-tls=none", "--smtp-user=relay",
	}, extra...)
}

// authOf is the password the fake server received with AUTH PLAIN.
func authOf(t *testing.T, srv *fakeSMTP) string {
	t.Helper()
	<-srv.done
	raw, err := base64.StdEncoding.DecodeString(srv.auth)
	if err != nil {
		t.Fatalf("AUTH PLAIN %q: %v", srv.auth, err)
	}
	return strings.TrimPrefix(string(raw), "\x00relay\x00")
}

func TestScanMailsWithThePasswordFromTheFile(t *testing.T) {
	srv := startFakeSMTP(t)
	passFile := filepath.Join(t.TempDir(), "smtp.pass")
	if err := os.WriteFile(passFile, []byte("aus-der-datei\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(smtpPassEnv, "aus-der-umgebung")

	if code := cmdScan(scanMailArgs(t, srv, "--smtp-pass-file="+passFile)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := authOf(t, srv); got != "aus-der-datei" {
		t.Errorf("password %q, want the one from the file", got)
	}
}

func TestScanMailsWithThePasswordFromTheEnvironment(t *testing.T) {
	srv := startFakeSMTP(t)
	t.Setenv(smtpPassEnv, "aus-der-umgebung")

	if code := cmdScan(scanMailArgs(t, srv)); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := authOf(t, srv); got != "aus-der-umgebung" {
		t.Errorf("password %q, want the one from %s", got, smtpPassEnv)
	}
}

// --smtp-pass stays for existing calls, and as the switch it is it wins over
// the environment.
func TestScanStillTakesThePasswordFromTheSwitch(t *testing.T) {
	srv := startFakeSMTP(t)
	t.Setenv(smtpPassEnv, "aus-der-umgebung")

	if code := cmdScan(scanMailArgs(t, srv, "--smtp-pass=vom-schalter")); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if got := authOf(t, srv); got != "vom-schalter" {
		t.Errorf("password %q, want the one from --smtp-pass", got)
	}
}

func TestScanRefusesBothPasswordSwitchesBeforeScanning(t *testing.T) {
	passFile := filepath.Join(t.TempDir(), "smtp.pass")
	if err := os.WriteFile(passFile, []byte("geheim"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	var code int
	stderr := stderrOf(t, func() {
		code = cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--out=" + out,
			"--email=admin@example.com", "--smtp-pass=geheim", "--smtp-pass-file=" + passFile})
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if !strings.Contains(stderr, "--smtp-pass und --smtp-pass-file") || !strings.Contains(stderr, "Bitte nur --smtp-pass-file angeben") {
		t.Errorf("stderr %q does not name the two switches and the way out", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("the scan ran although the call was refused")
	}
}

func TestScanRefusesAnUnreadablePasswordFileBeforeScanning(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "fehlt.pass")
	out := filepath.Join(t.TempDir(), "r.json")
	var code int
	stderr := stderrOf(t, func() {
		code = cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--out=" + out,
			"--email=admin@example.com", "--smtp-pass-file=" + missing})
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if !strings.Contains(stderr, "Die Passwortdatei "+missing+" ist nicht lesbar") ||
		!strings.Contains(stderr, "Bitte Pfad und Rechte der Datei prüfen.") {
		t.Errorf("stderr %q does not name the file and the next step", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("the scan ran although the password file is missing")
	}
}

// Without --email the password is not needed, and a missing file holds no
// scan up.
func TestScanWithoutMailIgnoresThePasswordFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.json")
	code := cmdScan([]string{"--path=" + t.TempDir(), "--quiet", "--offline", "--no-clamav", "--json", "--out=" + out,
		"--smtp-pass-file=" + filepath.Join(t.TempDir(), "fehlt.pass")})
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("no report: %v", err)
	}
}

// The help points to the file and the environment for scan as for send-mail.
func TestUsageNamesThePasswordWaysForScan(t *testing.T) {
	var buf strings.Builder
	usage(&buf)
	help := strings.Join(strings.Fields(buf.String()), " ")
	for _, want := range []string{
		"--smtp-user=NAME Anmeldename für den SMTP-Server; das Kennwort kommt aus --smtp-pass-file=DATEI oder der Umgebungsvariablen MALWATCH_SMTP_PASS, die Datei geht vor",
		"--smtp-pass=WERT Kennwort auf der Befehlszeile, für bestehende Aufrufe; dort ist es für jeden Benutzer der Maschine lesbar, deshalb besser --smtp-pass-file",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}
