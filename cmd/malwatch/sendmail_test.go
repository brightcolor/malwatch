package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/brightcolor/malwatch/internal/mail"
)

// fakeSMTP answers one SMTP session on localhost and records what it got.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	auth string
	from string
	rcpt []string
	data string
	done chan struct{}
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		w("220 localhost ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				w("250-localhost")
				w("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH PLAIN"):
				f.mu.Lock()
				f.auth = strings.TrimSpace(line[len("AUTH PLAIN"):])
				f.mu.Unlock()
				w("235 ok")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				f.mu.Lock()
				f.from = line[len("MAIL FROM:"):]
				f.mu.Unlock()
				w("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				f.mu.Lock()
				f.rcpt = append(f.rcpt, line[len("RCPT TO:"):])
				f.mu.Unlock()
				w("250 ok")
			case cmd == "DATA":
				w("354 go ahead")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				f.mu.Lock()
				f.data = b.String()
				f.mu.Unlock()
				w("250 queued")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return f
}

func TestSendMailDeliversTheMessageAsItIs(t *testing.T) {
	srv := startFakeSMTP(t)
	dir := t.TempDir()
	msg := "From: malwatch <malwatch@example.com>\nTo: admin@example.com\nSubject: Test\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nZeile eins\n.Zeile mit Punkt\n"
	path := filepath.Join(dir, "mail.eml")
	if err := os.WriteFile(path, []byte(msg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(smtpPassEnv, "geheim-aus-der-umgebung")

	code := cmdSendMail([]string{"--message=" + path, "--to=admin@example.com, zweite@example.com",
		"--from=malwatch@example.com", "--smtp=" + srv.addr, "--smtp-tls=none", "--smtp-user=relay"})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	<-srv.done

	raw, _ := base64.StdEncoding.DecodeString(srv.auth)
	if got := string(raw); got != "\x00relay\x00geheim-aus-der-umgebung" {
		t.Errorf("auth = %q: the password must come from the environment", got)
	}
	if srv.from != "<malwatch@example.com>" {
		t.Errorf("envelope from = %q", srv.from)
	}
	if strings.Join(srv.rcpt, " ") != "<admin@example.com> <zweite@example.com>" {
		t.Errorf("recipients = %v", srv.rcpt)
	}
	if !strings.Contains(srv.data, "Subject: Test\r\n") || !strings.Contains(srv.data, "\r\nZeile eins\r\n") {
		t.Errorf("message not delivered with CRLF line ends:\n%q", srv.data)
	}
	if !strings.Contains(srv.data, "\r\n..Zeile mit Punkt\r\n") {
		t.Errorf("a line starting with a dot must be dot-stuffed on the wire:\n%q", srv.data)
	}
}

func TestSendMailPasswordFileWinsOverTheEnvironment(t *testing.T) {
	srv := startFakeSMTP(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.eml")
	os.WriteFile(path, []byte("Subject: x\n\nx\n"), 0o600)
	passFile := filepath.Join(dir, "pass")
	os.WriteFile(passFile, []byte("aus-der-datei\n"), 0o600)
	t.Setenv(smtpPassEnv, "aus-der-umgebung")

	if code := cmdSendMail([]string{"--message=" + path, "--to=a@example.com", "--smtp=" + srv.addr,
		"--smtp-tls=none", "--smtp-user=relay", "--smtp-pass-file=" + passFile}); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	<-srv.done
	raw, _ := base64.StdEncoding.DecodeString(srv.auth)
	if got := string(raw); got != "\x00relay\x00aus-der-datei" {
		t.Errorf("auth = %q", got)
	}
}

func TestSendMailTakesATimeoutWithinTheRange(t *testing.T) {
	srv := startFakeSMTP(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.eml")
	os.WriteFile(path, []byte("Subject: x\n\nx\n"), 0o600)

	if code := cmdSendMail([]string{"--message=" + path, "--to=a@example.com", "--smtp=" + srv.addr,
		"--smtp-tls=none", "--smtp-timeout=5s"}); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	<-srv.done
	if !strings.Contains(srv.data, "Subject: x") {
		t.Errorf("data = %q", srv.data)
	}
}

// The help names the default and the range of --smtp-timeout as the mail
// package holds them, so a changed value fails here until the text follows.
func TestUsageNamesTheSMTPTimeout(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	help := strings.Join(strings.Fields(buf.String()), " ")
	want := fmt.Sprintf("(Vorgabe: %s, erlaubt %s bis %s)", mail.DurationText(mail.DefaultTimeout),
		mail.DurationText(mail.MinTimeout), mail.DurationText(mail.MaxTimeout))
	if n := strings.Count(help, want); n != 2 {
		t.Errorf("the help names %q %d times, want it for scan and for send-mail", want, n)
	}
}

func TestScanRefusesAnSMTPTimeoutOutOfRange(t *testing.T) {
	if code := cmdScan([]string{"--smtp-timeout=0s", t.TempDir()}); code == 0 {
		t.Fatal("scan accepted --smtp-timeout=0s")
	}
}

func TestSendMailRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.eml")
	os.WriteFile(path, []byte("Subject: x\n\nx\n"), 0o600)
	for name, args := range map[string][]string{
		"no message":   {"--to=a@example.com"},
		"no recipient": {"--message=" + path},
		"unknown tls":  {"--message=" + path, "--to=a@example.com", "--smtp-tls=maybe"},
		"missing file": {"--message=" + filepath.Join(dir, "nope"), "--to=a@example.com"},
		"no timeout":   {"--message=" + path, "--to=a@example.com", "--smtp-timeout=0s"},
		"long timeout": {"--message=" + path, "--to=a@example.com", "--smtp-timeout=1h"},
	} {
		if code := cmdSendMail(args); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
