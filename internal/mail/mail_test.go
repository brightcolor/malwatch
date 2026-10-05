package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// smtpServer answers one SMTP session on 127.0.0.1 and records what reached
// it. With a certificate it offers STARTTLS.
type smtpServer struct {
	addr string
	cert *tls.Certificate

	mu         sync.Mutex
	from       string
	data       string
	tlsVersion uint16
	done       chan struct{}
}

func startSMTPServer(t *testing.T, cert *tls.Certificate) *smtpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{addr: ln.Addr().String(), cert: cert, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { conn.Close() }()
		r := bufio.NewReader(conn)
		w := func(line string) { conn.Write([]byte(line + "\r\n")) }
		w("220 relay ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				if s.cert != nil && s.version() == 0 {
					w("250-relay")
					w("250 STARTTLS")
				} else {
					w("250 relay")
				}
			case cmd == "STARTTLS" && s.cert != nil:
				w("220 go ahead")
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*s.cert}})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				s.mu.Lock()
				s.tlsVersion = tlsConn.ConnectionState().Version
				s.mu.Unlock()
				conn = tlsConn
				r = bufio.NewReader(conn)
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				s.mu.Lock()
				s.from = line[len("MAIL FROM:"):]
				s.mu.Unlock()
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
				s.mu.Lock()
				s.data = b.String()
				s.mu.Unlock()
				w("250 queued")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return s
}

func (s *smtpServer) version() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsVersion
}

// received waits for the session to end and returns what the server got.
func (s *smtpServer) received(t *testing.T) (from, data string) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the SMTP session did not end")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.from, s.data
}

// to dials the server whatever name the sender uses for it.
func (s *smtpServer) to() func(network, addr string) (net.Conn, error) {
	return func(network, _ string) (net.Conn, error) { return net.Dial(network, s.addr) }
}

// selfSigned returns a certificate for relay.example.com.
func selfSigned(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.example.com"},
		DNSNames:     []string{"relay.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

const testMessage = "Subject: Bericht\r\n\r\nZeile eins\r\n"

func TestStartTLSIsRequiredOfAServerElsewhere(t *testing.T) {
	srv := startSMTPServer(t, nil)
	s := Sender{To: []string{"admin@example.com"}, SMTPHost: "relay.example.com:25", TLSMode: "starttls", dial: srv.to()}

	err := s.SendRaw([]byte(testMessage))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") || !strings.Contains(err.Error(), "--smtp-tls=none") {
		t.Fatalf("err = %v, want a message that names STARTTLS and the way out", err)
	}
	if from, data := srv.received(t); from != "" || data != "" {
		t.Errorf("the server got MAIL FROM %q and data %q", from, data)
	}
}

func TestStartTLSMayBeLeftOutOnThisMachine(t *testing.T) {
	srv := startSMTPServer(t, nil)
	s := Sender{From: "malwatch@example.com", To: []string{"admin@example.com"}, SMTPHost: srv.addr, TLSMode: "starttls"}

	if err := s.SendRaw([]byte(testMessage)); err != nil {
		t.Fatalf("delivery to 127.0.0.1 failed: %v", err)
	}
	if _, data := srv.received(t); !strings.Contains(data, "Zeile eins") {
		t.Errorf("data = %q", data)
	}
}

func TestStartTLSEncryptsWithTLS12OrNewer(t *testing.T) {
	srv := startSMTPServer(t, selfSigned(t))
	s := Sender{To: []string{"admin@example.com"}, SMTPHost: "relay.example.com:587", TLSMode: "starttls",
		Insecure: true, dial: srv.to()}

	if err := s.SendRaw([]byte(testMessage)); err != nil {
		t.Fatalf("delivery after STARTTLS failed: %v", err)
	}
	if _, data := srv.received(t); !strings.Contains(data, "Zeile eins") {
		t.Errorf("data = %q", data)
	}
	if v := srv.version(); v < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x, want TLS 1.2 or newer", v)
	}
}

func TestTLSConfigSetsTheFloorAndTheName(t *testing.T) {
	cfg := Sender{}.tlsConfig("relay.example.com")
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ServerName != "relay.example.com" || cfg.InsecureSkipVerify {
		t.Errorf("ServerName %q, InsecureSkipVerify %v", cfg.ServerName, cfg.InsecureSkipVerify)
	}
	if !(Sender{Insecure: true}).tlsConfig("relay.example.com").InsecureSkipVerify {
		t.Error("Insecure does not reach the TLS setup")
	}
}

func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":         true,
		"LocalHost":         true,
		"127.0.0.1":         true,
		"127.0.0.2":         true,
		"::1":               true,
		"relay.example.com": false,
		"10.0.0.25":         false,
		"2001:db8::25":      false,
		"":                  false,
	} {
		if got := loopbackHost(host); got != want {
			t.Errorf("loopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestTimeoutBoundsTheTLSHandshake(t *testing.T) {
	// A server that accepts and then says nothing: the handshake of
	// --smtp-tls=tls waits for it until the timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop
	}()

	s := Sender{To: []string{"admin@example.com"}, SMTPHost: ln.Addr().String(), TLSMode: "tls", Timeout: 300 * time.Millisecond}
	start := time.Now()
	if err := s.SendRaw([]byte(testMessage)); err == nil {
		t.Fatal("a silent server took the mail")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("gave up after %v, want about the timeout of 300ms", took)
	}
}

func TestCheckTimeout(t *testing.T) {
	for _, ok := range []time.Duration{MinTimeout, DefaultTimeout, MaxTimeout} {
		if err := CheckTimeout(ok); err != nil {
			t.Errorf("CheckTimeout(%v) = %v", ok, err)
		}
	}
	for _, bad := range []time.Duration{0, -time.Second, MinTimeout - time.Millisecond, MaxTimeout + time.Second} {
		err := CheckTimeout(bad)
		if err == nil {
			t.Errorf("CheckTimeout(%v) accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "1s bis 10m, Vorgabe 30s") {
			t.Errorf("CheckTimeout(%v) = %q, want the range and the default", bad, err)
		}
	}
}

func TestDurationText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:       "30s",
		time.Second:            "1s",
		10 * time.Minute:       "10m",
		time.Hour:              "1h",
		90 * time.Minute:       "90m",
		90 * time.Second:       "1m30s",
		300 * time.Millisecond: "300ms",
		0:                      "0s",
	} {
		if got := DurationText(d); got != want {
			t.Errorf("DurationText(%v) = %q, want %q", d, got, want)
		}
	}
}
