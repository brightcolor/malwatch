// Package mail delivers a scan report, either through the local sendmail or
// over SMTP.
package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/report"
)

// DefaultTimeout is how long connecting to the SMTP server may take, the TLS
// handshake of --smtp-tls=tls included, while Sender.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// MinTimeout and MaxTimeout are the range --smtp-timeout accepts.
const (
	MinTimeout = time.Second
	MaxTimeout = 10 * time.Minute
)

// CheckTimeout says why d cannot serve as --smtp-timeout, or returns nil.
func CheckTimeout(d time.Duration) error {
	if d < MinTimeout || d > MaxTimeout {
		return fmt.Errorf("--smtp-timeout=%s liegt außerhalb des erlaubten Bereichs: %s bis %s, Vorgabe %s",
			DurationText(d), DurationText(MinTimeout), DurationText(MaxTimeout), DurationText(DefaultTimeout))
	}
	return nil
}

// DurationText writes d the way --smtp-timeout takes it: whole hours as
// "1h", whole minutes as "10m", the rest as Go writes a duration.
func DurationText(d time.Duration) string {
	switch {
	case d > 0 && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d > 0 && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// Sender holds the delivery settings.
type Sender struct {
	From     string
	To       []string
	SMTPHost string
	SMTPUser string
	SMTPPass string
	// TLSMode is none, starttls or tls. With starttls the mail goes out only
	// after STARTTLS; a server on this machine may do without it (see
	// loopbackHost).
	TLSMode string
	// Insecure accepts any server certificate. For a relay with a
	// self-signed certificate; the password still travels encrypted, but
	// nobody checks whom to.
	Insecure bool
	// Timeout bounds connecting to the SMTP server, the TLS handshake of
	// TLSMode tls included. Zero means DefaultTimeout.
	Timeout time.Duration

	// dial opens the plain connection of TLSMode none and starttls; nil means
	// a TCP dial. The tests reach a server under another name through it.
	dial func(network, addr string) (net.Conn, error)
}

// SendReport delivers the report. A clean report is only sent when
// sendEmpty is set, so a nightly job does not mail fifty "nothing found"
// messages that nobody reads. A known flaw counts as something to report even
// on an install that is up to date: a flaw the vendor has not fixed yet is
// exactly the case where nothing else would say so.
func (s Sender) SendReport(rep *report.Report, sendEmpty bool) error {
	if len(s.To) == 0 {
		return nil
	}
	if !sendEmpty && len(rep.Findings) == 0 && rep.OutdatedCount() == 0 && rep.VulnerableCount() == 0 {
		return nil
	}

	var body bytes.Buffer
	if err := rep.WriteText(&body, false); err != nil {
		return err
	}
	return s.Send(rep.Subject(), body.String())
}

// Send delivers one message.
func (s Sender) Send(subject, body string) error {
	from := s.From
	if from == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "localhost"
		}
		from = "malwatch@" + host
	}

	msg := buildMessage(from, s.To, subject, body)

	if s.SMTPHost != "" {
		return s.sendSMTP(from, msg)
	}
	return sendViaSendmail(s.To, msg)
}

// SendRaw delivers a message someone else built, headers and MIME parts
// included; line ends become CRLF. The envelope sender is From, or the
// default Send uses.
func (s Sender) SendRaw(msg []byte) error {
	if len(s.To) == 0 {
		return fmt.Errorf("kein Empfänger angegeben")
	}
	from := s.From
	if from == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "localhost"
		}
		from = "malwatch@" + host
	}
	msg = toCRLF(msg)
	if s.SMTPHost != "" {
		return s.sendSMTP(from, msg)
	}
	return sendViaSendmail(s.To, msg)
}

// toCRLF gives every line of msg a CRLF end, whatever it had before.
func toCRLF(msg []byte) []byte {
	msg = bytes.ReplaceAll(msg, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(msg, []byte("\n"), []byte("\r\n"))
}

// buildMessage assembles a UTF-8 mail. The subject is encoded so umlauts
// survive; the body is declared 8-bit UTF-8.
func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("X-Mailer: malwatch\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func sendViaSendmail(to []string, msg []byte) error {
	path, err := exec.LookPath("sendmail")
	if err != nil {
		// Try the usual absolute locations: sendmail is often outside the
		// PATH of a cron job.
		for _, cand := range []string{"/usr/sbin/sendmail", "/usr/lib/sendmail"} {
			if _, statErr := os.Stat(cand); statErr == nil {
				path = cand
				err = nil
				break
			}
		}
	}
	if path == "" {
		return fmt.Errorf("weder sendmail gefunden noch --smtp angegeben")
	}

	args := append([]string{"-t", "-i", "--"}, to...)
	cmd := exec.Command(path, args...)
	cmd.Stdin = bytes.NewReader(msg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sendmail: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s Sender) sendSMTP(from string, msg []byte) error {
	host := s.SMTPHost
	if !strings.Contains(host, ":") {
		host += ":25"
	}
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var conn net.Conn
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := s.tlsConfig(hostname)
	switch {
	case strings.EqualFold(s.TLSMode, "tls"):
		conn, err = tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	case s.dial != nil:
		conn, err = s.dial("tcp", host)
	default:
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if strings.EqualFold(s.TLSMode, "starttls") {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return err
			}
		} else if !loopbackHost(hostname) {
			return fmt.Errorf("der SMTP-Server %s bietet kein STARTTLS an, und mit --smtp-tls=starttls geht die Mail "+
				"nur verschlüsselt hinaus. STARTTLS am Server einschalten, mit --smtp-tls=tls einen Port mit TLS wählen "+
				"oder --smtp-tls=none setzen, wenn die Mail unverschlüsselt zu diesem Server gehen darf", hostname)
		}
	}

	if s.SMTPUser != "" {
		// PlainAuth refuses to send credentials over an unencrypted link, so
		// a misconfigured server cannot leak the password.
		if err := client.Auth(smtp.PlainAuth("", s.SMTPUser, s.SMTPPass, hostname)); err != nil {
			return err
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range s.To {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// tlsConfig is the TLS setup for a connection to hostname: TLS 1.2 or newer,
// the floor RFC 8996 sets, and the certificate checked unless Insecure says
// otherwise.
func (s Sender) tlsConfig(hostname string) *tls.Config {
	return &tls.Config{ServerName: hostname, InsecureSkipVerify: s.Insecure, MinVersion: tls.VersionTLS12}
}

// loopbackHost reports whether hostname names this machine: localhost or a
// loopback address. A mail to such a server stays on the machine, so
// --smtp-tls=starttls lets it go without STARTTLS, the same exception
// net/smtp makes for the password of PlainAuth.
func loopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
