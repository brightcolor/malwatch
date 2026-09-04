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

// Sender holds the delivery settings.
type Sender struct {
	From     string
	To       []string
	SMTPHost string
	SMTPUser string
	SMTPPass string
	// TLSMode is none, starttls or tls.
	TLSMode string
}

// SendReport delivers the report. A clean report is only sent when
// sendEmpty is set, so a nightly job does not mail fifty "nothing found"
// messages that nobody reads.
func (s Sender) SendReport(rep *report.Report, sendEmpty bool) error {
	if len(s.To) == 0 {
		return nil
	}
	if !sendEmpty && len(rep.Findings) == 0 && rep.OutdatedCount() == 0 {
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

	var conn net.Conn
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	if strings.EqualFold(s.TLSMode, "tls") {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: hostname})
	} else {
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
			if err := client.StartTLS(&tls.Config{ServerName: hostname}); err != nil {
				return err
			}
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
