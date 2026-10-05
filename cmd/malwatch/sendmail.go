package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/brightcolor/malwatch/internal/mail"
	"github.com/brightcolor/malwatch/internal/report"
)

// smtpPassEnv is where send-mail and scan find the SMTP password when no file
// names it. Every user of the machine can read a command line, so send-mail
// takes the password from here or from a file only.
const smtpPassEnv = "MALWATCH_SMTP_PASS"

// smtpPassword reads the SMTP password from smtpPassEnv, or from file when
// one is named; the file wins. A line break at its end is not part of the
// password. Without either the password is empty.
func smtpPassword(file string) (string, error) {
	pass := os.Getenv(smtpPassEnv)
	if file == "" {
		return pass, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("Die Passwortdatei %s ist nicht lesbar: %w", file, err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// cmdSendMail delivers a message someone else built - the ISPConfig addon
// writes its HTML mails with their images and hands them over here, because
// the mailer of ISPConfig cannot send an HTML part next to a text part with
// embedded images.
func cmdSendMail(args []string) int {
	fs := flag.NewFlagSet("send-mail", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	var to stringList
	fs.Var(&to, "to", "")
	message := fs.String("message", "", "")
	from := fs.String("from", "", "")
	smtpHost := fs.String("smtp", "", "")
	smtpUser := fs.String("smtp-user", "", "")
	smtpTLS := fs.String("smtp-tls", "starttls", "")
	smtpPassFile := fs.String("smtp-pass-file", "", "")
	insecure := fs.Bool("smtp-insecure", false, "")
	timeout := fs.Duration("smtp-timeout", mail.DefaultTimeout, "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *message == "" {
		fmt.Fprintln(os.Stderr, "send-mail braucht --message=DATEI mit der fertigen Mail. Beispiel: malwatch send-mail --message=/tmp/mail.eml --to=admin@example.com")
		return report.ExitError
	}
	var recipients []string
	for _, list := range to {
		for _, addr := range strings.Split(list, ",") {
			if addr = strings.TrimSpace(addr); addr != "" {
				recipients = append(recipients, addr)
			}
		}
	}
	if len(recipients) == 0 {
		fmt.Fprintln(os.Stderr, "send-mail braucht mindestens einen Empfänger: --to=admin@example.com")
		return report.ExitError
	}
	mode := strings.ToLower(*smtpTLS)
	if mode != "none" && mode != "starttls" && mode != "tls" {
		fmt.Fprintf(os.Stderr, "--smtp-tls=%s ist unbekannt. Erlaubt sind none, starttls und tls.\n", *smtpTLS)
		return report.ExitError
	}
	if err := mail.CheckTimeout(*timeout); err != nil {
		fmt.Fprintf(os.Stderr, "%v. Ohne den Schalter gilt die Vorgabe.\n", err)
		return report.ExitError
	}

	msg, err := os.ReadFile(*message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Die Mail %s ist nicht lesbar: %v\n", *message, err)
		return report.ExitError
	}

	pass, err := smtpPassword(*smtpPassFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. Bitte Pfad und Rechte der Datei prüfen.\n", err)
		return report.ExitError
	}

	sender := mail.Sender{
		From:     *from,
		To:       recipients,
		SMTPHost: *smtpHost,
		SMTPUser: *smtpUser,
		SMTPPass: pass,
		TLSMode:  mode,
		Insecure: *insecure,
		Timeout:  *timeout,
	}
	if err := sender.SendRaw(msg); err != nil {
		where := "über sendmail"
		if *smtpHost != "" {
			where = "über " + *smtpHost
		}
		fmt.Fprintf(os.Stderr, "Die Mail an %s ließ sich %s nicht zustellen: %v\n", strings.Join(recipients, ", "), where, err)
		return report.ExitError
	}
	return 0
}
