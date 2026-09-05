package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/mail"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/scanner"
)

// stringList collects a flag that may be given more than once.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Default locations. They sit under /var/lib so a scan started from a
// customer directory does not scatter state files there.
const (
	defaultSigDir   = "/var/lib/malwatch/signatures"
	defaultStateDir = "/var/lib/malwatch/state"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	var paths, excludes, excludeFrom, ignore, email stringList
	fs.Var(&paths, "path", "")
	fs.Var(&excludes, "exclude", "")
	fs.Var(&excludeFrom, "exclude-from", "")
	fs.Var(&ignore, "ignore", "")
	fs.Var(&email, "email", "")

	maxAge := fs.Int("max-age", 0, "")
	maxSize := fs.Int64("max-size", 0, "")
	threads := fs.Int("threads", 0, "")
	ignoreChmod0 := fs.Bool("ignore-chmod0", false, "")

	noMalware := fs.Bool("no-malware-scan", false, "")
	noVersion := fs.Bool("no-version-scan", false, "")
	noPlugin := fs.Bool("no-plugin-version-scan", false, "")
	noClamAV := fs.Bool("no-clamav", false, "")
	offline := fs.Bool("offline", false, "")

	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")
	minSeverity := fs.String("min-severity", "medium", "")
	showAll := fs.Bool("show-all", false, "")
	quiet := fs.Bool("quiet", false, "")

	emailFrom := fs.String("email-from", "", "")
	emailEmpty := fs.Bool("email-empty", false, "")
	smtpHost := fs.String("smtp", "", "")
	smtpUser := fs.String("smtp-user", "", "")
	smtpPass := fs.String("smtp-pass", "", "")
	smtpTLS := fs.String("smtp-tls", "starttls", "")

	sigDir := fs.String("sig-dir", defaultSigDir, "")
	stateDir := fs.String("state-dir", defaultStateDir, "")
	cacheFile := fs.String("cache", "", "")
	whitelistPath := fs.String("whitelist-path", "", "")
	progressFile := fs.String("progress", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	// A bare path argument is accepted too: "malwatch scan /var/www".
	paths = append(paths, fs.Args()...)

	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "Kein Pfad angegeben. Beispiel: malwatch scan --path=/var/www")
		return report.ExitError
	}

	min, err := report.ParseSeverity(*minSeverity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return report.ExitError
	}

	for _, file := range excludeFrom {
		loaded, err := readPatternFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ausschlussliste %s nicht lesbar: %v\n", file, err)
			return report.ExitError
		}
		excludes = append(excludes, loaded...)
	}

	wlPath := *whitelistPath
	if wlPath == "" {
		wlPath = defaultWhitelistPath()
	}
	whitelist, err := scanner.LoadWhitelist(wlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Freigabeliste %s nicht lesbar: %v\n", wlPath, err)
		return report.ExitError
	}

	opts := scanner.Options{
		Paths:         cleanPaths(paths),
		Excludes:      excludes,
		MaxAge:        time.Duration(*maxAge) * 24 * time.Hour,
		MaxSize:       *maxSize,
		Threads:       *threads,
		IgnoreChmod0:  *ignoreChmod0,
		NoMalwareScan: *noMalware,
		NoVersionScan: *noVersion,
		NoPluginScan:  *noPlugin,
		NoClamAV:      *noClamAV,
		Offline:       *offline,
		IgnoreRules:   ignore,
		Whitelist:     whitelist,
		SignatureDir:  *sigDir,
		StateDir:      *stateDir,
		CacheFile:     *cacheFile,
	}
	// The panel reads the same document for a scan as for a repair, so both
	// job kinds get the same view. Without it a scan says "eingeplant" and
	// then nothing at all for minutes.
	pw, err := progress.New(*progressFile, "scan")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fortschrittsdatei: %v\n", err)
		return report.ExitError
	}
	defer pw.Close()
	pw.Phase(1, 1, "scan")

	onTerminal := !*quiet && *out == "" && !*asJSON
	opts.Progress = func(n int64) {
		pw.File("", int(n), 0)
		if onTerminal {
			fmt.Fprintf(os.Stderr, "\r%d Dateien geprüft …", n)
		}
	}

	rep, err := scanner.Run(opts)
	if onTerminal {
		fmt.Fprint(os.Stderr, "\r                                   \r")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Der Lauf ist gescheitert: %v\n", err)
		return report.ExitError
	}

	if err := writeReport(rep, *out, *asJSON, *showAll); err != nil {
		fmt.Fprintf(os.Stderr, "Bericht konnte nicht geschrieben werden: %v\n", err)
		return report.ExitError
	}

	if len(email) > 0 {
		sender := mail.Sender{
			From:     *emailFrom,
			To:       email,
			SMTPHost: *smtpHost,
			SMTPUser: *smtpUser,
			SMTPPass: *smtpPass,
			TLSMode:  *smtpTLS,
		}
		if err := sender.SendReport(rep, *emailEmpty); err != nil {
			fmt.Fprintf(os.Stderr, "Bericht konnte nicht versendet werden: %v\n", err)
			// The scan itself succeeded; its result still decides the exit code.
		}
	}

	return rep.ExitCode(min)
}

// writeReport renders the report to the chosen destination.
func writeReport(rep *report.Report, out string, asJSON, showAll bool) error {
	w := os.Stdout
	if out != "" {
		// The report can name infected paths of other customers, so it is
		// created readable by its owner only.
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if asJSON {
		return rep.WriteJSON(w)
	}
	return rep.WriteText(w, showAll)
}

func readPatternFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func cleanPaths(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func defaultWhitelistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".malwatch.whitelist")
}

func cmdWhitelist(args []string) int {
	fs := flag.NewFlagSet("whitelist", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("file", "", "")
	path := fs.String("whitelist-path", "", "")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	target := *file
	if target == "" && fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "Keine Datei angegeben. Beispiel: malwatch whitelist --file=/var/www/web/tool.php")
		return report.ExitError
	}
	listPath := *path
	if listPath == "" {
		listPath = defaultWhitelistPath()
	}
	sum, err := scanner.AppendWhitelist(listPath, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Freigabe nicht möglich: %v\n", err)
		return report.ExitError
	}
	fmt.Printf("Freigegeben: %s\n%s\n", target, sum)
	return 0
}
