package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/phpinfo"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/upgrade"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

func cmdUpgrade(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	path := fs.String("path", "", "")
	planFile := fs.String("plan", "", "")
	runAs := fs.String("run-as", "", "")
	phpBinary := fs.String("php", "", "")
	wpCLI := fs.String("wp-cli", "/usr/local/bin/wp", "")
	connect := fs.String("connect", "127.0.0.1", "")
	quarantineDir := fs.String("quarantine-dir", "", "")
	stagingDir := fs.String("staging-dir", "", "")
	domain := fs.String("domain", "", "")
	progressFile := fs.String("progress", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")
	vendorBase := fs.String("vendor-base", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" || *planFile == "" {
		fmt.Fprintln(os.Stderr, "upgrade braucht --path und --plan. Beispiel: malwatch upgrade "+
			"--path=/var/www/clients/client3/web12/web --plan=job.plan.json --run-as=web12:client3 "+
			"--php=/usr/bin/php8.2 --quarantine-dir=/var/lib/malwatch/quarantine")
		return report.ExitError
	}

	// A check that fails before the run still leaves a report: the panel reads
	// the reason from there.
	early := report.NewUpgrade(*path, *dryRun)
	refuse := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, msg)
		early.Errors = append(early.Errors, msg)
		early.FinishedAt = time.Now().UTC()
		_ = writeUpgradeReport(early, *out, *asJSON)
		return report.ExitError
	}

	if *phpBinary == "" {
		return refuse("upgrade braucht --php, das PHP-Binary der Website.")
	}
	if *quarantineDir == "" && !*dryRun {
		return refuse("upgrade braucht --quarantine-dir, außer mit --dry-run.")
	}
	var userName, group string
	if !*dryRun || *runAs != "" {
		var err error
		if userName, group, err = upgrade.ParseRunAs(*runAs, user.Lookup); err != nil {
			return refuse("%v", err)
		}
	}
	plan, err := upgrade.LoadPlan(*planFile, *path)
	if err != nil {
		return refuse("%v", err)
	}
	phpVersion, err := phpinfo.Version(*phpBinary, 20*time.Second)
	if err != nil {
		return refuse("PHP-Version der Website nicht ermittelbar: %v", err)
	}

	base := *stagingDir
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return refuse("Bereitstellungsverzeichnis: %v", err)
	}
	staging, err := os.MkdirTemp(base, "malwatch-upgrade-")
	if err != nil {
		return refuse("Bereitstellungsverzeichnis: %v", err)
	}
	defer os.RemoveAll(staging)

	info, statErr := os.Stat(*wpCLI)
	hasWPCLI := statErr == nil && info.Mode().IsRegular()

	pw, err := progress.New(*progressFile, "upgrade")
	if err != nil {
		return refuse("Fortschrittsdatei: %v", err)
	}
	defer pw.Close()

	result, runErr := upgrade.Run(upgrade.Options{
		WebRoot:       *path,
		Plan:          plan,
		QuarantineDir: *quarantineDir,
		StagingDir:    staging,
		Domain:        *domain,
		DryRun:        *dryRun,
		PHPVersion:    phpVersion,
		WPCLI: upgrade.WPCLI{Exec: upgrade.SystemExecutor{}, User: userName, Group: group,
			PHP: *phpBinary, Binary: *wpCLI},
		HasWPCLI:  hasWPCLI,
		Fetcher:   vendorfiles.NewFetcher(vendorBaseURLs(*vendorBase), 5*time.Minute),
		Checksums: knownfiles.NewFetcher("", 30*time.Second),
		Prober:    upgrade.NewProber(*connect, 20*time.Second),
		Progress:  pw,
	})

	if err := writeUpgradeReport(result, *out, *asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "Bericht konnte nicht geschrieben werden: %v\n", err)
		return report.ExitError
	}
	if runErr != nil {
		return report.ExitError
	}
	return result.ExitCode()
}

// writeUpgradeReport writes the report readable by its owner only: it names
// paths of a customer.
func writeUpgradeReport(rep *report.Upgrade, out string, asJSON bool) error {
	var w io.Writer = os.Stdout
	if out != "" {
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
	return rep.WriteText(w)
}
