package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

func cmdRepair(args []string) int {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	path := fs.String("path", "", "")
	// --backup-dir is the old name; both write to the same variable so
	// either one works and, if a caller somehow passes both, the one parsed
	// last wins.
	var quarantineDir string
	fs.StringVar(&quarantineDir, "quarantine-dir", "", "")
	fs.StringVar(&quarantineDir, "backup-dir", "", "")
	stagingDir := fs.String("staging-dir", "", "")
	progressFile := fs.String("progress", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")
	vendorBase := fs.String("vendor-base", "", "")
	mode := fs.String("mode", "replace", "")
	noOriginal := fs.String("no-original", "keep", "")
	domain := fs.String("domain", "", "")
	var only stringList
	fs.Var(&only, "only", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "repair braucht --path. Beispiel: malwatch repair --path=/var/www/web1/web --quarantine-dir=/var/lib/malwatch/quarantine/web1")
		return report.ExitError
	}
	if quarantineDir == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "repair braucht --quarantine-dir (oder --backup-dir), außer mit --dry-run.")
		return report.ExitError
	}
	modeVal, err := repair.ParseMode(*mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return report.ExitError
	}
	noOriginalVal, err := repair.ParseNoOriginal(*noOriginal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return report.ExitError
	}

	staging := *stagingDir
	if staging == "" {
		var err error
		if staging, err = os.MkdirTemp("", "malwatch-staging-"); err != nil {
			fmt.Fprintf(os.Stderr, "Bereitstellungsverzeichnis: %v\n", err)
			return report.ExitError
		}
		defer os.RemoveAll(staging)
	}

	pw, err := progress.New(*progressFile, "repair")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fortschrittsdatei: %v\n", err)
		return report.ExitError
	}
	defer pw.Close()

	rep, runErr := repair.Run(repair.Options{
		Root:          *path,
		QuarantineDir: quarantineDir,
		StagingDir:    staging,
		DryRun:        *dryRun,
		Mode:          modeVal,
		Only:          only,
		NoOriginal:    noOriginalVal,
		Domain:        *domain,
		Fetcher:       vendorfiles.NewFetcher(vendorBaseURLs(*vendorBase), 5*time.Minute),
		Progress:      pw,
	})

	w := os.Stdout
	if *out != "" {
		fh, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return report.ExitError
		}
		defer fh.Close()
		w = fh
	}
	if *asJSON {
		_ = rep.WriteJSON(w)
	} else {
		_ = rep.WriteText(w)
	}

	if runErr != nil {
		return report.ExitError
	}
	return rep.ExitCode()
}

// vendorBaseURLs points every source at one address, which keeps the
// acceptance test off the network. An empty value means the real vendors.
func vendorBaseURLs(base string) vendorfiles.BaseURLs {
	if base == "" {
		return vendorfiles.BaseURLs{}
	}
	return vendorfiles.BaseURLs{
		Core:          base,
		LocalisedCore: base,
		Plugin:        base + "plugin/",
		Theme:         base + "theme/",
	}
}
