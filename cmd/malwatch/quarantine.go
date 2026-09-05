package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/report"
)

// cmdQuarantine removes single files: the shell in uploads, the one in the web
// root. Swapping a whole directory is the wrong tool for those, and they are
// exactly what a scan reports once a repair has run.
func cmdQuarantine(args []string) int {
	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	var files stringList
	fs.Var(&files, "file", "")
	path := fs.String("path", "", "")
	backupDir := fs.String("backup-dir", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" || len(files) == 0 || *backupDir == "" {
		fmt.Fprintln(os.Stderr, "quarantine braucht --path, --backup-dir und mindestens ein --file.")
		return report.ExitError
	}

	dest := filepath.Join(*backupDir, time.Now().UTC().Format("20060102T150405Z"))
	failed := 0

	for _, rel := range files {
		full := filepath.Join(*path, filepath.FromSlash(rel))
		if err := repair.InsideRoot(*path, full); err != nil {
			fmt.Fprintf(os.Stderr, "abgelehnt: %v\n", err)
			failed++
			continue
		}
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "übersprungen: %s ist keine gewöhnliche Datei\n", rel)
			failed++
			continue
		}
		// Kept before removed: a finding can be a false alarm, and an
		// unrecoverable deletion would make that mistake permanent.
		name := strings.ReplaceAll(strings.Trim(filepath.ToSlash(rel), "/"), "/", "_")
		if _, err := repair.BackupFile(full, dest, name); err != nil {
			fmt.Fprintf(os.Stderr, "Sicherung von %s fehlgeschlagen: %v\n", rel, err)
			failed++
			continue
		}
		if err := os.Remove(full); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", rel, err)
			failed++
			continue
		}
		fmt.Printf("entfernt %s\n", rel)
	}

	if failed > 0 {
		return report.ExitError
	}
	return 0
}
