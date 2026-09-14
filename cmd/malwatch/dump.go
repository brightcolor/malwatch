package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brightcolor/malwatch/internal/dump"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
)

// mysqldumpDumper exports one database with the client that ships with the
// database server.
//
// The credentials come from a defaults file the caller writes, or from the
// socket when it names none: malwatch never carries a password of its own,
// and a password on the command line would stand in every process list.
type mysqldumpDumper struct {
	defaults string
}

func (m mysqldumpDumper) Dump(name string, out io.Writer) error {
	args := []string{}
	if m.defaults != "" {
		// --defaults-file has to be the first argument; mysqldump refuses it
		// anywhere else.
		args = append(args, "--defaults-file="+m.defaults)
	}
	args = append(args,
		"--single-transaction",
		"--quick",
		"--routines",
		"--events",
		"--triggers",
		"--default-character-set=utf8mb4",
		name,
	)

	var stderr strings.Builder
	cmd := exec.Command("mysqldump", args...)
	cmd.Stdout = out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(stderr.String())
		if text == "" {
			return err
		}
		return fmt.Errorf("%v: %s", err, text)
	}
	return nil
}

// cmdDump packs one website: its web directory, on request its logs, and the
// databases the caller names. The panel queues it as a job and hands out the
// archive afterwards.
func cmdDump(args []string) int {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	path := fs.String("path", "", "")
	archive := fs.String("archive", "", "")
	logs := fs.String("logs", "", "")
	var databases stringList
	fs.Var(&databases, "db", "")
	defaults := fs.String("db-defaults", "", "")
	minFree := fs.Int64("min-free", 0, "")
	progressPath := fs.String("progress", "", "")
	expect := fs.Int("expect", 0, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" || *archive == "" {
		fmt.Fprintln(os.Stderr, "dump braucht --path und --archive.")
		return report.ExitError
	}

	pw, err := progress.New(*progressPath, "dump")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Die Fortschrittsdatei ließ sich nicht anlegen: %v\n", err)
		return report.ExitError
	}
	defer pw.Close()

	rep, runErr := dump.Run(dump.Options{
		WebRoot:   *path,
		LogRoot:   *logs,
		Databases: databases,
		Archive:   *archive,
		MinFree:   *minFree,
		Expect:    *expect,
		Dumper:    mysqldumpDumper{defaults: *defaults},
		Progress:  pw,
	})

	// The report goes out in every case: it carries the reason the panel shows
	// when the run ended early.
	if rep != nil && (*asJSON || *out != "") {
		if err := writeDumpReport(rep, *out); err != nil {
			fmt.Fprintf(os.Stderr, "Der Bericht ließ sich nicht schreiben: %v\n", err)
			return report.ExitError
		}
	}

	if runErr != nil {
		pw.Log("error", "%v", runErr)
		fmt.Fprintf(os.Stderr, "dump: %v\n", runErr)
		return report.ExitError
	}

	pw.Log("ok", "Archiv fertig: %d Dateien, %d Datenbanken, %d Bytes",
		rep.Files, len(rep.Databases), rep.ArchiveBytes)
	return 0
}

func writeDumpReport(rep *dump.Report, path string) error {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if path == "" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o640)
}
