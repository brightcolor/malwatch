package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/safepath"
)

// cmdQuarantine used to only take a single file off a website. The
// ISPConfig panel behind it now needs the rest of what a store implies too:
// listing what is in it, bringing an entry back, dropping it for good, and
// shipping a copy out for someone else to look at. Those five forms share
// one flag set - the action is just the first argument - because they all
// act on the same store and the panel already sends --quarantine-dir,
// --json and --out on every one of them.
func cmdQuarantine(args []string) int {
	action, rest := splitQuarantineAction(args)

	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	var files, ids stringList
	fs.Var(&files, "file", "")
	fs.Var(&ids, "id", "")
	path := fs.String("path", "", "")
	var quarantineDirFlag, backupDirFlag string
	fs.StringVar(&quarantineDirFlag, "quarantine-dir", "", "")
	fs.StringVar(&backupDirFlag, "backup-dir", "", "")
	domain := fs.String("domain", "", "")
	origin := fs.String("origin", "", "")
	reason := fs.String("reason", "", "")
	ruleID := fs.String("rule", "", "")
	severity := fs.String("severity", "", "")
	force := fs.Bool("force", false, "")
	zipOut := fs.String("zip", "", "")
	password := fs.String("password", quarantine.DefaultPassword, "")
	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")

	if err := fs.Parse(rest); err != nil {
		return report.ExitError
	}

	// --quarantine-dir is the current name; --backup-dir is what every
	// caller used before the store gained the other four actions. Both are
	// accepted, but the new name wins whenever it is actually set, whatever
	// order the two arrive in.
	quarantineDir := quarantineDirFlag
	if quarantineDir == "" {
		quarantineDir = backupDirFlag
	}
	if quarantineDir == "" {
		fmt.Fprintln(os.Stderr, "quarantine braucht --quarantine-dir (oder --backup-dir).")
		return report.ExitError
	}

	var failed int
	switch action {
	case "add":
		if *path == "" || len(files) == 0 {
			fmt.Fprintln(os.Stderr, "quarantine add braucht --path und mindestens ein --file.")
			return report.ExitError
		}
		failed = runQuarantineAdd(quarantineDir, quarantine.Source{
			Domain: *domain, Origin: *origin, Reason: *reason,
			RuleID: *ruleID, Severity: *severity,
		}, *path, files, *asJSON)

	case "list":
		// list has no work of its own: what it returns is exactly the index
		// every action writes below. Without --json there is nothing
		// defined to print, so - as rules does for the same reason - a
		// forgotten flag is an error instead of a silent no-op.
		if !*asJSON {
			fmt.Fprintln(os.Stderr, "quarantine list braucht --json. Beispiel: malwatch quarantine list --quarantine-dir=… --json")
			return report.ExitError
		}

	case "restore":
		if len(ids) == 0 {
			fmt.Fprintln(os.Stderr, "quarantine restore braucht mindestens ein --id.")
			return report.ExitError
		}
		failed = runQuarantineRestore(quarantineDir, ids, *force, *asJSON)

	case "delete":
		if len(ids) == 0 {
			fmt.Fprintln(os.Stderr, "quarantine delete braucht mindestens ein --id.")
			return report.ExitError
		}
		failed = runQuarantineDelete(quarantineDir, ids, *asJSON)

	case "export":
		if len(ids) == 0 || *zipOut == "" {
			fmt.Fprintln(os.Stderr, "quarantine export braucht mindestens ein --id und --zip.")
			return report.ExitError
		}
		failed = runQuarantineExport(quarantineDir, ids, *zipOut, *password, *asJSON)

	default:
		fmt.Fprintf(os.Stderr, "unbekannte Aktion %q für quarantine.\n\n", action)
		usage(os.Stderr)
		return report.ExitError
	}

	// Self-healing index: whatever just happened, and however many entries
	// in it failed, the caller gets the store's complete current contents.
	// That is what lets the panel resync its own copy from one call instead
	// of trusting that a single action's result still matches the disk.
	if *asJSON {
		if err := writeQuarantineIndex(quarantineDir, *out); err != nil {
			fmt.Fprintf(os.Stderr, "Bestandsliste konnte nicht geschrieben werden: %v\n", err)
			return report.ExitError
		}
	}

	if failed > 0 {
		return report.ExitError
	}
	return 0
}

// splitQuarantineAction reads the leading action word. The invocation this
// replaces never had one, and flag.FlagSet has no way to tell a bare
// leading token from a missing one - so the default, add, applies both when
// args is empty and when args[0] is already a flag.
func splitQuarantineAction(args []string) (action string, rest []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "add", args
}

// runQuarantineAdd files each of files below quarantineDir and removes it
// from path. base carries the fields that describe the call as a whole -
// one reason, one origin, one rule - while Root and RelPath are filled in
// per file.
func runQuarantineAdd(quarantineDir string, base quarantine.Source, path string, files []string, asJSON bool) int {
	failed := 0
	for _, rel := range files {
		relSlash := filepath.ToSlash(rel)
		full := filepath.Join(path, filepath.FromSlash(relSlash))
		// The path arrives from a form field by way of a job queue; the
		// finding it names was checked once already on the way in, and this
		// is the second, independent check against a boundary a symlink or
		// a crafted relative path could otherwise slip past.
		if err := safepath.InsideRoot(path, full); err != nil {
			fmt.Fprintf(os.Stderr, "abgelehnt: %v\n", err)
			failed++
			continue
		}
		info, err := os.Lstat(full)
		if os.IsNotExist(err) {
			// Not a failure: the file is not on the website any more, which
			// is the whole point of the run. This is the ordinary case after
			// a repair - it replaces whole directories, and the findings
			// inside them are gone with the directory. Counting it as an
			// error made a batch of forty succeed and still report "the
			// quarantine job failed".
			fmt.Fprintf(os.Stderr, "bereits verschwunden: %s\n", rel)
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "übersprungen: %s ist keine gewöhnliche Datei\n", rel)
			failed++
			continue
		}

		src := base
		src.Root = path
		src.RelPath = relSlash
		entry, err := quarantine.Store(quarantineDir, src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Quarantäne von %s fehlgeschlagen: %v\n", rel, err)
			failed++
			continue
		}
		if !asJSON {
			fmt.Printf("in Quarantäne: %s (%s)\n", rel, entry.ID)
		}
	}
	return failed
}

// runQuarantineRestore puts back every entry named by ids, continuing past
// one that fails - a stale id in a batch download must not stop the ones
// still good from coming back.
func runQuarantineRestore(quarantineDir string, ids []string, force, asJSON bool) int {
	failed := 0
	for _, id := range ids {
		if err := quarantine.Restore(quarantineDir, id, force); err != nil {
			fmt.Fprintf(os.Stderr, "Wiederherstellung von %s fehlgeschlagen: %v\n", id, err)
			failed++
			continue
		}
		if !asJSON {
			fmt.Printf("wiederhergestellt: %s\n", id)
		}
	}
	return failed
}

// runQuarantineDelete removes every entry named by ids, same
// continue-past-a-failure rule as restore.
func runQuarantineDelete(quarantineDir string, ids []string, asJSON bool) int {
	failed := 0
	for _, id := range ids {
		if err := quarantine.Delete(quarantineDir, id); err != nil {
			fmt.Fprintf(os.Stderr, "Löschen von %s fehlgeschlagen: %v\n", id, err)
			failed++
			continue
		}
		if !asJSON {
			fmt.Printf("gelöscht: %s\n", id)
		}
	}
	return failed
}

// runQuarantineExport bundles every entry named by ids into one zip at
// zipOut. A collection download in the panel selects many entries at once;
// twenty separate export calls would be twenty waits, and the ISPConfig job
// queue runs quarantine jobs for one site one at a time, so the second
// would sit blocked behind the first. One call, one archive.
func runQuarantineExport(quarantineDir string, ids []string, zipOut, password string, asJSON bool) int {
	// quarantine.Export only knows how to write one entry to one file, so
	// each id is exported to its own throwaway zip first and then folded
	// into the real one below - see appendExportEntry.
	tmpDir, err := os.MkdirTemp("", "malwatch-export-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sammel-ZIP: %v\n", err)
		return len(ids)
	}
	defer os.RemoveAll(tmpDir)

	// The panel's spool directory is not guaranteed to exist yet - unlike
	// the runs directory a result file lands in, nothing creates it ahead
	// of the call that first writes into it.
	if err := os.MkdirAll(filepath.Dir(zipOut), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "Sammel-ZIP: %v\n", err)
		return len(ids)
	}
	out, err := os.OpenFile(zipOut, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sammel-ZIP: %v\n", err)
		return len(ids)
	}
	defer out.Close()
	zw := zip.NewWriter(out)

	failed := 0
	for _, id := range ids {
		if err := appendExportEntry(zw, quarantineDir, id, tmpDir, password); err != nil {
			fmt.Fprintf(os.Stderr, "Export von %s fehlgeschlagen: %v\n", id, err)
			failed++
			continue
		}
		if !asJSON {
			fmt.Printf("exportiert: %s\n", id)
		}
	}

	if err := zw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Sammel-ZIP: %v\n", err)
		failed++
	}
	return failed
}

// appendExportEntry exports one entry to a scratch zip and copies its
// entries into zw under id/ - the id, not the original relative path,
// because two websites can each quarantine "wp-content/uploads/shell.php"
// and the combined archive has to keep both instead of the second silently
// overwriting the first.
//
// OpenRaw and CreateRaw move the already-deflated, already-ZipCrypto-
// encrypted bytes across unchanged. That is what makes the copy possible
// without the password at all: re-encrypting here would mean duplicating
// the cipher quarantine.Export already applied.
func appendExportEntry(zw *zip.Writer, quarantineDir, id, tmpDir, password string) error {
	single := filepath.Join(tmpDir, id+".zip")
	if _, err := quarantine.Export(quarantineDir, id, single, password); err != nil {
		return err
	}
	// Registered before the reader below, so it runs after rc.Close() -
	// Windows refuses to remove a file that is still open.
	defer os.Remove(single)

	rc, err := zip.OpenReader(single)
	if err != nil {
		return err
	}
	defer rc.Close()

	for _, f := range rc.File {
		raw, err := f.OpenRaw()
		if err != nil {
			return err
		}
		hdr := f.FileHeader
		hdr.Name = id + "/" + f.Name
		w, err := zw.CreateRaw(&hdr)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, raw); err != nil {
			return err
		}
	}
	return nil
}

// quarantineIndex is the self-healing report every action ends with when
// --json is set: the store's complete state, not just what one action did.
type quarantineIndex struct {
	Schema      int    `json:"schema"`
	GeneratedAt string `json:"generated_at"`
	// Skipped counts the entry directories this listing could not read. The
	// panel rebuilds its index from the array below and removes what is not
	// in it, so a listing that is short of something has to say so - it is
	// the difference between "that entry is gone" and "I could not see it".
	Skipped int `json:"skipped"`
	// SkippedIDs names them. One directory that stays unreadable keeps the
	// panel's index permanently stale, and the count alone gives nobody a way
	// to find it: the store holds hundreds of directories whose names all look
	// the same, and nothing else anywhere says which one is the broken one.
	SkippedIDs []string           `json:"skipped_ids"`
	Entries    []quarantine.Entry `json:"entries"`
}

// writeQuarantineIndex writes the current contents of quarantineDir to out,
// or to stdout when out is empty.
func writeQuarantineIndex(quarantineDir, out string) error {
	entries, skipped, err := quarantine.List(quarantineDir)
	if err != nil {
		return err
	}
	if entries == nil {
		// nil marshals as null; the panel expects an array even when the
		// store is empty.
		entries = []quarantine.Entry{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	idx := quarantineIndex{
		Schema:      1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Skipped:     len(skipped),
		SkippedIDs:  skipped,
		Entries:     entries,
	}

	w := os.Stdout
	if out != "" {
		// Entries name infected paths on a customer's website, so the file
		// is created readable by its owner only - the same rule scan and
		// repair reports follow.
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(idx)
}
