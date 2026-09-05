package repair

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// Options is one repair run.
type Options struct {
	Root       string
	BackupDir  string
	StagingDir string
	DryRun     bool
	Fetcher    *vendorfiles.Fetcher
	Progress   *progress.Writer
}

// staged is one element together with the tree that will replace it. An empty
// dir means the vendor does not publish that version.
type staged struct {
	element Element
	dir     string
}

// phaseTotal is what the binary itself covers. The scan that follows a repair
// is a job of its own, with its own progress file.
const phaseTotal = 5

// Run walks the five phases.
//
// Nothing below Root is touched before every archive is on disk and unpacked:
// a download that breaks half way then costs a run, not a website.
func Run(opts Options) (*report.Repair, error) {
	rep := report.NewRepair(opts.Root)
	rep.DryRun = opts.DryRun
	rep.BackupDir = opts.BackupDir
	pw := opts.Progress

	defer func() {
		rep.FinishedAt = time.Now().UTC()
		rep.Log = pw.Entries()
	}()

	// Phase 1
	pw.Phase(1, phaseTotal, "detect")
	plan, err := BuildPlan(opts.Root)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
	rep.Untouched = plan.Untouched
	total := len(plan.Elements)
	pw.Log("info", "%d Element(e) gefunden", total)

	// Phases 2 and 3
	pw.Phase(2, phaseTotal, "fetch")
	items := make([]staged, 0, total)
	for i, el := range plan.Elements {
		pw.Element(el.Kind, el.Slug, el.Version, i, total)
		dir, err := fetchOne(opts.Fetcher, el, opts.StagingDir)
		switch {
		case errors.Is(err, vendorfiles.ErrNotPublished):
			pw.Log("warn", "%s %s: beim Hersteller nicht veröffentlicht",
				label(el), el.Version)
			items = append(items, staged{element: el})
		case err != nil:
			msg := fmt.Sprintf("%s %s: %v", label(el), el.Version, err)
			rep.Errors = append(rep.Errors, msg)
			pw.Log("error", "%s", msg)
			return rep, err
		default:
			items = append(items, staged{element: el, dir: dir})
		}
	}
	pw.Phase(3, phaseTotal, "verify")

	if opts.DryRun {
		pw.Log("info", "Probelauf - es wird nichts geändert")
		for _, it := range items {
			rep.Elements = append(rep.Elements, describe(it))
		}
		return rep, nil
	}

	// Phases 4 and 5
	for i, it := range items {
		el := it.element
		pw.Element(el.Kind, el.Slug, el.Version, i, total)

		pw.Phase(4, phaseTotal, "backup")
		archive, err := Backup(el.Path, opts.BackupDir, backupName(el))
		if err != nil {
			msg := fmt.Sprintf("%s: Sicherung fehlgeschlagen: %v", label(el), err)
			rep.Errors = append(rep.Errors, msg)
			pw.Log("error", "%s", msg)
			return rep, err
		}

		pw.Phase(5, phaseTotal, "swap")
		entry := report.RepairElement{
			Kind: el.Kind, Slug: el.Slug, Version: el.Version, Locale: el.Locale,
			Path: el.Path, Backup: archive,
		}

		switch {
		case it.dir == "":
			if err := removeInside(opts.Root, el.Path); err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.Outcome = report.OutcomeDeleted
			pw.Log("error", "gelöscht %s %s - kein Original verfügbar", label(el), el.Version)

		case el.Kind == "core":
			// The core cannot be swapped like a plugin: the element's path is
			// the web root itself, and replacing it would take wp-content and
			// wp-config.php along.
			n, err := SwapCore(opts.Root, it.dir)
			if err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.Outcome, entry.Files = report.OutcomeReplaced, n
			pw.Log("ok", "ersetzt Kern %s", el.Version)

		default:
			if err := Swap(opts.Root, el.Path, it.dir); err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.Outcome = report.OutcomeReplaced
			entry.Files = countFiles(el.Path)
			pw.Log("ok", "ersetzt %s %s", label(el), el.Version)
		}
		rep.Elements = append(rep.Elements, entry)
	}

	return rep, nil
}

func fetchOne(f *vendorfiles.Fetcher, el Element, staging string) (string, error) {
	dest, err := os.MkdirTemp(staging, "el-")
	if err != nil {
		return "", err
	}
	switch el.Kind {
	case "core":
		return f.Core(el.Version, el.Locale, dest)
	case "plugin":
		return f.Plugin(el.Slug, el.Version, dest)
	case "theme":
		return f.Theme(el.Slug, el.Version, dest)
	}
	return "", fmt.Errorf("unbekannte Art %q", el.Kind)
}

func removeInside(root, dir string) error {
	if err := InsideRoot(root, dir); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func label(el Element) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + " " + el.Slug
}

func backupName(el Element) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + "-" + el.Slug
}

func describe(it staged) report.RepairElement {
	out := report.RepairElement{
		Kind: it.element.Kind, Slug: it.element.Slug, Version: it.element.Version,
		Locale: it.element.Locale, Path: it.element.Path,
	}
	if it.dir == "" {
		out.Outcome = report.OutcomeDeleted
		out.Message = "kein Original verfügbar"
	} else {
		out.Outcome = report.OutcomeReplaced
	}
	return out
}

func countFiles(dir string) int {
	n := 0
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	return n
}
