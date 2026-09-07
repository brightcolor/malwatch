package repair

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// Options is one repair run.
type Options struct {
	Root          string
	QuarantineDir string // where quarantine.Store/StoreCopy file the replaced trees; was BackupDir
	StagingDir    string
	DryRun        bool
	Mode          string   // "replace" or "overlay"; empty means "replace"
	Only          []string // "core", "plugin:elementor"; empty means everything
	NoOriginal    string   // "keep" or "quarantine"; empty means "keep"
	Domain        string
	Fetcher       *vendorfiles.Fetcher
	Progress      *progress.Writer
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

// ParseMode validates a --mode value. An empty string is the default, replace.
func ParseMode(s string) (string, error) {
	switch s {
	case "":
		return "replace", nil
	case "replace", "overlay":
		return s, nil
	default:
		return "", fmt.Errorf("unbekannter Modus %q (erlaubt: replace, overlay)", s)
	}
}

// ParseNoOriginal validates a --no-original value. An empty string is the
// default, keep: deleting an element outright was the old behaviour, and it
// cost a site a feature whenever the missing version turned out to be a paid
// plugin or a custom theme rather than something actually withdrawn.
func ParseNoOriginal(s string) (string, error) {
	switch s {
	case "":
		return "keep", nil
	case "keep", "quarantine":
		return s, nil
	default:
		return "", fmt.Errorf("unbekannter Wert %q für --no-original (erlaubt: keep, quarantine)", s)
	}
}

// Run walks the five phases.
//
// Nothing below Root is touched before every archive is on disk and unpacked:
// a download that breaks half way then costs a run, not a website. Whatever
// Root is not left in that way in the phases that follow, both replace and
// overlay first file it into quarantine, so a run interrupted after that
// point still leaves the original recoverable rather than gone.
func Run(opts Options) (*report.Repair, error) {
	rep := report.NewRepair(opts.Root)
	rep.DryRun = opts.DryRun
	pw := opts.Progress

	defer func() {
		rep.FinishedAt = time.Now().UTC()
		rep.Log = pw.Entries()
	}()

	mode, err := ParseMode(opts.Mode)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
	rep.Mode = mode
	noOriginal, err := ParseNoOriginal(opts.NoOriginal)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}

	// Phase 1
	pw.Phase(1, phaseTotal, "detect")
	plan, err := BuildPlan(opts.Root)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
	rep.Untouched = plan.Untouched

	plan, err = plan.Filter(opts.Only)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, err
	}
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
			rep.Elements = append(rep.Elements, describe(it, mode, noOriginal))
		}
		return rep, nil
	}

	// Phases 4 and 5
	for i, it := range items {
		el := it.element
		pw.Element(el.Kind, el.Slug, el.Version, i, total)
		pw.Phase(4, phaseTotal, "quarantine")

		entry := report.RepairElement{
			Kind: el.Kind, Slug: el.Slug, Version: el.Version, Locale: el.Locale,
			Path: el.Path,
		}

		switch {
		case it.dir == "" && (noOriginal == "keep" || el.Kind == "core"):
			// el.Path is the web root itself for the core element - there is
			// no sensible way to "quarantine" that as a unit, so a core
			// without a fetchable version is always just left alone, no
			// matter what --no-original says. In practice the vendor always
			// publishes every WordPress core release; this only guards
			// against a stale cache or a withdrawn version ever reaching
			// here.
			entry.Outcome, entry.Message = report.OutcomeKept, "kein Original verfügbar"
			pw.Log("warn", "%s %s: kein Original verfügbar, unangetastet gelassen", label(el), el.Version)

		case it.dir == "":
			// No vendor version and --no-original=quarantine: file the element
			// away rather than leave a possibly-compromised directory behind.
			// This always archives by removing, in either Mode - there is no
			// new tree to overlay it with.
			qEntry, err := quarantineElement(opts, "replace", el, "Beim Ersetzen durch das Original abgelegt")
			if err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.Outcome, entry.QuarantineID = report.OutcomeDeleted, qEntry.ID
			pw.Log("error", "gelöscht %s %s - kein Original verfügbar, in Quarantäne %s",
				label(el), el.Version, qEntry.ID)

		case el.Kind == "core":
			// The core cannot be swapped like a plugin: the element's path is
			// the web root itself, and quarantining or replacing it wholesale
			// would take wp-content and wp-config.php along. repairCore only
			// ever touches wp-admin, wp-includes and the loose root files, the
			// same parts SwapCore always has.
			pw.Phase(5, phaseTotal, "swap")
			n, ids, err := repairCore(opts, mode, it.dir)
			if err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.Files, entry.QuarantineID = n, strings.Join(ids, ", ")
			if mode == "overlay" {
				entry.Outcome = report.OutcomeOverlaid
				pw.Log("ok", "überlagert Kern %s", el.Version)
			} else {
				entry.Outcome = report.OutcomeReplaced
				pw.Log("ok", "ersetzt Kern %s", el.Version)
			}

		default:
			reason := "Beim Ersetzen durch das Original abgelegt"
			if mode == "overlay" {
				reason = "Vor dem Darüberschreiben abgelegt"
			}

			// Store removes el.Path once it has archived it, so by the time
			// Swap could stat it there is nothing left to read a mode from.
			// Capturing it first and reapplying it after keeps a hardened
			// install hardened; overlay never removes its source, so Overlay
			// reads oldDir's mode itself and needs none of this.
			var savedMode os.FileMode
			var uid, gid int
			var hadMode bool
			if mode != "overlay" {
				savedMode, uid, gid, hadMode = captureMode(el.Path)
			}

			qEntry, err := quarantineElement(opts, mode, el, reason)
			if err != nil {
				entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
				rep.Elements = append(rep.Elements, entry)
				return rep, err
			}
			entry.QuarantineID = qEntry.ID

			pw.Phase(5, phaseTotal, "swap")
			if mode == "overlay" {
				n, err := Overlay(opts.Root, el.Path, it.dir)
				if err != nil {
					entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
					rep.Elements = append(rep.Elements, entry)
					return rep, err
				}
				entry.Outcome, entry.Files = report.OutcomeOverlaid, n
				pw.Log("ok", "überlagert %s %s", label(el), el.Version)
			} else {
				if err := Swap(opts.Root, el.Path, it.dir); err != nil {
					entry.Outcome, entry.Message = report.OutcomeFailed, err.Error()
					rep.Elements = append(rep.Elements, entry)
					return rep, err
				}
				if hadMode {
					_ = applyOwnership(el.Path, uid, gid, savedMode)
				}
				entry.Outcome = report.OutcomeReplaced
				entry.Files = countFiles(el.Path)
				pw.Log("ok", "ersetzt %s %s", label(el), el.Version)
			}
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

// repairSource builds what quarantine.Store or StoreCopy needs to file el
// away under its own path, so a later Restore puts it back exactly where it
// came from rather than wherever the store happens to live.
func repairSource(opts Options, el Element, reason string) quarantine.Source {
	rel, _ := filepath.Rel(opts.Root, el.Path)
	return quarantine.Source{
		Root:    opts.Root,
		RelPath: filepath.ToSlash(rel),
		Domain:  opts.Domain,
		Origin:  "repair",
		Reason:  reason,
	}
}

// quarantineElement files el.Path away before it is touched: Store in
// replace mode, which also removes it, StoreCopy in overlay mode, which
// leaves it for Overlay to read from afterwards.
func quarantineElement(opts Options, mode string, el Element, reason string) (quarantine.Entry, error) {
	if err := InsideRoot(opts.Root, el.Path); err != nil {
		return quarantine.Entry{}, err
	}
	src := repairSource(opts, el, reason)
	if mode == "overlay" {
		return quarantine.StoreCopy(opts.QuarantineDir, src)
	}
	return quarantine.Store(opts.QuarantineDir, src)
}

// captureMode reads a directory's mode and owner before quarantine.Store
// removes it, so the tree that replaces it can be given the same identity
// back. ok is false when dir cannot be read, which just means there is
// nothing to restore afterwards rather than an error worth failing the run
// over - Swap already falls back to a sane default in that case.
func captureMode(dir string) (mode os.FileMode, uid, gid int, ok bool) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, -1, -1, false
	}
	uid, gid = ownerOf(info)
	return info.Mode().Perm(), uid, gid, true
}

// repairCore quarantines wp-admin and wp-includes - the two directories a
// core replacement removes or overlays as a whole - each as its own entry,
// before SwapCore (replace) or overlayCore (overlay) touch them. The loose
// root files neither function has ever backed up individually, even when
// this ran through the old tar-file Backup: there is no directory there for
// a quarantine entry to name, only files SwapCore has always overwritten one
// by one.
func repairCore(opts Options, mode string, stagedDir string) (int, []string, error) {
	var ids []string
	for _, dir := range coreDirs {
		target := filepath.Join(opts.Root, dir)
		if _, err := os.Lstat(target); err != nil {
			continue // nothing there yet to archive
		}
		if err := InsideRoot(opts.Root, target); err != nil {
			return 0, ids, err
		}

		reason := "Beim Ersetzen durch das Original abgelegt"
		src := quarantine.Source{
			Root: opts.Root, RelPath: dir, Domain: opts.Domain,
			Origin: "repair", Reason: reason,
		}
		var qEntry quarantine.Entry
		var err error
		if mode == "overlay" {
			src.Reason = "Vor dem Darüberschreiben abgelegt"
			qEntry, err = quarantine.StoreCopy(opts.QuarantineDir, src)
		} else {
			qEntry, err = quarantine.Store(opts.QuarantineDir, src)
		}
		if err != nil {
			return 0, ids, err
		}
		ids = append(ids, qEntry.ID)
	}

	if mode == "overlay" {
		n, err := overlayCore(opts.Root, stagedDir)
		return n, ids, err
	}
	// wp-admin and wp-includes are already gone, quarantined above; SwapCore
	// finds them missing and puts the staged tree straight in their place.
	n, err := SwapCore(opts.Root, stagedDir)
	return n, ids, err
}

// overlayCore is Overlay's counterpart to SwapCore: wp-admin and wp-includes
// through Overlay itself, so nothing already there is removed, and the loose
// root files the exact same way SwapCore always has, by name, since that was
// already an add-or-replace with nothing else touched.
func overlayCore(root, stagedDir string) (int, error) {
	if err := InsideRoot(root, stagedDir); err == nil {
		return 0, fmt.Errorf("das Bereitstellungsverzeichnis %s darf nicht im Webstamm liegen", stagedDir)
	}

	written := 0
	for _, dir := range coreDirs {
		src := filepath.Join(stagedDir, dir)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(root, dir)
		if err := InsideRoot(root, dst); err != nil {
			return written, err
		}
		n, err := Overlay(root, dst, src)
		if err != nil {
			return written, err
		}
		written += n
	}

	entries, err := os.ReadDir(stagedDir)
	if err != nil {
		return written, err
	}
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		dst := filepath.Join(root, de.Name())
		if err := InsideRoot(root, dst); err != nil {
			return written, err
		}
		raw, err := os.ReadFile(filepath.Join(stagedDir, de.Name()))
		if err != nil {
			return written, err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func label(el Element) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + " " + el.Slug
}

// describe reports what a dry run would do to one staged element, under the
// Mode and NoOriginal a real run would have used.
func describe(it staged, mode, noOriginal string) report.RepairElement {
	out := report.RepairElement{
		Kind: it.element.Kind, Slug: it.element.Slug, Version: it.element.Version,
		Locale: it.element.Locale, Path: it.element.Path,
	}
	switch {
	case it.dir == "" && (noOriginal == "keep" || it.element.Kind == "core"):
		out.Outcome, out.Message = report.OutcomeKept, "kein Original verfügbar"
	case it.dir == "":
		out.Outcome, out.Message = report.OutcomeDeleted, "kein Original verfügbar"
	case mode == "overlay":
		out.Outcome = report.OutcomeOverlaid
	default:
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
