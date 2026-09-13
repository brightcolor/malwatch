package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/safepath"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// phaseTotal is the number of phases a run goes through.
const phaseTotal = 4

// The states a step goes through in the progress file.
const (
	stateWaiting        = "waiting"
	stateFetched        = "fetched"
	stateVerified       = "verified"
	stateRefused        = "refused"
	stateSwapped        = "swapped"
	stateDatabase       = "database"
	stateUpdated        = "updated"
	stateWould          = "would_update"
	stateRolledBack     = "rolled_back"
	stateFailed         = "failed"
	stateRollbackFailed = "rollback_failed"
	stateSkipped        = "skipped"
)

// Options is one upgrade run. Fetcher and Checksums are required; the
// staging directory has to exist and lie outside the web root.
type Options struct {
	WebRoot       string // --path; the plan was checked against it
	Plan          Plan
	QuarantineDir string
	StagingDir    string
	Domain        string
	DryRun        bool

	PHPVersion string // what the PHP of the website says it is
	WPCLI      WPCLI  // runs the database steps
	HasWPCLI   bool   // the WP-CLI binary exists

	Fetcher   *vendorfiles.Fetcher
	Checksums Checksums
	Prober    PageProber
	Progress  *progress.Writer

	Now       func() time.Time // nil means time.Now
	DBTimeout time.Duration    // bound of each WP-CLI call; zero means an hour
}

// item is one element on its way through the run.
type item struct {
	index    int
	install  PlanInstall
	el       PlanElement
	path     string // element directory; the installation for the core
	from     string
	locale   string
	staged   string // unpacked release
	dbChange bool   // core: the release raises the database
	req      Requirements
	rep      report.UpgradeElement
}

// open reports whether the element still waits for its outcome.
func (it *item) open() bool { return it.rep.Outcome == "" }

type runner struct {
	opts  Options
	pw    *progress.Writer
	rep   *report.Upgrade
	items []*item
	cores map[string]CoreFacts // installed core per installation
}

// Run walks the four phases and returns the report. The error is set when
// the run itself failed; the report names it as well.
func Run(opts Options) (*report.Upgrade, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DBTimeout <= 0 {
		opts.DBTimeout = time.Hour
	}
	pw := opts.Progress
	if pw == nil {
		pw, _ = progress.New("", "upgrade")
	}
	r := &runner{opts: opts, pw: pw, rep: report.NewUpgrade(opts.WebRoot, opts.DryRun),
		cores: map[string]CoreFacts{}}
	r.rep.PHPVersion = opts.PHPVersion
	defer func() {
		r.collect()
		r.rep.FinishedAt = time.Now().UTC()
		r.rep.Log = r.pw.Entries()
	}()

	if opts.PHPVersion == "" {
		return r.fail(fmt.Errorf("die PHP-Version der Website ist unbekannt"))
	}

	r.pw.Phase(1, phaseTotal, "detect")
	r.detect()

	r.pw.Phase(2, phaseTotal, "fetch")
	if err := r.fetch(); err != nil {
		return r.fail(err)
	}

	r.pw.Phase(3, phaseTotal, "verify")
	if err := r.verify(); err != nil {
		return r.fail(err)
	}
	baselines := r.baselines()

	if opts.DryRun {
		r.pw.Log("info", "Probelauf - es wird nichts geändert")
		r.finishDryRun(baselines)
		return r.rep, nil
	}

	r.pw.Phase(4, phaseTotal, "upgrade")
	r.upgradeAll(baselines)
	return r.rep, nil
}

// detect reads what is installed and turns down what cannot go ahead, before
// anything is fetched.
func (r *runner) detect() {
	var steps []progress.Step
	for _, inst := range r.opts.Plan.Installs {
		facts, coreErr := ReadCore(inst.Path)
		r.cores[inst.Path] = facts
		extras := map[string]cms.Install{}
		for _, x := range cms.WordPressExtras(inst.Path) {
			extras[x.Kind+":"+x.Slug] = x
		}
		multisite := Multisite(inst.Path)
		busy := MaintenanceActive(inst.Path, r.opts.Now())

		for _, el := range inst.Elements {
			it := &item{index: len(r.items), install: inst, el: el, locale: facts.Locale}
			if el.Kind == "core" {
				it.path, it.from = inst.Path, facts.Version
			} else if x, ok := extras[el.Kind+":"+el.Slug]; ok {
				it.path, it.from = x.Path, x.Version
			}
			it.rep = report.UpgradeElement{
				Kind: el.Kind, Slug: el.Slug, Install: inst.Path, Path: it.path,
				From: it.from, To: el.Version,
			}

			switch {
			case coreErr != nil:
				r.refuse(it, coreErr.Error())
			case it.path == "":
				r.refuse(it, "ist in dieser Installation nicht vorhanden")
			case multisite:
				r.refuse(it, "WordPress-Multisite wird nicht aktualisiert")
			case busy:
				r.refuse(it, "WordPress aktualisiert diese Installation gerade selbst (.maintenance)")
			case cms.Compare(el.Version, it.from) <= 0:
				r.refuse(it, fmt.Sprintf("Zielversion %s ist nicht höher als die installierte %s", el.Version, it.from))
			}

			state := stateWaiting
			if !it.open() {
				state = stateRefused
			}
			steps = append(steps, progress.Step{
				Kind: el.Kind, Slug: el.Slug, Path: it.path, From: it.from, To: el.Version, State: state,
			})
			r.items = append(r.items, it)
		}
	}
	r.pw.SetSteps(steps)
	r.pw.Log("info", "%d Element(e) im Plan", len(r.items))
}

// fetch loads the release of every open element. A release wordpress.org does
// not publish turns its element down; any other failure ends the run while
// the site is still untouched.
func (r *runner) fetch() error {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		dest, err := os.MkdirTemp(r.opts.StagingDir, "up-")
		if err != nil {
			return err
		}
		switch it.el.Kind {
		case "core":
			it.staged, err = r.opts.Fetcher.Core(it.el.Version, it.locale, dest)
		case "plugin":
			it.staged, err = r.opts.Fetcher.Plugin(it.el.Slug, it.el.Version, dest)
		case "theme":
			it.staged, err = r.opts.Fetcher.Theme(it.el.Slug, it.el.Version, dest)
		}
		switch {
		case errors.Is(err, vendorfiles.ErrNotPublished):
			r.refuse(it, fmt.Sprintf("Version %s ist bei wordpress.org nicht veröffentlicht", it.el.Version))
		case err != nil:
			return fmt.Errorf("%s %s: %w", label(it.el), it.el.Version, err)
		default:
			r.pw.StepState(it.index, stateFetched)
		}
	}
	return nil
}

// verify holds every fetched release against its checksums and checks what it
// asks of the site. A checksum that does not match ends the run; a
// requirement the site does not meet turns the element down.
func (r *runner) verify() error {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		if info, err := os.Stat(it.staged); err != nil || !info.IsDir() {
			r.refuse(it, "das geladene Archiv enthält das erwartete Verzeichnis nicht")
			continue
		}
		unverified, err := verifyStaged(r.opts.Checksums, it.el, it.locale, it.staged)
		if err != nil {
			return fmt.Errorf("%s %s: %w", label(it.el), it.el.Version, err)
		}
		it.rep.Unverified = unverified
		if reason := r.requirements(it); reason != "" {
			r.refuse(it, reason)
			continue
		}
		r.pw.StepState(it.index, stateVerified)
	}
	return nil
}

// requirements reads what the release asks and returns why the site cannot
// take it, or "". A plugin or theme is checked against the core the
// installation will run: the target of a core update in the same plan that
// is still open, the installed core otherwise.
func (r *runner) requirements(it *item) string {
	php := r.opts.PHPVersion
	if it.el.Kind == "core" {
		facts, err := ReadCore(it.staged)
		if err != nil {
			return err.Error()
		}
		it.dbChange = facts.DBVersion != r.cores[it.install.Path].DBVersion
		if it.dbChange && !r.opts.HasWPCLI {
			return "das Kern-Update hebt die Datenbank an und braucht dafür WP-CLI"
		}
		return Requirements{PHP: facts.RequiredPHP}.Check("WordPress "+it.el.Version, "", php)
	}

	var req Requirements
	var err error
	if it.el.Kind == "theme" {
		req, err = ThemeRequirements(it.staged)
	} else {
		req, err = PluginRequirements(it.staged)
	}
	if err != nil {
		return err.Error()
	}
	it.req = req
	return req.Check(it.el.Version, r.plannedCore(it.install.Path), php)
}

// plannedCore is the core version an installation runs once the core element
// of the plan, while still open, is in.
func (r *runner) plannedCore(install string) string {
	for _, it := range r.items {
		if it.install.Path == install && it.el.Kind == "core" && it.open() {
			return it.el.Version
		}
	}
	return r.cores[install].Version
}

// baselines fetches both pages of every installation with an open element,
// before anything changes.
func (r *runner) baselines() map[string][]Probe {
	out := map[string][]Probe{}
	for _, it := range r.items {
		if _, seen := out[it.install.Path]; seen || !it.open() {
			continue
		}
		out[it.install.Path] = r.probe(it)
	}
	return out
}

// probe fetches both pages of the installation, or nothing without a prober.
func (r *runner) probe(it *item) []Probe {
	if r.opts.Prober == nil {
		return nil
	}
	return probeSite(r.opts.Prober, it.install.URL)
}

func (r *runner) finishDryRun(baselines map[string][]Probe) {
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		it.rep.Outcome = report.UpgradeWould
		it.rep.Checks = checks(pageURLs(it.install.URL), baselines[it.install.Path], nil, nil)
		r.pw.StepState(it.index, stateWould)
	}
}

// upgradeAll exchanges the open elements one by one. The check after each
// element is the baseline of the next. A site that stays broken after a
// rollback stops the run.
func (r *runner) upgradeAll(baselines map[string][]Probe) {
	current := map[string]string{}
	for path, facts := range r.cores {
		current[path] = facts.Version
	}
	for _, it := range r.items {
		if !it.open() {
			continue
		}
		if it.el.Kind != "core" {
			if reason := it.req.Check(it.el.Version, current[it.install.Path], r.opts.PHPVersion); reason != "" {
				r.refuse(it, reason)
				continue
			}
		}
		r.pw.Element(it.el.Kind, it.el.Slug, it.el.Version, it.index, len(r.items))
		baselines[it.install.Path] = r.upgradeOne(it, baselines[it.install.Path])

		switch it.rep.Outcome {
		case report.UpgradeUpdated:
			if it.el.Kind == "core" {
				current[it.install.Path] = it.el.Version
			}
		case report.UpgradeRollbackFailed:
			r.skipOpen("nach einem gescheiterten Zurückholen nicht begonnen")
			return
		}
	}
}

// upgradeOne exchanges one element and checks the site. It returns what the
// pages answer now, the baseline of the next element.
func (r *runner) upgradeOne(it *item, before []Probe) []Probe {
	install := it.install.Path
	repl := repair.Replacement{
		Root: install, QuarantineDir: r.opts.QuarantineDir, Domain: r.opts.Domain,
		Origin: "upgrade", Reason: fmt.Sprintf("Vor dem Update auf %s abgelegt", it.el.Version),
	}

	// The database first, while nothing has changed yet.
	dump := ""
	if it.dbChange {
		path, id, err := r.exportDB(it)
		if err != nil {
			r.refuse(it, "Datenbank-Export gescheitert: "+err.Error())
			return before
		}
		dump, it.rep.DBExportID = path, id
		defer os.Remove(dump)
	}

	if err := EnterMaintenance(install, r.opts.Now()); err != nil {
		r.refuse(it, "Wartungsmodus nicht setzbar: "+err.Error())
		return before
	}
	defer func() { _ = LeaveMaintenance(install) }()

	var added []string
	var err error
	if it.el.Kind == "core" {
		added = absentIn(install, it.staged)
		it.rep.Files, it.rep.QuarantineIDs, err = repair.ReplaceCore(repl, it.staged)
	} else {
		var entry quarantine.Entry
		entry, it.rep.Files, err = repair.ReplaceDir(repl, it.path, it.staged)
		if entry.ID != "" {
			it.rep.QuarantineIDs = []string{entry.ID}
		}
	}
	if err != nil {
		return r.rollBack(it, before, nil, added, "", report.UpgradeFailed, "Tausch gescheitert: "+err.Error())
	}
	r.pw.StepState(it.index, stateSwapped)

	if it.dbChange {
		r.pw.StepState(it.index, stateDatabase)
		ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
		err := r.opts.WPCLI.UpdateDB(ctx, install)
		cancel()
		if err != nil {
			return r.rollBack(it, before, nil, added, dump, report.UpgradeFailed,
				"Datenbank-Anhebung gescheitert: "+err.Error())
		}
	}

	if err := LeaveMaintenance(install); err != nil {
		r.pw.Log("warn", "%s: %v", install, err)
	}
	after := r.probe(it)
	it.rep.Checks = checks(pageURLs(it.install.URL), before, after, nil)
	if reason := siteBroken(before, after); reason != "" {
		return r.rollBack(it, before, after, added, dump, report.UpgradeRolledBack, reason)
	}

	it.rep.Outcome = report.UpgradeUpdated
	if !anyJudgeable(before) {
		it.rep.Message = "Nachprüfung ohne Aussage: keine Seite antwortete vorher mit einem Status unter 500"
	}
	r.pw.StepState(it.index, stateUpdated)
	r.pw.Log("ok", "aktualisiert %s %s → %s", label(it.el), it.from, it.el.Version)
	return after
}

// rollBack brings the old state back after a failed exchange or a broken
// site: the quarantine entries in reverse order, what the release added, the
// database when a dump is given, then a check. outcome is the verdict when the
// site answers as before; otherwise the element is rollback_failed.
func (r *runner) rollBack(it *item, before, after []Probe, added []string, dump string,
	outcome report.UpgradeOutcome, reason string) []Probe {
	install := it.install.Path
	r.pw.Log("warn", "%s %s: %s - der alte Stand wird zurückgeholt", label(it.el), it.el.Version, reason)
	var problems []string

	for i := len(it.rep.QuarantineIDs) - 1; i >= 0; i-- {
		if err := quarantine.Restore(r.opts.QuarantineDir, it.rep.QuarantineIDs[i], true); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, name := range added {
		target := filepath.Join(install, name)
		if err := safepath.InsideRoot(install, target); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if dump != "" {
		f, err := os.Open(dump)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
			err = r.opts.WPCLI.ImportDB(ctx, install, f)
			cancel()
			f.Close()
		}
		if err != nil {
			problems = append(problems, "Datenbank: "+err.Error())
		}
	}
	if err := LeaveMaintenance(install); err != nil {
		problems = append(problems, err.Error())
	}

	again := r.probe(it)
	it.rep.Checks = checks(pageURLs(it.install.URL), before, after, again)
	broken := siteBroken(before, again)
	if len(problems) > 0 || broken != "" {
		detail := broken
		if len(problems) > 0 {
			detail = strings.Join(problems, "; ")
		}
		it.rep.Outcome = report.UpgradeRollbackFailed
		it.rep.Message = reason + "; nach dem Zurückholen: " + detail
		r.pw.StepState(it.index, stateRollbackFailed)
		r.pw.Log("error", "%s: die Website bleibt nach dem Zurückholen fehlerhaft (%s)", install, detail)
		return again
	}

	it.rep.Outcome, it.rep.Message = outcome, reason
	if outcome == report.UpgradeFailed {
		r.pw.StepState(it.index, stateFailed)
	} else {
		r.pw.StepState(it.index, stateRolledBack)
	}
	r.pw.Log("warn", "zurückgeholt %s %s", label(it.el), it.from)
	return again
}

// exportDB writes the database of the installation into the staging
// directory and files a copy into quarantine. It returns the staged file,
// which a rollback imports, and the id of the quarantine entry.
func (r *runner) exportDB(it *item) (string, string, error) {
	name := "datenbank-" + randomHex() + ".sql"
	path := filepath.Join(r.opts.StagingDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.DBTimeout)
	err = r.opts.WPCLI.ExportDB(ctx, it.install.Path, f)
	cancel()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", "", err
	}
	entry, err := quarantine.StoreCopy(r.opts.QuarantineDir, quarantine.Source{
		Root: r.opts.StagingDir, RelPath: name, Domain: r.opts.Domain, Origin: "upgrade",
		Reason: fmt.Sprintf("Datenbank vor dem Kern-Update auf %s; einspielen mit wp db import", it.el.Version),
	})
	if err != nil {
		os.Remove(path)
		return "", "", err
	}
	return path, entry.ID, nil
}

// absentIn lists what a staged core adds to the installation: a core
// directory or a loose root file the installation lacks. A rollback removes
// them again.
func absentIn(install, staged string) []string {
	entries, err := os.ReadDir(staged)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && name != "wp-admin" && name != "wp-includes" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(install, name)); os.IsNotExist(err) {
			out = append(out, name)
		}
	}
	return out
}

// checks lines up what the pages answered before, after the exchange and
// after a rollback.
func checks(urls []string, before, after, afterRollback []Probe) []report.PageCheck {
	out := make([]report.PageCheck, len(urls))
	for i, u := range urls {
		out[i].URL = u
		if i < len(before) {
			out[i].Before = before[i].Status
		}
		if i < len(after) {
			out[i].After = after[i].Status
		}
		if i < len(afterRollback) {
			out[i].AfterRollback = afterRollback[i].Status
		}
	}
	return out
}

func anyJudgeable(probes []Probe) bool {
	for _, p := range probes {
		if Judgeable(p) {
			return true
		}
	}
	return false
}

// refuse turns an element down with its reason; nothing of it changes.
func (r *runner) refuse(it *item, reason string) {
	it.rep.Outcome, it.rep.Message = report.UpgradeRefused, reason
	r.pw.StepState(it.index, stateRefused)
	r.pw.Log("warn", "%s %s: %s", label(it.el), it.el.Version, reason)
}

// skipOpen marks every element without an outcome as skipped.
func (r *runner) skipOpen(reason string) {
	for _, it := range r.items {
		if it.open() {
			it.rep.Outcome, it.rep.Message = report.UpgradeSkipped, reason
			r.pw.StepState(it.index, stateSkipped)
		}
	}
}

// fail records a run error. Every element without an outcome is skipped.
func (r *runner) fail(err error) (*report.Upgrade, error) {
	r.rep.Errors = append(r.rep.Errors, err.Error())
	r.pw.Log("error", "%s", err.Error())
	r.skipOpen("Lauf abgebrochen")
	return r.rep, err
}

// collect writes the elements into the report, in plan order.
func (r *runner) collect() {
	r.rep.Elements = make([]report.UpgradeElement, 0, len(r.items))
	for _, it := range r.items {
		r.rep.Elements = append(r.rep.Elements, it.rep)
	}
}

func randomHex() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
