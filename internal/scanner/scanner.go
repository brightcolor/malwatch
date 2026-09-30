// Package scanner ties the stages together: it walks the tree, asks the
// signature and heuristic engines, and folds in what the vendors published.
package scanner

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brightcolor/malwatch/internal/clamav"
	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/fileview"
	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/phpcode"
	"github.com/brightcolor/malwatch/internal/phpinfo"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/rules"
	"github.com/brightcolor/malwatch/internal/sigs"
	"github.com/brightcolor/malwatch/internal/textpos"
	"github.com/brightcolor/malwatch/internal/traits"
	"github.com/brightcolor/malwatch/internal/version"
	"github.com/brightcolor/malwatch/internal/vulns"
	"github.com/brightcolor/malwatch/internal/walk"
)

// Options configure one run.
type Options struct {
	Paths        []string
	Excludes     []string
	MaxAge       time.Duration
	MaxSize      int64
	Threads      int
	IgnoreChmod0 bool

	NoMalwareScan bool
	NoVersionScan bool
	NoPluginScan  bool
	NoClamAV      bool
	// NoVulnScan skips the lookup of known flaws. The detected versions and
	// their comparison with the newest release stay in the report.
	NoVulnScan bool
	// WPScanToken switches WPScan on as an additional source for WordPress.
	// WPScanTokenFile names a file holding it and wins when both are set.
	WPScanToken     string
	WPScanTokenFile string
	// PHPBinary names the PHP of the website; the report then carries its
	// version, so the panel can tell which releases the site can take.
	PHPBinary string
	// PHPVersion names the PHP version of the website directly and wins over
	// the one read from PHPBinary. Rules about constructs that PHP no longer
	// runs stay silent on a site whose PHP is newer (rules.Rule.DeadFrom).
	PHPVersion string

	IgnoreRules []string
	Whitelist   map[string]bool
	// UploadDirs names the directories that hold nothing but uploads, for the
	// rules that judge a file by lying below one. Empty means
	// rules.DefaultUploadDirs.
	UploadDirs []string
	// ModifiedExts are the extensions where a vendor file that differs from
	// the release counts as core.modified. Empty means DefaultModifiedExts.
	ModifiedExts []string
	// ScriptHosts are the hosts a script written by document.write may load
	// from, see rules.DefaultScriptHosts. It only counts when ScriptHostsSet
	// is true, because an empty list is a choice too: only the site itself.
	ScriptHosts    []string
	ScriptHostsSet bool

	// Verify steers the check of files with findings against the sources that
	// know them; the zero value checks nothing, the command line starts from
	// DefaultVerify.
	Verify VerifyOptions

	// verified counts the files whose content a source confirmed; Run
	// creates it and puts the counts into the report.
	verified *verifiedCount
	// verifyTransport replaces the network of the check for the tests.
	verifyTransport http.RoundTripper
	// originals loads single files of a vendor's release, see rebuilt.
	originals *originFetcher
	// View limits what the report shows of a file with findings: its marks,
	// its traits and the lines around them. The zero value reports neither
	// marks nor code; the command line starts from fileview.Default.
	View fileview.Options

	SignatureDir string
	CacheFile    string
	StateDir     string

	// Offline skips every network lookup. Version findings then report the
	// installed version without a verdict rather than guessing.
	Offline bool

	// Progress meldet, wie viele Dateien der Lauf bisher ANGESEHEN hat -
	// geprüfte und übersprungene zusammen. Nicht nur die geprüften: bei
	// eingeschaltetem Cache verfehlt ein zweiter Lauf über dieselbe Website
	// fast jede Datei nicht, sondern trifft sie im Cache, und der Zähler der
	// geprüften Dateien bliebe bei null stehen (siehe scanner_test.go). Der
	// Nenner, den das Panel über --expect mitgibt, zählt dasselbe.
	Progress func(considered int64)
}

// progressEvery ist der Abstand, in dem der Fortschritt gemeldet wird. Eine
// Meldung je Datei wären hunderttausend Schreibvorgänge für einen Lauf.
const progressEvery = 500

// maxReadSize caps how much of one file is examined. A 300 MB log file has
// nothing to say about malware and would stall a worker for seconds.
const maxReadSize = 32 * 1024 * 1024

// Run performs a scan and returns the report.
func Run(opts Options) (*report.Report, error) {
	if len(opts.Paths) == 0 {
		return nil, fmt.Errorf("kein Pfad angegeben")
	}
	if opts.Threads <= 0 {
		opts.Threads = runtime.NumCPU()
	}
	if opts.MaxSize <= 0 {
		opts.MaxSize = maxReadSize
	}

	rep := report.New(opts.Paths)
	if opts.PHPBinary != "" {
		if v, err := phpinfo.Version(opts.PHPBinary, 10*time.Second); err != nil {
			rep.Errors = append(rep.Errors, "PHP-Version nicht ermittelbar: "+err.Error())
		} else {
			rep.PHPVersion = v
		}
	}

	sigDB, err := sigs.Load(opts.SignatureDir)
	if err != nil {
		rep.Errors = append(rep.Errors, "Signaturen unvollständig geladen: "+err.Error())
	}
	rep.Engines["signaturen"] = sigDB.Describe()

	engine := rules.NewEngine(opts.IgnoreRules)
	engine.SetMarkLimit(opts.View.MaxMarks)
	if opts.PHPVersion != "" {
		engine.SetPHPVersion(opts.PHPVersion)
	} else {
		engine.SetPHPVersion(rep.PHPVersion)
	}
	if len(opts.UploadDirs) > 0 {
		if err := engine.SetUploadDirs(opts.UploadDirs); err != nil {
			return nil, fmt.Errorf("--upload-dirs: %w", err)
		}
	}
	if opts.ScriptHostsSet {
		if err := engine.SetScriptHosts(opts.ScriptHosts); err != nil {
			return nil, fmt.Errorf("--script-hosts: %w", err)
		}
	}
	rep.Engines["heuristik"] = fmt.Sprintf("%d Regeln", engine.RuleCount())

	known := knownfiles.New()
	if !opts.NoVersionScan {
		collectSoftware(rep, &opts, known)
	}
	if installs, sums := known.Counts(); installs > 0 {
		rep.Engines["herstellerdateien"] = fmt.Sprintf("%d Installationen, %d Prüfsummen", installs, sums)
	}

	opts.verified = &verifiedCount{m: map[string]int{}}
	opts.originals = newOriginFetcher(&opts)
	if !opts.NoMalwareScan {
		if err := scanFiles(rep, &opts, sigDB, engine, known); err != nil {
			return rep, err
		}
		if !opts.NoClamAV {
			runClamAV(rep, &opts)
		}
	}

	verifyComposer(rep, &opts)
	verifyHashlookup(rep, &opts)
	applyWhitelist(rep, opts.Whitelist)
	if len(opts.verified.m) > 0 {
		rep.Verified = opts.verified.m
	}
	pruneViews(rep)
	rep.FinishedAt = time.Now()
	rep.Sort()
	return rep, nil
}

// scanFiles walks every path and applies the engines.
func scanFiles(rep *report.Report, opts *Options, sigDB *sigs.DB, engine *rules.Engine, known *knownfiles.Index) error {
	counters := &walk.Counters{}
	cache := newCleanCache(opts.CacheFile, fingerprint(sigDB, engine, opts))

	type job struct{ file walk.File }
	jobs := make(chan job, opts.Threads*8)

	var (
		mu       sync.Mutex
		findings []report.Finding
		errs     []string
		views    = map[string]*report.FileView{}
		// spent counts the code bytes of the views so far, against the
		// budget of opts.View.
		spent int64
	)
	var wg sync.WaitGroup

	// Gemeldet wird die Summe aus geprüften und übersprungenen Dateien, und
	// zwar aus beiden Richtungen: aus den Arbeitern, die prüfen, und aus dem
	// Lauf über den Baum, der überspringt. Ein warmer Lauf schickt kaum eine
	// Datei an die Arbeiter - dann meldet nur noch der Baumlauf, und der Balken
	// bewegt sich trotzdem. lastPublished ist die Drossel: gemeldet wird erst,
	// wenn seit der letzten Meldung progressEvery Dateien dazugekommen sind.
	// Das CompareAndSwap macht das zwischen den Arbeitern eindeutig, ein
	// Modulo auf einen aus zwei Zählern gebildeten Wert wäre es nicht.
	var lastPublished atomic.Int64
	publish := func() {
		if opts.Progress == nil {
			return
		}
		n := counters.Files.Load() + counters.Skipped.Load()
		for {
			prev := lastPublished.Load()
			if n-prev < progressEvery {
				return
			}
			if lastPublished.CompareAndSwap(prev, n) {
				break
			}
		}
		opts.Progress(n)
	}

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				got, view, ferr := scanFile(j.file, sigDB, engine, known, opts)
				mu.Lock()
				findings = append(findings, got...)
				if ferr != "" {
					errs = append(errs, ferr)
				}
				if view != nil && len(got) > 0 && views[got[0].SHA256] == nil {
					size := viewBytes(view)
					if spent+size > opts.View.Budget() {
						view.Omitted = size > 0
						view.Show = nil
					} else {
						spent += size
					}
					views[got[0].SHA256] = view
				}
				mu.Unlock()

				if got == nil {
					cache.MarkClean(j.file.Path, j.file.Size, j.file.MTime)
				}
				counters.Files.Add(1)
				counters.Bytes.Add(j.file.Size)
				publish()
			}
		}()
	}

	// A file over the size limit is not read. A program says what it is in its
	// first bytes, though, so the rules that decide from the start of a file
	// get just that, and a program padded past the limit still shows up.
	large := func(f walk.File) {
		got, ferr := scanHead(f, engine, known, opts)
		if len(got) > 0 || ferr != "" {
			mu.Lock()
			findings = append(findings, got...)
			if ferr != "" {
				errs = append(errs, ferr)
			}
			mu.Unlock()
		}
		publish()
	}

	walker := walk.New(walk.Options{
		Excludes:     opts.Excludes,
		MaxAge:       opts.MaxAge,
		MaxSize:      opts.MaxSize,
		Large:        large,
		IgnoreChmod0: opts.IgnoreChmod0,
	}, counters)

	var walkErr error
	for _, root := range opts.Paths {
		err := walker.Walk(root, func(f walk.File) error {
			if !interesting(f) {
				counters.Skipped.Add(1)
				publish()
				return nil
			}
			if cache.IsClean(f.Path, f.Size, f.MTime) {
				cache.Keep(f.Path)
				counters.Skipped.Add(1)
				rep.Stats.FilesCached++
				publish()
				return nil
			}
			jobs <- job{file: f}
			return nil
		})
		if err != nil {
			walkErr = err
			break
		}
	}
	close(jobs)
	wg.Wait()

	cache.Save()

	if len(views) > 0 {
		rep.Files = views
	}
	rep.Findings = append(rep.Findings, findings...)
	rep.Errors = append(rep.Errors, errs...)
	rep.Errors = append(rep.Errors, walker.Errors()...)
	rep.Stats.FilesScanned = counters.Files.Load()
	rep.Stats.FilesSkipped = counters.Skipped.Load()
	rep.Stats.Directories = counters.Directories.Load()
	rep.Stats.Bytes = counters.Bytes.Load()
	return walkErr
}

// scanOne reads and examines a single file.
func scanOne(f walk.File, sigDB *sigs.DB, engine *rules.Engine, known *knownfiles.Index, opts *Options) ([]report.Finding, string) {
	got, _, ferr := scanFile(f, sigDB, engine, known, opts)
	return got, ferr
}

// scanFile reads and examines a single file and, when it has findings, cuts
// the view a reader gets to see of it.
func scanFile(f walk.File, sigDB *sigs.DB, engine *rules.Engine, known *knownfiles.Index, opts *Options) ([]report.Finding, *report.FileView, string) {
	content, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}

	if isGeneratedReport(content) {
		// A statistics report lists the URLs that were requested, which on any
		// public site includes the paths attackers probe for: c99shell,
		// FilesMan and the rest. Scanning them finds the attacker's wish list,
		// not an infection, and buries the real findings under it.
		return nil, nil, ""
	}

	status, label := known.Check(f.Path, content)
	if status == knownfiles.Original {
		// Byte identical to what the vendor shipped. Nothing to look for.
		return nil, nil, ""
	}

	var out []report.Finding
	if status == knownfiles.Modified && countsAsModified(f.Ext, opts.modifiedExts()) && !opts.rebuilt(f.Path, f.Ext, content, known) {
		out = append(out, report.Finding{
			Path:     f.Path,
			Rule:     "core.modified",
			Severity: report.SeverityHigh,
			Engine:   "herstellerdateien",
			Size:     f.Size,
			MTime:    f.MTime.Format(time.RFC3339),
			Excerpt:  "weicht von der Auslieferung ab (" + label + ")",
		})
	}
	if status == knownfiles.Foreign && runnableExt(f.Ext) && !inertFile(content) {
		// Die andere Frage: nicht ob eine Datei verdächtig aussieht, sondern
		// ob sie überhaupt dorthin gehört. Ein Plugin-Verzeichnis enthält das
		// Plugin; was der Hersteller nicht ausliefert, ist auf einem anderen
		// Weg hineingekommen. Verschleierung hilft dagegen nicht, denn
		// geprüft wird der Ort, nicht der Inhalt.
		//
		// Gemeldet wird nur, was der Server ausführen kann. Über acht
		// Websites mit zusammen rund 105.000 Dateien und 95 Plugins fand
		// diese Prüfung genau eine fremde Datei, und das war eine erzeugte
		// CSS-Datei, die Formidable Forms sich selbst in sein Verzeichnis
		// legt. Ein Stylesheet ist kein Einstieg; eine PHP-Datei, die der
		// Hersteller nicht ausliefert, ist einer.
		out = append(out, report.Finding{
			Path:     f.Path,
			Rule:     "vendor.foreign_file",
			Severity: report.SeverityHigh,
			Engine:   "herstellerdateien",
			Size:     f.Size,
			MTime:    f.MTime.Format(time.RFC3339),
			Excerpt:  "gehört nicht zur Auslieferung (" + label + ")",
		})
	}

	out = append(out, sigDB.Scan(f.Path, f.Size, content)...)
	out = append(out, engine.Scan(f.Path, f.Rel, f.Ext, content)...)

	if len(out) > 0 {
		if _, ok := known.Copy(content); ok {
			// A copy of a file the vendor shipped: its content is confirmed,
			// where it lies stays a question.
			out = keepPlace(out)
			opts.count(verifiedCopy)
		}
	}
	if len(out) == 0 {
		return nil, nil, ""
	}

	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	if opts.Whitelist[hexSum] {
		return nil, nil, ""
	}
	mtime := f.MTime.Format(time.RFC3339)
	for i := range out {
		out[i].SHA256 = hexSum
		out[i].Size = f.Size
		out[i].MTime = mtime
	}
	return out, buildView(content, out, opts), ""
}

// scanHead asks the rules for the start of a file about one the size limit
// keeps from being read, see rules.HeadSize.
func scanHead(f walk.File, engine *rules.Engine, known *knownfiles.Index, opts *Options) ([]report.Finding, string) {
	file, err := os.Open(f.Path)
	if err != nil {
		return nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}
	defer file.Close()
	head := make([]byte, rules.HeadSize)
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}
	out := engine.ScanHead(f.Path, f.Rel, f.Ext, head[:n])
	if len(out) == 0 {
		return nil, ""
	}
	// Only a finding pays for reading the whole file: its sum is what the
	// whitelist and the report go by.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}
	hash := sha256.New()
	sum5 := md5.New()
	if _, err := io.Copy(io.MultiWriter(hash, sum5), file); err != nil {
		return nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}
	hexSum := hex.EncodeToString(hash.Sum(nil))
	if opts.Whitelist[hexSum] {
		return nil, ""
	}
	if _, ok := known.CopySum(hex.EncodeToString(sum5.Sum(nil))); ok {
		// As in scanFile: the content is confirmed, the place is not.
		opts.count(verifiedCopy)
		if out = keepPlace(out); len(out) == 0 {
			return nil, ""
		}
	}
	mtime := f.MTime.Format(time.RFC3339)
	for i := range out {
		out[i].SHA256 = hexSum
		out[i].Size = f.Size
		out[i].MTime = mtime
	}
	return out, ""
}

// reportMarkers identify a page generated by a web statistics tool.
//
// The marker has to sit in the first few kilobytes, where these tools put
// their generator line. Searching the whole file would let an attacker
// disable the scan for a page by pasting the word "AWStats" into it.
//
// GoAccess is the exception that needs its own marker: it inlines its whole
// stylesheet, font and templates first, so its "generated by GoAccess" line
// lands around byte 100000, far past the header window. What it does put in
// the head, right after the meta tags, is a fixed favicon. The slice below is
// the GoAccess brand palette inside that favicon (grey, purple, the GoAccess
// gold and teal); it has been byte identical across every report version in
// use from 2022 to 2025 and sits near byte 450, well inside the window. No
// other favicon carries this palette, so a page an attacker crafts has to
// reproduce the GoAccess icon in its head to be skipped - the same bar the
// head-only rule sets for every other tool here.
var reportMarkers = [][]byte{
	[]byte("Created by awstats"),
	[]byte("Advanced Web Statistics"),
	[]byte("Generated by Webalizer"),
	[]byte("The Webalizer"),
	[]byte("generated by GoAccess"),
	[]byte("goaccess.io"),
	[]byte("DGxsYAWFhYABwcHABfAP8A/9dfAADXrwAA"), // GoAccess favicon palette
	[]byte("Analog "),
	[]byte("Generated by AWFFull"),
}

// reportHeader is how far into a file the generator marker is looked for.
const reportHeader = 8192

// isGeneratedReport reports whether the content is a statistics page.
func isGeneratedReport(content []byte) bool {
	head := content
	if len(head) > reportHeader {
		head = head[:reportHeader]
	}
	for _, marker := range reportMarkers {
		if bytes.Contains(head, marker) {
			return true
		}
	}
	return false
}

// interesting decides whether a file is worth reading at all.
//
// Every file with content is. The extension only says what the web server
// does with a file; PHP runs whatever it is told to include, and the shell
// scripts of a web shell carry a name of their own choosing. A list of
// extensions worth reading let a payload parked as .dat or .alfa through
// unread. What a file is gets decided from its first bytes instead, see
// rules.Looks.
func interesting(f walk.File) bool {
	return f.Size > 0
}

// fingerprint identifies the detection state. Any change invalidates the
// clean-file cache.
func fingerprint(sigDB *sigs.DB, engine *rules.Engine, opts *Options) string {
	return fmt.Sprintf("%s|%s|%s|%s", version.Version, sigDB.Describe(), engine.Fingerprint(),
		strings.Join(opts.modifiedExts(), ","))
}

// runClamAV adds the optional third engine.
func runClamAV(rep *report.Report, opts *Options) {
	scan := clamav.Detect()
	if !scan.Available() {
		rep.Engines["clamav"] = "nicht installiert"
		return
	}
	rep.Engines["clamav"] = scan.Describe()
	found, err := scan.Scan(opts.Paths, opts.Excludes)
	if err != nil {
		rep.Errors = append(rep.Errors, "ClamAV: "+err.Error())
		return
	}
	for _, hit := range found {
		if opts.Whitelist != nil {
			if sum, err := fileSHA256(hit.Path); err == nil && opts.Whitelist[sum] {
				continue
			}
		}
		rep.Findings = append(rep.Findings, report.Finding{
			Path:     hit.Path,
			Rule:     hit.Signature,
			Severity: report.SeverityCritical,
			Engine:   "clamav",
		})
	}
}

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

// buildView cuts the view of a file with findings: the marks of the rules
// first, then those of the traits, most telling first, so a view that cannot
// hold every place keeps the reason for the finding.
func buildView(content []byte, found []report.Finding, opts *Options) *report.FileView {
	lines := textpos.New(content)
	var marks []report.Mark
	for _, f := range found {
		marks = append(marks, f.Marks...)
	}
	var fileTraits []report.Trait
	if !fileview.IsBinary(content) && opts.View.MaxMarks > 0 {
		fileTraits = traits.Detect(content, lines, opts.View.MaxMarks)
	}
	for _, kind := range []string{report.TraitRisk, report.TraitCaution, report.TraitGuard, report.TraitInfo} {
		for _, t := range fileTraits {
			if t.Kind == kind {
				marks = append(marks, t.Marks...)
			}
		}
	}
	v := fileview.Build(content, lines, marks, opts.View)
	v.Traits = fileTraits
	return v
}

// viewBytes is what the lines of a view weigh in a report.
func viewBytes(v *report.FileView) int64 {
	var n int64
	for _, l := range v.Show {
		n += int64(len(l.Text))
	}
	return n
}

// pruneViews drops the views no finding points to any more, after the
// whitelist took the findings of a released file out of the report.
func pruneViews(rep *report.Report) {
	if len(rep.Files) == 0 {
		return
	}
	used := map[string]bool{}
	for _, f := range rep.Findings {
		used[f.SHA256] = true
	}
	for sum := range rep.Files {
		if !used[sum] {
			delete(rep.Files, sum)
		}
	}
	if len(rep.Files) == 0 {
		rep.Files = nil
	}
}

// applyWhitelist drops findings for files the operator released, and folds
// duplicates that two engines reported for the same file and rule.
func applyWhitelist(rep *report.Report, whitelist map[string]bool) {
	seen := map[string]bool{}
	out := rep.Findings[:0]
	for _, f := range rep.Findings {
		if f.SHA256 != "" && whitelist[f.SHA256] {
			continue
		}
		key := f.Path + "|" + f.Rule + "|" + f.Engine
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	rep.Findings = out
}

// collectSoftware detects installed applications, records their version and
// loads the vendor checksums for them.
func collectSoftware(rep *report.Report, opts *Options, known *knownfiles.Index) {
	excluded := func(dir string) bool {
		for _, pat := range opts.Excludes {
			if walk.Match(pat, dir) {
				return true
			}
		}
		return false
	}

	var installs []cms.Install
	seen := map[string]bool{}
	for _, root := range opts.Paths {
		for _, inst := range cms.Detect(root, excluded) {
			key := inst.Path + "|" + inst.Product + "|" + inst.Kind + "|" + inst.Slug
			if seen[key] {
				continue
			}
			seen[key] = true
			installs = append(installs, inst)
		}
	}
	if len(installs) == 0 {
		return
	}

	var lookup *cms.Lookup
	var fetcher *knownfiles.Fetcher
	if !opts.Offline {
		cache := cms.NewCache(stateFile(opts.StateDir, "versions.json"), 24*time.Hour)
		lookup = cms.NewLookup(cache, 20*time.Second)
		defer cache.Save()
		fetcher = knownfiles.NewFetcher(stateFile(opts.StateDir, "checksums"), 30*time.Second)
	}

	var checker *vulns.Checker
	if !opts.Offline && !opts.NoVulnScan {
		token := opts.WPScanToken
		if opts.WPScanTokenFile != "" {
			if raw, err := os.ReadFile(opts.WPScanTokenFile); err != nil {
				rep.Errors = append(rep.Errors, "WPScan-Schlüssel nicht lesbar ("+err.Error()+"); WPScan wurde nicht gefragt")
				token = ""
			} else {
				token = strings.TrimSpace(string(raw))
			}
		}
		checker = vulns.New(vulns.Options{
			CacheDir:    stateFile(opts.StateDir, "vulnerabilities"),
			WPScanToken: token,
		})
	}

	for _, inst := range installs {
		if inst.Kind != "core" && opts.NoPluginScan {
			continue
		}
		entry := report.Software{
			Path:    inst.Path,
			Product: inst.Product,
			Kind:    inst.Kind,
			Slug:    inst.Slug,
			Version: inst.Version,
		}

		if lookup != nil {
			var latest string
			if inst.Kind == "core" {
				latest = lookup.Latest(inst.Product, inst.Version)
				if inst.Product == "wordpress" {
					entry.LatestInBranch = lookup.WordPressBranchLatest(inst.Version)
					entry.LatestRequiresPHP = lookup.WordPressRequiresPHP()
					entry.Versions = lookup.WordPressNewer(inst.Version)
				}
			} else {
				info := lookup.LatestPluginInfo(inst.Kind, inst.Slug)
				latest = info.Version
				entry.LatestRequiresWP, entry.LatestRequiresPHP = info.RequiresWP, info.RequiresPHP
				entry.Versions = cms.Newer(info.Versions, inst.Version)
			}
			entry.Latest = latest
			if latest == "" {
				entry.Unknown = true
			} else {
				entry.Outdated = cms.Compare(inst.Version, latest) < 0
			}
		} else {
			entry.Unknown = true
		}
		if checker != nil {
			list, checked := checker.Check(inst)
			entry.Vulns = list
			entry.UpdateTo = vulns.UpdateTo(list)
			entry.VulnsChecked = checked
		}
		rep.Software = append(rep.Software, entry)

		if fetcher != nil {
			loadChecksums(known, fetcher, inst)
		}
	}

	if lookup != nil {
		rep.Errors = append(rep.Errors, lookup.Errors()...)
	}
	if fetcher != nil {
		rep.Errors = append(rep.Errors, fetcher.Failures()...)
	}
	if checker != nil {
		if used := checker.Describe(); used != "" {
			rep.Engines["schwachstellen"] = used
		}
		rep.Errors = append(rep.Errors, checker.Notes()...)
	}
	if opts.Offline {
		rep.Errors = append(rep.Errors,
			"ohne Netzzugriff gelaufen: erkannte Versionen wurden nicht mit dem Hersteller abgeglichen")
	}
}

// loadChecksums registers the vendor file list of one installation.
func loadChecksums(known *knownfiles.Index, fetcher *knownfiles.Fetcher, inst cms.Install) {
	if inst.Product != "wordpress" {
		// Only WordPress publishes per-release checksums. For the other
		// products the generic sum list from the release build is used.
		return
	}
	switch inst.Kind {
	case "core":
		if files, err := fetcher.WordPressCore(inst.Version, inst.Locale); err == nil {
			label := "WordPress " + inst.Version
			if inst.Locale != "" {
				label += " " + inst.Locale
			}
			// wp-admin and wp-includes hold nothing of the site, so what the
			// release lacks there came in some other way - the question that
			// found wp-admin/wp-admin.php on a live site. The root stays
			// partial: wp-config.php and wp-content are the site's own.
			known.AddCore(inst.Path, label, files, "wp-admin", "wp-includes")
			known.SetOrigin(inst.Path, label, "https://core.svn.wordpress.org/tags/"+inst.Version+"/")
		}
	case "plugin":
		if files, err := fetcher.WordPressPlugin(inst.Slug, inst.Version); err == nil {
			// Als ganzer Baum: was wordpress.org für dieses Plugin ausliefert,
			// ist alles, was in dem Verzeichnis stehen sollte.
			label := "Plugin " + inst.Slug + " " + inst.Version
			known.AddVendorTree(inst.Path, label, files)
			known.SetOrigin(inst.Path, label, "https://plugins.svn.wordpress.org/"+inst.Slug+"/tags/"+inst.Version+"/")
		}
	case "theme":
		if files, err := fetcher.WordPressTheme(inst.Slug, inst.Version); err == nil {
			// Nur zur Bestätigung: ein Theme wird oft an die Website angepasst,
			// eine geänderte oder zusätzliche Datei sagt dort nichts.
			known.AddVerified(inst.Path, "Theme "+inst.Slug+" "+inst.Version, files)
		}
	}
}

// inertFile reports whether a file can do nothing when requested or included,
// see phpcode.Inert. Plugins write such files into their own directories at
// run time - guards, plain text, data behind an exit - and a file the vendor
// does not ship is only a way in when it can run something.
func inertFile(content []byte) bool {
	inert, _ := phpcode.Inert(content)
	return inert
}

// runnableExt reports whether the web server would hand this file to PHP.
//
// Die Liste ist absichtlich dieselbe, die auch die Regeln als phpExts
// benutzen, ohne .js: eine erzeugte JavaScript-Datei im Plugin-Verzeichnis
// ist gewöhnlich, und ob eine fremde davon vorkommt, ist nicht gemessen.
func runnableExt(ext string) bool {
	switch ext {
	case "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phps", "inc", "module":
		return true
	}
	return false
}

func stateFile(dir, name string) string {
	if dir == "" {
		return ""
	}
	return dir + string(os.PathSeparator) + name
}

// LoadWhitelist reads a file of SHA-256 sums, one per line.
func LoadWhitelist(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i > 0 {
			line = line[:i]
		}
		line = strings.ToLower(line)
		if len(line) == 64 {
			out[line] = true
		}
	}
	return out, nil
}

// AppendWhitelist adds the SHA-256 of a file to the whitelist file.
func AppendWhitelist(path, target string) (string, error) {
	sum, err := fileSHA256(target)
	if err != nil {
		return "", err
	}
	existing, err := LoadWhitelist(path)
	if err != nil {
		return "", err
	}
	if existing[sum] {
		return sum, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// The leading newline guards against a previous write that ended without
	// one; an appended line would otherwise fuse with the last entry.
	if _, err := fmt.Fprintf(f, "\n%s  %s\n", sum, target); err != nil {
		return "", err
	}
	return sum, nil
}

// SortedWhitelist returns the sums in a stable order, for tests.
func SortedWhitelist(w map[string]bool) []string {
	out := make([]string, 0, len(w))
	for k := range w {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
