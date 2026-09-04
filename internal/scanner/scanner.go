// Package scanner ties the stages together: it walks the tree, asks the
// signature and heuristic engines, and folds in what the vendors published.
package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/brightcolor/malwatch/internal/clamav"
	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/rules"
	"github.com/brightcolor/malwatch/internal/sigs"
	"github.com/brightcolor/malwatch/internal/version"
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

	IgnoreRules []string
	Whitelist   map[string]bool

	SignatureDir string
	CacheFile    string
	StateDir     string

	// Offline skips every network lookup. Version findings then report the
	// installed version without a verdict rather than guessing.
	Offline bool

	Progress func(scanned int64)
}

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

	sigDB, err := sigs.Load(opts.SignatureDir)
	if err != nil {
		rep.Errors = append(rep.Errors, "Signaturen unvollständig geladen: "+err.Error())
	}
	rep.Engines["signaturen"] = sigDB.Describe()

	engine := rules.NewEngine(opts.IgnoreRules)
	rep.Engines["heuristik"] = fmt.Sprintf("%d Regeln", engine.RuleCount())

	known := knownfiles.New()
	if !opts.NoVersionScan {
		collectSoftware(rep, &opts, known)
	}
	if installs, sums := known.Counts(); installs > 0 {
		rep.Engines["herstellerdateien"] = fmt.Sprintf("%d Installationen, %d Prüfsummen", installs, sums)
	}

	if !opts.NoMalwareScan {
		if err := scanFiles(rep, &opts, sigDB, engine, known); err != nil {
			return rep, err
		}
		if !opts.NoClamAV {
			runClamAV(rep, &opts)
		}
	}

	applyWhitelist(rep, opts.Whitelist)
	rep.FinishedAt = time.Now()
	rep.Sort()
	return rep, nil
}

// scanFiles walks every path and applies the engines.
func scanFiles(rep *report.Report, opts *Options, sigDB *sigs.DB, engine *rules.Engine, known *knownfiles.Index) error {
	counters := &walk.Counters{}
	cache := newCleanCache(opts.CacheFile, fingerprint(sigDB, engine))

	type job struct{ file walk.File }
	jobs := make(chan job, opts.Threads*8)

	var (
		mu       sync.Mutex
		findings []report.Finding
		errs     []string
	)
	var wg sync.WaitGroup

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				got, ferr := scanOne(j.file, sigDB, engine, known, opts)
				mu.Lock()
				findings = append(findings, got...)
				if ferr != "" {
					errs = append(errs, ferr)
				}
				mu.Unlock()

				if got == nil {
					cache.MarkClean(j.file.Path, j.file.Size, j.file.MTime)
				}
				n := counters.Files.Add(1)
				counters.Bytes.Add(j.file.Size)
				if opts.Progress != nil && n%500 == 0 {
					opts.Progress(n)
				}
			}
		}()
	}

	walker := walk.New(walk.Options{
		Excludes:     opts.Excludes,
		MaxAge:       opts.MaxAge,
		MaxSize:      opts.MaxSize,
		IgnoreChmod0: opts.IgnoreChmod0,
	}, counters)

	var walkErr error
	for _, root := range opts.Paths {
		err := walker.Walk(root, func(f walk.File) error {
			if !interesting(f) {
				counters.Skipped.Add(1)
				return nil
			}
			if cache.IsClean(f.Path, f.Size, f.MTime) {
				cache.Keep(f.Path)
				counters.Skipped.Add(1)
				rep.Stats.FilesCached++
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
	content, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, "nicht lesbar: " + f.Path + " (" + err.Error() + ")"
	}

	if isGeneratedReport(content) {
		// A statistics report lists the URLs that were requested, which on any
		// public site includes the paths attackers probe for: c99shell,
		// FilesMan and the rest. Scanning them finds the attacker's wish list,
		// not an infection, and buries the real findings under it.
		return nil, ""
	}

	status, label := known.Check(f.Path, content)
	if status == knownfiles.Original {
		// Byte identical to what the vendor shipped. Nothing to look for.
		return nil, ""
	}

	var out []report.Finding
	if status == knownfiles.Modified {
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

	out = append(out, sigDB.Scan(f.Path, f.Size, content)...)
	out = append(out, engine.Scan(f.Path, f.Rel, f.Ext, content)...)

	if len(out) == 0 {
		return nil, ""
	}

	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	if opts.Whitelist[hexSum] {
		return nil, ""
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
var reportMarkers = [][]byte{
	[]byte("Created by awstats"),
	[]byte("Advanced Web Statistics"),
	[]byte("Generated by Webalizer"),
	[]byte("The Webalizer"),
	[]byte("generated by GoAccess"),
	[]byte("goaccess.io"),
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
func interesting(f walk.File) bool {
	if f.Size == 0 {
		return false
	}
	if _, ok := textExt[f.Ext]; ok {
		return true
	}
	if _, ok := imageExt[f.Ext]; ok {
		// Images are read because a PHP payload appended to a JPEG is a
		// standard trick; the rule catalog looks for exactly that.
		return true
	}
	// Files without an extension are common for .htaccess and for dropped
	// shells, so they are read as well.
	return f.Ext == ""
}

var textExt = map[string]struct{}{
	"php": {}, "php3": {}, "php4": {}, "php5": {}, "php7": {}, "php8": {},
	"phtml": {}, "phps": {}, "inc": {}, "module": {}, "tpl": {}, "twig": {},
	"js": {}, "mjs": {}, "cjs": {}, "html": {}, "htm": {}, "shtml": {},
	"htaccess": {}, "css": {}, "txt": {}, "xml": {}, "json": {}, "sh": {},
	"pl": {}, "py": {}, "cgi": {}, "asp": {}, "aspx": {}, "jsp": {},
}

var imageExt = map[string]struct{}{
	"jpg": {}, "jpeg": {}, "png": {}, "gif": {}, "bmp": {}, "webp": {},
	"ico": {}, "svg": {},
}

// fingerprint identifies the detection state. Any change invalidates the
// clean-file cache.
func fingerprint(sigDB *sigs.DB, engine *rules.Engine) string {
	return fmt.Sprintf("%s|%s|%d", version.Version, sigDB.Describe(), engine.RuleCount())
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
			} else {
				latest = lookup.LatestPlugin(inst.Kind, inst.Slug)
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
			known.AddInstall(inst.Path, label, files)
		}
	case "plugin":
		if files, err := fetcher.WordPressPlugin(inst.Slug, inst.Version); err == nil {
			known.AddInstall(inst.Path, "Plugin "+inst.Slug+" "+inst.Version, files)
		}
	}
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
