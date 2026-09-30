package scanner

import (
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brightcolor/malwatch/internal/composer"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/rules"
)

// The sources that confirm the content of a file with findings, as the report
// counts them (report.Report.Verified).
const (
	verifiedCopy = "Kopie einer geprüften Herstellerdatei"
)

// verifiedCount counts confirmed files per source across the workers.
type verifiedCount struct {
	mu sync.Mutex
	m  map[string]int
}

// count notes one file confirmed by source.
func (o *Options) count(source string) {
	if o == nil || o.verified == nil {
		return
	}
	o.verified.mu.Lock()
	o.verified.m[source]++
	o.verified.mu.Unlock()
}

// keepPlace keeps the findings about where a file lies and about how it
// differs from the vendor's release, and drops those about its content: the
// content is confirmed.
func keepPlace(out []report.Finding) []report.Finding {
	kept := out[:0]
	for _, f := range out {
		if f.Engine == "herstellerdateien" {
			kept = append(kept, f)
			continue
		}
		if r := rules.ByID(f.Rule); r != nil && r.ByPlace {
			kept = append(kept, f)
		}
	}
	return kept
}

// verifiedComposer is the source of files confirmed against the archive of
// their Composer package.
const verifiedComposer = "Datei eines Composer-Pakets"

// VerifyOptions steer the check of files with findings against the sources
// that know them: the archives of Composer packages and, when an address is
// set, a database of known file hashes.
type VerifyOptions struct {
	// Composer confirms files of Composer packages against their archives.
	Composer bool
	// Hosts are the only hosts archives are loaded from.
	Hosts []string
	// MaxDownloads caps the archives one run loads, MaxMB the size of one,
	// TimeoutSeconds one download; RetryHours is how long a failed archive
	// is not asked for again.
	MaxDownloads   int
	MaxMB          int
	TimeoutSeconds int
	RetryHours     int
}

// DefaultVerify returns the check as the command line starts from it.
func DefaultVerify() VerifyOptions {
	return VerifyOptions{
		Composer:       true,
		Hosts:          append([]string(nil), composer.DefaultHosts...),
		MaxDownloads:   composer.DefaultMaxDownloads,
		MaxMB:          composer.DefaultMaxMB,
		TimeoutSeconds: composer.DefaultTimeoutSeconds,
		RetryHours:     composer.DefaultRetryHours,
	}
}

// contentFinding reports whether a finding is about what a file contains,
// which a confirmed content answers; see keepPlace.
func contentFinding(f report.Finding) bool {
	if f.Engine == "herstellerdateien" {
		return false
	}
	if r := rules.ByID(f.Rule); r != nil && r.ByPlace {
		return false
	}
	return true
}

// verifyComposer confirms files with content findings against the archives
// of the Composer packages they belong to, and drops those findings for a
// file that is byte for byte the package's own. Only files with findings are
// looked at, so only the packages that hold one are loaded.
func verifyComposer(rep *report.Report, opts *Options) {
	if opts.Offline || !opts.Verify.Composer {
		return
	}
	fetcher := composer.NewFetcher(composer.Options{
		CacheDir:     stateFile(opts.StateDir, "composer"),
		Hosts:        opts.Verify.Hosts,
		MaxDownloads: opts.Verify.MaxDownloads,
		MaxMB:        opts.Verify.MaxMB,
		Timeout:      time.Duration(opts.Verify.TimeoutSeconds) * time.Second,
		RetryHours:   opts.Verify.RetryHours,
		Transport:    opts.verifyTransport,
	})
	vendors := map[string][]composer.Package{}
	confirmed := map[string]bool{}
	decided := map[string]bool{}
	for _, f := range rep.Findings {
		if !contentFinding(f) || decided[f.Path] {
			continue
		}
		decided[f.Path] = true
		pkg, rel := packageOf(f.Path, opts.Paths, vendors)
		if pkg == nil {
			continue
		}
		files, err := fetcher.Files(pkg.URL, pkg.Reference)
		if err != nil {
			continue
		}
		sum := f.SHA256
		if sum == "" {
			if s, err := fileSHA256(f.Path); err == nil {
				sum = s
			}
		}
		if sum != "" && files[rel] == sum {
			confirmed[f.Path] = true
		}
	}
	if len(confirmed) > 0 {
		kept := rep.Findings[:0]
		for _, f := range rep.Findings {
			if confirmed[f.Path] && contentFinding(f) {
				continue
			}
			kept = append(kept, f)
		}
		rep.Findings = kept
		for range confirmed {
			opts.count(verifiedComposer)
		}
	}
	rep.Errors = append(rep.Errors, fetcher.Failures()...)
}

// packageOf finds the Composer package a file belongs to: the nearest
// directory above it, inside a scanned path, that holds composer/installed.json
// and names a package installed around the file. rel is the file's path below
// the package, with slashes.
func packageOf(file string, roots []string, vendors map[string][]composer.Package) (*composer.Package, string) {
	file = filepath.Clean(file)
	root := ""
	for _, r := range roots {
		r = filepath.Clean(r)
		if strings.HasPrefix(file, r+string(filepath.Separator)) && len(r) > len(root) {
			root = r
		}
	}
	if root == "" {
		return nil, ""
	}
	for dir := filepath.Dir(file); len(dir) >= len(root) && strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		pkgs, seen := vendors[dir]
		if !seen {
			pkgs, _ = composer.Installed(dir)
			vendors[dir] = pkgs
		}
		best := -1
		for i, p := range pkgs {
			if strings.HasPrefix(file, p.Dir+string(filepath.Separator)) && (best < 0 || len(p.Dir) > len(pkgs[best].Dir)) {
				best = i
			}
		}
		if best >= 0 {
			rel, err := filepath.Rel(pkgs[best].Dir, file)
			if err != nil {
				return nil, ""
			}
			p := pkgs[best]
			return &p, filepath.ToSlash(rel)
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return nil, ""
}
