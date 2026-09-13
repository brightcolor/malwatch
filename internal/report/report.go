// Package report defines the result format of a scan and renders it as text
// or JSON. The JSON form is the contract with the ISPConfig addon.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/version"
)

// Severity of a finding, ordered from harmless to certain.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns the numeric weight of a severity. Unknown values rank 0 so
// they never satisfy a threshold by accident.
func (s Severity) Rank() int { return severityRank[s] }

// AtLeast reports whether s is as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// ParseSeverity converts a command line value into a Severity.
func ParseSeverity(s string) (Severity, error) {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := severityRank[v]; !ok {
		return "", fmt.Errorf("unbekannte Schwere %q (erlaubt: low, medium, high, critical)", s)
	}
	return v, nil
}

// German labels for the text report.
var severityLabel = map[Severity]string{
	SeverityLow:      "gering",
	SeverityMedium:   "mittel",
	SeverityHigh:     "hoch",
	SeverityCritical: "kritisch",
}

// Label returns the German name of the severity.
func (s Severity) Label() string {
	if l, ok := severityLabel[s]; ok {
		return l
	}
	return string(s)
}

// Finding is one suspicious spot in one file.
type Finding struct {
	Path     string   `json:"path"`
	Line     int      `json:"line,omitempty"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Engine   string   `json:"engine"`
	SHA256   string   `json:"sha256,omitempty"`
	Excerpt  string   `json:"excerpt,omitempty"`
	Size     int64    `json:"size,omitempty"`
	MTime    string   `json:"mtime,omitempty"`
}

// Software is one detected web application install.
type Software struct {
	Path     string `json:"path"`
	Product  string `json:"product"`
	Kind     string `json:"kind"` // core, plugin, theme
	Slug     string `json:"slug,omitempty"`
	Version  string `json:"version"`
	Latest   string `json:"latest,omitempty"`
	Outdated bool   `json:"outdated"`
	// Unknown marks an install whose latest version could not be determined,
	// so a missing "outdated" flag is not mistaken for "up to date".
	Unknown bool `json:"unknown,omitempty"`
	// Vulns are the publicly known flaws of exactly this version, worst
	// first. See Vulnerability.
	Vulns []Vulnerability `json:"vulnerabilities,omitempty"`
	// UpdateTo is the lowest version that fixes every flaw in Vulns for which
	// a fix exists. Empty when none of them has one.
	UpdateTo string `json:"update_to,omitempty"`
	// VulnsChecked is set when a vulnerability database answered for this
	// install. It is written out when false as well: a report from a scanner
	// before 0.13.0 carries no such field, and its absence has to read as
	// "not checked" - the same reasoning as Unknown above.
	VulnsChecked bool `json:"vulnerabilities_checked"`
}

// Vulnerability is a publicly known flaw in the installed version of a piece
// of software.
//
// It is kept apart from Finding on purpose. A finding points at a file that
// can be quarantined or put back; a known flaw points at a version, and the
// only thing that removes it is an update. Mixed into the findings it would
// be offered to the automatic quarantine, which would then move a working
// plugin out of a website because of a line in a database.
type Vulnerability struct {
	// ID is the CVE number where one exists. Several databases describe the
	// same flaw under their own names, and the CVE is the name they share.
	ID    string `json:"id,omitempty"`
	Title string `json:"title"`
	// Severity is empty when no source rated the flaw.
	Severity Severity `json:"severity,omitempty"`
	Score    float64  `json:"score,omitempty"`
	// FixedIn is the first version without the flaw, empty when unknown.
	FixedIn string `json:"fixed_in,omitempty"`
	// LastAffected is the newest version known to carry the flaw, for a
	// database that records the end of a flaw that way instead of a fix.
	LastAffected string `json:"last_affected,omitempty"`
	// Unfixed marks a flaw for which the vendor has not released a fix.
	Unfixed bool   `json:"unfixed,omitempty"`
	Link    string `json:"link,omitempty"`
	// Sources names the databases that list the flaw.
	Sources []string `json:"sources"`
}

// Stats counts what the walk did.
type Stats struct {
	FilesScanned int64 `json:"files_scanned"`
	FilesSkipped int64 `json:"files_skipped"`
	FilesCached  int64 `json:"files_cached"`
	Bytes        int64 `json:"bytes"`
	Directories  int64 `json:"directories"`
}

// Report is the complete result of one scan run.
type Report struct {
	Schema          int               `json:"schema"`
	MalwatchVersion string            `json:"malwatch_version"`
	Host            string            `json:"host,omitempty"`
	StartedAt       time.Time         `json:"started_at"`
	FinishedAt      time.Time         `json:"finished_at"`
	Paths           []string          `json:"paths"`
	Engines         map[string]string `json:"engines"`
	Stats           Stats             `json:"stats"`
	Findings        []Finding         `json:"findings"`
	Software        []Software        `json:"software"`
	Errors          []string          `json:"errors,omitempty"`
}

// New returns an empty report stamped with the current version.
func New(paths []string) *Report {
	host, _ := os.Hostname()
	return &Report{
		Schema:          version.SchemaVersion,
		MalwatchVersion: version.Version,
		Host:            host,
		StartedAt:       time.Now(),
		Paths:           paths,
		Engines:         map[string]string{},
		Findings:        []Finding{},
		Software:        []Software{},
	}
}

// Sort orders findings by severity (worst first) and then by path, so two
// runs over the same tree produce a comparable report.
func (r *Report) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	sort.SliceStable(r.Software, func(i, j int) bool {
		a, b := r.Software[i], r.Software[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Slug < b.Slug
	})
}

// CountBySeverity returns how many findings each severity has.
func (r *Report) CountBySeverity() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// MaxSeverity returns the worst severity present, or "" for a clean report.
func (r *Report) MaxSeverity() Severity {
	var worst Severity
	for _, f := range r.Findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// OutdatedCount returns how many detected installs are behind.
func (r *Report) OutdatedCount() int {
	n := 0
	for _, s := range r.Software {
		if s.Outdated {
			n++
		}
	}
	return n
}

// VulnerableCount returns how many detected installs have known flaws.
func (r *Report) VulnerableCount() int {
	n := 0
	for _, s := range r.Software {
		if len(s.Vulns) > 0 {
			n++
		}
	}
	return n
}

// Exit codes. The addon and cron jobs branch on these.
const (
	ExitClean    = 0 // nothing found
	ExitFindings = 1 // findings at or above the threshold
	ExitOutdated = 2 // only outdated software or software with known flaws
	ExitError    = 3 // the run itself failed
)

// ExitCode derives the process exit code from the report.
//
// A known flaw shares the code of outdated software. Both ask for the same
// thing, an update, and a caller that already acts on 2 needs no change to
// see the new case.
func (r *Report) ExitCode(min Severity) int {
	for _, f := range r.Findings {
		if f.Severity.AtLeast(min) {
			return ExitFindings
		}
	}
	if r.OutdatedCount() > 0 || r.VulnerableCount() > 0 {
		return ExitOutdated
	}
	return ExitClean
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
