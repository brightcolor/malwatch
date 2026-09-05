package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/version"
)

// RepairOutcome is what became of one element.
type RepairOutcome string

const (
	// OutcomeReplaced means the vendor's own files are back in place.
	OutcomeReplaced RepairOutcome = "replaced"
	// OutcomeDeleted means the directory went without a replacement, because
	// the vendor does not publish that version.
	OutcomeDeleted RepairOutcome = "deleted-no-origin"
	// OutcomeFailed means the exchange broke off part way.
	OutcomeFailed RepairOutcome = "failed"
	// OutcomeSkipped means the element was left as it was.
	OutcomeSkipped RepairOutcome = "skipped"
)

// RepairElement is what happened to one core, plugin or theme.
type RepairElement struct {
	Kind    string        `json:"kind"`
	Slug    string        `json:"slug,omitempty"`
	Version string        `json:"version"`
	Locale  string        `json:"locale,omitempty"`
	Path    string        `json:"path"`
	Outcome RepairOutcome `json:"outcome"`
	Files   int           `json:"files"`
	Backup  string        `json:"backup,omitempty"`
	Message string        `json:"message,omitempty"`
}

// Repair is the report of one run.
type Repair struct {
	Schema     int                 `json:"schema"`
	Version    string              `json:"malwatch_version"`
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
	Root       string              `json:"root"`
	DryRun     bool                `json:"dry_run"`
	BackupDir  string              `json:"backup_dir,omitempty"`
	Elements   []RepairElement     `json:"elements"`
	Untouched  []string            `json:"untouched"`
	Log        []progress.LogEntry `json:"log"`
	Errors     []string            `json:"errors"`
}

// NewRepair starts a report for root.
func NewRepair(root string) *Repair {
	return &Repair{
		Schema:    1,
		Version:   version.Version,
		StartedAt: time.Now().UTC(),
		Root:      root,
		Elements:  []RepairElement{},
		Untouched: []string{},
		Log:       []progress.LogEntry{},
		Errors:    []string{},
	}
}

// ExitCode is 0 when everything came back, 2 when something was deleted
// without a replacement, and 3 when the run itself failed.
func (r *Repair) ExitCode() int {
	if len(r.Errors) > 0 {
		return 3
	}
	for _, e := range r.Elements {
		if e.Outcome == OutcomeFailed {
			return 3
		}
	}
	for _, e := range r.Elements {
		if e.Outcome == OutcomeDeleted {
			return 2
		}
	}
	return 0
}

// WriteJSON writes the report for machines.
func (r *Repair) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the report for a person.
func (r *Repair) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Wiederherstellung: %s\n", r.Root)
	if r.DryRun {
		b.WriteString("Probelauf - es wurde nichts geändert.\n")
	}
	b.WriteString("\n")

	for _, e := range r.Elements {
		name := e.Kind
		if e.Slug != "" {
			name = e.Kind + " " + e.Slug
		}
		// A dry run reports in the conditional. Reading "ersetzt" for something
		// that was not replaced is worst in exactly the moment this report
		// matters most: before someone starts the run that does change things.
		if r.DryRun {
			switch e.Outcome {
			case OutcomeReplaced:
				fmt.Fprintf(&b, "  würde ersetzen  %s %s\n", name, e.Version)
			case OutcomeDeleted:
				fmt.Fprintf(&b, "  WÜRDE LÖSCHEN   %s %s - kein Original verfügbar\n", name, e.Version)
			default:
				fmt.Fprintf(&b, "  unverändert     %s %s - %s\n", name, e.Version, e.Message)
			}
			continue
		}

		switch e.Outcome {
		case OutcomeReplaced:
			fmt.Fprintf(&b, "  ersetzt       %s %s (%d Dateien)\n", name, e.Version, e.Files)
		case OutcomeDeleted:
			fmt.Fprintf(&b, "  GELÖSCHT      %s %s - kein Original verfügbar\n", name, e.Version)
			if e.Backup != "" {
				fmt.Fprintf(&b, "                Sicherung: %s\n", e.Backup)
			}
		case OutcomeFailed:
			fmt.Fprintf(&b, "  FEHLER        %s %s - %s\n", name, e.Version, e.Message)
			if e.Backup != "" {
				fmt.Fprintf(&b, "                Sicherung: %s\n", e.Backup)
			}
		case OutcomeSkipped:
			fmt.Fprintf(&b, "  übersprungen  %s %s - %s\n", name, e.Version, e.Message)
		}
	}

	if len(r.Untouched) > 0 {
		b.WriteString("\nUnangetastet:\n")
		for _, u := range r.Untouched {
			fmt.Fprintf(&b, "  %s\n", u)
		}
	}
	if len(r.Errors) > 0 {
		b.WriteString("\nFehler:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
