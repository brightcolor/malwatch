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

// UpgradeOutcome is what became of one element of an upgrade.
type UpgradeOutcome string

const (
	// UpgradeUpdated means the new release is in place and the site answered.
	UpgradeUpdated UpgradeOutcome = "updated"
	// UpgradeWould is a dry run's verdict on an element it found nothing against.
	UpgradeWould UpgradeOutcome = "would_update"
	// UpgradeRefused means the element was turned down before anything changed.
	UpgradeRefused UpgradeOutcome = "refused"
	// UpgradeRolledBack means the site broke after the exchange and the old
	// release is back, with the site answering as before.
	UpgradeRolledBack UpgradeOutcome = "rolled_back"
	// UpgradeFailed means the exchange or the database step broke off and the
	// old release is back, with the site answering as before.
	UpgradeFailed UpgradeOutcome = "failed"
	// UpgradeRollbackFailed means the old release is back and the site still
	// answers worse than before. The run stops there.
	UpgradeRollbackFailed UpgradeOutcome = "rollback_failed"
	// UpgradeSkipped means the element was never started.
	UpgradeSkipped UpgradeOutcome = "skipped"
)

// PageCheck is what one page of the site answered around an element. A status
// of 0 means no answer, or no check at that point.
type PageCheck struct {
	URL           string `json:"url"`
	Before        int    `json:"before"`
	After         int    `json:"after,omitempty"`
	AfterRollback int    `json:"after_rollback,omitempty"`
}

// UpgradeElement is one core, plugin or theme of an upgrade.
type UpgradeElement struct {
	Kind    string         `json:"kind"`
	Slug    string         `json:"slug,omitempty"`
	Install string         `json:"install"`
	Path    string         `json:"path"`
	From    string         `json:"from"`
	To      string         `json:"to"`
	Outcome UpgradeOutcome `json:"outcome"`
	Message string         `json:"message,omitempty"`
	Files   int            `json:"files,omitempty"`
	// Unverified marks an archive no checksum list covered: a theme, or a
	// plugin wordpress.org keeps no list for. It was unpacked in full.
	Unverified    bool        `json:"unverified,omitempty"`
	QuarantineIDs []string    `json:"quarantine_ids,omitempty"`
	DBExportID    string      `json:"db_export_id,omitempty"`
	Checks        []PageCheck `json:"checks,omitempty"`
}

// Upgrade is the report of one upgrade run.
type Upgrade struct {
	Schema     int                 `json:"schema"`
	Version    string              `json:"malwatch_version"`
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
	Root       string              `json:"root"`
	DryRun     bool                `json:"dry_run"`
	PHPVersion string              `json:"php_version,omitempty"`
	Elements   []UpgradeElement    `json:"elements"`
	Log        []progress.LogEntry `json:"log"`
	Errors     []string            `json:"errors"`
}

// NewUpgrade starts a report for the web root.
func NewUpgrade(root string, dryRun bool) *Upgrade {
	return &Upgrade{
		Schema:    1,
		Version:   version.Version,
		StartedAt: time.Now().UTC(),
		Root:      root,
		DryRun:    dryRun,
		Elements:  []UpgradeElement{},
		Log:       []progress.LogEntry{},
		Errors:    []string{},
	}
}

// ExitCode is 0 when every element was updated or a dry run found nothing
// against it, 2 when an element was refused, rolled back or failed with the
// old release back in place, and 3 when the run failed or a site stayed
// broken after the rollback.
func (u *Upgrade) ExitCode() int {
	if len(u.Errors) > 0 {
		return ExitError
	}
	code := 0
	for _, e := range u.Elements {
		switch e.Outcome {
		case UpgradeRollbackFailed:
			return ExitError
		case UpgradeRefused, UpgradeRolledBack, UpgradeFailed, UpgradeSkipped:
			code = 2
		}
	}
	return code
}

// WriteJSON writes the report for machines.
func (u *Upgrade) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(u)
}

var upgradeLabels = map[UpgradeOutcome]string{
	UpgradeUpdated:        "aktualisiert",
	UpgradeWould:          "würde aktualisieren",
	UpgradeRefused:        "abgelehnt",
	UpgradeRolledBack:     "zurückgeholt",
	UpgradeFailed:         "FEHLER, zurückgeholt",
	UpgradeRollbackFailed: "WEBSITE FEHLERHAFT",
	UpgradeSkipped:        "übersprungen",
}

// WriteText writes the report for a person.
func (u *Upgrade) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Update: %s\n", u.Root)
	if u.PHPVersion != "" {
		fmt.Fprintf(&b, "PHP %s\n", u.PHPVersion)
	}
	if u.DryRun {
		b.WriteString("Probelauf - es wurde nichts geändert.\n")
	}
	b.WriteString("\n")

	for _, e := range u.Elements {
		name := e.Kind
		if e.Slug != "" {
			name += " " + e.Slug
		}
		label := upgradeLabels[e.Outcome]
		if label == "" {
			label = string(e.Outcome)
		}
		fmt.Fprintf(&b, "  %-22s %s %s → %s", label, name, e.From, e.To)
		if e.Message != "" {
			fmt.Fprintf(&b, " - %s", e.Message)
		}
		b.WriteString("\n")
		if e.Unverified {
			b.WriteString("      ohne Prüfsummenliste; geprüft wurde, dass das Archiv vollständig ist\n")
		}
		if len(e.QuarantineIDs) > 0 {
			fmt.Fprintf(&b, "      Quarantäne: %s\n", strings.Join(e.QuarantineIDs, ", "))
		}
		if e.DBExportID != "" {
			fmt.Fprintf(&b, "      Datenbank-Export: %s\n", e.DBExportID)
		}
	}

	if len(u.Errors) > 0 {
		b.WriteString("\nFehler:\n")
		for _, msg := range u.Errors {
			fmt.Fprintf(&b, "  %s\n", msg)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
