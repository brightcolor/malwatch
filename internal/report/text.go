package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// WriteText renders the report for a human reader. German, because the
// output is read by people; identifiers stay English.
func (r *Report) WriteText(w io.Writer, showAll bool) error {
	b := &strings.Builder{}

	dur := r.FinishedAt.Sub(r.StartedAt).Round(time.Second)
	fmt.Fprintf(b, "Geprüfte Pfade: %s\n", strings.Join(r.Paths, ", "))
	fmt.Fprintf(b, "Dauer: %s, geprüfte Dateien: %d", dur, r.Stats.FilesScanned)
	if r.Stats.FilesCached > 0 {
		fmt.Fprintf(b, ", aus dem Zwischenspeicher: %d", r.Stats.FilesCached)
	}
	if r.Stats.FilesSkipped > 0 {
		fmt.Fprintf(b, ", übersprungen: %d", r.Stats.FilesSkipped)
	}
	b.WriteString("\n")

	if len(r.Engines) > 0 {
		keys := make([]string, 0, len(r.Engines))
		for k := range r.Engines {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+" "+r.Engines[k])
		}
		fmt.Fprintf(b, "Prüfstufen: %s\n", strings.Join(parts, ", "))
	}
	b.WriteString("\n")

	writeFindings(b, r)
	writeSoftware(b, r, showAll)

	if len(r.Errors) > 0 {
		b.WriteString("Hinweise\n")
		b.WriteString(strings.Repeat("-", 60) + "\n")
		for _, e := range r.Errors {
			fmt.Fprintf(b, "  %s\n", e)
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeFindings(b *strings.Builder, r *Report) {
	if len(r.Findings) == 0 {
		b.WriteString("Kein Schadcode gefunden.\n\n")
		return
	}

	counts := r.CountBySeverity()
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	summary := make([]string, 0, len(order))
	for _, s := range order {
		if counts[s] > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", counts[s], s.Label()))
		}
	}
	fmt.Fprintf(b, "%d Fund(e): %s\n", len(r.Findings), strings.Join(summary, ", "))
	b.WriteString(strings.Repeat("-", 60) + "\n")

	for _, f := range r.Findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(b, "[%s] %s\n  %s\n", f.Severity.Label(), f.Rule, loc)
		if f.Excerpt != "" {
			fmt.Fprintf(b, "  %s\n", f.Excerpt)
		}
	}
	b.WriteString("\n")
}

func writeSoftware(b *strings.Builder, r *Report, showAll bool) {
	if len(r.Software) == 0 {
		return
	}

	outdated := make([]Software, 0)
	unknown := make([]Software, 0)
	current := 0
	for _, s := range r.Software {
		switch {
		case s.Outdated:
			outdated = append(outdated, s)
		case s.Unknown:
			unknown = append(unknown, s)
		default:
			current++
		}
	}

	fmt.Fprintf(b, "Web-Software: %d erkannt, %d veraltet, %d aktuell\n", len(r.Software), len(outdated), current)
	b.WriteString(strings.Repeat("-", 60) + "\n")

	for _, s := range outdated {
		name := s.Product
		if s.Slug != "" {
			name = fmt.Sprintf("%s %s", s.Product, s.Slug)
		}
		fmt.Fprintf(b, "veraltet: %s %s (aktuell ist %s) in %s\n", name, s.Version, s.Latest, s.Path)
		if s.Vuln != "" {
			fmt.Fprintf(b, "  Schwachstelle: %s\n", s.Vuln)
		}
	}

	// An install whose latest version is unknown is reported as unknown, never
	// silently as up to date - a failed version lookup must not read as a clean bill.
	for _, s := range unknown {
		name := s.Product
		if s.Slug != "" {
			name = fmt.Sprintf("%s %s", s.Product, s.Slug)
		}
		fmt.Fprintf(b, "ungeprüft: %s %s in %s (aktuelle Version nicht ermittelbar)\n", name, s.Version, s.Path)
	}

	if showAll {
		for _, s := range r.Software {
			if s.Outdated || s.Unknown {
				continue
			}
			name := s.Product
			if s.Slug != "" {
				name = fmt.Sprintf("%s %s", s.Product, s.Slug)
			}
			fmt.Fprintf(b, "aktuell: %s %s in %s\n", name, s.Version, s.Path)
		}
	}
	b.WriteString("\n")
}

// Subject returns a one-line summary for a mail subject.
func (r *Report) Subject() string {
	host := r.Host
	if host == "" {
		host = "Server"
	}
	switch {
	case len(r.Findings) > 0:
		return fmt.Sprintf("malwatch: %d Fund(e) auf %s", len(r.Findings), host)
	case r.OutdatedCount() > 0:
		return fmt.Sprintf("malwatch: %d veraltete Installation(en) auf %s", r.OutdatedCount(), host)
	default:
		return fmt.Sprintf("malwatch: nichts gefunden auf %s", host)
	}
}
