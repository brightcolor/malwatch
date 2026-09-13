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

	vulnerable := make([]Software, 0)
	outdated := make([]Software, 0)
	unknown := make([]Software, 0)
	current := 0
	for _, s := range r.Software {
		switch {
		case len(s.Vulns) > 0:
			vulnerable = append(vulnerable, s)
		case s.Outdated:
			outdated = append(outdated, s)
		case s.Unknown:
			unknown = append(unknown, s)
		default:
			current++
		}
	}

	fmt.Fprintf(b, "Web-Software: %d erkannt, %d mit bekannten Lücken, %d veraltet, %d aktuell\n",
		len(r.Software), len(vulnerable), r.OutdatedCount(), current)
	b.WriteString(strings.Repeat("-", 60) + "\n")

	// Known flaws first. An outdated install can be harmless for years; one
	// with a published flaw is exactly what gets searched for across the
	// internet, and it is usually outdated as well, so it is listed once.
	for _, s := range vulnerable {
		fmt.Fprintf(b, "Lücken: %s %s in %s", softwareName(s), s.Version, s.Path)
		if s.UpdateTo != "" {
			// "alle" only when every flaw names its fix: an update to
			// UpdateTo leaves the others where they are.
			if fixed := fixedCount(s.Vulns); fixed == len(s.Vulns) {
				fmt.Fprintf(b, " (alle behoben ab %s)", s.UpdateTo)
			} else {
				fmt.Fprintf(b, " (%d von %d behoben ab %s)", fixed, len(s.Vulns), s.UpdateTo)
			}
		}
		b.WriteString("\n")
		for i, v := range s.Vulns {
			if i == maxVulnLines {
				fmt.Fprintf(b, "  … und %d weitere\n", len(s.Vulns)-maxVulnLines)
				break
			}
			fmt.Fprintf(b, "  %s\n", vulnLine(v))
		}
	}

	for _, s := range outdated {
		fmt.Fprintf(b, "veraltet: %s %s (aktuell ist %s) in %s\n", softwareName(s), s.Version, s.Latest, s.Path)
	}

	// An install whose latest version is unknown is reported as unknown, never
	// silently as up to date - a failed version lookup must not read as a clean bill.
	for _, s := range unknown {
		fmt.Fprintf(b, "ungeprüft: %s %s in %s (aktuelle Version nicht ermittelbar)\n", softwareName(s), s.Version, s.Path)
	}

	if showAll {
		for _, s := range r.Software {
			if s.Outdated || s.Unknown || len(s.Vulns) > 0 {
				continue
			}
			fmt.Fprintf(b, "aktuell: %s %s in %s\n", softwareName(s), s.Version, s.Path)
		}
	}
	b.WriteString("\n")
}

// maxVulnLines caps the flaws listed per install. An old plugin can carry
// forty of them; the first ten, worst first, say what there is to say.
const maxVulnLines = 10

// fixedCount returns how many flaws name the version that fixes them.
func fixedCount(list []Vulnerability) int {
	n := 0
	for _, v := range list {
		if v.FixedIn != "" {
			n++
		}
	}
	return n
}

func softwareName(s Software) string {
	if s.Slug != "" {
		return s.Product + " " + s.Slug
	}
	return s.Product
}

// vulnLine renders one flaw as "hoch 7.2  CVE-2023-6449  Titel, behoben in 5.8.4".
func vulnLine(v Vulnerability) string {
	rating := "nicht eingestuft"
	if v.Severity != "" {
		rating = v.Severity.Label()
		if v.Score > 0 {
			rating += fmt.Sprintf(" %.1f", v.Score)
		}
	}
	parts := []string{rating}
	if v.ID != "" {
		parts = append(parts, v.ID)
	}
	parts = append(parts, v.Title)
	line := strings.Join(parts, "  ")
	switch {
	case v.FixedIn != "":
		line += ", behoben in " + v.FixedIn
	case v.LastAffected != "":
		line += ", betroffen bis " + v.LastAffected
	case v.Unfixed:
		line += ", bisher ohne Korrektur"
	}
	return line
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
	case r.VulnerableCount() > 0:
		return fmt.Sprintf("malwatch: %d Installation(en) mit bekannten Lücken auf %s", r.VulnerableCount(), host)
	case r.OutdatedCount() > 0:
		return fmt.Sprintf("malwatch: %d veraltete Installation(en) auf %s", r.OutdatedCount(), host)
	default:
		return fmt.Sprintf("malwatch: nichts gefunden auf %s", host)
	}
}
