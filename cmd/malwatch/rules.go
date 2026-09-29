package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/rules"
)

// ruleDoc is one catalog entry as the ISPConfig addon sees it - enough to
// label a finding by its rule ID without linking against the Go catalog, and
// to tell the operator why it was reported and what to do.
type ruleDoc struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity report.Severity `json:"severity"`
	AutoSafe bool            `json:"auto_safe"`
	Explain  string          `json:"explain"`
	Advice   string          `json:"advice"`
}

// ruleCatalogDoc is what malwatch rules --json writes. Extras are the sources
// of findings outside the catalog (vendor checksums, signature engines),
// kept apart so that Rules stays exactly the catalog.
type ruleCatalogDoc struct {
	Schema int       `json:"schema"`
	Rules  []ruleDoc `json:"rules"`
	Extras []ruleDoc `json:"extras"`
}

func cmdRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	asJSON := fs.Bool("json", false, "")
	out := fs.String("out", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	// Text output has no defined shape yet, so an operator who forgets the
	// flag gets an explanation instead of a silently empty run.
	if !*asJSON {
		fmt.Fprintln(os.Stderr, "rules braucht --json. Beispiel: malwatch rules --json")
		return report.ExitError
	}

	all := rules.All()
	doc := ruleCatalogDoc{Schema: 1, Rules: make([]ruleDoc, 0, len(all))}
	for _, r := range all {
		e, _ := rules.Explain(r.ID)
		doc.Rules = append(doc.Rules, ruleDoc{
			ID:       r.ID,
			Title:    r.Description,
			Severity: r.Severity,
			AutoSafe: r.AutoSafe,
			Explain:  e.Why,
			Advice:   rules.Advice(r.ID, r.Severity, r.AutoSafe),
		})
	}
	for _, x := range rules.Extras {
		e, _ := rules.Explain(x.ID)
		doc.Extras = append(doc.Extras, ruleDoc{
			ID:       x.ID,
			Title:    x.Title,
			Severity: x.Severity,
			AutoSafe: x.AutoSafe,
			Explain:  e.Why,
			Advice:   rules.Advice(x.ID, x.Severity, x.AutoSafe),
		})
	}

	w := os.Stdout
	if *out != "" {
		// The catalog is not customer data, but every other report in this
		// tool writes owner-only, and a stray --out should not be the one
		// exception.
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return report.ExitError
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "Katalog konnte nicht geschrieben werden: %v\n", err)
		return report.ExitError
	}
	return 0
}
