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
// label a finding by its rule ID without linking against the Go catalog.
type ruleDoc struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity report.Severity `json:"severity"`
	AutoSafe bool            `json:"auto_safe"`
}

// ruleCatalogDoc is what malwatch rules --json writes.
type ruleCatalogDoc struct {
	Schema int       `json:"schema"`
	Rules  []ruleDoc `json:"rules"`
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
		doc.Rules = append(doc.Rules, ruleDoc{
			ID:       r.ID,
			Title:    r.Description,
			Severity: r.Severity,
			AutoSafe: r.AutoSafe,
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
