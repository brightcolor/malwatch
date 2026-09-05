package repair

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/cms"
)

// Element is one unit a repair replaces as a whole.
type Element struct {
	Kind    string // core, plugin, theme
	Slug    string // empty for the core
	Version string
	Locale  string
	Path    string // directory the element lives in
}

// Plan is what a run will do, and what it deliberately will not.
type Plan struct {
	Root      string
	Elements  []Element
	Untouched []string
}

// BuildPlan reads the installation and sorts it into what is the vendor's and
// what is the customer's.
//
// Everything below wp-content that is not a plugin or theme directory belongs
// to the customer: uploads, languages, caches and whatever a site has grown.
// Leaving it is not laziness - those leftovers are exactly what the scan after
// the repair is meant to show.
func BuildPlan(root string) (Plan, error) {
	plan := Plan{Root: filepath.Clean(root)}

	for _, inst := range cms.Detect(plan.Root, func(string) bool { return false }) {
		if inst.Product != "wordpress" {
			plan.Untouched = append(plan.Untouched, fmt.Sprintf(
				"%s (%s %s) - für dieses Produkt gibt es keine versionsgenaue Quelle",
				inst.Path, inst.Product, inst.Version))
			continue
		}
		plan.Elements = append(plan.Elements, Element{
			Kind:    inst.Kind,
			Slug:    inst.Slug,
			Version: inst.Version,
			Locale:  inst.Locale,
			Path:    inst.Path,
		})
	}

	plan.Untouched = append(plan.Untouched,
		"wp-config.php - Zugangsdaten und Schlüssel, kein Original vorhanden",
		"wp-content/uploads - Kundendaten ohne Herstellerfassung")

	// mu-plugins is a classic place for a backdoor and never has an original,
	// but it also carries legitimate code from hosters. It is named rather
	// than removed.
	mu := filepath.Join(plan.Root, "wp-content", "mu-plugins")
	if entries, err := os.ReadDir(mu); err == nil && len(entries) > 0 {
		plan.Untouched = append(plan.Untouched, fmt.Sprintf(
			"wp-content/mu-plugins - %d Eintrag/Einträge, kein Original; bitte von Hand ansehen",
			len(entries)))
	}

	return plan, nil
}
