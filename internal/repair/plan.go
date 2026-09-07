package repair

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// Filter narrows Elements to what only names - "core", or "plugin:elementor"
// for one specific slug. An empty only leaves the plan as it is.
//
// A filter that matches nothing is an error rather than a silent no-op: a
// typo in --only must not quietly repair everything, or quietly repair
// nothing while looking like it ran.
func (p Plan) Filter(only []string) (Plan, error) {
	if len(only) == 0 {
		return p, nil
	}

	matched := make([]bool, len(only))
	out := p
	out.Elements = nil
	for _, el := range p.Elements {
		for i, f := range only {
			if elementMatches(el, f) {
				matched[i] = true
				out.Elements = append(out.Elements, el)
				break
			}
		}
	}
	for i, f := range only {
		if !matched[i] {
			return Plan{}, fmt.Errorf("--only=%s passt auf kein gefundenes Element", f)
		}
	}
	return out, nil
}

// elementMatches reports whether filter names el: either its kind alone
// ("plugin") or kind and slug together ("plugin:elementor").
func elementMatches(el Element, filter string) bool {
	if kind, slug, ok := strings.Cut(filter, ":"); ok {
		return el.Kind == kind && el.Slug == slug
	}
	return el.Kind == filter
}
