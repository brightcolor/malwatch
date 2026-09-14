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
// for one specific slug, either one limited to the installation in a folder
// with @ ("plugin:elementor@blog"). An empty only leaves the plan as it is.
//
// A filter that matches nothing is an error rather than a silent no-op: a
// typo in --only must not quietly repair everything, or quietly repair
// nothing while looking like it ran. Every filter an element matches counts
// as matched, so "plugin:akismet" next to "plugin:akismet@blog" is no error.
func (p Plan) Filter(only []string) (Plan, error) {
	if len(only) == 0 {
		return p, nil
	}

	matched := make([]bool, len(only))
	out := p
	out.Elements = nil
	for _, el := range p.Elements {
		hit := false
		for i, f := range only {
			if elementMatches(p.Root, el, f) {
				matched[i] = true
				hit = true
			}
		}
		if hit {
			out.Elements = append(out.Elements, el)
		}
	}
	for i, f := range only {
		if !matched[i] {
			return Plan{}, fmt.Errorf("--only=%s passt auf kein gefundenes Element", f)
		}
	}
	return out, nil
}

// elementMatches reports whether filter names el: its kind alone ("plugin")
// or kind and slug together ("plugin:elementor"), each optionally followed by
// @ and the folder of its WordPress installation below root
// ("plugin:elementor@blog", "core@." for an installation in root itself).
func elementMatches(root string, el Element, filter string) bool {
	name, folder, scoped := strings.Cut(filter, "@")
	if scoped {
		dir, ok := installFolder(root, folder)
		if !ok || installOf(el) != dir {
			return false
		}
	}
	if kind, slug, ok := strings.Cut(name, ":"); ok {
		return el.Kind == kind && el.Slug == slug
	}
	return el.Kind == name
}

// installFolder resolves the folder of a filter below root. An empty folder,
// an absolute one and one that climbs out of root name no installation.
func installFolder(root, folder string) (string, bool) {
	rel := filepath.FromSlash(folder)
	if folder == "" || filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return "", false
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.Join(root, rel), true
}

// installOf is the directory of the WordPress installation el belongs to: the
// core's own directory, three levels above a plugin or theme
// (<installation>/<content directory>/plugins/<slug>).
func installOf(el Element) string {
	dir := filepath.Clean(el.Path)
	if el.Kind == "core" {
		return dir
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(dir)))
}
