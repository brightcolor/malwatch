// Package upgrade brings WordPress core, plugins and themes to a newer release
// from wordpress.org: fetch and verify the archive, check what the release
// asks of the site, file the old tree into quarantine, exchange it, check the
// site, and bring the old tree back when the site broke.
package upgrade

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brightcolor/malwatch/internal/safepath"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// PlanElement is one element the plan asks for.
type PlanElement struct {
	Kind    string `json:"kind"`           // core, plugin, theme
	Slug    string `json:"slug,omitempty"` // empty for the core
	Version string `json:"version"`        // the target release
}

// PlanInstall is one WordPress installation of the website.
type PlanInstall struct {
	Path     string        `json:"path"`
	URL      string        `json:"url"`
	Elements []PlanElement `json:"elements"`
}

// Plan is what the panel asks the run to do.
type Plan struct {
	Schema   int           `json:"schema"`
	Installs []PlanInstall `json:"installs"`
}

var kindOrder = map[string]int{"core": 0, "plugin": 1, "theme": 2}

// LoadPlan reads a plan file and checks it against the web root.
//
// Every installation has to lie below webRoot, carry wp-includes/version.php
// and an http or https address. Every element needs a known kind, a slug and
// a version that may go into a URL, and may appear once. A plan that fails
// any of this is refused as a whole: half a plan would upgrade something
// nobody chose.
//
// The elements of each installation come back sorted: the core first, then
// plugins, then themes, each kind by slug.
func LoadPlan(path, webRoot string) (Plan, error) {
	f, err := os.Open(path)
	if err != nil {
		return Plan{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return Plan{}, err
	}

	var plan Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return Plan{}, fmt.Errorf("Plandatei %s ist unlesbar: %w", path, err)
	}
	if plan.Schema != 1 {
		return Plan{}, fmt.Errorf("Plandatei %s hat Format %d, erwartet wird 1", path, plan.Schema)
	}
	if len(plan.Installs) == 0 {
		return Plan{}, fmt.Errorf("Plandatei %s nennt keine Installation", path)
	}

	seen := map[string]bool{}
	for i := range plan.Installs {
		inst := &plan.Installs[i]
		if err := checkInstall(inst, webRoot); err != nil {
			return Plan{}, err
		}
		if seen[inst.Path] {
			return Plan{}, fmt.Errorf("die Installation %s steht zweimal im Plan", inst.Path)
		}
		seen[inst.Path] = true
		if err := checkElements(inst); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}

func checkInstall(inst *PlanInstall, webRoot string) error {
	if !filepath.IsAbs(inst.Path) {
		return fmt.Errorf("der Pfad %q ist kein absoluter Pfad", inst.Path)
	}
	inst.Path = filepath.Clean(inst.Path)
	if err := safepath.InsideRoot(webRoot, inst.Path); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(inst.Path, "wp-includes", "version.php"))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("unter %s liegt keine WordPress-Installation", inst.Path)
	}

	u, err := url.Parse(inst.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("die Adresse %q der Installation %s ist unbrauchbar", inst.URL, inst.Path)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery, u.Fragment = "", ""
	inst.URL = u.String()
	return nil
}

func checkElements(inst *PlanInstall) error {
	if len(inst.Elements) == 0 {
		return fmt.Errorf("für die Installation %s nennt der Plan kein Element", inst.Path)
	}
	seen := map[string]bool{}
	for _, el := range inst.Elements {
		if _, ok := kindOrder[el.Kind]; !ok {
			return fmt.Errorf("unbekannte Art %q in %s", el.Kind, inst.Path)
		}
		if el.Kind == "core" && el.Slug != "" {
			return fmt.Errorf("der Kern in %s trägt einen Slug", inst.Path)
		}
		if el.Kind != "core" && !vendorfiles.Safe(el.Slug) {
			return fmt.Errorf("unplausibler Slug %q in %s", el.Slug, inst.Path)
		}
		if !vendorfiles.Safe(el.Version) {
			return fmt.Errorf("unplausible Version %q in %s", el.Version, inst.Path)
		}
		key := el.Kind + ":" + el.Slug
		if seen[key] {
			return fmt.Errorf("%s steht zweimal in %s", label(el), inst.Path)
		}
		seen[key] = true
	}
	sort.SliceStable(inst.Elements, func(a, b int) bool {
		x, y := inst.Elements[a], inst.Elements[b]
		if kindOrder[x.Kind] != kindOrder[y.Kind] {
			return kindOrder[x.Kind] < kindOrder[y.Kind]
		}
		return x.Slug < y.Slug
	})
	return nil
}

// label names an element for messages: "core", "plugin akismet".
func label(el PlanElement) string {
	if el.Slug == "" {
		return el.Kind
	}
	return el.Kind + " " + el.Slug
}
