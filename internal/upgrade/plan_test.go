package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a file with its directories.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// jsonString quotes a path for a plan written by hand; a Windows path needs
// its backslashes escaped.
func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// planFile writes a plan into a fresh directory and returns its path.
func planFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "job.plan.json")
	writeFile(t, p, body)
	return p
}

// webRootWithTwoInstalls lays out a web root holding WordPress at its top and
// a second one in blog/.
func webRootWithTwoInstalls(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.2';\n")
	writeFile(t, filepath.Join(root, "blog", "wp-includes", "version.php"), "<?php\n$wp_version = '6.5.3';\n")
	return root
}

func TestLoadPlanAcceptsAValidPlanAndOrdersItsElements(t *testing.T) {
	root := webRootWithTwoInstalls(t)
	body := `{"schema":1,"installs":[
		{"path":` + jsonString(root) + `,"url":"https://beispiel.de","elements":[
			{"kind":"theme","slug":"twentytwentyfour","version":"1.2"},
			{"kind":"plugin","slug":"zzz","version":"2.0"},
			{"kind":"core","version":"6.4.5"},
			{"kind":"plugin","slug":"akismet","version":"5.3.3"}]},
		{"path":` + jsonString(filepath.Join(root, "blog")) + `,"url":"https://beispiel.de/blog","elements":[
			{"kind":"plugin","slug":"akismet","version":"5.3.3"}]}]}`

	plan, err := LoadPlan(planFile(t, body), root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, el := range plan.Installs[0].Elements {
		got = append(got, label(el))
	}
	if want := "core,plugin akismet,plugin zzz,theme twentytwentyfour"; strings.Join(got, ",") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
	if plan.Installs[0].URL != "https://beispiel.de/" || plan.Installs[1].URL != "https://beispiel.de/blog/" {
		t.Errorf("addresses not normalised: %q %q", plan.Installs[0].URL, plan.Installs[1].URL)
	}
}

func TestLoadPlanRefusesWhatItCannotVouchFor(t *testing.T) {
	root := webRootWithTwoInstalls(t)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.2';\n")
	empty := filepath.Join(root, "leer")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}

	install := func(path, url, elements string) string {
		return `{"schema":1,"installs":[{"path":` + jsonString(path) + `,"url":"` + url +
			`","elements":[` + elements + `]}]}`
	}
	core := `{"kind":"core","version":"6.4.5"}`
	cases := map[string]string{
		"schema 2":             `{"schema":2,"installs":[]}`,
		"no install":           `{"schema":1,"installs":[]}`,
		"outside the root":     install(outside, "https://beispiel.de/", core),
		"no WordPress":         install(empty, "https://beispiel.de/", core),
		"relative path":        install("web", "https://beispiel.de/", core),
		"ftp address":          install(root, "ftp://beispiel.de/", core),
		"unknown kind":         install(root, "https://beispiel.de/", `{"kind":"widget","slug":"x","version":"1"}`),
		"slug leaving a path":  install(root, "https://beispiel.de/", `{"kind":"plugin","slug":"../evil","version":"1.0"}`),
		"version with a slash": install(root, "https://beispiel.de/", `{"kind":"plugin","slug":"akismet","version":"5.3/3"}`),
		"core with a slug":     install(root, "https://beispiel.de/", `{"kind":"core","slug":"x","version":"6.4.5"}`),
		"twice the same": install(root, "https://beispiel.de/",
			`{"kind":"plugin","slug":"akismet","version":"5.3.3"},{"kind":"plugin","slug":"akismet","version":"5.3.4"}`),
		"no element": install(root, "https://beispiel.de/", ``),
	}
	for name, body := range cases {
		if _, err := LoadPlan(planFile(t, body), root); err == nil {
			t.Errorf("%s: the plan was accepted", name)
		}
	}
}
