package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWordPress builds the smallest tree cms.Detect recognises: a core, one
// plugin, one theme, plus the parts that belong to the customer.
func fakeWordPress(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n")
	mk("wp-login.php", "<?php")
	mk("wp-config.php", "<?php // secrets")
	mk("wp-content/plugins/akismet/akismet.php",
		"<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\n*/")
	mk("wp-content/themes/twentytwentyfour/style.css",
		"/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2\n*/")
	mk("wp-content/uploads/2026/06/photo.jpg", "binary")
	mk("wp-content/mu-plugins/loader.php", "<?php // hoster")
	return root
}

func TestBuildPlanFindsCorePluginAndTheme(t *testing.T) {
	plan, err := BuildPlan(fakeWordPress(t))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range plan.Elements {
		kinds[e.Kind+":"+e.Slug] = e.Version
	}
	if kinds["core:"] != "6.6.2" {
		t.Errorf("core missing or wrong: %v", kinds)
	}
	if kinds["plugin:akismet"] != "5.3.3" {
		t.Errorf("plugin missing or wrong: %v", kinds)
	}
	if kinds["theme:twentytwentyfour"] != "1.2" {
		t.Errorf("theme missing or wrong: %v", kinds)
	}
}

func TestBuildPlanLeavesUploadsAndConfigAlone(t *testing.T) {
	plan, err := BuildPlan(fakeWordPress(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range plan.Elements {
		if strings.Contains(filepath.ToSlash(e.Path), "uploads") ||
			strings.HasSuffix(e.Path, "wp-config.php") {
			t.Fatalf("%s is not the vendor's to replace", e.Path)
		}
	}
	joined := strings.Join(plan.Untouched, "\n")
	for _, want := range []string{"wp-config.php", "wp-content/uploads", "mu-plugins"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s is not reported as untouched: %v", want, plan.Untouched)
		}
	}
}

func TestBuildPlanReportsAProductItCannotRestore(t *testing.T) {
	root := t.TempDir()
	// A Joomla next to the WordPress: there is no source for a version exact
	// archive, so it has to be named rather than silently passed over.
	p := filepath.Join(root, "joomla", "libraries", "src", "Version.php")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "<?php\nconst MAJOR_VERSION = 5;\nconst MINOR_VERSION = 1;\nconst PATCH_VERSION = 4;\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildPlan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Elements) != 0 {
		t.Errorf("joomla must not become an element: %+v", plan.Elements)
	}
	if !strings.Contains(strings.Join(plan.Untouched, "\n"), "joomla") {
		t.Errorf("joomla is not reported: %v", plan.Untouched)
	}
}
