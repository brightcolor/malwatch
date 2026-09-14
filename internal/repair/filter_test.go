package repair

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Two installations carry the same plugin. The folder after @ picks the one
// in that folder; the name alone keeps meaning every installation.
func TestFilterNarrowsToTheFolderAfterTheAt(t *testing.T) {
	root := fakeWordPress(t)
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("campus/wp-includes/version.php", "<?php\n$wp_version = '6.4.5';\n")
	mk("campus/wp-login.php", "<?php")
	mk("campus/wp-content/plugins/akismet/akismet.php",
		"<?php\n/*\nPlugin Name: Akismet\nVersion: 5.1\n*/")

	plan, err := BuildPlan(root)
	if err != nil {
		t.Fatal(err)
	}
	picked := func(only ...string) []string {
		t.Helper()
		got, err := plan.Filter(only)
		if err != nil {
			t.Fatalf("Filter(%v): %v", only, err)
		}
		var out []string
		for _, e := range got.Elements {
			out = append(out, e.Kind+":"+e.Slug+"="+e.Version)
		}
		sort.Strings(out)
		return out
	}

	if got := picked("plugin:akismet@campus"); !reflect.DeepEqual(got, []string{"plugin:akismet=5.1"}) {
		t.Errorf("@campus = %v", got)
	}
	if got := picked("plugin:akismet@."); !reflect.DeepEqual(got, []string{"plugin:akismet=5.3.3"}) {
		t.Errorf("@. = %v", got)
	}
	if got := picked("core@campus"); !reflect.DeepEqual(got, []string{"core:=6.4.5"}) {
		t.Errorf("core@campus = %v", got)
	}
	if got := picked("plugin:akismet"); !reflect.DeepEqual(got, []string{"plugin:akismet=5.1", "plugin:akismet=5.3.3"}) {
		t.Errorf("without a folder = %v", got)
	}

	// A folder without that element, one that climbs out of --path and an
	// absolute one match nothing, and a filter matching nothing is an error.
	for _, bad := range []string{"plugin:akismet@blog", "plugin:akismet@../campus", "plugin:akismet@" + filepath.Join(root, "campus")} {
		if _, err := plan.Filter([]string{bad}); err == nil {
			t.Errorf("Filter(%s) matched an element", bad)
		}
	}
}
