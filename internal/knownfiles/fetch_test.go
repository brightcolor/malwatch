package knownfiles

import "testing"

func TestCoreOnlyDropsBundledContent(t *testing.T) {
	in := map[string]string{
		"wp-load.php":                              "a",
		"wp-admin/index.php":                       "b",
		"wp-includes/functions.php":                "c",
		"wp-content/themes/twentytwenty/style.css": "d",
		"wp-content/plugins/akismet/akismet.php":   "e",
	}
	out := coreOnly(in)

	for _, keep := range []string{"wp-load.php", "wp-admin/index.php", "wp-includes/functions.php"} {
		if _, ok := out[keep]; !ok {
			t.Errorf("%s was dropped but belongs to the core", keep)
		}
	}
	for _, drop := range []string{"wp-content/themes/twentytwenty/style.css", "wp-content/plugins/akismet/akismet.php"} {
		if _, ok := out[drop]; ok {
			t.Errorf("%s was kept; bundled themes update on their own schedule", drop)
		}
	}
	if len(out) != 3 {
		t.Fatalf("kept %d entries, want 3", len(out))
	}
}

func TestCoreOnlyKeepsAPathThatOnlyLooksLikeContent(t *testing.T) {
	// "wp-contents" and "my-wp-content" are not the content directory. Only
	// the exact prefix counts, otherwise a core file could be dropped and its
	// modification would never be reported.
	in := map[string]string{
		"wp-contents/x.php":            "a",
		"wp-admin/wp-content-tool.php": "b",
	}
	if len(coreOnly(in)) != 2 {
		t.Fatal("a path that merely resembles wp-content was dropped")
	}
}
