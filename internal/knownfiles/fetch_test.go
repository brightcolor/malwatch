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

func TestCoreOnlyDropsTheSampleConfig(t *testing.T) {
	// wordpress.org publishes the English checksum of wp-config-sample.php for
	// every locale, while the localised archives ship a translated file. The
	// entry can therefore never match on a German install and would report a
	// file that WordPress does not load at all.
	in := map[string]string{
		"wp-config-sample.php": "a",
		"wp-login.php":         "b",
	}
	out := coreOnly(in)

	if _, ok := out["wp-config-sample.php"]; ok {
		t.Error("wp-config-sample.php was kept; its checksum is not published per locale")
	}
	if _, ok := out["wp-login.php"]; !ok {
		t.Error("wp-login.php was dropped but belongs to the core")
	}
}
