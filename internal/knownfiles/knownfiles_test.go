package knownfiles

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
func sha(b []byte) string    { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestOriginalModifiedUnknown(t *testing.T) {
	root := filepath.FromSlash("/var/www/web")
	original := []byte("<?php // the vendor's file\n")

	idx := New()
	idx.AddInstall(root, "wordpress 6.6.2", map[string]string{
		"wp-load.php":             md5hex(original),
		"wp-includes/version.php": md5hex(original),
	})

	if st, label := idx.Check(filepath.Join(root, "wp-load.php"), original); st != Original || label != "wordpress 6.6.2" {
		t.Errorf("unmodified vendor file: status %v label %q", st, label)
	}

	changed := append(append([]byte{}, original...), []byte("eval($_POST['x']);")...)
	if st, _ := idx.Check(filepath.Join(root, "wp-load.php"), changed); st != Modified {
		t.Errorf("changed vendor file: status %v, want Modified", st)
	}

	// A file inside the install that the vendor never shipped stays unknown,
	// so an upload is scanned normally instead of being waved through.
	if st, _ := idx.Check(filepath.Join(root, "wp-content/uploads/x.php"), original); st != Unknown {
		t.Errorf("unlisted file: status %v, want Unknown", st)
	}

	// A file outside the install is not covered at all.
	if st, _ := idx.Check(filepath.FromSlash("/var/www/other/wp-load.php"), original); st != Unknown {
		t.Errorf("file outside the install: status %v, want Unknown", st)
	}
}

func TestRootPrefixDoesNotLeakIntoASiblingDirectory(t *testing.T) {
	// "/var/www/web" must not claim files under "/var/www/website".
	original := []byte("x")
	idx := New()
	idx.AddInstall(filepath.FromSlash("/var/www/web"), "wp", map[string]string{"a.php": md5hex(original)})

	if st, _ := idx.Check(filepath.FromSlash("/var/www/website/a.php"), original); st != Unknown {
		t.Fatalf("sibling directory matched: status %v", st)
	}
}

func TestMoreSpecificInstallWins(t *testing.T) {
	// A plugin with its own checksum list lives inside the WordPress tree.
	// Its entry must decide, not the surrounding core list.
	core := filepath.FromSlash("/var/www/web")
	plugin := filepath.FromSlash("/var/www/web/wp-content/plugins/akismet")
	content := []byte("plugin file")

	idx := New()
	idx.AddInstall(core, "core", map[string]string{
		"wp-content/plugins/akismet/akismet.php": md5hex([]byte("something else")),
	})
	idx.AddInstall(plugin, "akismet 5.7.2", map[string]string{
		"akismet.php": md5hex(content),
	})

	st, label := idx.Check(filepath.Join(plugin, "akismet.php"), content)
	if st != Original || label != "akismet 5.7.2" {
		t.Fatalf("status %v label %q, want Original from the plugin list", st, label)
	}
}

func TestGenericSumsMatchAnywhere(t *testing.T) {
	content := []byte("<?php // shipped by a vendor\n")
	idx := New()
	idx.AddGeneric([]string{sha(content)})

	if st, _ := idx.Check(filepath.FromSlash("/anywhere/at/all.php"), content); st != Original {
		t.Fatal("a known vendor sum was not recognised")
	}
	if st, _ := idx.Check(filepath.FromSlash("/anywhere/at/all.php"), []byte("other")); st != Unknown {
		t.Fatal("unknown content was treated as a vendor file")
	}
}

func TestEmptyIndexClaimsNothing(t *testing.T) {
	idx := New()
	if !idx.Empty() {
		t.Fatal("a fresh index reports content")
	}
	if st, _ := idx.Check(filepath.FromSlash("/x.php"), []byte("anything")); st != Unknown {
		t.Fatalf("empty index returned %v", st)
	}
}

func TestUnsafeSlugAndVersionAreRejected(t *testing.T) {
	f := NewFetcher(t.TempDir(), 0)
	if _, err := f.WordPressPlugin("../../etc", "1.0"); err == nil {
		t.Error("a slug with a path traversal was accepted")
	}
	if _, err := f.WordPressPlugin("akismet", "../1.0"); err == nil {
		t.Error("a version with a path traversal was accepted")
	}
	if _, err := f.WordPressCore("1.0/../../x", "en_US"); err == nil {
		t.Error("a core version with a path traversal was accepted")
	}
	// A locale is sanitised rather than refused: it falls back to en_US, so a
	// nonsense value costs the comparison nothing and never reaches the URL.
	if safeSlug("../../etc") {
		t.Error("a locale with a path traversal passed the check")
	}
	if !safeSlug("de_DE") {
		t.Error("an ordinary locale was refused")
	}
}

// A CMS core ships some of its directories whole. WordPress puts nothing of
// the site into wp-admin and wp-includes, so a file there that the release
// does not contain came in some other way. The root of the install stays
// partial: wp-config.php and wp-content belong to the site.
func TestACoreShipsItsDirectoriesWhole(t *testing.T) {
	root := filepath.FromSlash("/web")
	index := []byte("<?php // wp-admin/index.php")
	idx := New()
	idx.AddCore(root, "WordPress 6.5.5", map[string]string{
		"wp-admin/index.php":      md5hex(index),
		"wp-includes/version.php": md5hex([]byte("<?php $wp_version = '6.5.5';")),
		"wp-load.php":             md5hex([]byte("<?php // wp-load")),
	}, "wp-admin", "wp-includes")

	cases := []struct {
		path string
		want Status
	}{
		{"wp-admin/index.php", Original},
		{"wp-admin/wp-admin.php", Foreign},
		{"wp-includes/load.php.orig", Foreign},
		{"wp-config.php", Unknown},
		{"wp-content/plugins/akismet/akismet.php", Unknown},
		// A sibling whose name starts the same is not inside wp-admin.
		{"wp-admin-alt/tool.php", Unknown},
	}
	for _, c := range cases {
		content := []byte("<?php // eine Datei")
		if c.want == Original {
			content = index
		}
		got, label := idx.Check(filepath.Join(root, filepath.FromSlash(c.path)), content)
		if got != c.want {
			t.Errorf("%s = %v, want %v", c.path, got, c.want)
		}
		if got == Foreign && label != "WordPress 6.5.5" {
			t.Errorf("%s: label %q, want the release", c.path, label)
		}
	}
}

// TestAVendorTreeReportsWhatTheVendorDoesNotShip covers the difference
// between the two ways of registering a checksum list. A CMS core is
// surrounded by files its list never mentions - the configuration, the
// uploads, every plugin - so an unlisted file there says nothing. A plugin
// directory holds the plugin and nothing else, so an unlisted file there is
// the whole finding: no pattern, no content, just the question of whether it
// belongs.
func TestAVendorTreeReportsWhatTheVendorDoesNotShip(t *testing.T) {
	shipped := []byte("<?php // vom Hersteller")
	sum := md5.Sum(shipped)
	files := map[string]string{"akismet.php": hex.EncodeToString(sum[:])}

	t.Run("vollstaendiger Baum", func(t *testing.T) {
		idx := New()
		idx.AddVendorTree(filepath.FromSlash("/web/wp-content/plugins/akismet"), "Plugin akismet 4.2.4", files)

		if got, _ := idx.Check(filepath.FromSlash("/web/wp-content/plugins/akismet/akismet.php"), shipped); got != Original {
			t.Errorf("die ausgelieferte Datei = %v, erwartet Original", got)
		}
		got, label := idx.Check(filepath.FromSlash("/web/wp-content/plugins/akismet/untergeschoben.php"), []byte("<?php // nur ein Platzhalter"))
		if got != Foreign {
			t.Errorf("die fremde Datei = %v, erwartet Foreign", got)
		}
		if label != "Plugin akismet 4.2.4" {
			t.Errorf("Label = %q, erwartet den Namen des Plugins", label)
		}
	})

	t.Run("unvollstaendige Liste", func(t *testing.T) {
		idx := New()
		idx.AddInstall(filepath.FromSlash("/web"), "WordPress 6.6.2", files)

		// Dieselbe Frage an eine Liste, die nur einen Teil des Baums
		// beschreibt: hier ist eine unbekannte Datei eine Datei, ueber die
		// niemand etwas behauptet.
		if got, _ := idx.Check(filepath.FromSlash("/web/wp-config.php"), []byte("<?php // Konfiguration")); got != Unknown {
			t.Errorf("unbekannte Datei unter einem Kern = %v, erwartet Unknown", got)
		}
	})
}
