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
	if _, err := f.WordPressCore("1.0/../../x"); err == nil {
		t.Error("a core version with a path traversal was accepted")
	}
}
