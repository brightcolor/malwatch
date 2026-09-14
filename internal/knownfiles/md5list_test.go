package knownfiles

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func md5OfText(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// wordpress.org lists several MD5 values for a file that changed between two
// builds of the same plugin release, readme.txt most of all.
func TestAPluginListWithSeveralSumsForOneFileLoads(t *testing.T) {
	cache := t.TempDir()
	body := `{"plugin":"kontakt","version":"2.0","files":{` +
		`"kontakt.php":{"md5":"` + strings.ToUpper(md5OfText("<?php // 2.0")) + `","sha256":"x"},` +
		`"readme.txt":{"md5":["` + md5OfText("readme build 1") + `","` + md5OfText("readme build 2") + `"],"sha256":["a","b"]}}}`
	if err := os.WriteFile(filepath.Join(cache, "wordpress-plugin-kontakt-2.0.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := NewFetcher(cache, 5*time.Second).WordPressPlugin("kontakt", "2.0")
	if err != nil {
		t.Fatalf("the list did not load: %v", err)
	}
	if !SumMatches(files["kontakt.php"], md5OfText("<?php // 2.0")) {
		t.Errorf("kontakt.php = %q", files["kontakt.php"])
	}
	for _, build := range []string{"readme build 1", "readme build 2"} {
		if !SumMatches(files["readme.txt"], md5OfText(build)) {
			t.Errorf("readme.txt %q does not accept %q", files["readme.txt"], build)
		}
	}
	if SumMatches(files["readme.txt"], md5OfText("readme build 3")) {
		t.Error("a sum outside the list matched")
	}

	idx := New()
	idx.AddVendorTree("/w/wp-content/plugins/kontakt", "Plugin kontakt 2.0", files)
	if status, _ := idx.Check("/w/wp-content/plugins/kontakt/readme.txt", []byte("readme build 2")); status != Original {
		t.Errorf("the second build of readme.txt reads as %v", status)
	}
	if status, _ := idx.Check("/w/wp-content/plugins/kontakt/readme.txt", []byte("changed")); status != Modified {
		t.Errorf("a changed readme.txt reads as %v", status)
	}
}
