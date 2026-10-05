package knownfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wordpress.org publishes a SHA-256 next to the MD5 of a plugin file. The
// comparison takes the SHA-256, as wp plugin verify-checksums does; a file the
// list gives no SHA-256 for keeps its MD5.
func TestAPluginListIsComparedBySHA256(t *testing.T) {
	cache := t.TempDir()
	shipped := []byte("<?php // kontakt 2.0")
	other := []byte("<?php // eine andere Datei")
	// The MD5 of kontakt.php belongs to another content than its SHA-256, so
	// the outcome shows which of the two decides.
	body := `{"plugin":"kontakt","version":"2.0","files":{` +
		`"kontakt.php":{"md5":"` + md5hex(other) + `","sha256":"` + strings.ToUpper(sha(shipped)) + `"},` +
		`"readme.txt":{"md5":["` + md5hex([]byte("build 1")) + `","` + md5hex([]byte("build 2")) + `"],` +
		`"sha256":["` + sha([]byte("build 1")) + `","` + sha([]byte("build 2")) + `"]},` +
		`"style.css":{"md5":"` + md5hex([]byte("body{}")) + `"}}}`
	if err := os.WriteFile(filepath.Join(cache, "wordpress-plugin-kontakt-2.0.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := NewFetcher(cache, 5*time.Second).WordPressPlugin("kontakt", "2.0")
	if err != nil {
		t.Fatalf("the list did not load: %v", err)
	}
	if files["kontakt.php"] != sha(shipped) {
		t.Errorf("kontakt.php = %q, want its SHA-256 in lower case", files["kontakt.php"])
	}
	if files["style.css"] != md5hex([]byte("body{}")) {
		t.Errorf("style.css = %q, want its MD5", files["style.css"])
	}

	idx := New()
	idx.AddVendorTree("/w/wp-content/plugins/kontakt", "Plugin kontakt 2.0", files)
	for _, c := range []struct {
		name    string
		content []byte
		want    Status
	}{
		{"kontakt.php", shipped, Original},
		{"kontakt.php", other, Modified},
		{"readme.txt", []byte("build 1"), Original},
		{"readme.txt", []byte("build 2"), Original},
		{"readme.txt", []byte("build 3"), Modified},
		{"style.css", []byte("body{}"), Original},
		{"style.css", []byte("body{color:red}"), Modified},
	} {
		if got, _ := idx.Check("/w/wp-content/plugins/kontakt/"+c.name, c.content); got != c.want {
			t.Errorf("%s with %q reads as %v, want %v", c.name, c.content, got, c.want)
		}
	}
}

func TestMatchesTakesTheKindOfSumFromItsLength(t *testing.T) {
	content := []byte("<?php // eine Datei")
	for _, c := range []struct {
		entry string
		want  bool
	}{
		{md5hex(content), true},
		{sha(content), true},
		{md5hex([]byte("x")) + "," + sha(content), true},
		{sha([]byte("x")) + "," + md5hex(content), true},
		{sha([]byte("x")), false},
		{md5hex([]byte("x")), false},
		{sha(content)[:40], false},
		{"", false},
	} {
		if got := Matches(c.entry, content); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.entry, got, c.want)
		}
	}
}

func TestPluginSumsTakesOnlyAWellFormedSHA256(t *testing.T) {
	md5Sum := md5hex([]byte("a"))
	if got := pluginSums(sumValues{md5Sum}, sumValues{"x", ""}); len(got) != 1 || got[0] != md5Sum {
		t.Errorf("a list without a usable SHA-256 gives %v, want the MD5", got)
	}
	if got := pluginSums(sumValues{md5Sum}, sumValues{" " + strings.ToUpper(sha([]byte("a"))) + " "}); len(got) != 1 || got[0] != sha([]byte("a")) {
		t.Errorf("got %v, want the SHA-256 trimmed and in lower case", got)
	}
	if got := pluginSums(nil, nil); len(got) != 0 {
		t.Errorf("an entry without sums gives %v", got)
	}
}
