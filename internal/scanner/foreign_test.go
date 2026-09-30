package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/fileview"
	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/rules"
	"github.com/brightcolor/malwatch/internal/sigs"
	"github.com/brightcolor/malwatch/internal/walk"
)

// scanOneFile writes body under root/rel and runs scanFile over it with known.
func scanOneFile(t *testing.T, root, rel, body string, known *knownfiles.Index) []string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sigDB, _ := sigs.Load(filepath.Join(root, "no-signatures"))
	f := walk.File{Path: p, Size: int64(len(body)), MTime: time.Now(), Ext: strings.TrimPrefix(filepath.Ext(p), "."), Rel: "/" + rel}
	found, _, _ := scanFile(f, sigDB, rules.NewEngine(nil), known, &Options{View: fileview.Default})
	var out []string
	for _, x := range found {
		out = append(out, x.Rule)
	}
	return out
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// A file the vendor does not ship is reported because it can be a way in.
// Plugins write guards and plain text files into their own directories at
// run time - All-in-One WP Migration its storage/index.php with "Kangaroos
// cannot jump here" - and such a file can do nothing.
func TestStrangersThatDoNothingAreNoForeignFile(t *testing.T) {
	root := t.TempDir()
	plugin := filepath.Join(root, "wp-content", "plugins", "x")
	main := "<?php /* Plugin Name: x */"
	sum := md5.Sum([]byte(main))
	known := knownfiles.New()
	known.AddVendorTree(plugin, "Plugin x 1.0", map[string]string{"x.php": hex.EncodeToString(sum[:])})
	scanOneFile(t, root, "wp-content/plugins/x/x.php", main, known)

	for _, c := range []struct{ rel, body string }{
		{"wp-content/plugins/x/storage/index.php", "Kangaroos cannot jump here"},
		{"wp-content/plugins/x/cache/index.php", "<?php // Silence is golden."},
	} {
		if got := scanOneFile(t, root, c.rel, c.body, known); has(got, "vendor.foreign_file") {
			t.Errorf("%s: gemeldet, obwohl die Datei nichts tun kann", c.rel)
		}
	}
	if got := scanOneFile(t, root, "wp-content/plugins/x/extra.php", "<?php echo 1;", known); !has(got, "vendor.foreign_file") {
		t.Errorf("eine fremde Datei mit Code wird nicht mehr gemeldet: %v", got)
	}
}

// scanWithExts is scanOneFile with a list of extensions where a deviation
// from the vendor counts.
func scanWithExts(t *testing.T, root, rel, body string, known *knownfiles.Index, exts []string) []string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sigDB, _ := sigs.Load(filepath.Join(root, "no-signatures"))
	f := walk.File{Path: p, Size: int64(len(body)), MTime: time.Now(), Ext: strings.TrimPrefix(filepath.Ext(p), "."), Rel: "/" + rel}
	found, _, _ := scanFile(f, sigDB, rules.NewEngine(nil), known, &Options{View: fileview.Default, ModifiedExts: exts})
	var out []string
	for _, x := range found {
		out = append(out, x.Rule)
	}
	return out
}

// A vendor file that no longer matches counts where it can carry code. A
// readme, a translation template or a font that differs is a vendor that
// rebuilt a release, not a way in: on 2026-09-30 nine of the thirteen open
// core.modified findings were such files.
func TestADeviationCountsInCodeFilesOnly(t *testing.T) {
	root := t.TempDir()
	plugin := filepath.Join(root, "wp-content", "plugins", "x")
	sum := func(s string) string { m := md5.Sum([]byte(s)); return hex.EncodeToString(m[:]) }
	known := knownfiles.New()
	known.AddVendorTree(plugin, "Plugin x 1.0", map[string]string{
		"readme.txt":           sum("=== x ==="),
		"languages/x.pot":      sum("msgid \"\""),
		"assets/fonts/x.woff2": sum("wOF2"),
		"x.php":                sum("<?php // x"),
		"assets/x.js":          sum("var x = 1;"),
	})

	for _, c := range []struct {
		rel  string
		want bool
	}{
		{"wp-content/plugins/x/readme.txt", false},
		{"wp-content/plugins/x/languages/x.pot", false},
		{"wp-content/plugins/x/assets/fonts/x.woff2", false},
		{"wp-content/plugins/x/x.php", true},
		{"wp-content/plugins/x/assets/x.js", true},
	} {
		got := has(scanWithExts(t, root, c.rel, "changed", known, nil), "core.modified")
		if got != c.want {
			t.Errorf("%s: core.modified %v, erwartet %v", c.rel, got, c.want)
		}
	}

	// Another list than the default decides as well.
	if !has(scanWithExts(t, root, "wp-content/plugins/x/readme.txt", "changed", known, []string{"txt"}), "core.modified") {
		t.Error("mit der Liste txt: readme.txt nicht gemeldet")
	}
	if has(scanWithExts(t, root, "wp-content/plugins/x/x.php", "changed", known, []string{"txt"}), "core.modified") {
		t.Error("mit der Liste txt: x.php trotzdem gemeldet")
	}
}

// The list decides what a clean file means, so a clean result from a run with
// another list must not be taken over.
func TestTheListOfCodeFilesIsPartOfTheCacheKey(t *testing.T) {
	sigDB, _ := sigs.Load(filepath.Join(t.TempDir(), "none"))
	e := rules.NewEngine(nil)
	a := fingerprint(sigDB, e, &Options{ModifiedExts: []string{"php"}})
	b := fingerprint(sigDB, e, &Options{ModifiedExts: []string{"php", "txt"}})
	if a == b {
		t.Fatal("zwei verschiedene Listen ergeben denselben Schlüssel des Caches")
	}
}
