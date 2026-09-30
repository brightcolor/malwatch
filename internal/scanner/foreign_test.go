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
