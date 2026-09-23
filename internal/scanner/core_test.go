package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
	"github.com/brightcolor/malwatch/internal/knownfiles"
	"github.com/brightcolor/malwatch/internal/rules"
	"github.com/brightcolor/malwatch/internal/walk"
)

// The checksum list of a WordPress release decides wp-admin and wp-includes
// as a whole. A runnable file there that the release lacks is reported; the
// root of the install stays the site's own, and a copy under a name the web
// server does not run is left to the rules.
func TestForeignFilesInTheWordPressCoreDirectories(t *testing.T) {
	admin := "<?php // wp-admin/index.php\n"
	root := tree(t, map[string]string{
		"wp-admin/index.php":        admin,
		"wp-admin/wp-admin.php":     "<?php // nicht Teil der Auslieferung\n",
		"wp-includes/load.php.orig": "<?php // alte Kopie einer Kerndatei\n",
		"wp-config.php":             "<?php // Konfiguration der Website\n",
	})

	// The fetcher reads its cache before the network, so the test stays
	// offline.
	cache := t.TempDir()
	sum := md5.Sum([]byte(admin))
	list := `{"checksums":{"wp-admin/index.php":"` + hex.EncodeToString(sum[:]) +
		`","wp-includes/version.php":"00000000000000000000000000000000"}}`
	if err := os.WriteFile(filepath.Join(cache, "wordpress-core-6.5.5-en_US.json"), []byte(list), 0o640); err != nil {
		t.Fatal(err)
	}

	known := knownfiles.New()
	loadChecksums(known, knownfiles.NewFetcher(cache, time.Second),
		cms.Install{Path: root, Product: "wordpress", Kind: "core", Version: "6.5.5"})

	engine := rules.NewEngine(nil)
	opts := baseOptions(root)
	foreign := func(rel string) bool {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		ext := strings.TrimPrefix(filepath.Ext(path), ".")
		got, _ := scanOne(walk.File{Path: path, Size: info.Size(), MTime: info.ModTime(), Ext: ext, Rel: "/" + rel}, nil, engine, known, &opts)
		for _, f := range got {
			if f.Rule == "vendor.foreign_file" {
				return true
			}
		}
		return false
	}

	if !foreign("wp-admin/wp-admin.php") {
		t.Error("a PHP file the release does not contain was not reported in wp-admin")
	}
	for _, rel := range []string{"wp-admin/index.php", "wp-includes/load.php.orig", "wp-config.php"} {
		if foreign(rel) {
			t.Errorf("%s was reported as foreign", rel)
		}
	}
}
