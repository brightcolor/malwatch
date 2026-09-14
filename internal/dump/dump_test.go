package dump

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeDumper stands in for mysqldump: the tests need a database export
// without a database.
type fakeDumper struct {
	fail map[string]bool
}

func (f fakeDumper) Dump(name string, out io.Writer) error {
	if f.fail[name] {
		return errors.New("Zugang verweigert")
	}
	_, err := fmt.Fprintf(out, "-- dump of %s\nSELECT 1;\n", name)
	return err
}

// site builds a small website: two files below the web root, one of them in a
// subdirectory, and one log file next to it.
func site(t *testing.T) (web, logs string) {
	t.Helper()
	base := t.TempDir()
	web = filepath.Join(base, "web")
	logs = filepath.Join(base, "log")
	if err := os.MkdirAll(filepath.Join(web, "wp-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(web, "index.php"), "<?php echo 'beispiel'; ?>")
	write(t, filepath.Join(web, "wp-content", "plugin.php"), "<?php // plugin")
	write(t, filepath.Join(logs, "access.log"), "beispiel.de - - [15/Sep/2026] GET /\n")
	return web, logs
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// entries reads the archive back: name to header, so a test can ask for the
// layout without unpacking anything.
func entries(t *testing.T, archive string) map[string]*tar.Header {
	t.Helper()
	fh, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	found := map[string]*tar.Header{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found[hdr.Name] = hdr
	}
	return found
}

func TestRunPacksWebLogsAndDatabases(t *testing.T) {
	web, logs := site(t)
	archive := filepath.Join(t.TempDir(), "dump.tar.gz")

	rep, err := Run(Options{
		WebRoot:   web,
		LogRoot:   logs,
		Databases: []string{"web12_shop", "web12_blog"},
		Archive:   archive,
		Dumper:    fakeDumper{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	found := entries(t, archive)
	for _, name := range []string{
		"web/index.php",
		"web/wp-content/plugin.php",
		"protokolle/access.log",
		"datenbanken/web12_shop.sql",
		"datenbanken/web12_blog.sql",
		"dump.json",
	} {
		if found[name] == nil {
			t.Errorf("Eintrag %s fehlt im Archiv", name)
		}
	}

	if rep.Files != 3 {
		t.Errorf("Files = %d, erwartet 3", rep.Files)
	}
	if len(rep.Databases) != 2 || rep.Databases[0].Name != "web12_shop" {
		t.Fatalf("Databases = %+v", rep.Databases)
	}
	if rep.Databases[0].Bytes == 0 {
		t.Error("die Datenbank im Bericht wiegt nichts")
	}
	if rep.Reason != "" {
		t.Errorf("Reason = %q, erwartet leer", rep.Reason)
	}

	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ArchiveBytes != info.Size() {
		t.Errorf("ArchiveBytes = %d, Datei hat %d", rep.ArchiveBytes, info.Size())
	}
	if rep.SHA256 != fileSum(t, archive) {
		t.Errorf("SHA256 = %q passt nicht zur Datei", rep.SHA256)
	}

	// The report inside the archive carries the same numbers as the returned
	// one, so an unpacked dump explains itself.
	var inside Report
	if err := json.Unmarshal(member(t, archive, "dump.json"), &inside); err != nil {
		t.Fatal(err)
	}
	if inside.Files != rep.Files || len(inside.Databases) != len(rep.Databases) {
		t.Errorf("dump.json im Archiv weicht ab: %+v", inside)
	}
}

func TestRunKeepsSymlinkAsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlinks brauchen unter Windows eigene Rechte")
	}
	web, _ := site(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(web, "link.php")); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "dump.tar.gz")

	if _, err := Run(Options{WebRoot: web, Archive: archive, Dumper: fakeDumper{}}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	hdr := entries(t, archive)["web/link.php"]
	if hdr == nil {
		t.Fatal("der Symlink fehlt im Archiv")
	}
	if hdr.Typeflag != tar.TypeSymlink {
		t.Errorf("Typeflag = %v, erwartet Symlink", hdr.Typeflag)
	}
	if hdr.Linkname != "/etc/passwd" {
		t.Errorf("Linkname = %q", hdr.Linkname)
	}
	if hdr.Size != 0 {
		t.Errorf("der Symlink traegt %d Bytes Inhalt", hdr.Size)
	}
}

func TestRunFailsWhenDatabaseFails(t *testing.T) {
	web, _ := site(t)
	archive := filepath.Join(t.TempDir(), "dump.tar.gz")

	rep, err := Run(Options{
		WebRoot:   web,
		Databases: []string{"web12_shop", "web12_blog"},
		Archive:   archive,
		Dumper:    fakeDumper{fail: map[string]bool{"web12_blog": true}},
	})
	if err == nil {
		t.Fatal("Run meldet keinen Fehler")
	}
	if rep == nil || rep.Reason != "database" {
		t.Fatalf("Reason = %+v, erwartet database", rep)
	}
	if _, statErr := os.Stat(archive); !os.IsNotExist(statErr) {
		t.Error("das halbe Archiv liegt noch da")
	}
}

func TestRunRefusesWithoutSpace(t *testing.T) {
	web, _ := site(t)
	archive := filepath.Join(t.TempDir(), "dump.tar.gz")

	rep, err := Run(Options{
		WebRoot: web,
		Archive: archive,
		Dumper:  fakeDumper{},
		MinFree: 10000,
		// Measured on purpose, so the gate answers the same on every machine.
		Free: func(string) (int64, error) { return 1024, nil },
	})
	if err == nil {
		t.Fatal("Run packt trotz fehlendem Platz")
	}
	if rep == nil || rep.Reason != "space" {
		t.Fatalf("Reason = %+v, erwartet space", rep)
	}
	if _, statErr := os.Stat(archive); !os.IsNotExist(statErr) {
		t.Error("die Zieldatei wurde angelegt")
	}
}

func fileSum(t *testing.T, path string) string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, fh); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func member(t *testing.T, archive, name string) []byte {
	t.Helper()
	fh, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name != name {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	t.Fatalf("%s fehlt im Archiv", name)
	return nil
}
