package repair

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

// zipOf builds an archive in memory, so the tests need no network.
func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// treeOf renders a tree as a string, so a test can assert that nothing
// changed at all.
func treeOf(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() {
			fmt.Fprintf(&b, "d %s\n", filepath.ToSlash(rel))
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "f %s %x\n", filepath.ToSlash(rel), sha256.Sum256(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// zipFor answers a request with an archive whose contents say where it came
// from, which is enough to tell a replaced tree from the old one.
func zipFor(t *testing.T, urlPath string) []byte {
	t.Helper()
	switch {
	case strings.Contains(urlPath, "wordpress-"):
		return zipOf(t, map[string]string{
			"wordpress/wp-includes/version.php": "<?php\n$wp_version = '6.6.2';\n",
			"wordpress/wp-login.php":            "<?php // original",
		})
	case strings.Contains(urlPath, "twentytwentyfour"):
		return zipOf(t, map[string]string{
			"twentytwentyfour/style.css": "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2\n*/",
		})
	case strings.Contains(urlPath, "akismet"):
		return zipOf(t, map[string]string{
			"akismet/akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\n*/",
		})
	default:
		return zipOf(t, map[string]string{"unknown/file.php": "<?php"})
	}
}

func fetcherFor(srv *httptest.Server) *vendorfiles.Fetcher {
	return vendorfiles.NewFetcher(vendorfiles.BaseURLs{
		Core:          srv.URL + "/",
		LocalisedCore: srv.URL + "/%s/",
		Plugin:        srv.URL + "/p/",
		Theme:         srv.URL + "/t/",
	}, 10*time.Second)
}

func TestNothingIsTouchedWhenAFetchFails(t *testing.T) {
	root := fakeWordPress(t)
	before := treeOf(t, root)

	// The server answers everything with 500: a broken download has to stop
	// the run before phase five, not half way through it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, runErr := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if runErr == nil && len(rep.Errors) == 0 {
		t.Fatal("a failing download did not stop the run")
	}
	if got := treeOf(t, root); got != before {
		t.Fatal("the site was modified although the run failed before phase five")
	}
}

func TestAnElementWithoutAnOriginIsDeletedAndNamed(t *testing.T) {
	root := fakeWordPress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything is published except the plugin.
		if strings.Contains(r.URL.Path, "akismet") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(zipFor(t, r.URL.Path))
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, runErr := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		NoOriginal:    "quarantine",
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if runErr != nil {
		t.Fatalf("a missing version must not fail the run: %v", runErr)
	}

	var deleted *report.RepairElement
	for i := range rep.Elements {
		if rep.Elements[i].Slug == "akismet" {
			deleted = &rep.Elements[i]
		}
	}
	if deleted == nil || deleted.Outcome != report.OutcomeDeleted {
		t.Fatalf("akismet was not reported as deleted: %+v", rep.Elements)
	}
	if deleted.Version != "5.3.3" || deleted.QuarantineID == "" {
		t.Errorf("version or quarantine id missing: %+v", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet")); !os.IsNotExist(err) {
		t.Error("the directory without an original is still there")
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2", rep.ExitCode())
	}
}

func TestThePlantedFileInAReplacedPluginIsGone(t *testing.T) {
	root := fakeWordPress(t)
	planted := filepath.Join(root, "wp-content", "plugins", "akismet", "backdoor.php")
	if err := os.WriteFile(planted, []byte("<?php @eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipFor(t, r.URL.Path))
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	// Replacing the whole directory is the point: a dropped file only
	// disappears with the directory it hides in.
	if _, err := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Error("the planted file survived the exchange")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php")); err != nil {
		t.Errorf("the original is not in place: %v", err)
	}
}

func TestADryRunChangesNothingAndStillReports(t *testing.T) {
	root := fakeWordPress(t)
	before := treeOf(t, root)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipFor(t, r.URL.Path))
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{
		Root:       root,
		StagingDir: t.TempDir(),
		DryRun:     true,
		Fetcher:    fetcherFor(srv),
		Progress:   pw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := treeOf(t, root); got != before {
		t.Fatal("a dry run modified the tree")
	}
	if len(rep.Elements) == 0 {
		t.Fatal("a dry run has to report what it would do")
	}
}

// TestOverlayLeavesAForeignFileReplaceDoesNotBothQuarantine covers the
// central promise of both modes: overlay only adds and replaces what the
// vendor ships, so a foreign file in the element's directory survives it,
// while replace removes the whole directory and takes it along - and either
// way the tree that was there before is filed into quarantine first, so
// nothing is lost even in the mode that does remove it.
func TestOverlayLeavesAForeignFileReplaceDoesNotBothQuarantine(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		foreignGone bool
	}{
		{mode: "overlay", foreignGone: false},
		{mode: "replace", foreignGone: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			root := fakeWordPress(t)
			// A harmless placeholder, not a webshell pattern: this file only
			// needs to be foreign to the vendor archive, not malicious.
			foreign := filepath.Join(root, "wp-content", "plugins", "akismet", "not-from-vendor.txt")
			if err := os.WriteFile(foreign, []byte("// nur ein Platzhalter"), 0o644); err != nil {
				t.Fatal(err)
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(zipFor(t, r.URL.Path))
			}))
			defer srv.Close()

			pw, err := progress.New("", "repair")
			if err != nil {
				t.Fatal(err)
			}
			qdir := t.TempDir()
			rep, err := Run(Options{
				Root:          root,
				QuarantineDir: qdir,
				StagingDir:    t.TempDir(),
				Mode:          tc.mode,
				Only:          []string{"plugin:akismet"},
				Fetcher:       fetcherFor(srv),
				Progress:      pw,
			})
			if err != nil {
				t.Fatalf("mode %s: run failed: %v", tc.mode, err)
			}

			_, statErr := os.Stat(foreign)
			gone := os.IsNotExist(statErr)
			if gone != tc.foreignGone {
				t.Errorf("mode %s: foreign file gone=%v, want %v", tc.mode, gone, tc.foreignGone)
			}
			if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php")); err != nil {
				t.Errorf("mode %s: the original is not in place: %v", tc.mode, err)
			}

			if len(rep.Elements) != 1 || rep.Elements[0].QuarantineID == "" {
				t.Fatalf("mode %s: no quarantine entry recorded: %+v", tc.mode, rep.Elements)
			}
			entries, _, err := quarantine.List(qdir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].ID != rep.Elements[0].QuarantineID {
				t.Fatalf("mode %s: quarantine store does not hold the reported entry: %+v", tc.mode, entries)
			}
		})
	}
}

// TestOnlyLeavesNonMatchingElementsAlone covers --only: naming plugin:eins
// must not touch plugin:zwei, which sits right next to it.
func TestOnlyLeavesNonMatchingElementsAlone(t *testing.T) {
	root := fakeWordPress(t)
	for _, slug := range []string{"eins", "zwei"} {
		dir := filepath.Join(root, "wp-content", "plugins", slug)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf("<?php\n/*\nPlugin Name: %s\nVersion: 1.0.0\n*/", slug)
		if err := os.WriteFile(filepath.Join(dir, slug+".php"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	zweiFile := filepath.Join(root, "wp-content", "plugins", "zwei", "zwei.php")
	before, err := os.ReadFile(zweiFile)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "eins") {
			_, _ = w.Write(zipOf(t, map[string]string{
				"eins/eins.php": "<?php\n/*\nPlugin Name: eins\nVersion: 1.0.1\n*/",
			}))
			return
		}
		// zwei must never be requested: Only names eins alone.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Only:          []string{"plugin:eins"},
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Elements) != 1 || rep.Elements[0].Slug != "eins" {
		t.Fatalf("Only did not narrow the run to plugin:eins: %+v", rep.Elements)
	}

	after, err := os.ReadFile(zweiFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("plugin:zwei was touched although Only named only plugin:eins")
	}
}

// TestOnlyRefusesATypo makes sure a name that matches nothing fails loudly
// instead of quietly repairing everything, or nothing.
func TestOnlyRefusesATypo(t *testing.T) {
	root := fakeWordPress(t)
	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Only:          []string{"plugin:tippfehler"},
		Fetcher:       fetcherFor(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))),
		Progress:      pw,
	})
	if err == nil {
		t.Fatal("an --only value matching nothing was accepted silently")
	}
}

// TestNoOriginalKeepLeavesTheElementAndReportsKept covers the new default:
// an element the vendor does not publish stays exactly as it is, rather than
// being deleted for lacking a version that may just never have been public,
// such as a paid plugin.
func TestNoOriginalKeepLeavesTheElementAndReportsKept(t *testing.T) {
	root := fakeWordPress(t)
	pluginFile := filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php")
	before, err := os.ReadFile(pluginFile)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Only:          []string{"plugin:akismet"},
		NoOriginal:    "keep",
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(rep.Elements) != 1 || rep.Elements[0].Outcome != report.OutcomeKept {
		t.Fatalf("akismet was not reported as kept: %+v", rep.Elements)
	}
	if rep.Elements[0].QuarantineID != "" {
		t.Errorf("a kept element must not be quarantined: %+v", rep.Elements[0])
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2 - the site still carries an element without its vendor original", rep.ExitCode())
	}

	after, err := os.ReadFile(pluginFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a kept element was modified")
	}
}

// TestCoreWithoutAnOriginIsKeptEvenWithNoOriginalQuarantine guards a
// dangerous corner: the core element's Path is the web root itself, so
// routing it through the same "quarantine and remove" path a plugin or
// theme without an origin gets would archive and then empty out the entire
// site. --no-original=quarantine must not be able to do that just because
// the vendor, implausibly, stopped publishing a WordPress release.
func TestCoreWithoutAnOriginIsKeptEvenWithNoOriginalQuarantine(t *testing.T) {
	root := fakeWordPress(t)
	before := treeOf(t, root)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Only:          []string{"core"},
		NoOriginal:    "quarantine",
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Elements) != 1 || rep.Elements[0].Outcome != report.OutcomeKept {
		t.Fatalf("the core without an origin was not kept: %+v", rep.Elements)
	}
	if rep.Elements[0].QuarantineID != "" {
		t.Errorf("the core without an origin must not be quarantined as a whole: %+v", rep.Elements[0])
	}
	if got := treeOf(t, root); got != before {
		t.Fatal("the site was modified even though the core has no fetchable origin")
	}
}

// TestNoOriginalDefaultIsKeep locks in --no-original=keep as the default
// when Options leaves NoOriginal empty, the way a direct API caller might.
func TestNoOriginalDefaultIsKeep(t *testing.T) {
	root := fakeWordPress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pw, err := progress.New("", "repair")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{
		Root:          root,
		QuarantineDir: t.TempDir(),
		StagingDir:    t.TempDir(),
		Only:          []string{"plugin:akismet"},
		Fetcher:       fetcherFor(srv),
		Progress:      pw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Elements) != 1 || rep.Elements[0].Outcome != report.OutcomeKept {
		t.Fatalf("the default did not keep the element: %+v", rep.Elements)
	}
	if rep.Mode != "replace" {
		t.Errorf("the default mode is %q, want replace", rep.Mode)
	}
}
