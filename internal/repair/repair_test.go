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
		Root:       root,
		BackupDir:  t.TempDir(),
		StagingDir: t.TempDir(),
		Fetcher:    fetcherFor(srv),
		Progress:   pw,
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
		Root:       root,
		BackupDir:  t.TempDir(),
		StagingDir: t.TempDir(),
		Fetcher:    fetcherFor(srv),
		Progress:   pw,
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
	if deleted.Version != "5.3.3" || deleted.Backup == "" {
		t.Errorf("version or backup missing: %+v", deleted)
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
		Root:       root,
		BackupDir:  t.TempDir(),
		StagingDir: t.TempDir(),
		Fetcher:    fetcherFor(srv),
		Progress:   pw,
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
