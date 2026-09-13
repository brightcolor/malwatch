package upgrade

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
	"sync"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/progress"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/vendorfiles"
)

const siteURL = "https://beispiel.de/"

var (
	planAkismet = PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.3.3"}
	planCore    = PlanElement{Kind: "core", Version: "6.4.5"}

	// Release contents the fake vendor hands out.
	akismet533 = map[string]string{
		"akismet/akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.3\nRequires PHP: 7.2\n*/",
	}
	core645 = map[string]string{
		"wordpress/wp-includes/version.php": "<?php\n$wp_version = '6.4.5';\n$wp_db_version = 56657;\n$required_php_version = '7.0.0';\n",
		"wordpress/wp-login.php":            "<?php // 6.4.5",
		"wordpress/wp-admin/index.php":      "<?php // admin 6.4.5",
	}
)

// site lays out WordPress 6.4.2 with akismet 5.3.0 at the web root.
func site(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "wp-includes", "version.php"),
		"<?php\n$wp_version = '6.4.2';\n$wp_db_version = 56657;\n$required_php_version = '7.0.0';\n")
	writeFile(t, filepath.Join(root, "wp-login.php"), "<?php // 6.4.2")
	writeFile(t, filepath.Join(root, "wp-config.php"), "<?php // secrets")
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php"),
		"<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3.0\n*/")
	return root
}

// treeOf renders a tree, so a test can assert that nothing changed at all.
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

// zipOf builds an archive in memory.
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

// vendor serves archives by URL path and 404 for everything else.
func vendor(t *testing.T, archives map[string]map[string]string) *vendorfiles.Fetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files, ok := archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zipOf(t, files))
	}))
	t.Cleanup(srv.Close)
	return vendorfiles.NewFetcher(vendorfiles.BaseURLs{
		Core: srv.URL + "/", LocalisedCore: srv.URL + "/%s/",
		Plugin: srv.URL + "/p/", Theme: srv.URL + "/t/",
	}, 10*time.Second)
}

// sumsOf is the checksum list wordpress.org would publish for release
// contents, relative to the unpacked directory.
func sumsOf(files map[string]string) map[string]string {
	out := map[string]string{}
	for name, body := range files {
		_, rel, _ := strings.Cut(name, "/")
		out[rel] = md5Of(body)
	}
	return out
}

// copyOf returns release contents with one file replaced.
func copyOf(files map[string]string, name, body string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	out[name] = body
	return out
}

// scripted answers each URL from a queue whose last answer repeats. A URL
// without a queue answers 200.
type scripted struct {
	mu      sync.Mutex
	answers map[string][]Probe
}

func (s *scripted) Get(url string) Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.answers[url]
	if len(queue) == 0 {
		return Probe{Status: 200}
	}
	answer := queue[0]
	if len(queue) > 1 {
		s.answers[url] = queue[1:]
	}
	return answer
}

func healthy() *scripted { return &scripted{answers: map[string][]Probe{}} }

func onePlan(root string, elements ...PlanElement) Plan {
	return Plan{Schema: 1, Installs: []PlanInstall{{Path: root, URL: siteURL, Elements: elements}}}
}

// options assembles a run against the fake vendor.
func options(t *testing.T, root string, plan Plan, prober PageProber, rec *recorder) Options {
	t.Helper()
	pw, err := progress.New("", "upgrade")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		WebRoot: root, Plan: plan,
		QuarantineDir: t.TempDir(), StagingDir: t.TempDir(), Domain: "beispiel.de",
		PHPVersion: "8.2.10",
		WPCLI: WPCLI{Exec: rec, User: "web12", Group: "client3",
			PHP: "/usr/bin/php8.2", Binary: "/usr/local/bin/wp"},
		HasWPCLI: true,
		Fetcher: vendor(t, map[string]map[string]string{
			"/p/akismet.5.3.3.zip": akismet533,
			"/wordpress-6.4.5.zip": core645,
		}),
		Checksums: fakeChecksums{
			core:    map[string]map[string]string{"6.4.5": sumsOf(core645)},
			plugins: map[string]map[string]string{"akismet@5.3.3": sumsOf(akismet533)},
		},
		Prober:   prober,
		Progress: pw,
	}
}

func TestAPluginIsUpdatedAndChecked(t *testing.T) {
	root := site(t)
	rec := &recorder{}
	rep, err := Run(options(t, root, onePlan(root, planAkismet), healthy(), rec))
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeUpdated || el.From != "5.3.0" || el.To != "5.3.3" || len(el.QuarantineIDs) != 1 {
		t.Fatalf("element = %+v", el)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php"))
	if !strings.Contains(string(raw), "5.3.3") {
		t.Errorf("the new release is not in place: %s", raw)
	}
	if len(rec.commands) != 0 {
		t.Errorf("a plugin update ran WP-CLI: %v", rec.subcommands())
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error(".maintenance is left behind")
	}
	if rep.ExitCode() != 0 {
		t.Errorf("exit code %d", rep.ExitCode())
	}
}

func TestABrokenSiteBringsTheOldPluginBack(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	prober := &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 200}}}}

	rep, err := Run(options(t, root, onePlan(root, planAkismet), prober, &recorder{}))
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRolledBack || !strings.Contains(el.Message, "Startseite: Antwort 500") {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before {
		t.Error("the site is not byte for byte what it was")
	}
	if c := el.Checks[0]; c.Before != 200 || c.After != 500 || c.AfterRollback != 200 {
		t.Errorf("checks = %+v", el.Checks)
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2", rep.ExitCode())
	}
}

func TestARequirementRefusesBeforeAnythingChanges(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	opts.PHPVersion = "7.1.33" // akismet 5.3.3 asks for 7.2

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRefused || el.Message != "5.3.3 braucht PHP 7.2, die Website läuft mit 7.1.33" {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before {
		t.Error("a refused element changed the site")
	}
	if entries, _, _ := quarantine.List(opts.QuarantineDir); len(entries) != 0 {
		t.Errorf("a refused element filed %d entries", len(entries))
	}
}

func TestAManipulatedArchiveStopsTheRun(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	opts.Checksums = fakeChecksums{plugins: map[string]map[string]string{
		"akismet@5.3.3": {"akismet.php": md5Of("<?php // the real 5.3.3")},
	}}

	rep, err := Run(opts)
	if err == nil || len(rep.Errors) == 0 {
		t.Fatal("a checksum mismatch did not stop the run")
	}
	if rep.Elements[0].Outcome != report.UpgradeSkipped || rep.ExitCode() != 3 {
		t.Errorf("element = %+v, exit code %d", rep.Elements[0], rep.ExitCode())
	}
	if got := treeOf(t, root); got != before {
		t.Error("the site changed although the run stopped before phase four")
	}
}

func TestTheCoreRaisesTheDatabaseOnlyWhenItsVersionChanges(t *testing.T) {
	for _, tc := range []struct{ name, dbVersion, want string }{
		{"same database", "56657", ""},
		{"new database", "57155", "db export,core update-db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := site(t)
			release := copyOf(core645, "wordpress/wp-includes/version.php",
				"<?php\n$wp_version = '6.4.5';\n$wp_db_version = "+tc.dbVersion+";\n$required_php_version = '7.0.0';\n")
			rec := &recorder{stdout: map[string]string{"db export": "-- dump 6.4.2"}}
			opts := options(t, root, onePlan(root, planCore), healthy(), rec)
			opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
			opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

			rep, err := Run(opts)
			if err != nil {
				t.Fatal(err)
			}
			el := rep.Elements[0]
			if el.Outcome != report.UpgradeUpdated {
				t.Fatalf("element = %+v", el)
			}
			if got := strings.Join(rec.subcommands(), ","); got != tc.want {
				t.Errorf("WP-CLI = %q, want %q", got, tc.want)
			}
			if (tc.want != "") != (el.DBExportID != "") {
				t.Errorf("db export id = %q", el.DBExportID)
			}
			if raw, _ := os.ReadFile(filepath.Join(root, "wp-includes", "version.php")); !strings.Contains(string(raw), "6.4.5") {
				t.Error("the new core is not in place")
			}
			if stray, _ := filepath.Glob(filepath.Join(opts.StagingDir, "datenbank-*.sql")); len(stray) != 0 {
				t.Errorf("the export stayed in the staging directory: %v", stray)
			}
		})
	}
}

func TestARollbackAfterTheDatabaseUpdateImportsTheExport(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	release := copyOf(core645, "wordpress/wp-includes/version.php",
		"<?php\n$wp_version = '6.4.5';\n$wp_db_version = 57155;\n$required_php_version = '7.0.0';\n")
	rec := &recorder{stdout: map[string]string{"db export": "-- dump 6.4.2"}}
	prober := &scripted{answers: map[string][]Probe{
		siteURL + "wp-login.php": {{Status: 200}, {Status: 500}, {Status: 200}},
	}}
	opts := options(t, root, onePlan(root, planCore), prober, rec)
	opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
	opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRolledBack || !strings.Contains(el.Message, "Anmeldeseite") || el.DBExportID == "" {
		t.Fatalf("element = %+v", el)
	}
	if got := strings.Join(rec.subcommands(), ","); got != "db export,core update-db,db import" {
		t.Errorf("WP-CLI = %s", got)
	}
	if rec.stdins[2] != "-- dump 6.4.2" {
		t.Errorf("the import read %q", rec.stdins[2])
	}
	if got := treeOf(t, root); got != before {
		t.Error("the core is not byte for byte what it was; wp-admin, added by the release, has to go too")
	}
}

func TestMaintenanceIsGoneAfterAFailedExchange(t *testing.T) {
	root := site(t)
	writeFile(t, filepath.Join(root, "wp-admin", "index.php"), "<?php // admin 6.4.2")
	before := treeOf(t, root)
	// A release without wp-admin: ReplaceCore refuses it before it touches anything.
	release := map[string]string{
		"wordpress/wp-includes/version.php": core645["wordpress/wp-includes/version.php"],
		"wordpress/wp-login.php":            core645["wordpress/wp-login.php"],
	}
	opts := options(t, root, onePlan(root, planCore), healthy(), &recorder{})
	opts.Fetcher = vendor(t, map[string]map[string]string{"/wordpress-6.4.5.zip": release})
	opts.Checksums = fakeChecksums{core: map[string]map[string]string{"6.4.5": sumsOf(release)}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeFailed || !strings.Contains(el.Message, "Tausch gescheitert") {
		t.Fatalf("element = %+v", el)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error(".maintenance is left behind")
	}
	if got := treeOf(t, root); got != before {
		t.Error("a failed exchange changed the site")
	}
}

func TestAFreshMaintenanceFileRefusesTheInstallAndStays(t *testing.T) {
	root := site(t)
	if err := EnterMaintenance(root, time.Now()); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(options(t, root, onePlan(root, planAkismet), healthy(), &recorder{}))
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeRefused || !strings.Contains(el.Message, ".maintenance") {
		t.Fatalf("element = %+v", el)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); err != nil {
		t.Error("the .maintenance of WordPress itself was removed")
	}
}

func TestASiteThatStaysBrokenStopsTheRun(t *testing.T) {
	root := site(t)
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "kontakt", "kontakt.php"),
		"<?php\n/*\nPlugin Name: Kontakt\nVersion: 1.0\n*/")
	kontakt := map[string]string{"kontakt/kontakt.php": "<?php\n/*\nPlugin Name: Kontakt\nVersion: 2.0\n*/"}
	prober := &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 500}}}}
	plan := onePlan(root, planAkismet, PlanElement{Kind: "plugin", Slug: "kontakt", Version: "2.0"})
	opts := options(t, root, plan, prober, &recorder{})
	opts.Fetcher = vendor(t, map[string]map[string]string{
		"/p/akismet.5.3.3.zip": akismet533,
		"/p/kontakt.2.0.zip":   kontakt,
	})

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Elements[0].Outcome != report.UpgradeRollbackFailed || rep.Elements[1].Outcome != report.UpgradeSkipped {
		t.Fatalf("elements = %+v", rep.Elements)
	}
	if rep.ExitCode() != 3 {
		t.Errorf("exit code %d, want 3", rep.ExitCode())
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "kontakt", "kontakt.php")); !strings.Contains(string(raw), "1.0") {
		t.Error("the skipped plugin was touched")
	}
}

func TestADryRunChangesNothingAndReportsWhatItWould(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	rec := &recorder{}
	prober := &scripted{answers: map[string][]Probe{siteURL + "wp-login.php": {{Status: 403}}}}
	opts := options(t, root, onePlan(root, planAkismet), prober, rec)
	opts.DryRun = true

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeWould || el.Checks[1].Before != 403 {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before || len(rec.commands) != 0 {
		t.Error("a dry run changed something")
	}
}

func TestWhatCannotGoAheadIsRefusedWithItsReason(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(root string)
		element PlanElement
		want    string
	}{
		{"lower target", func(string) {}, PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.2.0"}, "nicht höher"},
		{"unpublished release", func(string) {}, PlanElement{Kind: "plugin", Slug: "akismet", Version: "9.9.9"}, "nicht veröffentlicht"},
		{"missing plugin", func(string) {}, PlanElement{Kind: "plugin", Slug: "fehlt", Version: "1.0"}, "nicht vorhanden"},
		{"multisite", func(root string) {
			writeFile(t, filepath.Join(root, "wp-config.php"), "<?php\ndefine('MULTISITE', true);\n")
		}, planAkismet, "Multisite"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := site(t)
			c.prepare(root)
			rep, err := Run(options(t, root, onePlan(root, c.element), healthy(), &recorder{}))
			if err != nil {
				t.Fatal(err)
			}
			if el := rep.Elements[0]; el.Outcome != report.UpgradeRefused || !strings.Contains(el.Message, c.want) {
				t.Errorf("element = %+v, want a refusal naming %q", el, c.want)
			}
		})
	}
}
