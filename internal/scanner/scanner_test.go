package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/report"
)

// tree writes files into a temporary directory and returns its path.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// baseOptions runs offline and without ClamAV, so the test measures the
// scanner and not the network.
func baseOptions(root string) Options {
	return Options{
		Paths:         []string{root},
		Offline:       true,
		NoClamAV:      true,
		NoVersionScan: true,
		Threads:       2,
	}
}

func run(t *testing.T, opts Options) *report.Report {
	t.Helper()
	rep, err := Run(opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

func findingsFor(rep *report.Report, suffix string) []report.Finding {
	var out []report.Finding
	for _, f := range rep.Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), suffix) {
			out = append(out, f)
		}
	}
	return out
}

func TestFindsAPlantedShellAndLeavesHonestCodeAlone(t *testing.T) {
	root := tree(t, map[string]string{
		"web/index.php":        "<?php\nrequire __DIR__ . '/config.php';\necho 'Hallo';\n",
		"web/config.php":       "<?php\n$db = ['host' => 'localhost', 'user' => 'web1'];\n",
		"web/lib/helper.php":   "<?php\nfunction render($tpl, $vars) {\n  extract($vars, EXTR_SKIP);\n  include $tpl;\n}\n",
		"web/assets/app.js":    "document.addEventListener('DOMContentLoaded', function () { console.log('ok'); });\n",
		"web/uploads/note.txt": "just a note\n",
		"web/shell.php":        "<?php @eval($_POST['cmd']);\n",
	})

	rep := run(t, baseOptions(root))

	shell := findingsFor(rep, "web/shell.php")
	if len(shell) == 0 {
		t.Fatal("the planted shell was not found")
	}
	if rep.MaxSeverity() != report.SeverityCritical {
		t.Errorf("MaxSeverity = %q, want critical", rep.MaxSeverity())
	}

	// The counter-check that matters: everything else must stay quiet. A rule
	// set that flags honest code is worse than none, because nobody reads the
	// report after the third false alarm.
	for _, clean := range []string{"web/index.php", "web/config.php", "web/lib/helper.php", "web/assets/app.js"} {
		if got := findingsFor(rep, clean); len(got) > 0 {
			t.Errorf("false positive in %s: %+v", clean, got)
		}
	}
}

func TestExitCodeFollowsTheThreshold(t *testing.T) {
	root := tree(t, map[string]string{
		// eval on a plain variable is a medium finding, nothing worse.
		"web/a.php": "<?php eval($payload);\n",
	})
	rep := run(t, baseOptions(root))

	if code := rep.ExitCode(report.SeverityMedium); code != report.ExitFindings {
		t.Errorf("exit code at threshold medium = %d, want %d", code, report.ExitFindings)
	}
	if code := rep.ExitCode(report.SeverityCritical); code != report.ExitClean {
		t.Errorf("exit code at threshold critical = %d, want %d", code, report.ExitClean)
	}
}

func TestWhitelistSuppressesAFinding(t *testing.T) {
	content := "<?php @eval($_POST['cmd']);\n"
	root := tree(t, map[string]string{"web/tool.php": content})

	sum := sha256.Sum256([]byte(content))
	opts := baseOptions(root)
	opts.Whitelist = map[string]bool{hex.EncodeToString(sum[:]): true}

	rep := run(t, opts)
	if len(rep.Findings) != 0 {
		t.Fatalf("whitelisted file still reported: %+v", rep.Findings)
	}

	// Counter-check: without the whitelist the very same file is reported.
	// Otherwise the test would pass even if the scan had found nothing.
	plain := run(t, baseOptions(root))
	if len(plain.Findings) == 0 {
		t.Fatal("without the whitelist nothing was found either - the test proves nothing")
	}
}

func TestExcludeSkipsAPath(t *testing.T) {
	root := tree(t, map[string]string{
		"web/cache/evil.php": "<?php @eval($_POST['cmd']);\n",
	})

	opts := baseOptions(root)
	opts.Excludes = []string{"**/cache/**"}
	if rep := run(t, opts); len(rep.Findings) != 0 {
		t.Fatalf("excluded path was scanned: %+v", rep.Findings)
	}

	if rep := run(t, baseOptions(root)); len(rep.Findings) == 0 {
		t.Fatal("without the exclude nothing was found - the test proves nothing")
	}
}

func TestMaxAgeSkipsOldFiles(t *testing.T) {
	root := tree(t, map[string]string{"web/old.php": "<?php @eval($_POST['cmd']);\n"})
	old := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, "web", "old.php"), old, old); err != nil {
		t.Fatal(err)
	}

	opts := baseOptions(root)
	opts.MaxAge = 2 * 24 * time.Hour
	if rep := run(t, opts); len(rep.Findings) != 0 {
		t.Fatalf("a file older than the limit was scanned: %+v", rep.Findings)
	}

	opts.MaxAge = 30 * 24 * time.Hour
	if rep := run(t, opts); len(rep.Findings) == 0 {
		t.Fatal("within the limit the file should have been scanned")
	}
}

func TestCacheSkipsUnchangedFilesButNotAfterARuleChange(t *testing.T) {
	root := tree(t, map[string]string{
		"web/a.php": "<?php echo 1;\n",
		"web/b.php": "<?php echo 2;\n",
	})
	cache := filepath.Join(t.TempDir(), "clean.json")

	opts := baseOptions(root)
	opts.CacheFile = cache
	first := run(t, opts)
	if first.Stats.FilesScanned != 2 {
		t.Fatalf("first run scanned %d files, want 2", first.Stats.FilesScanned)
	}

	second := run(t, opts)
	if second.Stats.FilesScanned != 0 || second.Stats.FilesCached != 2 {
		t.Fatalf("second run scanned %d and reused %d, want 0 and 2",
			second.Stats.FilesScanned, second.Stats.FilesCached)
	}

	// A changed rule set must invalidate the cache. Without this a new rule
	// would never be applied to files that were clean under the old one - the
	// scan stays fast and goes blind.
	opts.IgnoreRules = []string{"php.eval.request"}
	third := run(t, opts)
	if third.Stats.FilesScanned != 2 {
		t.Fatalf("after a rule change %d files were scanned, want 2", third.Stats.FilesScanned)
	}
}

func TestCacheDoesNotHideAChangedFile(t *testing.T) {
	root := tree(t, map[string]string{"web/a.php": "<?php echo 1;\n"})
	cache := filepath.Join(t.TempDir(), "clean.json")
	opts := baseOptions(root)
	opts.CacheFile = cache
	run(t, opts)

	// The file becomes malicious after it was cached as clean.
	target := filepath.Join(root, "web", "a.php")
	if err := os.WriteFile(target, []byte("<?php @eval($_POST['cmd']);\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Size and mtime both change here; force a distinct mtime so the test
	// does not depend on the file system's timestamp resolution.
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatal(err)
	}

	rep := run(t, opts)
	if len(rep.Findings) == 0 {
		t.Fatal("a file that changed after being cached was not looked at again")
	}
}

func TestFindingsCarryTheFileIdentity(t *testing.T) {
	root := tree(t, map[string]string{"web/shell.php": "<?php @eval($_POST['cmd']);\n"})
	rep := run(t, baseOptions(root))
	if len(rep.Findings) == 0 {
		t.Fatal("nothing found")
	}
	f := rep.Findings[0]
	if len(f.SHA256) != 64 {
		t.Errorf("SHA256 = %q, want 64 hex characters", f.SHA256)
	}
	if f.Size == 0 {
		t.Error("Size is missing")
	}
	if f.MTime == "" {
		t.Error("MTime is missing")
	}
	if f.Line == 0 {
		t.Error("Line is missing")
	}
}

func TestNoMalwareScanSkipsTheFileStage(t *testing.T) {
	root := tree(t, map[string]string{"web/shell.php": "<?php @eval($_POST['cmd']);\n"})
	opts := baseOptions(root)
	opts.NoMalwareScan = true
	rep := run(t, opts)
	if len(rep.Findings) != 0 {
		t.Fatalf("findings despite --no-malware-scan: %+v", rep.Findings)
	}
}

func TestSymlinkIsNotFollowed(t *testing.T) {
	outside := tree(t, map[string]string{"secret/shell.php": "<?php @eval($_POST['cmd']);\n"})
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(outside, "secret"), link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	rep := run(t, baseOptions(root))
	if len(rep.Findings) != 0 {
		t.Fatalf("the scan followed a symlink out of the tree: %+v", rep.Findings)
	}
}

func TestWhitelistFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tool.php")
	if err := os.WriteFile(target, []byte("<?php echo 1;\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(dir, "list")

	sum, err := AppendWhitelist(list, target)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadWhitelist(list)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded[sum] {
		t.Fatalf("the appended sum %s is not in the loaded list %v", sum, SortedWhitelist(loaded))
	}

	// Appending twice must not duplicate the entry.
	if _, err := AppendWhitelist(list, target); err != nil {
		t.Fatal(err)
	}
	again, _ := LoadWhitelist(list)
	if len(again) != 1 {
		t.Fatalf("list holds %d entries after a repeat, want 1", len(again))
	}
}

func TestMissingWhitelistFileIsEmptyNotAnError(t *testing.T) {
	got, err := LoadWhitelist(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("a missing whitelist returned an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a missing whitelist returned %d entries", len(got))
	}
}
