package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

// The pieces keep the virus scanner of the workstation off the samples.
var (
	evTest   = "ev" + "al"
	postTest = "$_PO" + "ST"
)

// testFiles are the tests of libraries the scheduled scans of 2026-09-28 and
// 29 reported: a mail library that starts a fake POP server with nohup, a
// fixture of PHP_CodeSniffer that exists to contain eval, and the mock server
// of the SendGrid SDK, which the SDK's .gitignore names as a test file.
var testFiles = map[string]string{
	"web/apps/common/vendors/PHPMailer-5x/test/phpmailerTest.php": "<?php\nclass PHPMailerTest extends PHPUnit_Framework_TestCase {\n" +
		"  public function testPopBeforeSmtpGood() {\n" +
		"    $pid = shell_exec('nohup ./runfakepopserver.sh >/dev/null 2>/dev/null & printf \"%u\" $!');\n  }\n}\n",
	"web/wp-content/plugins/s/vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/PHP/EvalUnitTest.inc": "<?php\n" +
		evTest + "('$var = $_GET[\"var\"];');\n" + evTest + "($code);\n",
	"web/apps/common/vendors/Composer/vendor/sendgrid/sendgrid/.gitignore": "test/coverage/*\ndist/\n" +
		"test/prism_linux_amd64\ntest/prism/*\n!test/prism/bin/prism.sh\n",
	"web/apps/common/vendors/Composer/vendor/sendgrid/sendgrid/prism_linux_amd64": elfHead + strings.Repeat("\x00", 256),
}

func TestHintsInTheTestsOfALibraryAreDropped(t *testing.T) {
	root := tree(t, testFiles)
	rep := run(t, baseOptions(root))
	for name := range testFiles {
		if got := findingsFor(rep, "/"+filepath.Base(name)); len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// Past the size limit only the start of the program is read; the
	// .gitignore stays below it.
	opts := baseOptions(root)
	opts.MaxSize = 128
	if got := findingsFor(run(t, opts), "/prism_linux_amd64"); len(got) != 0 {
		t.Errorf("Programm über der Größengrenze: %+v", got)
	}
}

// What a test folder of a library does not excuse: a webshell there, a hint
// in the library's own code, a test folder of the website, a library below
// an upload folder, and a program its library does not name as a test file.
func TestTheTestsOfALibraryKeepEverythingElse(t *testing.T) {
	elf := elfHead + strings.Repeat("\x00", 256)
	bg := "<?php $pid = shell_exec('nohup ./server.sh > /dev/null 2>&1 &');\n"
	root := tree(t, map[string]string{
		"web/vendor/acme/lib/tests/shell.php":            "<?php @" + evTest + "(" + postTest + "['c']);\n",
		"web/vendor/acme/lib/src/Runner.php":             bg,
		"web/tests/run.php":                              bg,
		"web/wp-content/uploads/vendor/x/tests/y.inc":    "<?php " + evTest + "($x);\n",
		"web/vendor/acme/tool/.gitignore":                "test/prism_linux_amd64\nbin/helper\ntest/*\n",
		"web/vendor/acme/tool/miner":                     elf,
		"web/vendor/acme/tool/helper":                    elf,
		"web/vendor/acme/tool/src/prism_linux_amd64.php": bg,
		"web/vendor/other/pkg/prism_linux_amd64":         elf,
	})
	rep := run(t, baseOptions(root))
	for suffix, rule := range map[string]string{
		"/lib/tests/shell.php":            "php.eval.request",
		"/lib/src/Runner.php":             "php.exec.background",
		"/web/tests/run.php":              "php.exec.background",
		"/x/tests/y.inc":                  "php.eval.variable",
		"/tool/miner":                     "binary.elf",
		"/tool/helper":                    "binary.elf",
		"/tool/src/prism_linux_amd64.php": "php.exec.background",
		"/other/pkg/prism_linux_amd64":    "binary.elf",
	} {
		found := false
		for _, f := range findingsFor(rep, suffix) {
			found = found || f.Rule == rule
		}
		if !found {
			t.Errorf("%s: %s nicht mehr gemeldet", suffix, rule)
		}
	}
}

// The three lists are settings: other names and other rules work alike, and
// an empty rule list silences nothing.
func TestTheTestsOfALibraryFollowTheSettings(t *testing.T) {
	bg := "<?php $pid = shell_exec('nohup ./server.sh > /dev/null 2>&1 &');\n"
	root := tree(t, map[string]string{
		"web/lib/acme/spec/run.php":    bg,
		"web/vendor/acme/test/run.php": bg,
	})
	opts := baseOptions(root)
	opts.TestDirs = []string{"spec"}
	opts.LibraryDirs = []string{"lib"}
	opts.TestRules, opts.TestRulesSet = []string{"php.exec.background"}, true
	rep := run(t, opts)
	if got := findingsFor(rep, "/spec/run.php"); len(got) != 0 {
		t.Errorf("eigene Ordnernamen: %+v", got)
	}
	if got := findingsFor(rep, "/vendor/acme/test/run.php"); len(got) != 1 {
		t.Errorf("vendor ist hier kein Bibliotheksordner, der Fund fehlt: %+v", got)
	}

	opts = baseOptions(tree(t, testFiles))
	opts.TestRules, opts.TestRulesSet = nil, true
	if got := findingsFor(run(t, opts), "/phpmailerTest.php"); len(got) != 1 {
		t.Errorf("leere Regelliste: %+v", got)
	}
}

func TestTheTestsOfALibraryRefuseStrongRules(t *testing.T) {
	opts := baseOptions(t.TempDir())
	opts.TestRules, opts.TestRulesSet = []string{"php.eval.request"}, true
	if _, err := Run(opts); err == nil || !strings.Contains(err.Error(), "php.eval.request") {
		t.Errorf("kritische Regel angenommen: %v", err)
	}
}

// A file the cache knows as clean was clean under the settings of its run.
// Other settings look at it again.
func TestOtherLibraryTestSettingsLookAgain(t *testing.T) {
	root := tree(t, testFiles)
	cache := filepath.Join(t.TempDir(), "cache.json")
	opts := baseOptions(root)
	opts.CacheFile = cache
	if got := findingsFor(run(t, opts), "/phpmailerTest.php"); len(got) != 0 {
		t.Fatalf("erster Lauf: %+v", got)
	}
	opts = baseOptions(root)
	opts.CacheFile = cache
	opts.TestRules, opts.TestRulesSet = nil, true
	if got := findingsFor(run(t, opts), "/phpmailerTest.php"); len(got) != 1 {
		t.Errorf("zweiter Lauf mit anderer Regelliste las den Cache: %+v", got)
	}
}
