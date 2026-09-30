package rules

import (
	"strings"
	"testing"
)

func TestDefaultLibraryTestsHold(t *testing.T) {
	if err := DefaultLibraryTests().Check(); err != nil {
		t.Fatalf("Vorgabe abgelehnt: %v", err)
	}
	lt := DefaultLibraryTests()
	for _, id := range []string{"php.exec.background", "php.eval.variable", "binary.elf"} {
		if !lt.Silences(id) {
			t.Errorf("%s zählt in Testordnern von Bibliotheken nach der Vorgabe weiter", id)
		}
	}
	for _, id := range []string{"php.eval.request", "php.in_uploads", "binary.elf_in_uploads"} {
		if lt.Silences(id) {
			t.Errorf("%s schweigt in Testordnern von Bibliotheken", id)
		}
	}
}

// The files of 2026-09-28 and 29 lie in the tests of libraries; a test folder
// of the website itself, a library below a test folder and a library that is
// only called test are none.
func TestInTestsOfALibrary(t *testing.T) {
	lt := DefaultLibraryTests()
	for rel, want := range map[string]bool{
		"/apps/common/vendors/PHPMailer-5x/test/phpmailerTest.php":                                         true,
		"/apps/common/vendors/Composer/vendor/sendgrid/sendgrid/test/unit/BaseTestClass.php":               true,
		"/apps/common/vendors/SwiftMailer/test-suite/lib/yaymock/classes/Yay/MockGenerator.php":            true,
		"/wp-content/plugins/x/vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/PHP/A.inc.fixed": true,
		"/Vendor/Acme/Lib/Fixtures/a.php":                                                                  true,
		"/tests/shell.php":                                                                                 false,
		"/vendor/tests.php":                                                                                false,
		"/vendor/test/x.php":                                                                               false,
		"/test/vendor/acme/x.php":                                                                          false,
		"/vendor/acme/lib/src/Runner.php":                                                                  false,
		"/vendor/acme/lib/test":                                                                            false,
	} {
		if got := lt.InTests(rel); got != want {
			t.Errorf("%s: %v, erwartet %v", rel, got, want)
		}
	}
}

// The three lists are settings; other values than the default work alike.
func TestLibraryTestsTakeOtherValues(t *testing.T) {
	lt := LibraryTests{TestDirs: []string{"spec"}, LibraryDirs: []string{"lib"}, Rules: []string{"php.upload.unchecked"}}
	if err := lt.Check(); err != nil {
		t.Fatalf("abgelehnt: %v", err)
	}
	if !lt.InTests("/lib/acme/spec/a.php") || lt.InTests("/vendor/acme/test/a.php") {
		t.Error("eigene Ordnernamen greifen nicht")
	}
	if !lt.Silences("php.upload.unchecked") || lt.Silences("php.eval.variable") {
		t.Error("eigene Regelliste greift nicht")
	}
	if err := (LibraryTests{TestDirs: []string{"test"}, LibraryDirs: []string{"vendor"}}).Check(); err != nil {
		t.Errorf("leere Regelliste abgelehnt: %v", err)
	}
}

// Only hints may fall silent: a rule that reports high or critical, moves a
// file on its own or does not exist is refused with a reason.
func TestLibraryTestsRefuseWhatTheyCannotUse(t *testing.T) {
	base := DefaultLibraryTests()
	for _, c := range []struct {
		name string
		lt   LibraryTests
		want string
	}{
		{"kritische Regel", LibraryTests{TestDirs: base.TestDirs, LibraryDirs: base.LibraryDirs, Rules: []string{"php.eval.request"}}, "php.eval.request"},
		{"hohe Regel", LibraryTests{TestDirs: base.TestDirs, LibraryDirs: base.LibraryDirs, Rules: []string{"php.stealth.touch_mtime"}}, "php.stealth.touch_mtime"},
		{"unbekannte Regel", LibraryTests{TestDirs: base.TestDirs, LibraryDirs: base.LibraryDirs, Rules: []string{"php.nope"}}, "php.nope"},
		{"Ordner mit Schrägstrich", LibraryTests{TestDirs: []string{"a/b"}, LibraryDirs: base.LibraryDirs}, "a/b"},
		{"Ordner ..", LibraryTests{TestDirs: base.TestDirs, LibraryDirs: []string{".."}}, ".."},
		{"keine Testordner", LibraryTests{LibraryDirs: base.LibraryDirs}, "Testordner"},
		{"keine Bibliotheksordner", LibraryTests{TestDirs: base.TestDirs}, "Bibliotheksordner"},
		{"zu viele Testordner", LibraryTests{TestDirs: strings.Split(strings.Repeat("t,", MaxLibraryTestNames+1), ",")[:MaxLibraryTestNames+1], LibraryDirs: base.LibraryDirs}, "höchstens"},
		{"zu langer Name", LibraryTests{TestDirs: []string{strings.Repeat("x", MaxLibraryTestNameLength+1)}, LibraryDirs: base.LibraryDirs}, "Zeichen"},
	} {
		err := c.lt.Check()
		if err == nil {
			t.Errorf("%s: angenommen", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Meldung %q nennt %q nicht", c.name, err, c.want)
		}
	}
}
