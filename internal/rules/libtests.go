package rules

import (
	"fmt"
	"strings"

	"github.com/brightcolor/malwatch/internal/report"
)

// The tests of libraries, as the scanner knows them without --test-dirs,
// --library-dirs and --test-rules: the names of test folders, of the folders
// libraries are installed into, and the rules that do not count below a test
// folder of a library. Tests start mock servers in the background, keep
// fixtures that contain eval and ship the programs they run; that is what
// they are for. The ISPConfig addon has the same lists as the defaults of its
// settings (malwatch_config_defaults()).
var (
	DefaultTestDirs    = []string{"test", "tests", "test-suite", "testsuite", "fixtures", "__tests__"}
	DefaultLibraryDirs = []string{"vendor", "vendors", "node_modules", "bower_components"}
	DefaultTestRules   = []string{"php.exec.background", "php.eval.variable", "binary.elf"}
)

// The limits of the lists: so many names, each so long, and so many rules.
// The addon has the same (malwatch_library_tests_limits()).
const (
	MaxLibraryTestNames      = 16
	MaxLibraryTestNameLength = 30
	MaxLibraryTestRules      = 16
)

// LibraryTests says which files are the tests of a library and which rules
// do not count in them. Names of folders match in any case.
type LibraryTests struct {
	TestDirs    []string
	LibraryDirs []string
	Rules       []string
}

// DefaultLibraryTests returns the default lists.
func DefaultLibraryTests() LibraryTests {
	return LibraryTests{
		TestDirs:    append([]string(nil), DefaultTestDirs...),
		LibraryDirs: append([]string(nil), DefaultLibraryDirs...),
		Rules:       append([]string(nil), DefaultTestRules...),
	}
}

// Check says in German why the lists cannot be used, or returns nil. Only
// rules up to medium that never move a file on their own may fall silent;
// an empty rule list silences nothing.
func (l LibraryTests) Check() error {
	if err := checkFolderNames("Testordner", "test", l.TestDirs); err != nil {
		return err
	}
	if err := checkFolderNames("Bibliotheksordner", "vendor", l.LibraryDirs); err != nil {
		return err
	}
	if len(l.Rules) > MaxLibraryTestRules {
		return fmt.Errorf("%d Regeln für Testordner angegeben, erlaubt sind höchstens %d", len(l.Rules), MaxLibraryTestRules)
	}
	for _, id := range l.Rules {
		r := ByID(id)
		if r == nil {
			return fmt.Errorf("die Regel %q gibt es nicht; welche es gibt, zeigt „malwatch rules“", id)
		}
		if r.AutoSafe || r.Severity.AtLeast(report.SeverityHigh) {
			return fmt.Errorf("die Regel %q meldet „%s“ und bleibt auch in Testordnern an; erlaubt sind Regeln bis zur Stufe „mittel“",
				id, r.Severity.Label())
		}
	}
	return nil
}

func checkFolderNames(what, example string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("keine %s angegeben, mindestens ein Name ist nötig, etwa %s", what, example)
	}
	if len(names) > MaxLibraryTestNames {
		return fmt.Errorf("%d %s angegeben, erlaubt sind höchstens %d", len(names), what, MaxLibraryTestNames)
	}
	for _, n := range names {
		if len(n) > MaxLibraryTestNameLength || !uploadDirName.MatchString(n) {
			return fmt.Errorf("der %s %q geht nicht: erlaubt sind bis zu %d Zeichen aus Buchstaben, Ziffern, Punkt, "+
				"Unterstrich und Bindestrich, ohne Punkt am Anfang", what, n, MaxLibraryTestNameLength)
		}
	}
	return nil
}

// Silences reports whether the rule does not count in the tests of a library.
func (l LibraryTests) Silences(rule string) bool {
	for _, id := range l.Rules {
		if id == rule {
			return true
		}
	}
	return false
}

// InTests reports whether rel, a path below the scanned root with slashes,
// lies in a test folder of a library: below a library folder, at least one
// folder deeper - the library itself - and there below a test folder.
func (l LibraryTests) InTests(rel string) bool {
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	lib := l.library(segs)
	if lib < 0 {
		return false
	}
	for _, s := range segs[lib+2 : len(segs)-1] {
		if nameIn(s, l.TestDirs) {
			return true
		}
	}
	return false
}

// Declared reports whether the library a file lies in names it as a file of
// its tests in a .gitignore: an entry whose folders include a test folder and
// whose last part is the name of the file, letter for letter. SendGrid's SDK
// lists test/prism_linux_amd64, the mock server its tests download, and a
// copy of it may lie anywhere in the library. read returns the .gitignore of
// a folder below the scanned root, nil for none; the folders from the file up
// to the library are asked.
func (l LibraryTests) Declared(rel string, read func(dir string) []byte) bool {
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	lib := l.library(segs)
	if lib < 0 {
		return false
	}
	name := segs[len(segs)-1]
	for d := len(segs) - 1; d >= lib+2; d-- {
		if l.namesTestFile(read("/"+strings.Join(segs[:d], "/")), name) {
			return true
		}
	}
	return false
}

// namesTestFile reports whether a .gitignore lists name as a file below a
// test folder.
func (l LibraryTests) namesTestFile(gitignore []byte, name string) bool {
	for _, line := range strings.Split(string(gitignore), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		parts := strings.Split(strings.Trim(line, "/"), "/")
		if len(parts) < 2 || parts[len(parts)-1] != name {
			continue
		}
		for _, p := range parts[:len(parts)-1] {
			if nameIn(p, l.TestDirs) {
				return true
			}
		}
	}
	return false
}

// library returns the index of the first library folder among segs that has
// the file at least one folder below it, or -1.
func (l LibraryTests) library(segs []string) int {
	for i := 0; i+2 < len(segs); i++ {
		if nameIn(segs[i], l.LibraryDirs) {
			return i
		}
	}
	return -1
}

func nameIn(name string, list []string) bool {
	for _, n := range list {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// SetLibraryTests replaces DefaultLibraryTests. Lists Check refuses leave the
// engine as it was.
func (e *Engine) SetLibraryTests(l LibraryTests) error {
	if err := l.Check(); err != nil {
		return err
	}
	e.libTests = LibraryTests{
		TestDirs:    append([]string(nil), l.TestDirs...),
		LibraryDirs: append([]string(nil), l.LibraryDirs...),
		Rules:       append([]string(nil), l.Rules...),
	}
	return nil
}

// DropLibraryTests takes the findings of the rules that do not count in the
// tests of a library out of out, for a file that is one of them: in a test
// folder of a library, or named as a test file by the library (Declared).
// Below an upload folder nothing counts as a library. rel is the place of the
// file below the scanned root, read as in Declared.
func (e *Engine) DropLibraryTests(rel string, out []report.Finding, read func(dir string) []byte) []report.Finding {
	silenced := false
	for _, f := range out {
		if e.libTests.Silences(f.Rule) {
			silenced = true
			break
		}
	}
	if !silenced || e.uploads.MatchString(rel) || !(e.libTests.InTests(rel) || e.libTests.Declared(rel, read)) {
		return out
	}
	kept := out[:0]
	for _, f := range out {
		if !e.libTests.Silences(f.Rule) {
			kept = append(kept, f)
		}
	}
	return kept
}
