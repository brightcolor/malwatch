package upgrade

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/cms"
)

// CoreFacts is what wp-includes/version.php says about a core tree.
type CoreFacts struct {
	Version     string // $wp_version
	DBVersion   string // $wp_db_version
	RequiredPHP string // $required_php_version
	Locale      string // $wp_local_package; empty for the international build
}

// Requirements are what a release asks of the site. An empty field asks
// nothing.
type Requirements struct {
	WordPress string // "Requires at least"
	PHP       string // "Requires PHP"
}

var (
	wpVersionRe   = regexp.MustCompile(`(?m)^\s*\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	dbVersionRe   = regexp.MustCompile(`(?m)^\s*\$wp_db_version\s*=\s*(\d+)`)
	requiredPHPRe = regexp.MustCompile(`(?m)^\s*\$required_php_version\s*=\s*['"]([^'"]+)['"]`)
	localeRe      = regexp.MustCompile(`(?m)^\s*\$wp_local_package\s*=\s*['"]([A-Za-z_]{2,10})['"]`)

	requiresWPRe  = regexp.MustCompile(`(?im)^[ \t/*#@]*Requires at least\s*:\s*([0-9][0-9.]*)`)
	requiresPHPRe = regexp.MustCompile(`(?im)^[ \t/*#@]*Requires PHP\s*:\s*([0-9][0-9.]*)`)
	pluginNameRe  = regexp.MustCompile(`(?im)^[ \t/*#@]*Plugin Name\s*:\s*\S`)
	themeNameRe   = regexp.MustCompile(`(?im)^[ \t/*#@]*Theme Name\s*:\s*\S`)

	multisiteRe = regexp.MustCompile(`(?i)define\s*\(\s*['"]MULTISITE['"]\s*,\s*(true|1|'1'|"1")\s*\)`)
	upgradingRe = regexp.MustCompile(`\$upgrading\s*=\s*(\d+)`)
)

// headBytes is how much of a header file WordPress reads, and so do we.
const headBytes = 8192

// ReadCore reads wp-includes/version.php below dir.
func ReadCore(dir string) (CoreFacts, error) {
	path := filepath.Join(dir, "wp-includes", "version.php")
	raw, err := readHead(path, 512*1024)
	if err != nil {
		return CoreFacts{}, err
	}
	facts := CoreFacts{
		Version:     group(wpVersionRe, raw),
		DBVersion:   group(dbVersionRe, raw),
		RequiredPHP: group(requiredPHPRe, raw),
		Locale:      group(localeRe, raw),
	}
	if facts.Version == "" {
		return facts, fmt.Errorf("%s nennt keine WordPress-Version", path)
	}
	return facts, nil
}

// PluginRequirements reads the requirements of the plugin in dir from the
// header of its main file: the PHP file directly in dir that carries "Plugin
// Name", the one named after the directory first. A value the header leaves
// out comes from readme.txt, the order WordPress itself reads them in.
func PluginRequirements(dir string) (Requirements, error) {
	head, err := pluginHeader(dir)
	if err != nil {
		return Requirements{}, err
	}
	req := Requirements{WordPress: group(requiresWPRe, head), PHP: group(requiresPHPRe, head)}
	if req.WordPress == "" || req.PHP == "" {
		if readme, err := readHead(filepath.Join(dir, "readme.txt"), 16384); err == nil {
			if req.WordPress == "" {
				req.WordPress = group(requiresWPRe, readme)
			}
			if req.PHP == "" {
				req.PHP = group(requiresPHPRe, readme)
			}
		}
	}
	return req, nil
}

func pluginHeader(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	preferred := filepath.Base(dir) + ".php"
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
			names = append(names, e.Name())
		}
	}
	sort.SliceStable(names, func(a, b int) bool {
		return names[a] == preferred && names[b] != preferred
	})
	for _, name := range names {
		head, err := readHead(filepath.Join(dir, name), headBytes)
		if err == nil && pluginNameRe.Match(head) {
			return head, nil
		}
	}
	return nil, fmt.Errorf("in %s liegt keine Plugin-Hauptdatei", dir)
}

// ThemeRequirements reads the requirements of the theme in dir from style.css.
func ThemeRequirements(dir string) (Requirements, error) {
	path := filepath.Join(dir, "style.css")
	head, err := readHead(path, headBytes)
	if err != nil {
		return Requirements{}, err
	}
	if !themeNameRe.Match(head) {
		return Requirements{}, fmt.Errorf("%s trägt keinen Theme-Kopf", path)
	}
	return Requirements{WordPress: group(requiresWPRe, head), PHP: group(requiresPHPRe, head)}, nil
}

// Check returns why the release named label cannot go into a site running
// wordpress and php, or "" when it can. An empty site version checks nothing.
func (r Requirements) Check(label, wordpress, php string) string {
	if r.PHP != "" && php != "" && cms.Compare(php, r.PHP) < 0 {
		return fmt.Sprintf("%s braucht PHP %s, die Website läuft mit %s", label, r.PHP, php)
	}
	if r.WordPress != "" && wordpress != "" && cms.Compare(wordpress, r.WordPress) < 0 {
		return fmt.Sprintf("%s braucht WordPress %s, installiert ist %s", label, r.WordPress, wordpress)
	}
	return ""
}

// Multisite reports whether wp-config.php switches a network on. WordPress
// also takes wp-config.php from the directory above, when that directory
// holds no WordPress of its own.
func Multisite(root string) bool {
	candidates := []string{filepath.Join(root, "wp-config.php")}
	parent := filepath.Dir(root)
	if _, err := os.Stat(filepath.Join(parent, "wp-settings.php")); os.IsNotExist(err) {
		candidates = append(candidates, filepath.Join(parent, "wp-config.php"))
	}
	for _, path := range candidates {
		if raw, err := readHead(path, 512*1024); err == nil {
			return multisiteRe.Match(raw)
		}
	}
	return false
}

const maintenanceFile = ".maintenance"

// maintenanceWindow is how long WordPress honours a .maintenance file.
const maintenanceWindow = 10 * time.Minute

// MaintenanceActive reports whether root carries a .maintenance file that
// WordPress still honours at now.
func MaintenanceActive(root string, now time.Time) bool {
	raw, err := readHead(filepath.Join(root, maintenanceFile), 64*1024)
	if err != nil {
		return false
	}
	m := upgradingRe.FindSubmatch(raw)
	if m == nil {
		return false
	}
	sec, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return false
	}
	return now.Sub(time.Unix(sec, 0)) < maintenanceWindow
}

// EnterMaintenance writes the file the updater of WordPress writes. A link in
// its place is refused: this file is written as root.
func EnterMaintenance(root string, now time.Time) error {
	path := filepath.Join(root, maintenanceFile)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s ist eine Verknüpfung und wird nicht beschrieben", path)
	}
	body := fmt.Sprintf("<?php $upgrading = %d; ?>", now.Unix())
	return os.WriteFile(path, []byte(body), 0o644)
}

// LeaveMaintenance removes the file. A file that is already gone is fine.
func LeaveMaintenance(root string) error {
	err := os.Remove(filepath.Join(root, maintenanceFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// readHead reads at most n bytes of a regular file.
func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s ist keine Datei", path)
	}
	return io.ReadAll(io.LimitReader(f, n))
}

func group(re *regexp.Regexp, raw []byte) string {
	m := re.FindSubmatch(raw)
	if m == nil || len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
