// Package cms detects installed web applications and compares their version
// against the current release published by the vendor.
package cms

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Install is one detected application.
type Install struct {
	Path    string // directory the application lives in
	Product string // wordpress, joomla, drupal, ...
	Kind    string // core, plugin, theme
	Slug    string // for plugins and themes
	Version string
	// Locale is the localised build a WordPress install came from, empty for
	// the international one. A German build ships different files, and
	// comparing it against the en_US checksums reports them as modified.
	Locale string
}

// marker describes how to recognise a product: a file that must exist below
// the candidate directory, and a pattern that pulls the version out of it.
type marker struct {
	product string
	file    string
	pattern *regexp.Regexp
	// join builds the version from the capture groups. Nil means group 1.
	join func([]string) string
}

var markers = []marker{
	{
		product: "wordpress",
		file:    "wp-includes/version.php",
		pattern: regexp.MustCompile(`(?m)^\s*\$wp_version\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "joomla",
		file:    "libraries/src/Version.php",
		pattern: regexp.MustCompile(`(?s)MAJOR_VERSION\s*=\s*(\d+).*?MINOR_VERSION\s*=\s*(\d+).*?PATCH_VERSION\s*=\s*(\d+)`),
		join:    func(m []string) string { return m[1] + "." + m[2] + "." + m[3] },
	},
	{
		product: "joomla",
		file:    "libraries/cms/version/version.php",
		pattern: regexp.MustCompile(`(?s)RELEASE\s*=\s*['"]([\d.]+)['"].*?DEV_LEVEL\s*=\s*['"]([\w.]+)['"]`),
		join:    func(m []string) string { return m[1] + "." + m[2] },
	},
	{
		product: "drupal",
		file:    "core/lib/Drupal.php",
		pattern: regexp.MustCompile(`(?m)const\s+VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "drupal",
		file:    "includes/bootstrap.inc",
		pattern: regexp.MustCompile(`(?m)define\s*\(\s*['"]VERSION['"]\s*,\s*['"]([^'"]+)['"]`),
	},
	{
		product: "typo3",
		file:    "typo3/sysext/core/Classes/Information/Typo3Version.php",
		pattern: regexp.MustCompile(`(?m)const\s+VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "nextcloud",
		file:    "version.php",
		pattern: regexp.MustCompile(`(?m)\$OC_VersionString\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "phpmyadmin",
		file:    "libraries/classes/Version.php",
		pattern: regexp.MustCompile(`(?m)VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "phpmyadmin",
		file:    "src/Version.php",
		pattern: regexp.MustCompile(`(?m)VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "phpmyadmin",
		file:    "libraries/Config.class.php",
		pattern: regexp.MustCompile(`(?m)PMA_VERSION['"]\s*,\s*['"]([^'"]+)['"]`),
	},
	{
		product: "matomo",
		file:    "core/Version.php",
		pattern: regexp.MustCompile(`(?m)const\s+VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "mediawiki",
		file:    "includes/Defines.php",
		pattern: regexp.MustCompile(`(?m)define\s*\(\s*['"]MW_VERSION['"]\s*,\s*['"]([^'"]+)['"]`),
	},
	{
		product: "mediawiki",
		file:    "includes/DefaultSettings.php",
		pattern: regexp.MustCompile(`(?m)\$wgVersion\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "shopware",
		file:    "engine/Shopware/Application.php",
		pattern: regexp.MustCompile(`(?m)VERSION\s*=\s*['"]([^'"]+)['"]`),
	},
	{
		product: "magento",
		file:    "app/Mage.php",
		pattern: regexp.MustCompile(`(?s)'major'\s*=>\s*'(\d+)'.*?'minor'\s*=>\s*'(\d+)'.*?'revision'\s*=>\s*'(\d+)'`),
		join:    func(m []string) string { return m[1] + "." + m[2] + "." + m[3] },
	},
}

// composerPackages maps a composer package name to a product name. Modern
// Contao, Shopware and Magento carry no version constant of their own; the
// lock file is the only honest source.
var composerPackages = map[string]string{
	"contao/core-bundle":                 "contao",
	"shopware/core":                      "shopware",
	"magento/product-community-edition":  "magento",
	"typo3/cms-core":                     "typo3",
	"drupal/core":                        "drupal",
	"joomla/cms":                         "joomla",
	"phpmyadmin/phpmyadmin":              "phpmyadmin",
	"matomo/matomo":                      "matomo",
	"shopware/platform":                  "shopware",
	"magento/product-enterprise-edition": "magento",
}

// maxDepth limits how far below a scanned path a second installation is
// looked for. Two levels find the common cases - a shop in /shop, an old
// copy in /old - without walking every customer's node_modules.
const maxDepth = 3

// Detect finds installations at or below root.
func Detect(root string, excluded func(string) bool) []Install {
	var out []Install
	seen := map[string]bool{}

	visit := func(dir string) {
		if seen[dir] {
			return
		}
		if inst, ok := detectDir(dir); ok {
			seen[dir] = true
			out = append(out, inst)
			if inst.Product == "wordpress" {
				out = append(out, wordpressExtras(dir)...)
			}
		}
	}

	visit(root)
	walkShallow(root, maxDepth, excluded, visit)
	return out
}

// detectDir tests one directory against every marker.
func detectDir(dir string) (Install, bool) {
	for _, m := range markers {
		content, err := readLimited(filepath.Join(dir, m.file), 512*1024)
		if err != nil {
			continue
		}
		groups := m.pattern.FindStringSubmatch(string(content))
		if groups == nil {
			continue
		}
		v := ""
		if m.join != nil {
			v = m.join(groups)
		} else {
			v = groups[1]
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		inst := Install{Path: dir, Product: m.product, Kind: "core", Version: v}
		if m.product == "wordpress" {
			inst.Locale = wordpressLocale(content)
		}
		return inst, true
	}
	if inst, ok := detectComposer(dir); ok {
		return inst, true
	}
	return Install{}, false
}

// composerLock is the subset of composer.lock that matters here.
type composerLock struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
}

func detectComposer(dir string) (Install, bool) {
	content, err := readLimited(filepath.Join(dir, "composer.lock"), 8*1024*1024)
	if err != nil {
		return Install{}, false
	}
	var lock composerLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return Install{}, false
	}
	for _, p := range lock.Packages {
		product, ok := composerPackages[p.Name]
		if !ok {
			continue
		}
		v := strings.TrimPrefix(strings.TrimSpace(p.Version), "v")
		if v == "" || strings.HasPrefix(v, "dev-") {
			continue
		}
		return Install{Path: dir, Product: product, Kind: "core", Version: v}, true
	}
	return Install{}, false
}

// walkShallow visits directories up to depth levels below root.
func walkShallow(root string, depth int, excluded func(string) bool, fn func(string)) {
	if depth <= 0 {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := e.Name()
		if skipDir[name] || strings.HasPrefix(name, ".") {
			continue
		}
		sub := filepath.Join(root, name)
		if excluded != nil && excluded(sub) {
			continue
		}
		fn(sub)
		walkShallow(sub, depth-1, excluded, fn)
	}
}

// skipDir lists directories that never hold a second installation but do
// hold tens of thousands of files.
var skipDir = map[string]bool{
	"node_modules": true, "vendor": true, "cache": true, "tmp": true,
	"temp": true, "logs": true, "log": true, "wp-includes": true,
	"wp-admin": true, "uploads": true, "storage": true, "var": true,
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fs.ErrInvalid
	}
	buf := make([]byte, info.Size())
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
