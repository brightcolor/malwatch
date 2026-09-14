package upgrade

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brightcolor/malwatch/internal/knownfiles"
)

// Checksums is where the verification takes its lists from: a
// *knownfiles.Fetcher, or a fake in the tests.
type Checksums interface {
	WordPressCore(version, locale string) (map[string]string, error)
	WordPressPlugin(slug, version string) (map[string]string, error)
}

// VerifyTree holds a staged tree against a checksum list: every file the list
// names has to be there with that MD5. The list decides what it covers; the
// core list leaves out wp-content, for instance.
func VerifyTree(dir string, sums map[string]string) error {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		clean := path.Clean("/" + name)
		if strings.Contains(name, "..") || clean == "/" {
			return fmt.Errorf("die Prüfsummenliste nennt den Pfad %q", name)
		}
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(clean, "/"))))
		if err != nil {
			return fmt.Errorf("%s fehlt im geladenen Archiv", name)
		}
		sum := md5.Sum(raw)
		if !knownfiles.SumMatches(strings.ToLower(sums[name]), hex.EncodeToString(sum[:])) {
			return fmt.Errorf("%s weicht von der Prüfsumme ab", name)
		}
	}
	return nil
}

// verifyStaged verifies the staged tree of one element. unverified is true
// when no list covers it: a theme, or a plugin wordpress.org keeps no list
// for. Every other failure to get a list is an error: a release that cannot
// be verified for a reason nobody knows stays out.
func verifyStaged(cs Checksums, el PlanElement, locale, dir string) (unverified bool, err error) {
	switch el.Kind {
	case "core":
		sums, err := cs.WordPressCore(el.Version, locale)
		if err != nil {
			return false, fmt.Errorf("Prüfsummen für WordPress %s nicht ladbar: %w", el.Version, err)
		}
		return false, VerifyTree(dir, sums)
	case "plugin":
		sums, err := cs.WordPressPlugin(el.Slug, el.Version)
		if errors.Is(err, knownfiles.ErrNotPublished) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("Prüfsummen für %s %s nicht ladbar: %w", label(el), el.Version, err)
		}
		return false, VerifyTree(dir, sums)
	}
	return true, nil
}
