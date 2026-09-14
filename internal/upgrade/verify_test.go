package upgrade

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/knownfiles"
)

func md5Of(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fakeChecksums answers from maps keyed "6.4.5" and "akismet@5.3.3". A plugin
// without a list is ErrNotPublished, a core without a list a server error, and
// so is a plugin named in failing.
type fakeChecksums struct {
	core    map[string]map[string]string
	plugins map[string]map[string]string
	failing map[string]bool
}

func (f fakeChecksums) WordPressCore(version, locale string) (map[string]string, error) {
	if sums, ok := f.core[version]; ok {
		return sums, nil
	}
	return nil, fmt.Errorf("HTTP 500")
}

func (f fakeChecksums) WordPressPlugin(slug, version string) (map[string]string, error) {
	if f.failing[slug+"@"+version] {
		return nil, fmt.Errorf("HTTP 500")
	}
	if sums, ok := f.plugins[slug+"@"+version]; ok {
		return sums, nil
	}
	return nil, fmt.Errorf("HTTP 404: %w", knownfiles.ErrNotPublished)
}

func TestVerifyTreeChecksEveryListedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "akismet.php"), "<?php // 5.3.3")
	writeFile(t, filepath.Join(dir, "readme.txt"), "=== Akismet ===")

	good := map[string]string{
		"akismet.php": md5Of("<?php // 5.3.3"),
		"readme.txt":  md5Of("=== Akismet ==="),
	}
	if err := VerifyTree(dir, good); err != nil {
		t.Fatalf("a matching tree failed: %v", err)
	}
	cases := map[string]map[string]string{
		"changed file": {"akismet.php": md5Of("<?php // anders")},
		"missing file": {"class.akismet.php": md5Of("x")},
		"path with ..": {"../etc/passwd": md5Of("x")},
	}
	for name, sums := range cases {
		if err := VerifyTree(dir, sums); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestVerifyStagedTellsAMissingListFromABrokenOne(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "akismet.php"), "<?php // 5.3.3")
	cs := fakeChecksums{
		core:    map[string]map[string]string{},
		plugins: map[string]map[string]string{"akismet@5.3.3": {"akismet.php": md5Of("<?php // 5.3.3")}},
	}

	if unverified, err := verifyStaged(cs, PlanElement{Kind: "plugin", Slug: "akismet", Version: "5.3.3"}, "", dir); err != nil || unverified {
		t.Errorf("listed plugin: unverified=%v err=%v", unverified, err)
	}
	if unverified, err := verifyStaged(cs, PlanElement{Kind: "plugin", Slug: "bezahlt", Version: "1.0"}, "", dir); err != nil || !unverified {
		t.Errorf("plugin without a list: unverified=%v err=%v", unverified, err)
	}
	if unverified, err := verifyStaged(cs, PlanElement{Kind: "theme", Slug: "vier", Version: "1.0"}, "", dir); err != nil || !unverified {
		t.Errorf("theme: unverified=%v err=%v", unverified, err)
	}
	if _, err := verifyStaged(cs, PlanElement{Kind: "core", Version: "6.4.5"}, "", dir); err == nil || !strings.Contains(err.Error(), "6.4.5") {
		t.Errorf("a core without a list has to fail: %v", err)
	}
}

func TestVerifyTreeAcceptsAnyListedSum(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "readme.txt"), "readme build 2")

	listed := md5Of("readme build 1") + "," + md5Of("readme build 2")
	if err := VerifyTree(dir, map[string]string{"readme.txt": listed}); err != nil {
		t.Errorf("a file matching the second listed sum failed: %v", err)
	}
	other := md5Of("readme build 1") + "," + md5Of("readme build 3")
	if err := VerifyTree(dir, map[string]string{"readme.txt": other}); err == nil {
		t.Error("a file matching no listed sum verified")
	}
}
