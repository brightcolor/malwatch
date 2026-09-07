package repair

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brightcolor/malwatch/internal/quarantine"
)

// coreOnlyRoot builds a web root that is nothing but a WordPress core: the
// two directories repairCore quarantines as a whole, plus a loose root file.
// Used where a test needs wp-admin to actually exist on disk, unlike
// fakeWordPress (plan_test.go), which never creates one.
func coreOnlyRoot(t *testing.T, indexBody string) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n")
	mk("wp-admin/admin.php", "<?php // admin")
	mk("index.php", indexBody)
	mk("wp-config.php", "<?php // secrets")
	return root
}

// TestRepairCoreQuarantinesAChangedLooseRootFileInBothModes guards K2. The
// loose files beside wp-admin and wp-includes - index.php first among them -
// used to be overwritten in both modes with no copy anywhere, because only
// the two core directories ever got a quarantine entry of their own. A root
// index.php customised the way WordPress's own documentation describes, for
// a site served from a subdirectory, was gone for good the moment a repair
// ran. Both modes write the loose files back "by name" the same way, so both
// must file away a copy first - overlay's usual promise (leave what is not
// the vendor's alone) does not cover these, since they are the vendor's own
// files, just with local edits.
func TestRepairCoreQuarantinesAChangedLooseRootFileInBothModes(t *testing.T) {
	const customised = "<?php // KUNDENANPASSUNG: WordPress liegt in /cms\n"
	const original = "<?php // ORIGINAL WORDPRESS\n"

	for _, mode := range []string{"replace", "overlay"} {
		t.Run(mode, func(t *testing.T) {
			// No wp-admin/wp-includes here on purpose: their presence would
			// pull in the W4 staged-tree check this test does not exercise.
			// Isolating the loose-file path is the point.
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.php"), []byte(customised), 0o644); err != nil {
				t.Fatal(err)
			}
			staged := t.TempDir()
			if err := os.WriteFile(filepath.Join(staged, "index.php"), []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			qdir := t.TempDir()
			opts := Options{Root: root, QuarantineDir: qdir}

			if _, _, err := repairCore(opts, mode, staged); err != nil {
				t.Fatalf("repairCore failed: %v", err)
			}

			raw, err := os.ReadFile(filepath.Join(root, "index.php"))
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != original {
				t.Fatalf("index.php on disk = %q, want the vendor's %q", raw, original)
			}

			entries, _, err := quarantine.List(qdir)
			if err != nil {
				t.Fatal(err)
			}
			var found *quarantine.Entry
			for i := range entries {
				if entries[i].RelPath == "index.php" {
					found = &entries[i]
				}
			}
			if found == nil {
				t.Fatalf("mode %s: no quarantine entry for index.php: %+v", mode, entries)
			}

			// Not just an id - the entry has to actually hold the customer's
			// content, or it is a name in a list pointing at nothing, which
			// is exactly what K2 originally left behind.
			if err := quarantine.Restore(qdir, found.ID, true); err != nil {
				t.Fatalf("mode %s: restoring the quarantined index.php failed: %v", mode, err)
			}
			got, err := os.ReadFile(filepath.Join(root, "index.php"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != customised {
				t.Errorf("mode %s: restored quarantine entry = %q, want the customer's %q", mode, got, customised)
			}
		})
	}
}

// TestRepairCoreSkipsALooseRootFileIdenticalToTheVendors guards the other
// side of the same fix: archiving every loose root file regardless of
// content would bury the one file anyone actually customised under a pile
// of entries that are just the vendor's own bytes coming back unchanged - a
// row nobody would ever need to read. Identical content must produce no
// quarantine entry at all.
func TestRepairCoreSkipsALooseRootFileIdenticalToTheVendors(t *testing.T) {
	const content = "<?php // wp-login, unveraendert\n"
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-login.php"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, "wp-login.php"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	qdir := t.TempDir()
	opts := Options{Root: root, QuarantineDir: qdir}

	_, ids, err := repairCore(opts, "replace", staged)
	if err != nil {
		t.Fatalf("repairCore failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("quarantine ids = %v, want none for a loose file identical to the vendor's", ids)
	}
	entries, _, err := quarantine.List(qdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("quarantine store holds %d entries, want 0 for an unchanged loose file: %+v", len(entries), entries)
	}
}

// TestRepairCoreAbortsWhenTheStagedTreeIsMissingWpAdmin guards W4:
// repairCore used to quarantine wp-admin - which removes it from the site -
// and then, finding no wp-admin in the staged tree to put it back with,
// silently move on; the run reported success with the administration area
// simply gone. coreDirs is walked wp-admin-first, so a staged tree missing
// it (a truncated download, a mirror out of sync, a vendor layout that
// changed) must fail before wp-admin - or anything else - is touched, not
// after it has already been filed away.
func TestRepairCoreAbortsWhenTheStagedTreeIsMissingWpAdmin(t *testing.T) {
	root := coreOnlyRoot(t, "<?php // eigene Version\n")
	before := treeOf(t, root)

	// A vendor archive that unpacked fine but never had wp-admin in it.
	staged := t.TempDir()
	if err := os.MkdirAll(filepath.Join(staged, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.6.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "index.php"), []byte("<?php // ORIGINAL\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := Options{Root: root, QuarantineDir: t.TempDir()}
	if _, _, err := repairCore(opts, "replace", staged); err == nil {
		t.Fatal("repairCore did not report an error for a staged tree missing wp-admin")
	}

	if _, err := os.Stat(filepath.Join(root, "wp-admin")); err != nil {
		t.Errorf("wp-admin is gone from the site although repairCore should have aborted before touching it: %v", err)
	}
	if got := treeOf(t, root); got != before {
		t.Error("the web root changed even though repairCore aborted for a missing wp-admin")
	}
}
