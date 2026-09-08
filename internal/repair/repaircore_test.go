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

// TestOverlayCoreRefusesToWriteThroughASymlinkedLooseRootFile is the same
// attack SwapCore already refuses, aimed at the other mode. The loop that
// writes the loose root files existed twice, and only the copy SwapCore
// calls got the check: in overlay mode an index.php pointing at
// wp-config.php still passed InsideRoot - the target is inside the root -
// and os.WriteFile followed it, so the vendor's index.php landed in
// wp-config.php as root. Overlay is the mode that leaves the old tree
// standing, so it is also the mode where a planted link is still there when
// the writing starts.
func TestOverlayCoreRefusesToWriteThroughASymlinkedLooseRootFile(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "wp-config.php")
	if err := os.WriteFile(configPath, []byte("<?php // secrets\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.php")
	symlinkOrSkip(t, configPath, indexPath)

	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, "index.php"),
		[]byte("<?php // ORIGINAL WORDPRESS\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := overlayCore(root, staged); err == nil {
		t.Fatal("overlayCore wrote through a symlinked loose core file instead of refusing")
	}

	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "<?php // secrets\n" {
		t.Errorf("overlayCore wrote through the link: wp-config.php now %q", got)
	}
}

// TestRepairCoreTouchesNothingWhenTheStagedTreeIsIncomplete guards the order
// of the two steps, not just their presence. The check for "does the staged
// core actually contain this directory" used to sit inside the loop, right
// before each directory was filed away: with wp-admin first and wp-includes
// missing from the download, wp-admin was already in quarantine and off the
// website by the time the run noticed and stopped. The website then had no
// administration area and the run reported an error - the copy existed, but
// the site was down either way. Checking every directory before touching any
// of them is the whole fix, and a test that only asserts "it returns an
// error" would pass on the broken version too.
func TestRepairCoreTouchesNothingWhenTheStagedTreeIsIncomplete(t *testing.T) {
	root := coreOnlyRoot(t, "<?php // index")
	store := t.TempDir()

	// The staged core has wp-admin but no wp-includes - a truncated download,
	// or a vendor layout that moved. coreDirs visits wp-admin first.
	staged := t.TempDir()
	if err := os.MkdirAll(filepath.Join(staged, "wp-admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "wp-admin", "admin.php"),
		[]byte("<?php // original admin"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ids, err := repairCore(Options{Root: root, QuarantineDir: store, Domain: "beispiel.de"},
		"replace", staged)
	if err == nil {
		t.Fatal("an incomplete staged core did not stop the repair")
	}
	if len(ids) != 0 {
		t.Errorf("the run filed %d entr(ies) away before it stopped: %v", len(ids), ids)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-admin", "admin.php")); err != nil {
		t.Errorf("wp-admin is gone from the website although the run refused: %v", err)
	}
	entries, _, err := quarantine.List(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("quarantine holds %d entr(ies) from a run that changed nothing", len(entries))
	}
}

// TestAFailedCoreRepairStillNamesWhatItFiled covers what happens when the
// run breaks after the first directory is already in quarantine. The ids are
// the only thread back to it: the store names entries by id, and a caller
// that drops them on the error path leaves the archived tree on disk with
// nothing in the report or the panel pointing at it. Present but unfindable
// is worse than lost, because nobody goes looking.
func TestAFailedCoreRepairStillNamesWhatItFiled(t *testing.T) {
	root := coreOnlyRoot(t, "<?php // index")
	store := t.TempDir()

	// wp-includes is replaced by a link pointing out of the web root, so
	// InsideRoot refuses it - after wp-admin has been filed away. The staged
	// tree is complete, so the up-front check passes and the run gets far
	// enough to archive the first directory.
	outside := t.TempDir()
	if err := os.RemoveAll(filepath.Join(root, "wp-includes")); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, outside, filepath.Join(root, "wp-includes"))

	staged := t.TempDir()
	for _, dir := range coreDirs {
		if err := os.MkdirAll(filepath.Join(staged, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staged, dir, "x.php"), []byte("<?php // original"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, ids, err := repairCore(Options{Root: root, QuarantineDir: store, Domain: "beispiel.de"},
		"replace", staged)
	if err == nil {
		t.Skip("the link was not refused on this platform; nothing to assert about the failure path")
	}
	entries, _, listErr := quarantine.List(store)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(entries) != len(ids) {
		t.Fatalf("the store holds %d entr(ies) but the run reported %d id(s): %v",
			len(entries), len(ids), ids)
	}
	for _, entry := range entries {
		found := false
		for _, id := range ids {
			if id == entry.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("entry %s sits in the store and no returned id names it", entry.ID)
		}
	}
}
