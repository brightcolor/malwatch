package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/diskspace"
	"github.com/brightcolor/malwatch/internal/quarantine"
	"github.com/brightcolor/malwatch/internal/report"
)

// An update whose old release does not fit into the quarantine stops before
// the exchange: the site stays as it was, and the element says why.
func TestAnUpdateWithoutRoomInTheQuarantineLeavesTheSite(t *testing.T) {
	root := site(t)
	before := treeOf(t, root)
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	store := opts.QuarantineDir
	opts.Space = quarantine.Space{ReserveMiB: 2, Stat: func(path string) (diskspace.Usage, error) {
		if _, err := os.Stat(path); err != nil {
			return diskspace.Usage{}, err
		}
		if path == store || strings.HasPrefix(path, store+string(filepath.Separator)) {
			return diskspace.Usage{Free: 1 << 20, Block: 4096, Device: 2}, nil
		}
		return diskspace.Usage{Free: 1 << 40, Block: 4096, Device: 1}, nil
	}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeFailed || !strings.Contains(el.Message, "reicht der Platz nicht") ||
		!strings.Contains(el.Message, "--quarantine-reserve") {
		t.Fatalf("element = %+v", el)
	}
	if got := treeOf(t, root); got != before {
		t.Error("the site changed although the old release found no room in the quarantine")
	}
	if entries, _, _ := quarantine.List(store); len(entries) != 0 {
		t.Errorf("the quarantine holds %d entries", len(entries))
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit code %d, want 2", rep.ExitCode())
	}

	// The same update with a reserve that fits goes through.
	opts.Space.ReserveMiB = 0
	rep, err = Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if el := rep.Elements[0]; el.Outcome != report.UpgradeUpdated {
		t.Fatalf("with no reserve: element = %+v", el)
	}
}

// A rollback measures its room like any restore and says so when it fails:
// the element is rollback_failed with the reason, and the quarantine keeps the
// old release for a restore by hand.
func TestARollbackWithoutRoomKeepsTheOldReleaseInTheQuarantine(t *testing.T) {
	root := site(t)
	prober := &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 500}}}}
	opts := options(t, root, onePlan(root, planAkismet), prober, &recorder{})
	plugins := filepath.Join(root, "wp-content", "plugins")
	stored := false
	opts.Space = quarantine.Space{Stat: func(path string) (diskspace.Usage, error) {
		if _, err := os.Stat(path); err != nil {
			return diskspace.Usage{}, err
		}
		entries, _, _ := quarantine.List(opts.QuarantineDir)
		stored = stored || len(entries) > 0
		if stored && (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) {
			// Once the old release is filed, the website's disk is full.
			return diskspace.Usage{Free: 0, Block: 4096, Device: 2}, nil
		}
		return diskspace.Usage{Free: 1 << 40, Block: 4096, Device: 1}, nil
	}}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := rep.Elements[0]
	if el.Outcome != report.UpgradeRollbackFailed || !strings.Contains(el.Message, "reicht der Platz nicht") {
		t.Fatalf("element = %+v", el)
	}
	if len(el.QuarantineIDs) != 1 {
		t.Fatalf("quarantine ids = %v, want the old release", el.QuarantineIDs)
	}
	entry, err := quarantine.Get(opts.QuarantineDir, el.QuarantineIDs[0])
	if err != nil {
		t.Fatalf("the old release is gone from the quarantine: %v", err)
	}
	if entry.RelPath != "wp-content/plugins/akismet" {
		t.Errorf("entry = %+v", entry)
	}
	var se *quarantine.SpaceError
	if err := quarantine.RestoreWith(opts.QuarantineDir, entry.ID, true, opts.Space); !errors.As(err, &se) {
		t.Errorf("RestoreWith = %v, want the same refusal", err)
	}
	if _, err := os.Stat(filepath.Join(plugins, "akismet", "akismet.php")); err != nil {
		t.Errorf("the new release left its place: %v", err)
	}
}
