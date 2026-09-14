package upgrade

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// A checksum list that cannot be loaded keeps its element out and lets the
// others go on. A list that loads and does not match the archive still ends
// the run (TestAManipulatedArchiveStopsTheRun).
func TestAnUnloadableChecksumListRefusesOnlyItsElement(t *testing.T) {
	root := site(t)
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "kontakt", "kontakt.php"),
		"<?php\n/*\nPlugin Name: Kontakt\nVersion: 1.0\n*/")
	kontakt := map[string]string{"kontakt/kontakt.php": "<?php\n/*\nPlugin Name: Kontakt\nVersion: 2.0\n*/"}
	plan := onePlan(root, planAkismet, PlanElement{Kind: "plugin", Slug: "kontakt", Version: "2.0"})
	opts := options(t, root, plan, healthy(), &recorder{})
	opts.Fetcher = vendor(t, map[string]map[string]string{
		"/p/akismet.5.3.3.zip": akismet533,
		"/p/kontakt.2.0.zip":   kontakt,
	})
	opts.Checksums = fakeChecksums{
		plugins: map[string]map[string]string{"akismet@5.3.3": sumsOf(akismet533)},
		failing: map[string]bool{"kontakt@2.0": true},
	}

	rep, err := Run(opts)
	if err != nil {
		t.Fatalf("the run stopped: %v", err)
	}
	if got := rep.Elements[0].Outcome; got != report.UpgradeUpdated {
		t.Errorf("akismet = %s, want updated", got)
	}
	if el := rep.Elements[1]; el.Outcome != report.UpgradeRefused || !strings.Contains(el.Message, "nicht ladbar") {
		t.Errorf("kontakt = %+v, want refused naming the list", el)
	}
	if len(rep.Errors) != 0 || rep.ExitCode() != 2 {
		t.Errorf("errors %v, exit code %d; want none and 2", rep.Errors, rep.ExitCode())
	}
}
