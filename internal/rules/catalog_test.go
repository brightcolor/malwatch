package rules

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// TestAutoSafeNeverGoesBelowHigh guards the meaning of the flag: quarantine
// moves a file on an AutoSafe match without a human looking at it first, so
// a rule that the catalog itself only trusts at medium or low severity must
// never carry the mark.
func TestAutoSafeNeverGoesBelowHigh(t *testing.T) {
	for _, r := range All() {
		if r.AutoSafe && !r.Severity.AtLeast(report.SeverityHigh) {
			t.Errorf("rule %s is AutoSafe but severity is only %q", r.ID, r.Severity)
		}
	}
}

// TestAutoSafeRulesHaveATitle keeps the panel from ever having to show a
// blank label for a rule whose match alone can move a file.
func TestAutoSafeRulesHaveATitle(t *testing.T) {
	for _, r := range All() {
		if r.AutoSafe && strings.TrimSpace(r.Description) == "" {
			t.Errorf("rule %s is AutoSafe but has no title", r.ID)
		}
	}
}

// TestLibraryLookalikesLeaveTheMoveToAHuman pins rules whose pattern honest
// library code also has. On 2026-09-29 php.remote.fetch_eval_indirect moved
// SeedProd's XML-RPC library (infusionsoft/xmlrpc-2.0/lib/xmlrpc.inc) into
// quarantine on four websites by itself. Such a rule reports at its severity;
// whether the file goes, a human decides.
func TestLibraryLookalikesLeaveTheMoveToAHuman(t *testing.T) {
	for _, id := range []string{"php.remote.fetch_eval_indirect"} {
		found := false
		for _, r := range All() {
			if r.ID != id {
				continue
			}
			found = true
			if r.AutoSafe {
				t.Errorf("rule %s is AutoSafe, but it also matches honest library code", id)
			}
		}
		if !found {
			t.Errorf("rule %s is missing from the catalog", id)
		}
	}
}

// TestSomeRulesAreAutoSafe keeps the catalog from silently losing every
// AutoSafe mark in some future edit - the automatic move has nothing to act
// on without at least one.
func TestSomeRulesAreAutoSafe(t *testing.T) {
	n := 0
	for _, r := range All() {
		if r.AutoSafe {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no rule in the catalog is marked AutoSafe")
	}
}
