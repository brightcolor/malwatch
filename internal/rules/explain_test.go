package rules

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// Every rule the scanner can report has to explain itself; a finding the
// panel cannot explain is the kind nobody acts on.
func TestEveryRuleIsExplained(t *testing.T) {
	for _, r := range All() {
		e, ok := Explain(r.ID)
		if !ok || strings.TrimSpace(e.Why) == "" {
			t.Errorf("rule %s has no explanation", r.ID)
		}
	}
	for _, x := range Extras {
		if e, ok := Explain(x.ID); !ok || strings.TrimSpace(e.Why) == "" || e.Advice == "" {
			t.Errorf("extra %s needs an explanation and an advice", x.ID)
		}
	}
}

// An explanation for an ID nothing reports is a leftover of a renamed rule.
func TestNoExplanationWithoutRule(t *testing.T) {
	known := map[string]bool{}
	for _, r := range All() {
		known[r.ID] = true
	}
	for _, x := range Extras {
		known[x.ID] = true
	}
	for id := range explanations {
		if !known[id] {
			t.Errorf("explanation for %s, which no rule or extra reports", id)
		}
	}
}

func TestAdviceFollowsTheRule(t *testing.T) {
	if got := Advice("php.in_uploads", report.SeverityHigh, false); !strings.Contains(got, "index.php") {
		t.Errorf("php.in_uploads gets the general advice: %q", got)
	}
	if got := Advice("php.eval.encoded", report.SeverityCritical, true); got != adviceAutoSafe {
		t.Errorf("an AutoSafe rule without its own advice gets %q", got)
	}
	if got := Advice("unknown.rule", report.SeverityHigh, false); got != adviceSevere {
		t.Errorf("a high finding without advice gets %q", got)
	}
	if got := Advice("unknown.rule", report.SeverityMedium, false); got != adviceMild {
		t.Errorf("a medium finding without advice gets %q", got)
	}
}

// The texts are read by people: real umlauts, no stand-ins.
func TestExplanationsUseRealUmlauts(t *testing.T) {
	for id, e := range explanations {
		for _, text := range []string{e.Why, e.Advice} {
			for _, bad := range []string{"fuer ", "ueber ", "koennen", "muessen", "Loeschen", "Pruef", "gehoert", "faehig"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s: %q uses %q instead of an umlaut", id, text, bad)
				}
			}
		}
	}
}
