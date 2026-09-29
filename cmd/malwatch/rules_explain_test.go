package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brightcolor/malwatch/internal/rules"
)

// The panel shows why a file was reported and what to do about it; both come
// from this document, for the catalog and for the sources outside it.
func TestRulesJSONExplainsEveryRuleAndExtra(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.json")
	if code := cmdRules([]string{"--json", "--out=" + out}); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Explain string `json:"explain"`
		Advice  string `json:"advice"`
	}
	var doc struct {
		Rules  []entry `json:"rules"`
		Extras []entry `json:"extras"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range append(doc.Rules, doc.Extras...) {
		if r.Explain == "" || r.Advice == "" {
			t.Errorf("%s: explain %q, advice %q", r.ID, r.Explain, r.Advice)
		}
	}
	if len(doc.Extras) != len(rules.Extras) {
		t.Fatalf("extras = %d, want %d", len(doc.Extras), len(rules.Extras))
	}
	ids := map[string]bool{}
	for _, x := range doc.Extras {
		ids[x.ID] = true
	}
	for _, want := range []string{"vendor.foreign_file", "core.modified", "engine:signature", "engine:clamav"} {
		if !ids[want] {
			t.Errorf("extra %s missing", want)
		}
	}
}
