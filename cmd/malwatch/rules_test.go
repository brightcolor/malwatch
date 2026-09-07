package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brightcolor/malwatch/internal/rules"
)

// TestRulesJSONWritesTheWholeCatalog is the contract the ISPConfig addon
// reads: one entry per rule, with a title and severity it can show and an
// auto_safe flag it can act on without knowing anything about the engine.
func TestRulesJSONWritesTheWholeCatalog(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.json")

	if code := cmdRules([]string{"--json", "--out=" + out}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int `json:"schema"`
		Rules  []struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			AutoSafe bool   `json:"auto_safe"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}

	if doc.Schema != 1 {
		t.Errorf("schema = %d, want 1", doc.Schema)
	}
	want := len(rules.All())
	if len(doc.Rules) != want {
		t.Fatalf("got %d rules, want %d", len(doc.Rules), want)
	}

	seenAutoSafe := false
	byID := map[string]bool{}
	for _, r := range doc.Rules {
		byID[r.ID] = true
		if r.Title == "" {
			t.Errorf("rule %s has no title", r.ID)
		}
		switch r.Severity {
		case "low", "medium", "high", "critical":
		default:
			t.Errorf("rule %s has an unexpected severity %q", r.ID, r.Severity)
		}
		if r.AutoSafe {
			seenAutoSafe = true
		}
	}
	if !seenAutoSafe {
		t.Error("no rule in the output is auto_safe, but the catalog has some")
	}

	// The catalog's own rules must all show up under their stable ID -
	// that ID is what --ignore and the panel's findings already use.
	for _, r := range rules.All() {
		if !byID[r.ID] {
			t.Errorf("rule %s from the catalog is missing from the JSON output", r.ID)
		}
	}
}

// TestRulesReportsAKnownWebshellRuleAsAutoSafe pins one concrete example so
// a change that flips severities or AutoSafe marks around does not pass
// silently just because the aggregate counts still line up.
func TestRulesReportsAKnownWebshellRuleAsAutoSafe(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.json")
	if code := cmdRules([]string{"--json", "--out=" + out}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			AutoSafe bool   `json:"auto_safe"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Rules {
		if r.ID == "php.webshell.known" {
			if r.Severity != "critical" {
				t.Errorf("php.webshell.known severity = %q, want %q", r.Severity, "critical")
			}
			if !r.AutoSafe {
				t.Error("php.webshell.known is not reported as auto_safe")
			}
			return
		}
	}
	t.Fatal("php.webshell.known is not in the output")
}

// TestRulesWithoutJSONIsAnError keeps a bare "malwatch rules" from silently
// doing nothing - there is no text format yet, so the flag is mandatory.
func TestRulesWithoutJSONIsAnError(t *testing.T) {
	if code := cmdRules(nil); code == 0 {
		t.Fatal("rules without --json returned 0, want an error")
	}
}
