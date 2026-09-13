package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestUpgradeExitCode(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []UpgradeOutcome
		errs     []string
		want     int
	}{
		{"all updated", []UpgradeOutcome{UpgradeUpdated, UpgradeUpdated}, nil, 0},
		{"dry run", []UpgradeOutcome{UpgradeWould}, nil, 0},
		{"one refused", []UpgradeOutcome{UpgradeUpdated, UpgradeRefused}, nil, 2},
		{"one rolled back", []UpgradeOutcome{UpgradeRolledBack}, nil, 2},
		{"one failed", []UpgradeOutcome{UpgradeFailed}, nil, 2},
		{"rollback failed", []UpgradeOutcome{UpgradeRollbackFailed, UpgradeSkipped}, nil, 3},
		{"run error", []UpgradeOutcome{UpgradeSkipped}, []string{"Prüfsumme weicht ab"}, 3},
	}
	for _, c := range cases {
		u := NewUpgrade("/w", false)
		for _, o := range c.outcomes {
			u.Elements = append(u.Elements, UpgradeElement{Kind: "plugin", Outcome: o})
		}
		u.Errors = append(u.Errors, c.errs...)
		if got := u.ExitCode(); got != c.want {
			t.Errorf("%s: exit code %d, want %d", c.name, got, c.want)
		}
	}
}

func TestUpgradeTextNamesOutcomeVersionsAndReason(t *testing.T) {
	u := NewUpgrade("/var/www/clients/client3/web12/web", false)
	u.Elements = append(u.Elements, UpgradeElement{
		Kind: "plugin", Slug: "akismet", From: "5.3.0", To: "5.3.3",
		Outcome: UpgradeRolledBack, Message: "Startseite: Antwort 500",
		QuarantineIDs: []string{"20260914T101500Z-0a1b2c3d"},
	})
	var buf bytes.Buffer
	if err := u.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"zurückgeholt", "plugin akismet 5.3.0 → 5.3.3",
		"Startseite: Antwort 500", "20260914T101500Z-0a1b2c3d"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
}

func TestUpgradeJSONCarriesTheContract(t *testing.T) {
	u := NewUpgrade("/w", true)
	u.PHPVersion = "8.2.10"
	u.Elements = append(u.Elements, UpgradeElement{
		Kind: "core", Install: "/w", Path: "/w", From: "6.4.2", To: "6.4.5",
		Outcome: UpgradeWould, Checks: []PageCheck{{URL: "https://beispiel.de/", Before: 200}},
	})
	var buf bytes.Buffer
	if err := u.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != float64(1) || doc["dry_run"] != true || doc["php_version"] != "8.2.10" {
		t.Errorf("head is wrong: %v", doc)
	}
	el := doc["elements"].([]any)[0].(map[string]any)
	if el["install"] != "/w" || el["outcome"] != "would_update" || el["to"] != "6.4.5" {
		t.Errorf("element is wrong: %v", el)
	}
	check := el["checks"].([]any)[0].(map[string]any)
	if check["before"] != float64(200) {
		t.Errorf("check is wrong: %v", check)
	}
}
