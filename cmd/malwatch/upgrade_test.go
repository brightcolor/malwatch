package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRefusesWithoutPathOrPlan(t *testing.T) {
	if code := cmdUpgrade([]string{}); code != 3 {
		t.Errorf("exit code %d without --path, want 3", code)
	}
	if code := cmdUpgrade([]string{"--path=" + t.TempDir()}); code != 3 {
		t.Errorf("exit code %d without --plan, want 3", code)
	}
}

func TestUpgradeRefusesRootAndSaysSoInTheReport(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.json")
	code := cmdUpgrade([]string{
		"--path=" + root, "--plan=" + filepath.Join(root, "plan.json"),
		"--php=/usr/bin/php", "--quarantine-dir=" + t.TempDir(),
		"--run-as=root", "--json", "--out=" + out,
	})
	if code != 3 {
		t.Fatalf("exit code %d for --run-as=root, want 3", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	var doc struct {
		Schema int      `json:"schema"`
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || len(doc.Errors) == 0 || !strings.Contains(doc.Errors[0], "root") {
		t.Errorf("report = %s", raw)
	}
}

func TestUpgradeReportsARefusedPlan(t *testing.T) {
	root := t.TempDir()
	plan := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(plan, []byte(`{"schema":1,"installs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	code := cmdUpgrade([]string{
		"--path=" + root, "--plan=" + plan, "--php=/usr/bin/php", "--dry-run", "--json", "--out=" + out,
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), "keine Installation") {
		t.Errorf("the report does not name the refusal: %s", raw)
	}
}
