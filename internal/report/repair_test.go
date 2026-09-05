package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRepairExitCodeSaysWhetherSomethingWasLost(t *testing.T) {
	clean := NewRepair("/var/www/web1/web")
	clean.Elements = append(clean.Elements, RepairElement{Kind: "core", Outcome: OutcomeReplaced})
	if got := clean.ExitCode(); got != 0 {
		t.Errorf("a clean run returned %d, want 0", got)
	}

	lost := NewRepair("/var/www/web1/web")
	lost.Elements = append(lost.Elements,
		RepairElement{Kind: "core", Outcome: OutcomeReplaced},
		RepairElement{Kind: "plugin", Slug: "elementor-pro", Version: "3.21.0", Outcome: OutcomeDeleted})
	if got := lost.ExitCode(); got != 2 {
		t.Errorf("a run that deleted without a replacement returned %d, want 2", got)
	}

	broken := NewRepair("/var/www/web1/web")
	broken.Elements = append(broken.Elements,
		RepairElement{Kind: "plugin", Slug: "akismet", Outcome: OutcomeDeleted},
		RepairElement{Kind: "theme", Slug: "x", Outcome: OutcomeFailed})
	if got := broken.ExitCode(); got != 3 {
		t.Errorf("a failed swap returned %d, want 3", got)
	}
}

func TestRepairTextNamesWhatCannotComeBack(t *testing.T) {
	r := NewRepair("/var/www/web1/web")
	r.Elements = append(r.Elements, RepairElement{
		Kind: "plugin", Slug: "elementor-pro", Version: "3.21.0",
		Outcome: OutcomeDeleted, Backup: "/var/lib/malwatch/backups/x/elementor-pro.tar.gz",
	})
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Name and version have to be in the text: without them the operator
	// cannot tell the customer what to buy again.
	for _, want := range []string{"elementor-pro", "3.21.0", "elementor-pro.tar.gz"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

func TestRepairJSONCarriesTheSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := NewRepair("/x").WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int    `json:"schema"`
		Root   string `json:"root"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Root != "/x" {
		t.Fatalf("head is wrong: %+v", doc)
	}
}

func TestADryRunReportsInTheConditional(t *testing.T) {
	r := NewRepair("/var/www/web1/web")
	r.DryRun = true
	r.Elements = append(r.Elements,
		RepairElement{Kind: "core", Version: "6.6.2", Outcome: OutcomeReplaced},
		RepairElement{Kind: "plugin", Slug: "elementor-pro", Version: "3.21.0", Outcome: OutcomeDeleted})

	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// "ersetzt" for something that was not replaced misleads in exactly the
	// moment the report matters most.
	if strings.Contains(out, "  ersetzt ") || strings.Contains(out, "GELÖSCHT") {
		t.Errorf("a dry run reports in the past tense:\n%s", out)
	}
	for _, want := range []string{"würde ersetzen", "WÜRDE LÖSCHEN", "elementor-pro"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0 Dateien") {
		t.Errorf("a dry run must not claim a file count:\n%s", out)
	}
}
