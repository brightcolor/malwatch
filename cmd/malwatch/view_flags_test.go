package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/fileview"
)

// The help repeats the defaults and bounds of the view settings; it must say
// what the code does, so a changed default fails here until the text follows.
func TestUsageNamesTheViewDefaultsAndBounds(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	help := strings.Join(strings.Fields(buf.String()), " ")
	d, l := fileview.Default, fileview.Limits
	for _, want := range []string{
		fmt.Sprintf("--view-lines=N Dateien bis N Zeilen ganz zeigen, längere in Ausschnitten mit höchstens N Zeilen; 0 zeigt keinen Code (Vorgabe: %d, erlaubt %d bis %d)", d.MaxLines, l.MaxLines.Min, l.MaxLines.Max),
		fmt.Sprintf("(Vorgabe: %d, erlaubt %d bis %d)", d.Context, l.Context.Min, l.Context.Max),
		fmt.Sprintf("(Vorgabe: %d, erlaubt %d bis %d)", d.LineLength, l.LineLength.Min, l.LineLength.Max),
		fmt.Sprintf("(Vorgabe: %d, erlaubt %d bis %d)", d.MaxMarks, l.MaxMarks.Min, l.MaxMarks.Max),
		fmt.Sprintf("(Vorgabe: %d, erlaubt %d bis %d)", d.BudgetMiB, l.BudgetMiB.Min, l.BudgetMiB.Max),
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func TestScanRefusesAViewSettingOutOfBounds(t *testing.T) {
	if code := cmdScan([]string{"--view-context=99", t.TempDir()}); code == 0 {
		t.Fatal("scan accepted --view-context=99")
	}
}
