package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Der Balken im Panel rechnet seine Breite aus done/total. Ohne total stand er
// auf festen fünf Prozent, und ein Scan sah minutenlang aus wie ein Absturz.
func TestScanReportsATotalWhenExpectIsGiven(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.php", "b.php", "c.php"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("<?php echo 1;"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	code := cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog, "--expect=3",
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})
	if code > 1 {
		t.Fatalf("Rückgabewert %d", code)
	}

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 3 {
		t.Errorf("files_total ist %d, erwartet 3", doc.FilesTotal)
	}
}

// Ohne den Schalter bleibt alles wie bisher: ein Zähler ohne Nenner ist eine
// ehrliche Aussage, eine erfundene Gesamtzahl wäre keine.
func TestScanLeavesTheTotalAtZeroWithoutExpect(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog,
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 0 {
		t.Errorf("files_total ist %d, erwartet 0", doc.FilesTotal)
	}
}

// Ein zweiter Lauf über dieselbe Website trifft fast jede Datei im Cache. Der
// Zähler der geprüften Dateien bleibt dann bei null, und solange der Nenner
// die Dateizahl des ersten Laufs war, stand der Balken die ganze Zeit auf 0 %
// und sprang am Ende auf 100. Zähler und Nenner zählen jetzt beide die
// angesehenen Dateien - geprüfte und übersprungene zusammen.
func TestWarmRunReportsProgressAgainstTheSameCount(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		name := filepath.Join(root, fmt.Sprintf("f%02d.php", i))
		if err := os.WriteFile(name, []byte("<?php echo "+strconv.Itoa(i)+";"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cache := filepath.Join(t.TempDir(), "clean.json")

	kalt := runScanForProgress(t, root, cache, 0)
	if kalt.FilesDone == 0 {
		t.Fatalf("der kalte Lauf meldete keine einzige Datei")
	}

	warm := runScanForProgress(t, root, cache, kalt.FilesDone)
	if warm.Scanned != 0 {
		t.Fatalf("der zweite Lauf prüfte %d Dateien, der Cache griff also nicht - "+
			"der Test würde nichts beweisen", warm.Scanned)
	}
	if warm.FilesTotal != kalt.FilesDone {
		t.Errorf("Nenner %d, erwartet %d", warm.FilesTotal, kalt.FilesDone)
	}
	if warm.FilesDone != warm.FilesTotal {
		t.Errorf("warmer Lauf: %d von %d Dateien - der Balken stünde bei %d %%",
			warm.FilesDone, warm.FilesTotal, warm.FilesDone*100/warm.FilesTotal)
	}
}

type progressResult struct {
	FilesDone  int
	FilesTotal int
	Scanned    int
}

// runScanForProgress läuft einmal über root und liefert, was in der
// Fortschrittsdatei und im Bericht steht. expect = 0 lässt --expect weg.
func runScanForProgress(t *testing.T, root, cache string, expect int) progressResult {
	t.Helper()

	prog := filepath.Join(t.TempDir(), "job.progress")
	out := filepath.Join(t.TempDir(), "r.json")
	args := []string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog, "--cache=" + cache,
		"--out=" + out, "--json",
	}
	if expect > 0 {
		args = append(args, "--expect="+strconv.Itoa(expect))
	}
	if code := cmdScan(args); code > 1 {
		t.Fatalf("Rückgabewert %d", code)
	}

	var doc struct {
		FilesDone  int `json:"files_done"`
		FilesTotal int `json:"files_total"`
	}
	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var rep struct {
		Stats struct {
			FilesScanned int `json:"files_scanned"`
		} `json:"stats"`
	}
	raw, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}

	return progressResult{FilesDone: doc.FilesDone, FilesTotal: doc.FilesTotal, Scanned: rep.Stats.FilesScanned}
}
