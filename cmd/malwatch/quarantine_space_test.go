package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/diskspace"
	"github.com/brightcolor/malwatch/internal/quarantine"
)

// stderrOf runs fn and returns what it wrote to os.Stderr.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		raw, _ := io.ReadAll(r)
		done <- string(raw)
	}()
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	return <-done
}

// withFreeSpace lets every filesystem below the dirs in tight report free
// bytes, and every other one plenty, until the test ends.
func withFreeSpace(t *testing.T, free int64, tight ...string) {
	t.Helper()
	quarantineStat = func(path string) (diskspace.Usage, error) {
		if _, err := os.Stat(path); err != nil {
			return diskspace.Usage{}, err
		}
		for i, dir := range tight {
			if path == dir || strings.HasPrefix(path, dir+string(filepath.Separator)) {
				return diskspace.Usage{Free: free, Block: 4096, Device: uint64(i + 2)}, nil
			}
		}
		return diskspace.Usage{Free: 1 << 40, Block: 4096, Device: 1}, nil
	}
	t.Cleanup(func() { quarantineStat = nil })
}

// readIndex reads the store's listing quarantine writes with --json --out.
func readIndex(t *testing.T, path string) []quarantine.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no listing was written: %v", err)
	}
	var doc struct {
		Entries []quarantine.Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the listing is no JSON: %v", err)
	}
	return doc.Entries
}

// The automatic measure of the addon is this call: add with --json and
// --out, files of new findings. Without room the file stays, the listing is
// still written, and the message says what is missing and what to do.
func TestQuarantineAddWithoutRoomKeepsTheFileAndSaysWhy(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "wp-content", "uploads", "shell.php")
	writeHarmlessFile(t, victim)
	store := t.TempDir()
	withFreeSpace(t, 100<<20, store)
	out := filepath.Join(t.TempDir(), "job.json")

	var code int
	stderr := stderrOf(t, func() {
		code = cmdQuarantine([]string{
			"add", "--path=" + root, "--quarantine-dir=" + store, "--origin=auto",
			"--file=wp-content/uploads/shell.php", "--json", "--out=" + out,
		})
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the file left its place although the store had no room: %v", err)
	}
	if entries := readIndex(t, out); len(entries) != 0 {
		t.Errorf("listing = %+v, want an empty store", entries)
	}
	for _, want := range []string{
		"Quarantäne von wp-content/uploads/shell.php fehlgeschlagen: Auf " + store + " reicht der Platz nicht",
		"frei sind 100,0 MiB",
		"davon 256,0 MiB Reserve",
		"wp-content/uploads/shell.php bleibt unverändert liegen.",
		"Platz schaffen oder die Reserve senken (--quarantine-reserve)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q lacks %q", stderr, want)
		}
	}
	// The panel shows the first 400 bytes of the last lines a job wrote. With
	// the store where the addon keeps it, the refusal fits on one line.
	line := strings.ReplaceAll(strings.TrimSpace(stderr), store, "/var/lib/malwatch/quarantine")
	if len(line) > 400 || strings.Contains(line, "\n") {
		t.Errorf("the refusal takes %d bytes on %d lines, the panel shows 400 of one: %q",
			len(line), strings.Count(line, "\n")+1, line)
	}

	// The same call with a reserve that fits stores the file.
	if code := cmdQuarantine([]string{
		"add", "--path=" + root, "--quarantine-dir=" + store, "--quarantine-reserve=50",
		"--file=wp-content/uploads/shell.php", "--json", "--out=" + out,
	}); code != 0 {
		t.Fatalf("with --quarantine-reserve=50: exit code %d, want 0", code)
	}
	if entries := readIndex(t, out); len(entries) != 1 {
		t.Errorf("listing = %+v, want the stored file", entries)
	}
}

func TestQuarantineRestoreWithoutRoomKeepsTheEntry(t *testing.T) {
	root := t.TempDir()
	writeHarmlessFile(t, filepath.Join(root, "note.php"))
	store := t.TempDir()
	entry, err := quarantine.Store(store, quarantine.Source{Root: root, RelPath: "note.php", Domain: "beispiel.de"})
	if err != nil {
		t.Fatal(err)
	}
	withFreeSpace(t, 10<<20, root)
	out := filepath.Join(t.TempDir(), "job.json")

	var code int
	stderr := stderrOf(t, func() {
		code = cmdQuarantine([]string{"restore", "--quarantine-dir=" + store, "--id=" + entry.ID, "--json", "--out=" + out})
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if _, err := os.Stat(filepath.Join(root, "note.php")); !os.IsNotExist(err) {
		t.Errorf("a refused restore wrote the file: %v", err)
	}
	if entries := readIndex(t, out); len(entries) != 1 || entries[0].ID != entry.ID {
		t.Errorf("listing = %+v, want the entry still in the store", entries)
	}
	if !strings.Contains(stderr, "Der Eintrag "+entry.ID+" bleibt in der Quarantäne") {
		t.Errorf("stderr %q does not say the entry stays", stderr)
	}

	if code := cmdQuarantine([]string{"restore", "--quarantine-dir=" + store, "--id=" + entry.ID,
		"--quarantine-reserve=1"}); code != 0 {
		t.Fatalf("with --quarantine-reserve=1: exit code %d, want 0", code)
	}
}

func TestQuarantineExportWithoutRoomWritesNoArchive(t *testing.T) {
	root := t.TempDir()
	writeHarmlessFile(t, filepath.Join(root, "note.php"))
	store := t.TempDir()
	entry, err := quarantine.Store(store, quarantine.Source{Root: root, RelPath: "note.php", Domain: "beispiel.de"})
	if err != nil {
		t.Fatal(err)
	}
	spool := t.TempDir()
	withFreeSpace(t, 100<<20, spool)
	zipOut := filepath.Join(spool, "token.zip")

	var code int
	stderr := stderrOf(t, func() {
		code = cmdQuarantine([]string{"export", "--quarantine-dir=" + store, "--id=" + entry.ID, "--zip=" + zipOut})
	})
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
	if _, err := os.Stat(zipOut); !os.IsNotExist(err) {
		t.Errorf("a refused export left %s", zipOut)
	}
	if !strings.Contains(stderr, "Es wurde kein ZIP geschrieben.") {
		t.Errorf("stderr %q does not say that no archive was written", stderr)
	}

	if code := cmdQuarantine([]string{"export", "--quarantine-dir=" + store, "--id=" + entry.ID, "--zip=" + zipOut,
		"--quarantine-reserve=10"}); code != 0 {
		t.Fatalf("with --quarantine-reserve=10: exit code %d, want 0", code)
	}
}

func TestCommandsRefuseAReserveOutOfRange(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "note.php")
	writeHarmlessFile(t, victim)
	for _, value := range []int64{quarantine.MinReserveMiB - 1, quarantine.MaxReserveMiB + 1} {
		flagValue := fmt.Sprintf("--quarantine-reserve=%d", value)
		want := fmt.Sprintf("erlaubt sind %d bis %d MiB, Vorgabe %d", quarantine.MinReserveMiB,
			quarantine.MaxReserveMiB, quarantine.DefaultReserveMiB)
		for name, run := range map[string]func() int{
			"quarantine add": func() int {
				return cmdQuarantine([]string{"add", "--path=" + root, "--quarantine-dir=" + t.TempDir(),
					"--file=note.php", flagValue})
			},
			"repair": func() int {
				return cmdRepair([]string{"--path=" + root, "--quarantine-dir=" + t.TempDir(), flagValue})
			},
			"upgrade": func() int {
				return cmdUpgrade([]string{"--path=" + root, "--plan=" + filepath.Join(root, "plan.json"),
					"--php=php", "--quarantine-dir=" + t.TempDir(), flagValue})
			},
		} {
			var code int
			stderr := stderrOf(t, func() { code = run() })
			if code != 3 {
				t.Errorf("%s %s: exit code %d, want 3", name, flagValue, code)
			}
			if !strings.Contains(stderr, want) || !strings.Contains(stderr, "Ohne den Schalter gilt die Vorgabe.") {
				t.Errorf("%s %s: stderr %q does not name the range and the default", name, flagValue, stderr)
			}
		}
		if _, err := os.Stat(victim); err != nil {
			t.Fatalf("%s: the file is gone: %v", flagValue, err)
		}
	}
}

// The help names --quarantine-reserve with the default and the range the
// code has, for repair, upgrade and quarantine.
func TestUsageNamesTheQuarantineReserve(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	help := strings.Join(strings.Fields(buf.String()), " ")
	want := fmt.Sprintf("(Vorgabe: %d, erlaubt %d bis %d)", quarantine.DefaultReserveMiB,
		quarantine.MinReserveMiB, quarantine.MaxReserveMiB)
	if n := strings.Count(help, want); n != 3 {
		t.Errorf("the help names %q %d times, want it for repair, upgrade and quarantine", want, n)
	}
	if n := strings.Count(help, "--quarantine-reserve=MIB"); n != 3 {
		t.Errorf("the help names --quarantine-reserve=MIB %d times, want 3", n)
	}
}
