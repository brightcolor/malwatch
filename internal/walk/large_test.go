package walk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAFileOverTheSizeLimitGoesToLarge(t *testing.T) {
	root := t.TempDir()
	for name, size := range map[string]int{"small.txt": 10, "sub/big.bin": 100} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(strings.Repeat("x", size)), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	counters := &Counters{}
	var large []File
	w := New(Options{MaxSize: 50, Large: func(f File) { large = append(large, f) }}, counters)
	var seen []string
	if err := w.Walk(root, func(f File) error {
		seen = append(seen, f.Rel)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "/small.txt" {
		t.Errorf("an die Prüfung gingen %v, erwartet nur /small.txt", seen)
	}
	if len(large) != 1 || large[0].Rel != "/sub/big.bin" || large[0].Size != 100 || large[0].Ext != "bin" {
		t.Errorf("über der Größengrenze: %+v, erwartet /sub/big.bin mit 100 Bytes", large)
	}
	if counters.Skipped.Load() != 1 {
		t.Errorf("übersprungen %d, erwartet 1", counters.Skipped.Load())
	}
}

func TestWithoutLargeABigFileIsOnlySkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "big.bin"), []byte(strings.Repeat("x", 100)), 0o640); err != nil {
		t.Fatal(err)
	}
	counters := &Counters{}
	n := 0
	if err := New(Options{MaxSize: 50}, counters).Walk(root, func(File) error {
		n++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 || counters.Skipped.Load() != 1 {
		t.Errorf("%d Dateien geprüft und %d übersprungen, erwartet 0 und 1", n, counters.Skipped.Load())
	}
}
