package dump

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceSizeAddsRootsAndSkipsMissing(t *testing.T) {
	base := t.TempDir()
	web := filepath.Join(base, "web")
	logs := filepath.Join(base, "log")
	if err := os.MkdirAll(filepath.Join(web, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(web, "a.php"), "1234567890")          // 10
	write(t, filepath.Join(web, "sub", "b.php"), "12345")        // 5
	write(t, filepath.Join(logs, "access.log"), "1234567890123") // 13

	got, err := SourceSize(web, logs, filepath.Join(base, "fehlt"))
	if err != nil {
		t.Fatalf("SourceSize: %v", err)
	}
	if got != 28 {
		t.Errorf("SourceSize = %d, erwartet 28", got)
	}
}

func TestSourceSizeWithoutRootsIsZero(t *testing.T) {
	got, err := SourceSize()
	if err != nil {
		t.Fatalf("SourceSize: %v", err)
	}
	if got != 0 {
		t.Errorf("SourceSize = %d, erwartet 0", got)
	}
}

func TestFreeSpaceReportsSomething(t *testing.T) {
	got, err := FreeSpace(t.TempDir())
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if got <= 0 {
		t.Errorf("FreeSpace = %d, erwartet mehr als 0", got)
	}
}
