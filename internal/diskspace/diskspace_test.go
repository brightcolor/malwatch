package diskspace

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestStatReportsRoomOnAnExistingDirectory(t *testing.T) {
	got, err := Stat(t.TempDir())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got.Free <= 0 {
		t.Errorf("Free = %d, want more than 0", got.Free)
	}
	if got.Block < 0 {
		t.Errorf("Block = %d, want 0 or more", got.Block)
	}
}

func TestTwoDirectoriesOfOneTreeShareTheirFilesystem(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	a, err := Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if a.Device != b.Device {
		t.Errorf("Device %d and %d: a directory and its child sit on one filesystem", a.Device, b.Device)
	}
}

func TestStatOfAMissingPathSaysItIsMissing(t *testing.T) {
	_, err := Stat(filepath.Join(t.TempDir(), "fehlt"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want one that says the path does not exist", err)
	}
}

func TestAllocatedCountsAWrittenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "voll.bin")
	if err := os.WriteFile(path, make([]byte, 64<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := Allocated(info); got < 64<<10 {
		t.Errorf("Allocated = %d, want at least the %d bytes written", got, 64<<10)
	}
}
