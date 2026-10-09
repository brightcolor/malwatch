package quarantine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func storeTwoFileEntry(t *testing.T, storeRoot string) Entry {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "uploads", "a.txt"), []byte("quarantine export sample file A content"), 0o644)
	writeTestFile(t, filepath.Join(root, "uploads", "sub", "b.txt"), []byte("quarantine export sample file B, a little longer than A"), 0o644)
	entry, err := Store(storeRoot, Source{
		Root: root, RelPath: "uploads", Domain: "beispiel.de",
		Origin: "manual", Reason: "export test",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	return entry
}

func TestExportProducesAZipTheStandardLibraryCanOpen(t *testing.T) {
	storeRoot := t.TempDir()
	entry := storeTwoFileEntry(t, storeRoot)

	outFile := filepath.Join(t.TempDir(), "sample.zip")
	results, err := Export(storeRoot, []string{entry.ID}, outFile, ExportOptions{Password: DefaultPassword})
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(results) != 1 || results[0].ID != entry.ID || results[0].Err != nil {
		t.Fatalf("results = %+v, want the one entry without an error", results)
	}
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 0 {
		t.Fatalf("the archive is empty")
	}

	rc, err := zip.OpenReader(outFile)
	if err != nil {
		t.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer rc.Close()

	byName := map[string]*zip.File{}
	for _, f := range rc.File {
		byName[f.Name] = f
	}
	for _, want := range []string{entry.ID + "/uploads/a.txt", entry.ID + "/uploads/sub/b.txt"} {
		f, ok := byName[want]
		if !ok {
			t.Errorf("zip is missing %q; has %v", want, byName)
			continue
		}
		if f.Flags&0x1 == 0 {
			t.Errorf("%s: Flags = %#x, encrypted bit (0x1) not set", want, f.Flags)
		}
	}
}

func TestExportRoundTripsContentThroughDecryptionAndInflate(t *testing.T) {
	storeRoot := t.TempDir()
	root := t.TempDir()
	content := []byte("quarantine export round-trip content, deliberately not shell-shaped text")
	writeTestFile(t, filepath.Join(root, "note.txt"), content, 0o644)
	entry, err := Store(storeRoot, Source{
		Root: root, RelPath: "note.txt", Domain: "beispiel.de",
		Origin: "manual", Reason: "export round trip",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	outFile := filepath.Join(t.TempDir(), "sample.zip")
	password := "infected"
	if _, err := Export(storeRoot, []string{entry.ID}, outFile, ExportOptions{Password: password}); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	rc, err := zip.OpenReader(outFile)
	if err != nil {
		t.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer rc.Close()
	if len(rc.File) != 1 {
		t.Fatalf("zip has %d entries, want 1", len(rc.File))
	}
	f := rc.File[0]
	if f.Name != entry.ID+"/note.txt" {
		t.Fatalf("entry name = %q, want %s/note.txt", f.Name, entry.ID)
	}

	// f.Open() would run Go's own flate reader straight over the still
	// encrypted bytes; OpenRaw hands back exactly what Export wrote, which
	// is what the round trip is meant to exercise.
	raw, err := f.OpenRaw()
	if err != nil {
		t.Fatalf("OpenRaw failed: %v", err)
	}
	cipher, err := io.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(cipher)) != f.CompressedSize64 {
		t.Fatalf("raw length %d does not match CompressedSize64 %d", len(cipher), f.CompressedSize64)
	}
	if len(cipher) < 12 {
		t.Fatalf("raw stream shorter than the 12-byte ZipCrypto header: %d bytes", len(cipher))
	}

	dec := newDecoderState(password)
	header := make([]byte, 12)
	for i := 0; i < 12; i++ {
		header[i] = dec.decrypt(cipher[i])
	}
	if header[11] != byte(f.CRC32>>24) {
		t.Errorf("decrypted header check byte = %#x, want %#x (high byte of CRC32)", header[11], byte(f.CRC32>>24))
	}

	deflated := make([]byte, len(cipher)-12)
	for i, b := range cipher[12:] {
		deflated[i] = dec.decrypt(b)
	}

	fr := flate.NewReader(bytes.NewReader(deflated))
	defer fr.Close()
	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("inflate failed: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("round-tripped content = %q, want %q", got, content)
	}
}

func TestExportOfAnEmptyPayloadProducesAValidEmptyZip(t *testing.T) {
	storeRoot := t.TempDir()
	id := "20260101T000000Z-00000000"
	dir := filepath.Join(storeRoot, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// A tar.gz with zero entries, built directly so this test does not
	// depend on what Store happens to produce for an empty directory.
	fh, err := os.Create(filepath.Join(dir, payloadName))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "empty.zip")
	if _, err := Export(storeRoot, []string{id}, outFile, ExportOptions{Password: DefaultPassword}); err != nil {
		t.Fatalf("Export of an empty payload returned an error: %v", err)
	}

	rc, err := zip.OpenReader(outFile)
	if err != nil {
		t.Fatalf("the result is not a valid zip: %v", err)
	}
	defer rc.Close()
	if len(rc.File) != 0 {
		t.Errorf("empty payload produced %d zip entries, want 0", len(rc.File))
	}
}
