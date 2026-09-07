package quarantine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStoreArchivesListsAndRestoresAFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "uploads", "shell.php")
	content := []byte("<?php // quarantined sample marker A")
	writeTestFile(t, target, content, 0o640)
	storeRoot := t.TempDir()

	entry, err := Store(storeRoot, Source{
		Root: root, RelPath: "uploads/shell.php", Domain: "beispiel.de",
		Origin: "manual", Reason: "PHP-Backdoor gefunden", RuleID: "eicar", Severity: "hoch",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if entry.EntryKind != "file" {
		t.Errorf("EntryKind = %q, want file", entry.EntryKind)
	}
	if entry.Bytes != int64(len(content)) {
		t.Errorf("Bytes = %d, want %d", entry.Bytes, len(content))
	}
	if entry.ArchiveBytes <= 0 {
		t.Errorf("ArchiveBytes = %d, want > 0", entry.ArchiveBytes)
	}
	if _, err := time.Parse(time.RFC3339, entry.CreatedAt); err != nil {
		t.Errorf("CreatedAt %q is not RFC3339: %v", entry.CreatedAt, err)
	}

	// Removed only after the archive is written and verified - the whole
	// point of quarantine is that the source is not lost along the way.
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("source survived Store: %v", err)
	}

	entries, _, err := List(storeRoot)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != entry.ID {
		t.Fatalf("List = %+v, want exactly the stored entry", entries)
	}

	if err := Restore(storeRoot, entry.ID, false); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("restored content = %q, want %q", got, content)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("restored mode = %o, want 640", info.Mode().Perm())
		}
	}
}

func TestStoreCopyLeavesTheSourceInPlace(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "uploads", "shell.php")
	content := []byte("<?php // quarantined sample marker B")
	writeTestFile(t, target, content, 0o644)
	storeRoot := t.TempDir()

	entry, err := StoreCopy(storeRoot, Source{
		Root: root, RelPath: "uploads/shell.php", Domain: "beispiel.de",
		Origin: "repair", Reason: "overlay repair",
	})
	if err != nil {
		t.Fatalf("StoreCopy failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("StoreCopy removed the source: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("source content changed: %q", got)
	}
	if entry.Bytes != int64(len(content)) {
		t.Errorf("Bytes = %d, want %d", entry.Bytes, len(content))
	}
}

func TestStoreDirectoryWithSubdirSymlinkAndEmptyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	base := filepath.Join(root, "wp-content", "plugins", "evil")
	configContent := []byte("<?php // config")
	payloadContent := []byte("<?php // payload")
	writeTestFile(t, filepath.Join(base, "config.php"), configContent, 0o644)
	writeTestFile(t, filepath.Join(base, "sub", "payload.php"), payloadContent, 0o644)
	if err := os.MkdirAll(filepath.Join(base, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "config.php"), filepath.Join(base, "link.php")); err != nil {
		t.Fatal(err)
	}

	storeRoot := t.TempDir()
	entry, err := Store(storeRoot, Source{
		Root: root, RelPath: "wp-content/plugins/evil", Domain: "beispiel.de",
		Origin: "manual", Reason: "suspicious plugin",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if entry.EntryKind != "dir" {
		t.Errorf("EntryKind = %q, want dir", entry.EntryKind)
	}
	if entry.Files != 2 {
		t.Errorf("Files = %d, want 2", entry.Files)
	}
	wantBytes := int64(len(configContent) + len(payloadContent))
	if entry.Bytes != wantBytes {
		t.Errorf("Bytes = %d, want %d", entry.Bytes, wantBytes)
	}
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("source survived Store: %v", err)
	}

	if err := Restore(storeRoot, entry.ID, false); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(base, "sub", "payload.php")); err != nil || string(got) != string(payloadContent) {
		t.Errorf("nested file wrong after restore: %q, %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(base, "empty")); err != nil || !info.IsDir() {
		t.Errorf("empty directory missing after restore: %v", err)
	}
	linkInfo, err := os.Lstat(filepath.Join(base, "link.php"))
	if err != nil {
		t.Fatalf("restored link missing: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Errorf("restored entry is not a symlink: %v", linkInfo.Mode())
	}
}

func TestRestoreRefusesAnExistingTargetWithoutForce(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "uploads", "shell.php")
	original := []byte("<?php // quarantined sample marker C")
	writeTestFile(t, target, original, 0o644)
	storeRoot := t.TempDir()

	entry, err := Store(storeRoot, Source{
		Root: root, RelPath: "uploads/shell.php", Domain: "beispiel.de",
		Origin: "manual", Reason: "test",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Something now occupies the spot the quarantined file came from.
	writeTestFile(t, target, []byte("<?php // replacement"), 0o644)

	err = Restore(storeRoot, entry.ID, false)
	if err == nil {
		t.Fatal("Restore overwrote an existing target without force")
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("error %q does not name the path %q", err, target)
	}

	if err := Restore(storeRoot, entry.ID, true); err != nil {
		t.Fatalf("Restore with force failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("content after forced restore = %q, want %q", got, original)
	}
}

func TestListSkipsADirectoryWithoutReadableMeta(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "shell.php"), []byte("<?php"), 0o644)
	storeRoot := t.TempDir()

	// A directory that never got a meta.json - as a run that died between
	// writing the archive and writing the metadata would leave behind.
	if err := os.MkdirAll(filepath.Join(storeRoot, "20260101T000000Z-deadbeef"), 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := Store(storeRoot, Source{Root: root, RelPath: "shell.php", Domain: "beispiel.de", Origin: "manual", Reason: "test"}); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	entries, _, err := List(storeRoot)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1 (the half-written directory must be skipped)", len(entries))
	}
}

func TestListSortsDescendingByID(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.php"), []byte("<?php // a"), 0o644)
	writeTestFile(t, filepath.Join(root, "b.php"), []byte("<?php // b"), 0o644)
	storeRoot := t.TempDir()

	first, err := Store(storeRoot, Source{Root: root, RelPath: "a.php", Domain: "beispiel.de", Origin: "manual", Reason: "t"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Store(storeRoot, Source{Root: root, RelPath: "b.php", Domain: "beispiel.de", Origin: "manual", Reason: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("two Store calls produced the same id")
	}

	entries, _, err := List(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
	wantFirst, wantSecond := first.ID, second.ID
	if wantFirst < wantSecond {
		wantFirst, wantSecond = wantSecond, wantFirst
	}
	if entries[0].ID != wantFirst || entries[1].ID != wantSecond {
		t.Errorf("List order = [%s, %s], want [%s, %s]", entries[0].ID, entries[1].ID, wantFirst, wantSecond)
	}
}

func TestGetReturnsTheStoredEntry(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "shell.php"), []byte("<?php"), 0o644)
	storeRoot := t.TempDir()
	stored, err := Store(storeRoot, Source{
		Root: root, RelPath: "shell.php", Domain: "beispiel.de",
		Origin: "manual", Reason: "test", RuleID: "r1", Severity: "hoch",
	})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := Get(storeRoot, stored.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != stored {
		t.Errorf("Get returned %+v, want %+v", got, stored)
	}
}

func TestGetOfAnUnknownIDIsAnError(t *testing.T) {
	storeRoot := t.TempDir()
	if _, err := Get(storeRoot, "does-not-exist"); err == nil {
		t.Fatal("Get of an unknown id returned no error")
	}
}

func TestDeleteRemovesTheEntryDirectory(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "shell.php"), []byte("<?php"), 0o644)
	storeRoot := t.TempDir()
	entry, err := Store(storeRoot, Source{Root: root, RelPath: "shell.php", Domain: "beispiel.de", Origin: "manual", Reason: "test"})
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if err := Delete(storeRoot, entry.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(storeRoot, entry.ID)); !os.IsNotExist(err) {
		t.Errorf("entry directory survived Delete: %v", err)
	}
}

func TestDeleteOfAnUnknownIDIsAnErrorNotASilentSuccess(t *testing.T) {
	storeRoot := t.TempDir()
	if err := Delete(storeRoot, "does-not-exist"); err == nil {
		t.Fatal("Delete of an unknown id returned no error")
	}
}

func TestTotalBytesSumsTheEntries(t *testing.T) {
	entries := []Entry{{Bytes: 10}, {Bytes: 32}, {Bytes: 0}}
	if got := TotalBytes(entries); got != 42 {
		t.Errorf("TotalBytes = %d, want 42", got)
	}
}
