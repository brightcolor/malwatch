package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeTestFile creates path with content and mode, making parent
// directories as needed. Shared by every test in this package.
func writeTestFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func TestWriteArchiveThenReadArchiveRoundTripsAFile(t *testing.T) {
	root := t.TempDir()
	content := []byte("<?php // quarantined sample marker A")
	writeTestFile(t, filepath.Join(root, "uploads", "shell.php"), content, 0o640)

	tarPath := filepath.Join(t.TempDir(), "entry", "payload.tar.gz")
	files, bytes, err := writeArchive(tarPath, root, "uploads/shell.php")
	if err != nil {
		t.Fatalf("writeArchive failed: %v", err)
	}
	if files != 1 {
		t.Errorf("files = %d, want 1", files)
	}
	if bytes != int64(len(content)) {
		t.Errorf("bytes = %d, want %d", bytes, len(content))
	}

	destRoot := t.TempDir()
	if err := readArchive(tarPath, destRoot); err != nil {
		t.Fatalf("readArchive failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destRoot, "uploads", "shell.php"))
	if err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestWriteArchiveCountsOnlyRegularFiles(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "evil")
	a := []byte("<?php // a")
	b := []byte("<?php // b longer content")
	writeTestFile(t, filepath.Join(base, "a.php"), a, 0o644)
	writeTestFile(t, filepath.Join(base, "sub", "b.php"), b, 0o644)
	if err := os.MkdirAll(filepath.Join(base, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(t.TempDir(), "entry", "payload.tar.gz")
	files, bytes, err := writeArchive(tarPath, root, "evil")
	if err != nil {
		t.Fatalf("writeArchive failed: %v", err)
	}
	if files != 2 {
		t.Errorf("files = %d, want 2", files)
	}
	if want := int64(len(a) + len(b)); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}

	destRoot := t.TempDir()
	if err := readArchive(tarPath, destRoot); err != nil {
		t.Fatalf("readArchive failed: %v", err)
	}
	if info, err := os.Stat(filepath.Join(destRoot, "evil", "empty")); err != nil || !info.IsDir() {
		t.Errorf("empty directory did not come back: %v", err)
	}
	if info, err := os.Stat(filepath.Join(destRoot, "evil", "sub", "b.php")); err != nil || info.IsDir() {
		t.Errorf("nested file did not come back: %v", err)
	}
}

func TestWriteArchiveKeepsASymlinkAsALinkAndNeverFollowsIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	base := filepath.Join(root, "wp-content")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	linkTarget := filepath.Join(root, "does-not-exist")
	link := filepath.Join(base, "evil")
	// The target does not exist. If writeArchive ever stat'd or opened it
	// instead of reading the link itself, this would fail right here.
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(t.TempDir(), "entry", "payload.tar.gz")
	if _, _, err := writeArchive(tarPath, root, "wp-content/evil"); err != nil {
		t.Fatalf("writeArchive followed the dangling symlink: %v", err)
	}

	destRoot := t.TempDir()
	if err := readArchive(tarPath, destRoot); err != nil {
		t.Fatalf("readArchive failed: %v", err)
	}
	restored := filepath.Join(destRoot, "wp-content", "evil")
	info, err := os.Lstat(restored)
	if err != nil {
		t.Fatalf("restored link missing: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("restored entry is not a symlink: %v", info.Mode())
	}
	got, err := os.Readlink(restored)
	if err != nil {
		t.Fatal(err)
	}
	if got != linkTarget {
		t.Errorf("link target = %q, want %q", got, linkTarget)
	}
}

func TestReadArchiveRestoresTheOriginalMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not exist on Windows")
	}
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "shell.php"), []byte("<?php"), 0o600)

	tarPath := filepath.Join(t.TempDir(), "entry", "payload.tar.gz")
	if _, _, err := writeArchive(tarPath, root, "shell.php"); err != nil {
		t.Fatalf("writeArchive failed: %v", err)
	}

	destRoot := t.TempDir()
	if err := readArchive(tarPath, destRoot); err != nil {
		t.Fatalf("readArchive failed: %v", err)
	}
	info, err := os.Stat(filepath.Join(destRoot, "shell.php"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

// writeEvilTar builds a gzipped tar by hand, bypassing writeArchive - a
// payload this package produced itself never contains a name like these, but
// readArchive is the one place such a name has to be refused regardless of
// how the tar came to exist. The payloads it reads back come off a website
// that was compromised often enough to end up in quarantine in the first
// place; nothing guarantees every one was written by this package's own
// writeArchive.
func writeEvilTar(t *testing.T, dst string, entries map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReadArchiveRefusesAnEntryThatEscapesDestRoot guards W1: readArchive
// joined a tar entry's name onto destRoot with filepath.Join, which cleans a
// ".." away rather than refusing it, so an entry named "../escaped.txt"
// landed one directory above destRoot with no error at all. Restore checked
// only the nominal target built from meta.json, one path that is never the
// one actually written to, so this was the only line of defence on the
// unpack side - and it did not defend anything.
func TestReadArchiveRefusesAnEntryThatEscapesDestRoot(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "web")
	payload := filepath.Join(base, "payload.tar.gz")
	writeEvilTar(t, payload, map[string]string{"../escaped.txt": "PWNED"})

	if err := readArchive(payload, dest); err == nil {
		t.Fatal("readArchive accepted a tar entry that climbs out of destRoot")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped.txt")); !os.IsNotExist(err) {
		t.Errorf("readArchive wrote outside destRoot despite refusing: stat err = %v", err)
	}
}

// tarEntry is one entry for writeTar: a symlink to link when link is set,
// otherwise a regular file holding body.
type tarEntry struct {
	name string
	link string
	body string
}

// writeTar builds a gzipped tar from entries in their order. writeEvilTar
// takes a map, which has no order and no symlinks; an archive that plants a
// link and then writes through it needs both.
func writeTar(t *testing.T, dst string, entries []tarEntry) {
	t.Helper()
	fh, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		if e.link != "" {
			hdr = &tar.Header{Typeflag: tar.TypeSymlink, Name: e.name, Linkname: e.link, Mode: 0o777}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.link == "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReadArchiveNeverWritesThroughASymlinkOut covers both ways a link in the
// archive could carry a later entry out of destRoot: a link to a directory and
// a dangling link to a file that does not exist yet. Both are refused, and
// nothing is created outside.
func TestReadArchiveNeverWritesThroughASymlinkOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	cases := []struct {
		name    string
		entries func(outside string) []tarEntry
		escaped string
	}{
		{
			name: "dangling link to a file",
			entries: func(outside string) []tarEntry {
				return []tarEntry{
					{name: "wp-content/cache", link: filepath.Join(outside, "cron-job")},
					{name: "wp-content/cache", body: "* * * * * root sh /tmp/x\n"},
				}
			},
			escaped: "cron-job",
		},
		{
			name: "link to a directory",
			entries: func(outside string) []tarEntry {
				return []tarEntry{
					{name: "uploads", link: outside},
					{name: "uploads/shell.php", body: "<?php"},
				}
			},
			escaped: "shell.php",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			outside := filepath.Join(base, "outside")
			if err := os.MkdirAll(outside, 0o750); err != nil {
				t.Fatal(err)
			}
			payload := filepath.Join(base, "payload.tar.gz")
			writeTar(t, payload, tc.entries(outside))

			err := readArchive(payload, filepath.Join(base, "web"))
			if err == nil {
				t.Fatal("readArchive accepted an entry behind a symlink that leads out of destRoot")
			}
			// The message is all the panel shows: it has to name the link.
			if !strings.Contains(err.Error(), "symbolischen Link") {
				t.Errorf("error = %q, want it to name the symlink", err)
			}
			if _, err := os.Lstat(filepath.Join(outside, tc.escaped)); !os.IsNotExist(err) {
				t.Errorf("readArchive wrote outside destRoot: lstat err = %v", err)
			}
		})
	}
}

// TestRemoveAllInStaysBelowTheRoot: Store and a forced Restore remove through
// removeBelow and removeAllIn. A link inside the tree goes and what it points
// at stays, the same as with os.RemoveAll; a name below a link that leads out
// is refused, where os.RemoveAll, running as root, would delete the target.
func TestRemoveAllInStaysBelowTheRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	web := filepath.Join(base, "web")
	outside := filepath.Join(base, "outside")
	keep := filepath.Join(outside, "keep.txt")
	writeTestFile(t, keep, []byte("bleibt"), 0o640)
	writeTestFile(t, filepath.Join(web, "plugin", "sub", "a.php"), []byte("<?php"), 0o640)
	if err := os.Symlink(outside, filepath.Join(web, "plugin", "shared")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(web, "uploads")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(web)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := removeAllIn(root, "plugin"); err != nil {
		t.Fatalf("removeAllIn(plugin) failed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(web, "plugin")); !os.IsNotExist(err) {
		t.Errorf("plugin survived: lstat err = %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the target of a link inside the tree was removed: %v", err)
	}

	err = removeBelow(web, "uploads/keep.txt")
	if err == nil {
		t.Error("removeBelow followed a symlink out of the root")
	} else if !strings.Contains(err.Error(), "symbolischen Link") {
		t.Errorf("error = %q, want it to name the symlink", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a file outside the root was removed: %v", err)
	}
}
