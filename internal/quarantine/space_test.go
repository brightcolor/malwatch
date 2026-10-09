package quarantine

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/diskspace"
)

const testBlock = 4096

// filesystems is a made-up set of filesystems for the space check: every
// path below one of the roots lies on the filesystem of that root, every
// other path on filesystem 1. free holds the room left per filesystem.
type filesystems struct {
	roots map[string]uint64
	free  map[uint64]int64
	asked []string
}

func newFilesystems(free int64) *filesystems {
	return &filesystems{roots: map[string]uint64{}, free: map[uint64]int64{1: free}}
}

// mount puts dir on filesystem dev with free bytes left.
func (f *filesystems) mount(dir string, dev uint64, free int64) {
	f.roots[filepath.Clean(dir)] = dev
	f.free[dev] = free
}

func (f *filesystems) stat(path string) (diskspace.Usage, error) {
	if _, err := os.Stat(path); err != nil {
		return diskspace.Usage{}, err
	}
	f.asked = append(f.asked, path)
	dev := uint64(1)
	best := -1
	for root, d := range f.roots {
		if (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) && len(root) > best {
			dev, best = d, len(root)
		}
	}
	return diskspace.Usage{Free: f.free[dev], Block: testBlock, Device: dev}, nil
}

func (f *filesystems) space(reserveMiB int64) Space {
	return Space{ReserveMiB: reserveMiB, Stat: f.stat}
}

// randomFile writes n bytes that do not compress.
func randomFile(t *testing.T, path string, n int) []byte {
	t.Helper()
	content := make([]byte, n)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, content, 0o644)
	return content
}

func spaceError(t *testing.T, err error) *SpaceError {
	t.Helper()
	var se *SpaceError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *SpaceError", err)
	}
	return se
}

// assertStoreUntouched fails when storeRoot holds anything at all: a refused
// write leaves no entry, no scratch directory and no half archive behind.
func assertStoreUntouched(t *testing.T, storeRoot string) {
	t.Helper()
	names, err := os.ReadDir(storeRoot)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(names) != 0 {
		var list []string
		for _, n := range names {
			list = append(list, n.Name())
		}
		t.Errorf("the store holds %v after a refused write, want nothing", list)
	}
}

func TestStoreWithoutRoomLeavesTheFileAndTheStoreAsTheyWere(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "wp-content", "uploads", "shell.php")
	content := randomFile(t, victim, 64<<10)
	storeRoot := t.TempDir()
	disks := newFilesystems(200 << 20)

	_, err := StoreWith(storeRoot, Source{Root: root, RelPath: "wp-content/uploads/shell.php"}, disks.space(256))
	se := spaceError(t, err)

	got, readErr := os.ReadFile(victim)
	if readErr != nil || !bytes.Equal(got, content) {
		t.Fatalf("the file changed after a refused store: %v", readErr)
	}
	assertStoreUntouched(t, storeRoot)

	if se.Dir != storeRoot || se.Free != 200<<20 || se.Reserve != 256<<20 {
		t.Errorf("SpaceError = %+v, want the store, 200 MiB free and 256 MiB reserve", se)
	}
	msg := err.Error()
	for _, want := range []string{
		"Auf " + storeRoot + " reicht der Platz nicht",
		"frei sind 200,0 MiB",
		"davon 256,0 MiB Reserve",
		"wp-content/uploads/shell.php bleibt unverändert liegen.",
		"Platz schaffen oder die Reserve senken (--quarantine-reserve), danach erneut versuchen.",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

// The reserve is a setting: the same file and the same free space are
// stored with one value and refused with another.
func TestStoreFollowsTheReserveItIsGiven(t *testing.T) {
	for _, c := range []struct {
		reserveMiB int64
		fits       bool
	}{
		{0, true},
		{6, true},
		{9, false},
		{DefaultReserveMiB, false},
	} {
		root := t.TempDir()
		randomFile(t, filepath.Join(root, "probe.bin"), 1<<20)
		storeRoot := t.TempDir()
		disks := newFilesystems(10 << 20)

		_, err := StoreWith(storeRoot, Source{Root: root, RelPath: "probe.bin"}, disks.space(c.reserveMiB))
		if c.fits && err != nil {
			t.Errorf("reserve %d MiB: refused although 10 MiB are free for a 1 MiB file: %v", c.reserveMiB, err)
		}
		if !c.fits {
			if se := spaceError(t, err); se.Reserve != c.reserveMiB<<20 {
				t.Errorf("reserve %d MiB: SpaceError.Reserve = %d", c.reserveMiB, se.Reserve)
			}
			if _, statErr := os.Stat(filepath.Join(root, "probe.bin")); statErr != nil {
				t.Errorf("reserve %d MiB: the file is gone after a refused store", c.reserveMiB)
			}
		}
	}
}

// Store needs room for the archive and for the copy it unpacks to read the
// archive back: a file of 4 MiB does not fit into 7 MiB, whatever the
// reserve.
func TestStoreCountsTheArchiveAndTheCopyItReadsBack(t *testing.T) {
	root := t.TempDir()
	randomFile(t, filepath.Join(root, "probe.bin"), 4<<20)

	disks := newFilesystems(7 << 20)
	_, err := StoreCopyWith(t.TempDir(), Source{Root: root, RelPath: "probe.bin"}, disks.space(0))
	if se := spaceError(t, err); se.Need <= 8<<20 {
		t.Errorf("Need = %d, want more than twice the 4 MiB file", se.Need)
	}

	disks = newFilesystems(9 << 20)
	if _, err := StoreCopyWith(t.TempDir(), Source{Root: root, RelPath: "probe.bin"}, disks.space(0)); err != nil {
		t.Errorf("9 MiB for a file of 4 MiB: %v", err)
	}
}

func TestStoreMeasuresAStoreDirectoryThatDoesNotExistYet(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.php"), []byte("<?php // a"), 0o644)
	base := t.TempDir()
	storeRoot := filepath.Join(base, "quarantine", "web1")
	disks := newFilesystems(1 << 30)

	if _, err := StoreWith(storeRoot, Source{Root: root, RelPath: "a.php"}, disks.space(1)); err != nil {
		t.Fatalf("StoreWith: %v", err)
	}
	if len(disks.asked) == 0 || disks.asked[0] != base {
		t.Errorf("measured %v, want the nearest existing directory %s first", disks.asked, base)
	}
}

// Several sources stored as one step are checked together: each would fit
// alone, both do not, so neither is touched.
func TestCheckStoreAddsUpTheArchivesOfAllSources(t *testing.T) {
	root := t.TempDir()
	randomFile(t, filepath.Join(root, "a.bin"), 2<<20)
	randomFile(t, filepath.Join(root, "b.bin"), 2<<20)
	storeRoot := t.TempDir()
	srcs := []Source{{Root: root, RelPath: "a.bin"}, {Root: root, RelPath: "b.bin"}}
	disks := newFilesystems(5 << 20)

	for _, src := range srcs {
		if err := CheckStore(storeRoot, []Source{src}, disks.space(0)); err != nil {
			t.Fatalf("%s alone: %v", src.RelPath, err)
		}
	}
	err := CheckStore(storeRoot, srcs, disks.space(0))
	if !strings.Contains(spaceError(t, err).Kept, "a.bin und b.bin bleiben unverändert liegen") {
		t.Errorf("Kept = %q, want both names", spaceError(t, err).Kept)
	}

	srcs = append(srcs, Source{Root: root, RelPath: "a.bin"}, Source{Root: root, RelPath: "b.bin"})
	err = CheckStore(storeRoot, srcs, disks.space(0))
	if kept := spaceError(t, err).Kept; kept != "a.bin, b.bin und 2 weitere bleiben unverändert liegen." {
		t.Errorf("Kept = %q", kept)
	}
}

func storedEntry(t *testing.T, size int) (root, storeRoot string, entry Entry, content []byte) {
	t.Helper()
	root = t.TempDir()
	target := filepath.Join(root, "wp-content", "plugins", "probe", "probe.bin")
	content = randomFile(t, target, size)
	storeRoot = t.TempDir()
	entry, err := Store(storeRoot, Source{Root: root, RelPath: "wp-content/plugins/probe"})
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	return root, storeRoot, entry, content
}

func TestRestoreWithoutRoomOnTheWebsiteKeepsTheEntry(t *testing.T) {
	root, storeRoot, entry, _ := storedEntry(t, 1<<20)
	disks := newFilesystems(1 << 30)
	disks.mount(root, 2, 3<<20)

	err := RestoreWith(storeRoot, entry.ID, false, disks.space(4))
	se := spaceError(t, err)
	if se.Dir != root || se.Free != 3<<20 {
		t.Errorf("SpaceError = %+v, want the web root with 3 MiB free", se)
	}
	if !strings.Contains(err.Error(), "Der Eintrag "+entry.ID+" bleibt in der Quarantäne, wp-content/plugins/probe unverändert.") {
		t.Errorf("message %q does not say the entry stays", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "wp-content", "plugins", "probe")); !os.IsNotExist(statErr) {
		t.Errorf("a refused restore wrote to the website: %v", statErr)
	}
	if _, getErr := Get(storeRoot, entry.ID); getErr != nil {
		t.Errorf("the entry is gone after a refused restore: %v", getErr)
	}

	// The same restore with a smaller reserve fits.
	if err := RestoreWith(storeRoot, entry.ID, false, disks.space(1)); err != nil {
		t.Fatalf("RestoreWith with 1 MiB reserve: %v", err)
	}
}

// With --force the payload goes into a scratch directory of the store first.
// On a filesystem of its own, the store has to hold that copy.
func TestRestoreForceNeedsRoomForTheScratchCopyInTheStore(t *testing.T) {
	root, storeRoot, entry, _ := storedEntry(t, 1<<20)
	live := []byte("LIVE")
	writeTestFile(t, filepath.Join(root, "wp-content", "plugins", "probe", "live.txt"), live, 0o644)

	disks := newFilesystems(1 << 30)
	disks.mount(storeRoot, 2, 512<<10)
	err := RestoreWith(storeRoot, entry.ID, true, disks.space(0))
	if se := spaceError(t, err); se.Dir != storeRoot {
		t.Errorf("SpaceError.Dir = %s, want the store %s", se.Dir, storeRoot)
	}
	got, readErr := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "probe", "live.txt"))
	if readErr != nil || !bytes.Equal(got, live) {
		t.Errorf("the live content changed after a refused restore --force: %v", readErr)
	}
	if _, statErr := os.Stat(filepath.Join(storeRoot, entry.ID+".restore")); !os.IsNotExist(statErr) {
		t.Errorf("a refused restore left its scratch directory: %v", statErr)
	}
}

// What --force removes at the target counts as given back: on one
// filesystem, a restore over a tree of the same size needs room for one copy,
// not for two.
func TestRestoreForceCountsWhatItRemovesAtTheTarget(t *testing.T) {
	root, storeRoot, entry, content := storedEntry(t, 1<<20)
	randomFile(t, filepath.Join(root, "wp-content", "plugins", "probe", "probe.bin"), 1<<20)

	disks := newFilesystems(1536 << 10)
	if err := RestoreWith(storeRoot, entry.ID, true, disks.space(0)); err != nil {
		t.Fatalf("RestoreWith --force over a tree of the same size, 1.5 MiB free: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "probe", "probe.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("the restored file differs: %v", err)
	}
}

func TestRestoreRefusesAnUnreadablePayloadBeforeWritingAnything(t *testing.T) {
	root, storeRoot, entry, _ := storedEntry(t, 4<<10)
	if err := os.WriteFile(filepath.Join(storeRoot, entry.ID, payloadName), []byte("kein gzip"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := Restore(storeRoot, entry.ID, false)
	if err == nil || !strings.Contains(err.Error(), "ist unlesbar") {
		t.Fatalf("err = %v, want the payload named unreadable", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "wp-content", "plugins", "probe")); !os.IsNotExist(statErr) {
		t.Errorf("an unreadable payload left something at the target: %v", statErr)
	}
}

func TestExportWithoutRoomWritesNoArchive(t *testing.T) {
	_, storeRoot, entry, _ := storedEntry(t, 2<<20)
	outDir := filepath.Join(t.TempDir(), "spool")
	outFile := filepath.Join(outDir, "token.zip")
	disks := newFilesystems(3 << 20)

	_, err := Export(storeRoot, []string{entry.ID}, outFile, ExportOptions{Password: DefaultPassword, Space: disks.space(1)})
	se := spaceError(t, err)
	if se.Dir != outDir || !strings.Contains(err.Error(), "Es wurde kein ZIP geschrieben.") {
		t.Errorf("SpaceError = %+v, want the directory of the archive and no archive", se)
	}
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Errorf("a refused export created %s: %v", outDir, statErr)
	}

	if _, err := Export(storeRoot, []string{entry.ID}, outFile, ExportOptions{Password: DefaultPassword, Space: disks.space(0)}); err == nil {
		t.Errorf("an archive of 2 MiB plus its scratch file fit into 3 MiB")
	}
	disks = newFilesystems(5 << 20)
	if _, err := Export(storeRoot, []string{entry.ID}, outFile, ExportOptions{Password: DefaultPassword, Space: disks.space(0)}); err != nil {
		t.Errorf("5 MiB for an archive of 2 MiB: %v", err)
	}
}

// Export streams: a file several MiB large comes out whole, deflated and
// enciphered, and the scratch file it went through is gone afterwards.
func TestExportStreamsALargeFileAndLeavesNoScratchFile(t *testing.T) {
	root := t.TempDir()
	content := randomFile(t, filepath.Join(root, "big.bin"), 6<<20)
	writeTestFile(t, filepath.Join(root, "small.txt"), []byte("klein"), 0o644)
	storeRoot := t.TempDir()
	entry, err := Store(storeRoot, Source{Root: root, RelPath: "big.bin"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Store(storeRoot, Source{Root: root, RelPath: "small.txt"})
	if err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "sample.zip")
	results, err := Export(storeRoot, []string{entry.ID, second.ID}, outFile, ExportOptions{Password: "probe"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s: %v", r.ID, r.Err)
		}
	}
	left, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Name() != "sample.zip" {
		var names []string
		for _, n := range left {
			names = append(names, n.Name())
		}
		t.Errorf("the directory holds %v, want only sample.zip", names)
	}

	rc, err := zip.OpenReader(outFile)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var big *zip.File
	for _, f := range rc.File {
		if f.Name == entry.ID+"/big.bin" {
			big = f
		}
	}
	if big == nil {
		t.Fatalf("the archive lacks %s/big.bin", entry.ID)
	}
	if got := decipher(t, big, "probe"); !bytes.Equal(got, content) {
		t.Errorf("big.bin comes back with %d bytes, not the %d written", len(got), len(content))
	}
}

// decipher reads one entry the way an unpacker with the password does.
func decipher(t *testing.T, f *zip.File, password string) []byte {
	t.Helper()
	raw, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := io.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	dec := newDecoderState(password)
	plain := make([]byte, len(cipher))
	for i, b := range cipher {
		plain[i] = dec.decrypt(b)
	}
	if plain[11] != byte(f.CRC32>>24) {
		t.Fatalf("%s: check byte %#x, want the high byte of the CRC", f.Name, plain[11])
	}
	content, err := io.ReadAll(flate.NewReader(bytes.NewReader(plain[12:])))
	if err != nil {
		t.Fatal(err)
	}
	if crc32.ChecksumIEEE(content) != f.CRC32 {
		t.Fatalf("%s: CRC does not match the content", f.Name)
	}
	return content
}

func TestExportLeavesOutAnUnreadableEntryAndKeepsTheOthers(t *testing.T) {
	_, storeRoot, good, _ := storedEntry(t, 4<<10)
	_, otherStore, broken, _ := storedEntry(t, 4<<10)
	// Both entries in one store, the second one damaged.
	if err := os.Rename(filepath.Join(otherStore, broken.ID), filepath.Join(storeRoot, broken.ID)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeRoot, broken.ID, payloadName), []byte("kein gzip"), 0o640); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "sample.zip")
	results, err := Export(storeRoot, []string{broken.ID, "20260101T000000Z-00000000", good.ID}, outFile,
		ExportOptions{Password: DefaultPassword})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "ist unlesbar") {
		t.Errorf("the damaged entry: %v", results[0].Err)
	}
	if results[1].Err == nil || !strings.Contains(results[1].Err.Error(), "nicht gefunden") {
		t.Errorf("the unknown id: %v", results[1].Err)
	}
	if results[2].Err != nil {
		t.Errorf("the good entry: %v", results[2].Err)
	}
	rc, err := zip.OpenReader(outFile)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	for _, f := range rc.File {
		if !strings.HasPrefix(f.Name, good.ID+"/") {
			t.Errorf("the archive holds %s, want only entries of %s", f.Name, good.ID)
		}
	}
}

func TestExportWithoutAReadableEntryWritesNoArchive(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "sample.zip")
	results, err := Export(t.TempDir(), []string{"20260101T000000Z-00000000"}, outFile, ExportOptions{Password: DefaultPassword})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if results[0].Err == nil {
		t.Error("an unknown id came back without an error")
	}
	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Errorf("an export without an entry wrote %s", outFile)
	}
}

func TestCheckReserveTakesTheRangeAndNamesIt(t *testing.T) {
	for _, ok := range []int64{MinReserveMiB, 1, DefaultReserveMiB, MaxReserveMiB} {
		if err := CheckReserve(ok); err != nil {
			t.Errorf("CheckReserve(%d) = %v", ok, err)
		}
	}
	for _, bad := range []int64{MinReserveMiB - 1, MaxReserveMiB + 1} {
		err := CheckReserve(bad)
		if err == nil {
			t.Errorf("CheckReserve(%d) accepted", bad)
			continue
		}
		want := fmt.Sprintf("--quarantine-reserve=%d liegt außerhalb der Grenzen: erlaubt sind %d bis %d MiB, Vorgabe %d",
			bad, MinReserveMiB, MaxReserveMiB, DefaultReserveMiB)
		if err.Error() != want {
			t.Errorf("CheckReserve(%d) = %q, want %q", bad, err, want)
		}
	}
}

func TestSizeText(t *testing.T) {
	for n, want := range map[int64]string{
		0:               "0 B",
		1023:            "1023 B",
		1024:            "1,0 KiB",
		1536:            "1,5 KiB",
		256 << 20:       "256,0 MiB",
		3<<30 + 512<<20: "3,5 GiB",
		1<<40 + 103<<30: "1,1 TiB",
	} {
		if got := SizeText(n); got != want {
			t.Errorf("SizeText(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPayloadTallyCountsWhatTheArchiveHolds(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "d", "a.txt"), []byte("12345"), 0o644)
	writeTestFile(t, filepath.Join(root, "d", "sub", "b.txt"), []byte("1234567"), 0o644)
	payload := filepath.Join(t.TempDir(), "p", payloadName)
	if _, _, err := writeArchive(payload, root, "d"); err != nil {
		t.Fatal(err)
	}
	got, err := payloadTally(payload)
	if err != nil {
		t.Fatalf("payloadTally: %v", err)
	}
	if got.files != 2 || got.dirs != 2 || got.bytes != 12 || got.biggest != 7 {
		t.Errorf("tally = %+v, want 2 files, 2 directories, 12 bytes, the largest 7", got)
	}

	var measured tally
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := measureTree(r, "d", &measured); err != nil {
		t.Fatal(err)
	}
	if measured.files != got.files || measured.dirs != got.dirs || measured.bytes != got.bytes || measured.names != got.names {
		t.Errorf("measureTree = %+v, payloadTally = %+v: both count the same tree", measured, got)
	}

	raw, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, raw[:len(raw)-6], 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := payloadTally(payload); err == nil {
		t.Error("a truncated archive passed")
	}
}

// The estimate of an archive is an upper bound: what writeArchive actually
// writes stays below it, for a tree of many small files as for one that does
// not compress.
func TestTheArchiveStaysWithinItsEstimate(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		writeTestFile(t, filepath.Join(root, "tree", "sub"+strings.Repeat("x", i), "f.txt"), []byte(strings.Repeat("a", i)), 0o644)
	}
	randomFile(t, filepath.Join(root, "tree", "random.bin"), 300<<10)
	writeTestFile(t, filepath.Join(root, "tree", strings.Repeat("lang", 40)+".php"), []byte("<?php"), 0o644)

	payload := filepath.Join(t.TempDir(), "p", payloadName)
	if _, _, err := writeArchive(payload, root, "tree"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(payload)
	if err != nil {
		t.Fatal(err)
	}
	measured, err := measureSource(Source{Root: root, RelPath: "tree"})
	if err != nil {
		t.Fatal(err)
	}
	if bound := payloadBound(measured, 1); info.Size() > bound {
		t.Errorf("the archive has %d bytes, the estimate %d", info.Size(), bound)
	}
}
