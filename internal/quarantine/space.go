package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brightcolor/malwatch/internal/diskspace"
	"github.com/brightcolor/malwatch/internal/rootio"
)

// The reserve, in MiB: the room every write of the quarantine leaves free on
// the filesystem it writes to - storing, restoring and packing a sample.
// --quarantine-reserve and the setting of the ISPConfig addon take it within
// MinReserveMiB and MaxReserveMiB; DefaultReserveMiB holds while nobody sets
// another. The addon keeps the same three values (malwatch_quarantine_settings
// and malwatch_helper::QUARANTINE_RESERVE, held together by
// ispconfig/tests/quarantine_space_test.php).
const (
	DefaultReserveMiB = 256
	MinReserveMiB     = 0
	MaxReserveMiB     = 1048576
)

// CheckReserve says why mib cannot serve as the reserve, or returns nil.
func CheckReserve(mib int64) error {
	if mib < MinReserveMiB || mib > MaxReserveMiB {
		return fmt.Errorf("--quarantine-reserve=%d liegt außerhalb der Grenzen: erlaubt sind %d bis %d MiB, Vorgabe %d",
			mib, MinReserveMiB, MaxReserveMiB, DefaultReserveMiB)
	}
	return nil
}

// Space says how a write of the quarantine measures its room.
//
// Before the first byte, every write adds up what it puts on each filesystem
// it touches - the archive, the copy it unpacks to check that archive, the
// files it brings back, the sample it packs - and compares the peak with the
// free space there, the reserve on top. A write that does not fit is refused
// with a *SpaceError, and nothing has changed.
type Space struct {
	// ReserveMiB is the room, in MiB, a write leaves free on every
	// filesystem it writes to. Zero leaves none; the commands fill it from
	// --quarantine-reserve.
	ReserveMiB int64
	// Stat measures the filesystem behind a path; nil means diskspace.Stat.
	// A test puts its own in, so the check answers the same on every machine.
	Stat func(path string) (diskspace.Usage, error)
}

// DefaultSpace measures the real filesystems with the default reserve.
func DefaultSpace() Space { return Space{ReserveMiB: DefaultReserveMiB} }

// SpaceError says that a filesystem lacks the room a step of the quarantine
// needs. The step has written nothing.
type SpaceError struct {
	Dir     string // where the step writes; its filesystem lacks the room
	Free    int64  // what that filesystem has left, in bytes
	Need    int64  // what the step needs there, the reserve included
	Reserve int64  // the part of Need that stays free
	Kept    string // what stays as it was, as a sentence
}

func (e *SpaceError) Error() string {
	return fmt.Sprintf("Auf %s reicht der Platz nicht: frei sind %s, gebraucht werden %s, davon %s Reserve. %s "+
		"Platz schaffen oder die Reserve senken (--quarantine-reserve), danach erneut versuchen.",
		e.Dir, SizeText(e.Free), SizeText(e.Need), SizeText(e.Reserve), e.Kept)
}

// SizeText writes n bytes the way the messages show a size: with a binary
// prefix and one decimal, a comma before the decimal.
func SizeText(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(n) / 1024
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	return strings.Replace(fmt.Sprintf("%.1f %s", value, units[i]), ".", ",", 1)
}

// ledger adds up, in order, what one operation writes and frees on each
// filesystem, and checks the peak of every filesystem against its free space.
type ledger struct {
	space Space
	parts []*ledgerPart
}

// ledgerPart is one filesystem of a ledger.
type ledgerPart struct {
	dir   string // the first directory named on it, for the message
	usage diskspace.Usage
	now   int64 // written minus freed so far
	peak  int64
}

// on returns the part of the filesystem that holds dir. dir need not exist
// yet: the nearest directory above it that does is measured.
func (l *ledger) on(dir string) (*ledgerPart, error) {
	stat := l.space.Stat
	if stat == nil {
		stat = diskspace.Stat
	}
	usage, err := statNearest(stat, dir)
	if err != nil {
		return nil, fmt.Errorf("der freie Platz auf %s lässt sich nicht messen (%w); Pfad und Rechte prüfen, danach erneut versuchen",
			dir, err)
	}
	for _, p := range l.parts {
		if p.usage.Device == usage.Device {
			return p, nil
		}
	}
	p := &ledgerPart{dir: dir, usage: usage}
	l.parts = append(l.parts, p)
	return p, nil
}

// statNearest measures dir, or the nearest directory above it that exists.
func statNearest(stat func(string) (diskspace.Usage, error), dir string) (diskspace.Usage, error) {
	p := filepath.Clean(dir)
	for {
		usage, err := stat(p)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			return usage, err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return usage, err
		}
		p = parent
	}
}

func (p *ledgerPart) write(n int64) {
	p.now += n
	if p.now > p.peak {
		p.peak = p.now
	}
}

func (p *ledgerPart) free(n int64) { p.now -= n }

// block is the unit files take up space in on this filesystem, at least 1.
func (p *ledgerPart) block() int64 {
	if p.usage.Block > 0 {
		return p.usage.Block
	}
	return 1
}

// check refuses with a *SpaceError the first filesystem whose peak and
// reserve exceed its free space. kept says what stays as it was. A
// filesystem the operation only frees room on needs no room at all.
func (l *ledger) check(kept string) error {
	reserve := l.space.ReserveMiB << 20
	for _, p := range l.parts {
		if p.peak <= 0 {
			continue
		}
		if need := p.peak + reserve; p.usage.Free < need {
			return &SpaceError{Dir: p.dir, Free: p.usage.Free, Need: need, Reserve: reserve, Kept: kept}
		}
	}
	return nil
}

// tally counts a tree the way the estimates need it.
type tally struct {
	files     int64 // regular files
	dirs      int64
	links     int64 // symbolic links
	others    int64 // sockets, devices, pipes: a header and no content
	bytes     int64 // the content of the regular files
	names     int64 // the length of every name, in bytes
	long      int64 // entries whose name or link target needs a PAX header
	longBytes int64 // the length of those names and link targets
	biggest   int64 // the largest regular file
	allocated int64 // the room the tree gives back once removed (measureTree only)
}

func (t *tally) entries() int64 { return t.files + t.dirs + t.links + t.others }

func (t *tally) add(name, link string, mode fs.FileMode, size int64) {
	switch {
	case mode.IsRegular():
		t.files++
		t.bytes += size
		if size > t.biggest {
			t.biggest = size
		}
	case mode.IsDir():
		t.dirs++
	case mode&fs.ModeSymlink != 0:
		t.links++
	default:
		t.others++
	}
	t.names += int64(len(name))
	if needsPAX(name) || needsPAX(link) {
		t.long++
		t.longBytes += int64(len(name) + len(link))
	}
}

// needsPAX reports whether archive/tar keeps s in a PAX record: a name or link
// target longer than a ustar header holds, or one with a character outside
// ASCII.
func needsPAX(s string) bool {
	if len(s) > ustarName {
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// The sizes the estimates rest on. Each comes from a format, so none of them
// is a setting.
const (
	// tarBlock: tar keeps every header and the content of every file in
	// blocks of 512 bytes, and two empty blocks close an archive (POSIX
	// ustar).
	tarBlock = 512
	// ustarName is the longest name and link target a ustar header holds
	// for certain; archive/tar puts a PAX header with its records in front
	// of an entry with a longer one or one outside ASCII.
	ustarName = 100
	// gzipFrame is the 10 byte header and the 8 byte trailer of RFC 1952.
	gzipFrame = 18
	// direntBytes is the most a directory spends on an entry besides its
	// name: ext4 and its relatives keep an 8 byte header per entry and pad
	// the name to 4 bytes.
	direntBytes = 12
	// The ZIP of a sample (PKWARE APPNOTE): a local header of 30 and a
	// central header of 46 bytes per entry, each with the name; the extended
	// timestamp archive/zip adds for Modified (9 bytes) and a zip64 field for
	// a large file (20 and 28 bytes) in both; the 12 byte header of
	// ZipCrypto per file; the end of the central directory (22 bytes) and its
	// zip64 record and locator (56 and 20 bytes).
	zipEntryBytes   = 30 + 46 + 2*9 + 20 + 28
	zipCryptoHeader = 12
	zipEndBytes     = 22 + 56 + 20
)

// deflateBound is the most deflate makes of n bytes, the bound zlib documents
// for its deflateBound: data that does not shrink goes into stored blocks,
// with five bytes of header for every block of 16 KiB. It adds up over files:
// the sum of the bounds of several files is at most the bound of their sum
// plus 13 bytes for each further file.
func deflateBound(n int64) int64 { return n + n>>12 + n>>14 + n>>25 + 13 }

func roundUp(n, block int64) int64 {
	if block <= 1 || n <= 0 {
		return n
	}
	return (n + block - 1) / block * block
}

// tarBound is the most archive/tar writes for t: a header per entry; in
// front of an entry with a long name a PAX header, its records - the name and
// link target, the keys and lengths, other values that did not fit - and the
// padding of those to a whole block; the content padded to whole blocks; and
// the two blocks that close the archive.
func tarBound(t tally) int64 {
	return (t.entries()+3*t.long+2)*tarBlock + t.longBytes + t.bytes + t.files*(tarBlock-1)
}

// payloadBound is the most a payload.tar.gz of t takes up on disk. The
// estimate assumes nothing shrinks: how well the files pack is unknown until
// they are packed.
func payloadBound(t tally, block int64) int64 {
	return roundUp(deflateBound(tarBound(t))+gzipFrame, block)
}

// treeBound is the most the unpacked t takes up on disk: every file in whole
// blocks, a block for every directory and link, the entries in the
// directories that hold them, and extra directories along the way.
func treeBound(t tally, block, extraDirs int64) int64 {
	return t.bytes + t.files*(block-1) + (t.dirs+t.links+extraDirs)*block + t.names + t.entries()*direntBytes
}

// zipBound is the most the files and directories of t add to a ZIP when every
// name in it carries prefix more bytes.
func zipBound(t tally, prefix int64) int64 {
	entries := t.files + t.dirs
	return entries*(zipEntryBytes+2*(prefix+1)) + 2*t.names + t.files*(zipCryptoHeader+13) + deflateBound(t.bytes)
}

// depth is the number of directories rel lies in below its root.
func depth(rel string) int64 {
	return int64(strings.Count(strings.Trim(filepath.ToSlash(rel), "/"), "/"))
}

// measureTree counts name below root and, for a directory, everything in it.
// It walks the way packEntry does: every step through root, a symlink as the
// link it is.
func measureTree(root *os.Root, name string, t *tally) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	link := ""
	if info.Mode()&fs.ModeSymlink != 0 {
		if link, err = rootio.ReadlinkIn(root, name); err != nil {
			return err
		}
	}
	t.add(filepath.ToSlash(name), link, info.Mode(), info.Size())
	t.allocated += diskspace.Allocated(info)
	if !info.IsDir() {
		return nil
	}
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	children, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, c := range children {
		if err := measureTree(root, filepath.Join(name, c.Name()), t); err != nil {
			return err
		}
	}
	return nil
}

// measureSource counts what src names below its root.
func measureSource(src Source) (tally, error) {
	var t tally
	root, err := os.OpenRoot(src.Root)
	if err != nil {
		return t, err
	}
	defer root.Close()
	if err := measureTree(root, filepath.Clean(filepath.FromSlash(src.RelPath)), &t); err != nil {
		return t, err
	}
	return t, nil
}

// payloadTally reads the archive at payload to its end and counts what it
// holds. Reading all of it, the gzip checksum included, proves the archive is
// whole before anything acts on it.
func payloadTally(payload string) (tally, error) {
	var t tally
	fh, err := os.Open(payload)
	if err != nil {
		return t, err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return t, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return t, err
		}
		t.add(hdr.Name, hdr.Linkname, hdr.FileInfo().Mode(), hdr.Size)
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return t, err
	}
	return t, nil
}

// CheckStore measures storing srcs into storeRoot one after another, the way
// Store and StoreCopy write: per source an entry directory, the archive, the
// copy unpacked once to read it back (removed again right after) and
// meta.json. It refuses with a *SpaceError when the store's filesystem lacks
// the room; nothing has been written then.
//
// A caller that stores several sources as one step checks them together
// first, so that a shortage stops the step before the first of them leaves
// its place.
func CheckStore(storeRoot string, srcs []Source, space Space) error {
	l := ledger{space: space}
	store, err := l.on(storeRoot)
	if err != nil {
		return err
	}
	block := store.block()
	for _, src := range srcs {
		t, err := measureSource(src)
		if err != nil {
			return err
		}
		verify := treeBound(t, block, depth(src.RelPath)+1)
		store.write(block + payloadBound(t, block))
		store.write(verify)
		store.free(verify)
		store.write(block)
	}
	return l.check(keptSources(srcs))
}

// keptSources says that srcs stay where they are, naming the first two.
func keptSources(srcs []Source) string {
	switch len(srcs) {
	case 0:
		return "Es wurde nichts abgelegt."
	case 1:
		return srcs[0].RelPath + " bleibt unverändert liegen."
	case 2:
		return srcs[0].RelPath + " und " + srcs[1].RelPath + " bleiben unverändert liegen."
	}
	return fmt.Sprintf("%s, %s und %d weitere bleiben unverändert liegen.",
		srcs[0].RelPath, srcs[1].RelPath, len(srcs)-2)
}

// checkRestore measures what restoring entry writes: the payload unpacked at
// the target, and with overwrite first into a scratch directory of the store,
// after which the target's old content goes.
func checkRestore(storeRoot string, entry Entry, t tally, overwrite bool, space Space) error {
	l := ledger{space: space}
	web, err := l.on(entry.Root)
	if err != nil {
		return err
	}
	parents := depth(entry.RelPath)
	if !overwrite {
		web.write(treeBound(t, web.block(), parents))
		return l.check(keptRestore(entry))
	}

	store, err := l.on(storeRoot)
	if err != nil {
		return err
	}
	var old tally
	if root, err := os.OpenRoot(entry.Root); err == nil {
		// What the target gives back is only counted when it can be
		// measured; without it the check asks for more room, never less.
		if measureTree(root, filepath.Clean(filepath.FromSlash(entry.RelPath)), &old) != nil {
			old = tally{}
		}
		root.Close()
	}
	scratch := treeBound(t, store.block(), parents+1)
	store.write(scratch)
	web.free(old.allocated)
	web.write(treeBound(t, web.block(), parents))
	store.free(scratch)
	return l.check(keptRestore(entry))
}

func keptRestore(entry Entry) string {
	return "Der Eintrag " + entry.ID + " bleibt in der Quarantäne, " + entry.RelPath + " unverändert."
}
