package sigs

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeDB(t *testing.T, hdb, ndb string) string {
	t.Helper()
	dir := t.TempDir()
	if hdb != "" {
		if err := os.WriteFile(filepath.Join(dir, "rfxn.hdb"), []byte(hdb), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if ndb != "" {
		if err := os.WriteFile(filepath.Join(dir, "rfxn.ndb"), []byte(ndb), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "version"), []byte("2026010112345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestHashMatchAndSizeGuard(t *testing.T) {
	payload := []byte("<?php eval($_POST['x']);")
	sum := md5.Sum(payload)
	hdb := hex.EncodeToString(sum[:]) + ":" + itoa(len(payload)) + ":{MD5}php.test.shell\n"

	db, err := Load(writeDB(t, hdb, ""))
	if err != nil {
		t.Fatal(err)
	}
	name, ok := db.MatchHash(int64(len(payload)), payload)
	if !ok || name != "{MD5}php.test.shell" {
		t.Fatalf("hash not matched: %q %v", name, ok)
	}

	// The size acts as a prefilter. The same content declared with a wrong
	// size must not match, otherwise the filter would be doing nothing.
	if _, ok := db.MatchHash(int64(len(payload))+1, payload); ok {
		t.Error("hash matched despite a different size")
	}

	// A different file of the same size must not match either.
	other := make([]byte, len(payload))
	copy(other, payload)
	other[0] = 'X'
	if _, ok := db.MatchHash(int64(len(other)), other); ok {
		t.Error("a different file of the same size matched")
	}
}

func TestPatternMatch(t *testing.T) {
	// hex of "IndoXploitShell"
	ndb := "{HEX}php.test.marker:0:*:496e646f58706c6f69745368656c6c\n"
	db, err := Load(writeDB(t, "", ndb))
	if err != nil {
		t.Fatal(err)
	}
	hits := db.MatchPatterns([]byte("prefix ... IndoXploitShell ... suffix"))
	if len(hits) != 1 || hits[0] != "{HEX}php.test.marker" {
		t.Fatalf("pattern hits = %v", hits)
	}
	if got := db.MatchPatterns([]byte("nothing to see here")); len(got) != 0 {
		t.Fatalf("pattern matched clean content: %v", got)
	}
}

func TestPatternWithGap(t *testing.T) {
	// "AAAA" * "BBBB" - both parts, in this order.
	ndb := "{HEX}php.test.gap:0:*:41414141*42424242\n"
	db, err := Load(writeDB(t, "", ndb))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.MatchPatterns([]byte("xx AAAA ....... BBBB yy")); len(got) != 1 {
		t.Fatalf("gap pattern did not match: %v", got)
	}
	// Order matters: the second part before the first is not a match.
	if got := db.MatchPatterns([]byte("xx BBBB ....... AAAA yy")); len(got) != 0 {
		t.Fatalf("gap pattern matched in the wrong order: %v", got)
	}
	// One part alone is not a match.
	if got := db.MatchPatterns([]byte("xx AAAA yy")); len(got) != 0 {
		t.Fatalf("gap pattern matched on the first part alone: %v", got)
	}
}

func TestUnsupportedPatternsAreCountedNotGuessed(t *testing.T) {
	ndb := "{HEX}a:0:*:41414141\n" +
		"{HEX}b:0:*:4141??41\n" +
		"{HEX}c:0:*:41(41|42)4141\n"
	db, err := Load(writeDB(t, "", ndb))
	if err != nil {
		t.Fatal(err)
	}
	if len(db.patterns) != 1 {
		t.Fatalf("loaded %d patterns, want 1", len(db.patterns))
	}
	if db.Unsupported != 2 {
		t.Fatalf("Unsupported = %d, want 2", db.Unsupported)
	}
}

func TestMissingDirectoryIsNotAnError(t *testing.T) {
	db, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load returned an error for a missing directory: %v", err)
	}
	if !db.Empty() {
		t.Error("database reports content although nothing was loaded")
	}
	// An empty database must not report findings; otherwise a server without
	// signatures would look clean and a server with them would look infected
	// for the same file.
	if got := db.Scan("/x.php", 10, []byte("anything")); len(got) != 0 {
		t.Errorf("empty database produced findings: %v", got)
	}
}

func TestOverlappingPatternsAreBothFound(t *testing.T) {
	// "BBBB" ends inside "AABBBBAA": the failure links must surface both.
	ndb := "{HEX}long:0:*:4141424242424141\n" +
		"{HEX}short:0:*:42424242\n"
	db, err := Load(writeDB(t, "", ndb))
	if err != nil {
		t.Fatal(err)
	}
	hits := db.MatchPatterns([]byte("zzAABBBBAAzz"))
	if len(hits) != 2 {
		t.Fatalf("hits = %v, want both patterns", hits)
	}
}

func TestScanPrefersTheHashOverPatterns(t *testing.T) {
	payload := []byte("AAAA IndoXploitShell AAAA")
	sum := md5.Sum(payload)
	hdb := hex.EncodeToString(sum[:]) + ":" + itoa(len(payload)) + ":{MD5}php.test.known\n"
	ndb := "{HEX}php.test.marker:0:*:496e646f58706c6f69745368656c6c\n"

	db, err := Load(writeDB(t, hdb, ndb))
	if err != nil {
		t.Fatal(err)
	}
	got := db.Scan("/x.php", int64(len(payload)), payload)
	if len(got) != 1 || got[0].Rule != "{MD5}php.test.known" {
		t.Fatalf("Scan = %+v, want a single hash finding", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
