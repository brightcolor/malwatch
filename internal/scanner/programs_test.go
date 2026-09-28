package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

// elfHead is the start of a Linux program.
var elfHead = "\x7f" + "ELF" + "\x02\x01\x01\x00"

// contentSum is the SHA-256 of content as the whitelist holds it.
func contentSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestAProgramPastTheSizeLimitIsStillSeen(t *testing.T) {
	root := tree(t, map[string]string{
		"web/wp-content/uploads/a/AzimutAV": elfHead + strings.Repeat("\x00", 4096),
		"web/wp-content/ewww/cwebp":         elfHead + strings.Repeat("\x00", 4096),
		// PHP in an upload directory is a finding once the whole file is read.
		// Past the size limit only the start is, and that alone is none.
		"web/wp-content/uploads/big.php": "<?php echo 1;\n" + strings.Repeat("//\n", 2048),
	})
	opts := baseOptions(root)
	opts.MaxSize = 1024
	rep := run(t, opts)
	if got := findingsFor(rep, "/AzimutAV"); len(got) != 1 || got[0].Rule != "binary.elf_in_uploads" ||
		got[0].Size == 0 || got[0].SHA256 == "" || got[0].MTime == "" {
		t.Errorf("Programm über der Größengrenze in uploads: %+v", got)
	}
	if got := findingsFor(rep, "/cwebp"); len(got) != 1 || got[0].Rule != "binary.elf" {
		t.Errorf("Programm über der Größengrenze anderswo: %+v", got)
	}
	if got := findingsFor(rep, "/big.php"); len(got) != 0 {
		t.Errorf("der Anfang einer großen PHP-Datei ergab Funde: %+v", got)
	}
	if rep.Stats.FilesSkipped != 3 {
		t.Errorf("übersprungen %d, erwartet 3: große Dateien bleiben übersprungen, nur ihr Anfang wird angesehen",
			rep.Stats.FilesSkipped)
	}
}

func TestAWhitelistedLargeProgramStaysQuiet(t *testing.T) {
	content := elfHead + strings.Repeat("\x00", 4096)
	root := tree(t, map[string]string{"web/wp-content/uploads/a/tool": content})
	opts := baseOptions(root)
	opts.MaxSize = 1024
	opts.Whitelist = map[string]bool{contentSum(content): true}
	if got := findingsFor(run(t, opts), "/tool"); len(got) != 0 {
		t.Errorf("freigegebenes Programm gemeldet: %+v", got)
	}
}

func TestUploadDirsReachTheRules(t *testing.T) {
	root := tree(t, map[string]string{
		"web/kundendateien/run.sh": "#!/bin/sh\necho x\n",
	})
	opts := baseOptions(root)
	opts.UploadDirs = []string{"kundendateien"}
	if got := findingsFor(run(t, opts), "/run.sh"); len(got) != 1 || got[0].Rule != "shell.in_uploads" {
		t.Errorf("Shell-Skript im eingestellten Upload-Ordner: %+v", got)
	}
	opts.UploadDirs = []string{"../x"}
	if _, err := Run(opts); err == nil {
		t.Error("ein ungültiger Upload-Ordner wurde angenommen")
	}
}

func TestTheCacheFollowsTheUploadDirs(t *testing.T) {
	root := tree(t, map[string]string{"web/kundendateien/run.sh": "#!/bin/sh\necho x\n"})
	opts := baseOptions(root)
	opts.CacheFile = filepath.Join(t.TempDir(), "clean.json")
	if got := findingsFor(run(t, opts), "/run.sh"); len(got) != 0 {
		t.Fatalf("mit der Vorgabe ist kundendateien kein Upload-Ordner: %+v", got)
	}
	opts.UploadDirs = []string{"kundendateien"}
	if got := findingsFor(run(t, opts), "/run.sh"); len(got) != 1 {
		t.Errorf("nach der Änderung der Upload-Ordner blieb die Datei im Cache: %+v", got)
	}
}
