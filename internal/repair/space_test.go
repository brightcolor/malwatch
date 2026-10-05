package repair

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/diskspace"
	"github.com/brightcolor/malwatch/internal/quarantine"
)

// smallDisk puts dir on a filesystem of capacity bytes, minus what dir holds
// right now; every other path has plenty of room. Each measurement reads dir
// afresh, so what a run has written there counts against it.
func smallDisk(t *testing.T, dir string, capacity int64) func(string) (diskspace.Usage, error) {
	t.Helper()
	return func(path string) (diskspace.Usage, error) {
		if _, err := os.Stat(path); err != nil {
			return diskspace.Usage{}, err
		}
		if path != dir && !strings.HasPrefix(path, dir+string(filepath.Separator)) {
			return diskspace.Usage{Free: 1 << 40, Block: 4096, Device: 1}, nil
		}
		var used int64
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || p == dir {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			used += (info.Size() + 4095) / 4096 * 4096
			if d.IsDir() {
				used += 4096
			}
			return nil
		})
		return diskspace.Usage{Free: capacity - used, Block: 4096, Device: 2}, err
	}
}

// The core goes into quarantine as one step: with room for wp-admin alone,
// neither wp-admin nor wp-includes leaves its place, so the website keeps a
// whole core.
func TestRepairCoreWithoutRoomForAllPartsTouchesNothing(t *testing.T) {
	const index = "<?php // index, wie beim Hersteller\n"
	root := coreOnlyRoot(t, index)
	staged := t.TempDir()
	writeFileTree(t, staged, map[string]string{
		"wp-admin/admin.php":      "<?php // neu",
		"wp-includes/version.php": "<?php // neu",
		"index.php":               index,
	})
	store := t.TempDir()

	opts := Options{Root: root, QuarantineDir: store, Space: quarantine.Space{Stat: smallDisk(t, store, 28<<10)}}
	_, ids, err := repairCore(opts, "replace", staged)
	var se *quarantine.SpaceError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *SpaceError", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want none", ids)
	}
	if !strings.Contains(se.Kept, "wp-admin und wp-includes bleiben unverändert liegen") {
		t.Errorf("Kept = %q", se.Kept)
	}
	for _, rel := range []string{"wp-admin/admin.php", "wp-includes/version.php"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s is gone after a refused repair: %v", rel, err)
		}
	}
	if entries, _, _ := quarantine.List(store); len(entries) != 0 {
		t.Errorf("the store holds %d entries after a refused repair", len(entries))
	}

	// With room for both, the same repair goes through.
	opts.Space = quarantine.Space{Stat: smallDisk(t, store, 64<<10)}
	if _, ids, err := repairCore(opts, "replace", staged); err != nil || len(ids) != 2 {
		t.Fatalf("with 64 KiB: ids %v, err %v", ids, err)
	}
}

func TestReplaceDirWithoutRoomLeavesThePluginAndTheRelease(t *testing.T) {
	root := t.TempDir()
	writeFileTree(t, root, map[string]string{"wp-content/plugins/akismet/akismet.php": "<?php // 5.3.0"})
	plugin := filepath.Join(root, "wp-content", "plugins", "akismet")
	stagedBase := t.TempDir()
	writeFileTree(t, stagedBase, map[string]string{"akismet/akismet.php": "<?php // 5.3.3"})
	staged := filepath.Join(stagedBase, "akismet")
	store := t.TempDir()

	_, _, err := ReplaceDir(Replacement{Root: root, QuarantineDir: store,
		Space: quarantine.Space{ReserveMiB: 1, Stat: smallDisk(t, store, 1<<20)}}, plugin, staged)
	var se *quarantine.SpaceError
	if !errors.As(err, &se) || se.Reserve != 1<<20 {
		t.Fatalf("err = %v, want a *SpaceError with 1 MiB reserve", err)
	}
	raw, err := os.ReadFile(filepath.Join(plugin, "akismet.php"))
	if err != nil || string(raw) != "<?php // 5.3.0" {
		t.Errorf("the plugin changed after a refused exchange: %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(staged, "akismet.php")); err != nil {
		t.Errorf("the staged release moved although nothing was exchanged: %v", err)
	}
}
