package repair

import (
	"fmt"
	"os"
	"path/filepath"
)

// coreDirs are the directories that belong to the core alone and are replaced
// as a whole. wp-content is deliberately not among them.
var coreDirs = []string{"wp-admin", "wp-includes"}

// SwapCore replaces the core without touching what belongs to the site.
//
// wp-admin and wp-includes go as a whole, because a file dropped inside them
// only disappears with the directory. The root is different: files are put
// back one by one, by name, so wp-config.php, wp-content and anything foreign
// stay. The foreign ones are the point - the scan after the repair is supposed
// to report them.
func SwapCore(root, stagedDir string) (int, error) {
	if err := InsideRoot(root, stagedDir); err == nil {
		// Staging inside the web root would make the new files part of what
		// is being replaced, and would serve them over the web meanwhile.
		return 0, fmt.Errorf("das Bereitstellungsverzeichnis %s darf nicht im Webstamm liegen", stagedDir)
	}

	replaced := 0
	for _, dir := range coreDirs {
		src := filepath.Join(stagedDir, dir)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(root, dir)
		if err := InsideRoot(root, dst); err != nil {
			return replaced, err
		}
		if _, err := os.Stat(dst); err == nil {
			if err := Swap(root, dst, src); err != nil {
				return replaced, err
			}
		} else if err := os.Rename(src, dst); err != nil {
			return replaced, err
		}
		replaced += countFiles(dst)
	}

	n, err := writeLooseRootFiles(root, stagedDir)
	return replaced + n, err
}

// writeLooseRootFiles puts the staged core's root files - index.php,
// wp-login.php and the rest - in place by name, adding and replacing and
// touching nothing else.
//
// One function for both modes, because there were two copies of this loop
// and only one of them got the check below. The other stayed open for a
// whole release, in the mode that leaves the old tree standing and therefore
// keeps whatever was planted in it.
func writeLooseRootFiles(root, stagedDir string) (int, error) {
	entries, err := os.ReadDir(stagedDir)
	if err != nil {
		return 0, err
	}

	written := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dst := filepath.Join(root, entry.Name())
		if err := InsideRoot(root, dst); err != nil {
			return written, err
		}
		// InsideRoot resolves the path and would catch a link pointing out of
		// the web root, but one pointing back inside passes - and os.WriteFile
		// follows it, so index.php could be made to overwrite wp-config.php.
		// A loose core file is a file; a link in its place is not something to
		// write through.
		if lst, err := os.Lstat(dst); err == nil && lst.Mode()&os.ModeSymlink != 0 {
			return written, fmt.Errorf("%s ist eine Verknüpfung und wird nicht überschrieben - "+
				"eine Kerndatei ist keine Verknüpfung", dst)
		}
		raw, err := os.ReadFile(filepath.Join(stagedDir, entry.Name()))
		if err != nil {
			return written, err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}
