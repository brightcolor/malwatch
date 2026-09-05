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

	entries, err := os.ReadDir(stagedDir)
	if err != nil {
		return replaced, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dst := filepath.Join(root, entry.Name())
		if err := InsideRoot(root, dst); err != nil {
			return replaced, err
		}
		raw, err := os.ReadFile(filepath.Join(stagedDir, entry.Name()))
		if err != nil {
			return replaced, err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return replaced, err
		}
		replaced++
	}
	return replaced, nil
}
