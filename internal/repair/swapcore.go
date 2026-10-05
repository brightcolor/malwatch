package repair

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/rootio"
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
//
// Every write goes through an os.Root on root, so a directory the website's
// user swaps for a symlink while the run works cannot steer a placement out of
// the web root (see Swap and writeLooseRootFiles).
func SwapCore(root, stagedDir string) (int, error) {
	if err := InsideRoot(root, stagedDir); err == nil {
		// Staging inside the web root would make the new files part of what
		// is being replaced, and would serve them over the web meanwhile.
		return 0, fmt.Errorf("das Bereitstellungsverzeichnis %s darf nicht im Webstamm liegen", stagedDir)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	replaced := 0
	for _, dir := range coreDirs {
		src := filepath.Join(stagedDir, dir)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		switch _, err := r.Stat(dir); {
		case err == nil:
			if err := Swap(root, filepath.Join(root, dir), src); err != nil {
				return replaced, err
			}
		case os.IsNotExist(err):
			if _, err := rootio.CopyTreeInto(r, dir, src, 0o755, 0o644, -1, -1); err != nil {
				return replaced, swapError(root, filepath.Join(root, dir), "angelegt", err)
			}
		default:
			return replaced, err
		}
		replaced += countFiles(filepath.Join(root, dir))
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
	r, err := os.OpenRoot(root)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	entries, err := os.ReadDir(stagedDir)
	if err != nil {
		return 0, err
	}

	written := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// os.Root resolves the name and would refuse a link pointing out of
		// the web root, but one pointing back inside it is followed - and that
		// would let index.php overwrite wp-config.php. A loose core file is a
		// file; a link in its place is not something to write through.
		switch lst, err := r.Lstat(name); {
		case err == nil && lst.Mode()&os.ModeSymlink != 0:
			return written, fmt.Errorf("%s ist eine Verknüpfung und wird nicht überschrieben - "+
				"eine Kerndatei ist keine Verknüpfung", filepath.Join(root, name))
		case err != nil && !os.IsNotExist(err):
			return written, swapError(root, filepath.Join(root, name), "geschrieben", err)
		}
		raw, err := os.ReadFile(filepath.Join(stagedDir, name))
		if err != nil {
			return written, err
		}
		out, err := r.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return written, swapError(root, filepath.Join(root, name), "geschrieben", err)
		}
		_, werr := out.Write(raw)
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return written, werr
		}
		written++
	}
	return written, nil
}
