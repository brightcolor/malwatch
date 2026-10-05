package repair

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/rootio"
)

// Overlay copies newDir over oldDir, adding and replacing, leaving everything
// else in place. Ownership and mode come from the tree being written into: a
// plugin overlaid onto a hardened install must not loosen it just because the
// vendor's own archive carries different permissions, and a file that is not
// part of the vendor's tree - a customer addition, or exactly the kind of
// planted file overlay mode is trusted to leave visible - is never touched.
//
// Overlay mode leaves the old tree standing, so whatever the attacker put
// there is still present while this writes, including a symlink. Every step
// goes through an os.Root on root: a link at a target position is a finding and
// stops the run with its name, and a directory the website's user swaps for a
// symlink mid-run cannot carry a write, or a chown, out of the web root.
func Overlay(root, oldDir, newDir string) (int, error) {
	if err := InsideRoot(root, oldDir); err != nil {
		return 0, err
	}
	rel, err := relInRoot(root, oldDir)
	if err != nil {
		return 0, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	// oldDir's own mode governs every file this writes, in place of whatever
	// the vendor's archive extracted with. When oldDir does not exist yet
	// there is nothing to inherit, so a plain default takes over.
	dirMode := os.FileMode(0o755)
	uid, gid := -1, -1
	switch info, err := r.Stat(rel); {
	case err == nil:
		dirMode = info.Mode().Perm()
		uid, gid = ownerOf(info)
	case os.IsNotExist(err):
	default:
		return 0, overlayError(root, oldDir, err)
	}
	fileMode := dirMode &^ 0o111

	if err := rootio.MkdirAllIn(r, rel); err != nil {
		return 0, overlayError(root, oldDir, err)
	}

	written := 0
	err = filepath.Walk(newDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		srel, err := filepath.Rel(newDir, path)
		if err != nil || srel == "." {
			return err
		}
		name := filepath.Join(rel, srel)

		// A link at this position is not something to write through and fix up
		// afterwards; it is a finding, and the repair says so and stops. Any
		// other refusal from os.Root is a step out of the web root.
		switch lst, err := r.Lstat(name); {
		case err == nil && lst.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s ist eine Verknüpfung und wird nicht überschrieben - "+
				"sie gehört nicht in ein Herstellerverzeichnis", filepath.Join(root, name))
		case err != nil && !os.IsNotExist(err):
			return overlayError(root, oldDir, err)
		}

		if info.IsDir() {
			if err := rootio.MkdirAllIn(r, name); err != nil {
				return overlayError(root, oldDir, err)
			}
			d, err := r.Open(name)
			if err != nil {
				return err
			}
			err = rootio.SetModeOwner(d, dirMode, uid, gid)
			if cerr := d.Close(); err == nil {
				err = cerr
			}
			return err
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out, err := r.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
		if err != nil {
			return overlayError(root, oldDir, err)
		}
		_, werr := out.Write(raw)
		if werr == nil {
			werr = rootio.SetModeOwner(out, fileMode, uid, gid)
		}
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		written++
		return nil
	})
	if err != nil {
		return written, err
	}
	return written, nil
}

// overlayError wraps a failure from the os.Root walk, naming a step out of the
// root as the symlink it is.
func overlayError(root, oldDir string, err error) error {
	if rootio.EscapesRoot(err) {
		return fmt.Errorf("ein Eintrag unter %s führt über einen symbolischen Link aus %s heraus und wurde nicht geschrieben (%v). "+
			"Den Link prüfen und entfernen, danach den Auftrag erneut starten", oldDir, root, err)
	}
	return fmt.Errorf("%s lässt sich unter %s nicht überlagern: %w", oldDir, root, err)
}
