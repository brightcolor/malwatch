package repair

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brightcolor/malwatch/internal/rootio"
)

// Swap replaces oldDir with newDir and carries over what the old tree was.
//
// Owner, group and mode are read off the tree being replaced rather than set
// to a default: a tree owned by root leaves the site on 500 or hands it the
// wrong write rights, and a fixed default would soften a hardened install.
//
// oldDir missing outright is not an error: a repair now quarantines it first,
// which already removed it, and there is simply nothing left to read a mode
// from or to remove before the new tree goes in its place.
//
// A repair runs as root in a tree that belongs to the website's user, who can
// swap a directory on the way to oldDir for a symlink between the check above
// and the removal and copy below. So removing and writing both go through an
// os.Root on root: it resolves each step at the moment of use and refuses one
// that leaves root, where os.Rename and os.RemoveAll by plain path would
// follow the link out. newDir is the staged vendor tree outside the web root,
// root-owned, and is read by its own path.
func Swap(root, oldDir, newDir string) error {
	if err := InsideRoot(root, oldDir); err != nil {
		return err
	}
	rel, err := relInRoot(root, oldDir)
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()

	mode := os.FileMode(0o755)
	uid, gid := -1, -1
	switch info, err := r.Stat(rel); {
	case err == nil:
		mode = info.Mode().Perm()
		uid, gid = ownerOf(info)
	case os.IsNotExist(err):
		// Nothing there to inherit a mode or owner from; the defaults apply.
	default:
		return err
	}

	if err := rootio.RemoveAllIn(r, rel); err != nil {
		return swapError(root, oldDir, "ersetzt", err)
	}
	if _, err := rootio.CopyTreeInto(r, rel, newDir, mode, mode&^0o111, uid, gid); err != nil {
		return swapError(root, oldDir, "ersetzt", err)
	}
	_ = os.RemoveAll(newDir)
	return nil
}

// applyOwnership gives every entry of the new tree the identity of the one it
// replaced, each through its own descriptor so a directory the website's user
// swaps for a symlink cannot steer a chmod or chown out of the tree.
func applyOwnership(dir string, uid, gid int, mode os.FileMode) error {
	return rootio.ApplyOwnershipIn(dir, uid, gid, mode)
}

// relInRoot is target as a path below root, refused when it would be root
// itself or lie outside it. InsideRoot already guards the boundary; this also
// yields the name os.Root works with.
func relInRoot(root, target string) (string, error) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return "", err
	}
	rel = filepath.Clean(rel)
	if rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%s liegt nicht unterhalb von %s", target, root)
	}
	return rel, nil
}

// swapError wraps a failure from the os.Root walk, naming a step out of the
// root as the symlink it is and saying what to do about it.
func swapError(root, dir, verb string, err error) error {
	if rootio.EscapesRoot(err) {
		return fmt.Errorf("%s führt über einen symbolischen Link aus %s heraus und wurde nicht %s (%v). "+
			"Den Link prüfen und entfernen, danach den Auftrag erneut starten", dir, root, verb, err)
	}
	return fmt.Errorf("%s lässt sich unter %s nicht %s: %w", dir, root, verb, err)
}
