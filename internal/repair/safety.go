// Package repair puts the vendor's own files back, so that whatever survives
// a following scan is by definition not part of the software.
package repair

import (
	"fmt"
	"path/filepath"
	"strings"
)

// InsideRoot reports whether candidate stays below root once every symlink
// has been resolved.
//
// A repair deletes whole directories. A symlink planted in a customer tree
// would otherwise point that deletion anywhere the process may write, so a
// path leaving the root is refused rather than skipped: skipping would accept
// the manipulation quietly.
func InsideRoot(root, candidate string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("Wurzelverzeichnis %s ist nicht lesbar: %w", root, err)
	}
	realRoot = filepath.Clean(realRoot)

	// The candidate need not exist yet - a target being moved into place does
	// not. Resolve the deepest existing parent instead.
	target := filepath.Clean(candidate)
	probe := target
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			rest := strings.TrimPrefix(target, probe)
			target = filepath.Clean(filepath.Join(resolved, rest))
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}

	if target == realRoot {
		return nil
	}
	if !strings.HasPrefix(target, realRoot+string(filepath.Separator)) {
		return fmt.Errorf("%s liegt außerhalb von %s", candidate, root)
	}
	return nil
}
