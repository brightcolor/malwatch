// Package safepath checks that a path a repair or a quarantine restore is
// about to write to or remove actually stays where its caller expects, once
// every symlink in the way has been resolved.
//
// It exists as its own package, rather than living in the repair or
// quarantine package that first needed it, because a repair now files what
// it replaces into quarantine and a quarantine restore checks its target the
// same way repair's own swap always has: each package imports the other for
// something else, and only a third, dependency-free package lets both sides
// use the same check.
package safepath

import (
	"fmt"
	"path/filepath"
	"strings"
)

// InsideRoot reports whether candidate stays below root once every symlink
// has been resolved.
//
// A repair deletes whole directories and a quarantine restore writes an
// archived tree back to disk. A symlink planted in a customer tree would
// otherwise point either one anywhere the process may write, so a path
// leaving the root is refused rather than skipped: skipping would accept the
// manipulation quietly.
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
