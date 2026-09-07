// Package repair puts the vendor's own files back, so that whatever survives
// a following scan is by definition not part of the software.
package repair

import "github.com/brightcolor/malwatch/internal/safepath"

// InsideRoot forwards to safepath.InsideRoot.
//
// The real check now lives in its own package: repair started importing
// quarantine in this task (to file what it replaces there before touching
// it), and quarantine already imported repair for this very function, which
// would make a two-package import cycle. InsideRoot stays exported here too
// - unchanged, same signature - so callers outside this package, such as the
// quarantine command, keep working without switching imports themselves.
func InsideRoot(root, candidate string) error {
	return safepath.InsideRoot(root, candidate)
}
