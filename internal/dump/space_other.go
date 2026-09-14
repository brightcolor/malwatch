//go:build !linux

package dump

import "math"

// FreeSpace outside Linux has no portable answer, and the scanner ships for
// Linux. This keeps the package building and testable on a workstation; the
// gate then passes, and Options.Free is the way a test measures on purpose.
func FreeSpace(string) (int64, error) {
	return math.MaxInt64, nil
}
