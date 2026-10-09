package rules

import (
	"strconv"
	"strings"
)

// SetPHPVersion names the PHP version the website runs, such as 7.4.33, as
// the scanner reads it from the PHP of the site. Rules with DeadFrom stay
// silent where that PHP no longer runs what they look for; an empty version
// keeps every rule on.
func (e *Engine) SetPHPVersion(v string) { e.phpVersion = strings.TrimSpace(v) }

// versionAtLeast reports whether version v is min or newer, comparing the
// numbers of major, minor and patch. A version that does not start with a
// number is not.
func versionAtLeast(v, min string) bool {
	a, ok := versionNumbers(v)
	if !ok {
		return false
	}
	b, _ := versionNumbers(min)
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// versionNumbers reads up to three numbers from the start of a version; a
// suffix such as -1ubuntu is ignored.
func versionNumbers(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(strings.TrimSpace(v), ".", 4)
	for i := 0; i < len(parts) && i < 3; i++ {
		digits := parts[i]
		end := 0
		for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
			end++
		}
		if end == 0 {
			if i == 0 {
				return out, false
			}
			break
		}
		n, err := strconv.Atoi(digits[:end])
		if err != nil {
			return out, false
		}
		out[i] = n
		if end < len(digits) {
			break
		}
	}
	return out, true
}
