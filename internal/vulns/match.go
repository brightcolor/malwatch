package vulns

import (
	"sort"
	"strings"

	"github.com/brightcolor/malwatch/internal/cms"
)

// bound is one end of a version range.
type bound struct {
	version   string
	inclusive bool
}

// span is a stretch of affected versions. An empty version leaves that side
// open, so a span with neither side set covers every version.
type span struct {
	from bound
	to   bound
}

func (s span) contains(v string) bool {
	if s.from.version != "" {
		c := cms.Compare(v, s.from.version)
		if c < 0 || (c == 0 && !s.from.inclusive) {
			return false
		}
	}
	if s.to.version != "" {
		c := cms.Compare(v, s.to.version)
		if c > 0 || (c == 0 && !s.to.inclusive) {
			return false
		}
	}
	return true
}

// osvEvent is one entry of an OSV range: exactly one field is set.
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

func (e osvEvent) version() string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	}
	return e.LastAffected
}

// osvAffected evaluates one OSV range the way the OSV schema describes it:
// sort the events by version, walk them up to the installed version, and the
// last event passed decides. A range may open and close several times - a
// flaw introduced in 8.0, fixed in 10.1.8, reintroduced in 10.2.0 - which is
// why a single "between" test would not do.
//
// introduced is the version the stretch v sits in begins with, "0" for one
// that reaches back to the first release. fixed is the version that closes
// the stretch, lastAffected its newest affected version for a range that
// records the end that way. Both ends are empty for a stretch without one.
func osvAffected(v string, events []osvEvent) (affected bool, introduced, fixed, lastAffected string) {
	sorted := append([]osvEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return cms.Compare(sorted[i].version(), sorted[j].version()) < 0
	})

	for _, e := range sorted {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || cms.Compare(v, e.Introduced) >= 0 {
				affected, introduced = true, e.Introduced
			}
		case e.Fixed != "":
			if cms.Compare(v, e.Fixed) >= 0 {
				affected, introduced = false, ""
			}
		case e.LastAffected != "":
			if cms.Compare(v, e.LastAffected) > 0 {
				affected, introduced = false, ""
			}
		}
	}
	if !affected {
		return false, "", "", ""
	}
	// The first end above v closes its stretch.
	for _, e := range sorted {
		switch {
		case e.Fixed != "" && cms.Compare(v, e.Fixed) < 0:
			return true, introduced, e.Fixed, ""
		case e.LastAffected != "" && cms.Compare(v, e.LastAffected) <= 0:
			return true, introduced, "", e.LastAffected
		}
	}
	return true, introduced, "", ""
}

// higherVersion returns the newer of two versions, ignoring empty ones.
func higherVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case cms.Compare(a, b) >= 0:
		return a
	}
	return b
}

// plausibleVersion keeps a version read off a customer's disk out of a URL
// and a file name. The value comes from a file an attacker may have written.
func plausibleVersion(s string) bool {
	if s == "" || len(s) > 40 || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '.' || c == '-' || c == '+' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// plausibleSlug does the same for a plugin or theme directory name.
func plausibleSlug(s string) bool {
	if s == "" || len(s) > 100 || strings.Contains(s, "..") || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// majorOf returns the leading number of a version, 0 when there is none.
func majorOf(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	n := 0
	for i := 0; i < len(v) && v[i] >= '0' && v[i] <= '9'; i++ {
		n = n*10 + int(v[i]-'0')
	}
	return n
}
