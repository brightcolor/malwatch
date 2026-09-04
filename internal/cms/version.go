package cms

import (
	"strconv"
	"strings"
)

// Compare compares two dotted version strings. It returns -1 if a is older
// than b, 0 if they are equal, 1 if a is newer.
//
// Numeric parts are compared as numbers, so 4.10 is newer than 4.9. A
// pre-release suffix ("6.0-beta1", "5.2.0-rc.2") sorts before the plain
// release, which is what both semver and the CMS vendors mean by it.
func Compare(a, b string) int {
	aNum, aPre := split(a)
	bNum, bPre := split(b)

	for i := 0; i < len(aNum) || i < len(bNum); i++ {
		var x, y int
		if i < len(aNum) {
			x = aNum[i]
		}
		if i < len(bNum) {
			y = bNum[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}

	switch {
	case aPre == "" && bPre == "":
		return 0
	case aPre == "":
		return 1 // a release beats its own pre-release
	case bPre == "":
		return -1
	case aPre < bPre:
		return -1
	case aPre > bPre:
		return 1
	}
	return 0
}

// split separates the numeric parts from a pre-release suffix.
func split(v string) ([]int, string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")

	pre := ""
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		pre = strings.ToLower(v[i+1:])
		v = v[:i]
	}

	var nums []int
	for _, part := range strings.Split(v, ".") {
		digits := part
		// A part like "2rc1" carries the suffix inside it.
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				digits = part[:i]
				if pre == "" {
					pre = strings.ToLower(part[i:])
				}
				break
			}
		}
		if digits == "" {
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// SameBranch reports whether two versions share the given number of leading
// numeric parts. It keeps a site on a maintained older branch from being
// compared against the newest major release.
func SameBranch(a, b string, parts int) bool {
	aNum, _ := split(a)
	bNum, _ := split(b)
	if len(aNum) < parts || len(bNum) < parts {
		return false
	}
	for i := 0; i < parts; i++ {
		if aNum[i] != bNum[i] {
			return false
		}
	}
	return true
}
