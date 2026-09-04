package cms

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.6.2", "6.6.2", 0},
		{"6.6.1", "6.6.2", -1},
		{"6.6.2", "6.6.1", 1},

		// Numeric, not lexical: this is the mistake that makes a scanner
		// report an up-to-date site as outdated.
		{"4.10", "4.9", 1},
		{"1.9.3", "1.26.0", -1},
		{"2.1.10", "2.1.9", 1},

		// Missing parts count as zero.
		{"6.6", "6.6.0", 0},
		{"6.6", "6.6.1", -1},

		// A pre-release is older than the release it leads to.
		{"6.0-beta1", "6.0", -1},
		{"6.0", "6.0-rc1", 1},
		{"5.2.0-rc.2", "5.2.0-rc.1", 1},
		{"13.4.0rc1", "13.4.0", -1},

		// A leading v is tolerated, vendors are inconsistent about it.
		{"v6.6.2", "6.6.2", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareIsAntisymmetric(t *testing.T) {
	pairs := [][2]string{
		{"1.0", "1.0.1"}, {"10.0", "9.9"}, {"3.0-beta", "3.0"}, {"2", "2.0.0"},
	}
	for _, p := range pairs {
		if Compare(p[0], p[1]) != -Compare(p[1], p[0]) {
			t.Errorf("Compare is not antisymmetric for %q and %q", p[0], p[1])
		}
	}
}

func TestSameBranch(t *testing.T) {
	if !SameBranch("10.3.5", "10.4.0", 1) {
		t.Error("10.3.5 and 10.4.0 should share the major branch")
	}
	if SameBranch("10.3.5", "11.0.0", 1) {
		t.Error("10.3.5 and 11.0.0 must not share the major branch")
	}
	if !SameBranch("3.4.5", "3.4.9", 2) {
		t.Error("3.4.5 and 3.4.9 should share two parts")
	}
	if SameBranch("3.4.5", "3.5.0", 2) {
		t.Error("3.4.5 and 3.5.0 must not share two parts")
	}
	// A version too short to compare is not on the branch, rather than
	// accidentally on every branch.
	if SameBranch("3", "3.4.0", 2) {
		t.Error("a one-part version must not count as being on a two-part branch")
	}
}
