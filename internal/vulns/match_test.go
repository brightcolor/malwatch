package vulns

import "testing"

func TestSpanBounds(t *testing.T) {
	below := span{to: bound{version: "5.3.2"}}
	upTo := span{to: bound{version: "5.3.1", inclusive: true}}
	between := span{from: bound{version: "2.0", inclusive: true}, to: bound{version: "2.4"}}
	open := span{}

	cases := []struct {
		name string
		s    span
		v    string
		want bool
	}{
		{"below the fix", below, "5.3.1", true},
		{"the fix itself", below, "5.3.2", false},
		{"numeric order, not text order", below, "5.10", false},
		{"last affected, inclusive", upTo, "5.3.1", true},
		{"after the last affected", upTo, "5.3.2", false},
		{"lower bound inclusive", between, "2.0", true},
		{"under the lower bound", between, "1.9.9", false},
		{"inside", between, "2.3.7", true},
		{"no bounds at all", open, "0.1", true},
	}
	for _, c := range cases {
		if got := c.s.contains(c.v); got != c.want {
			t.Errorf("%s: contains(%s) = %v, want %v", c.name, c.v, got, c.want)
		}
	}
}

func TestOSVRangeThatOpensTwice(t *testing.T) {
	// Taken from a Drupal core advisory: affected from 8.0.0 to before
	// 10.1.8, and again from 10.2.0 to before 10.2.2 - written as two ranges.
	first := []osvEvent{{Introduced: "8.0.0"}, {Fixed: "10.1.8"}}
	second := []osvEvent{{Introduced: "10.2.0"}, {Fixed: "10.2.2"}}

	check := func(v string, wantAffected bool, wantFix string) {
		t.Helper()
		gotAffected, gotFix := false, ""
		for _, r := range [][]osvEvent{first, second} {
			if a, _, f, _ := osvAffected(v, r); a {
				gotAffected, gotFix = true, f
			}
		}
		if gotAffected != wantAffected || gotFix != wantFix {
			t.Errorf("%s: affected=%v fix=%q, want affected=%v fix=%q", v, gotAffected, gotFix, wantAffected, wantFix)
		}
	}
	check("7.98", false, "")
	check("9.5.11", true, "10.1.8")
	check("10.1.8", false, "")
	check("10.1.9", false, "")
	check("10.2.1", true, "10.2.2")
	check("10.2.2", false, "")
}

func TestOSVEventsWithinOneRange(t *testing.T) {
	// The same shape written as one range, events deliberately out of order.
	events := []osvEvent{{Fixed: "2.3"}, {Introduced: "2.0"}, {Fixed: "1.5"}, {Introduced: "0"}}

	cases := []struct {
		v        string
		affected bool
		intro    string
		fix      string
	}{
		{"0.9", true, "0", "1.5"},
		{"1.7", false, "", ""},
		{"2.1", true, "2.0", "2.3"},
		{"2.3", false, "", ""},
	}
	for _, c := range cases {
		a, intro, f, _ := osvAffected(c.v, events)
		if a != c.affected || intro != c.intro || f != c.fix {
			t.Errorf("%s: affected=%v introduced=%q fix=%q, want %v %q %q", c.v, a, intro, f, c.affected, c.intro, c.fix)
		}
	}
}

func TestOSVLastAffectedWithoutFix(t *testing.T) {
	events := []osvEvent{{Introduced: "1.0"}, {LastAffected: "1.4"}}
	if a, intro, f, l := osvAffected("1.4", events); !a || intro != "1.0" || f != "" || l != "1.4" {
		t.Errorf("1.4: affected=%v introduced=%q fix=%q last=%q, want affected from 1.0 up to 1.4", a, intro, f, l)
	}
	if a, _, _, _ := osvAffected("1.5", events); a {
		t.Error("1.5 is past the last affected version")
	}
	if a, _, f, l := osvAffected("2.0", []osvEvent{{Introduced: "1.0"}}); !a || f != "" || l != "" {
		t.Errorf("a range without an end: affected=%v fix=%q last=%q", a, f, l)
	}
}

func TestPlausibleNames(t *testing.T) {
	for _, ok := range []string{"contact-form-7", "wp_super_cache", "jetpack.old"} {
		if !plausibleSlug(ok) {
			t.Errorf("%q refused as a slug", ok)
		}
	}
	for _, bad := range []string{"", "..", "a/b", "../etc", ".hidden", "x y", "a%2f"} {
		if plausibleSlug(bad) {
			t.Errorf("%q accepted as a slug", bad)
		}
	}
	for _, ok := range []string{"6.4.2", "5.0.0-beta1", "10.2.0+build"} {
		if !plausibleVersion(ok) {
			t.Errorf("%q refused as a version", ok)
		}
	}
	for _, bad := range []string{"", "6.4/../..", "1 .2", "6.4.2;rm"} {
		if plausibleVersion(bad) {
			t.Errorf("%q accepted as a version", bad)
		}
	}
}

func TestMajorOf(t *testing.T) {
	cases := map[string]int{"5.7.17": 5, "v6.4.20.2": 6, "10": 10, "": 0, "x1": 0}
	for v, want := range cases {
		if got := majorOf(v); got != want {
			t.Errorf("majorOf(%q) = %d, want %d", v, got, want)
		}
	}
}
