package rules

import "testing"

// preg_replace with the modifier e ran code up to PHP 5.6; PHP 7.0 dropped
// it, and the call fails instead. Old releases of RevSlider, Jupiter and
// WPBakery still carry it: on 2026-09-30 they were six critical findings on
// websites running PHP 7.2 to 7.4.
func TestConstructsTheSitesPHPNoLongerRunsAreNoFinding(t *testing.T) {
	src := `<?php $s = preg_replace('!s:(\d+):"(.*?)";!e', "'s:'.strlen('$2').':\"$2\";'", $data);`
	for _, c := range []struct {
		version string
		want    bool
	}{
		{"7.4.33", false},
		{"7.0.0", false},
		{"8.2", false},
		{"5.6.40", true},
		{"", true},
	} {
		e := NewEngine(nil)
		e.SetPHPVersion(c.version)
		if got := hitRules(e, "/web/wp-content/plugins/revslider/includes/slider.class.php", "php", src)["php.preg_replace.eval"]; got != c.want {
			t.Errorf("PHP %q: gemeldet %v, erwartet %v", c.version, got, c.want)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"7.0", "7.0", true}, {"7.4.33", "7.0", true}, {"10.0", "7.0", true}, {"6.9.9", "7.0", false},
		{"5.6.40", "7.0", false}, {"7", "7.0", true}, {"7.0.0-1ubuntu", "7.0", true}, {"x", "7.0", false},
	} {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
}
