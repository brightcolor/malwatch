package walk

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		// A single star stays inside one path segment.
		{"*.png", "logo.png", true},
		{"*.png", "img/logo.png", false},
		{"*.png", "logo.PNG", false}, // case sensitive, like the shell

		// A doublestar crosses segments.
		{"**/log/*.log", "var/log/error.log", true},
		{"**/log/*.log", "log/error.log", true},
		{"**/log/*.log", "var/log/sub/error.log", false},
		{"**/cache/**", "web/wp-content/cache/a/b.php", true},

		// Question mark matches exactly one character, never a slash.
		{"file?.php", "file1.php", true},
		{"file?.php", "file12.php", false},
		{"a?b", "a/b", false},

		// Literals.
		{"wp-config.php", "wp-config.php", true},
		{"wp-config.php", "wp-config.php.bak", false},

		// A bare doublestar matches everything.
		{"**", "a/b/c", true},
		{"**", "", true},
	}

	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchDoubleStarDoesNotSwallowSegmentStart(t *testing.T) {
	// "**/log/*.log" must not match a directory merely ending in "log",
	// otherwise an exclude for log directories would also drop "catalog".
	if Match("**/log/*.log", "var/catalog/error.log") {
		t.Error("pattern matched a directory that only ends in log")
	}
}
