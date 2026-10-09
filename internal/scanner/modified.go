package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultModifiedExts are the extensions where a vendor file that differs from
// the release counts as core.modified: what PHP, the web server or a browser
// runs or reads as instructions. A readme, a translation template or a font
// that differs is a vendor that rebuilt a release, not a way in. The ISPConfig
// addon has the same list as the default of its setting (malwatch_config
// modified_exts).
var DefaultModifiedExts = []string{
	"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phps", "phar", "inc", "module", "tpl", "twig",
	"js", "mjs", "cjs", "html", "htm", "svg", "htaccess", "ini",
}

// The limits of the list: so many extensions, each so long. The setting of
// the addon has the same limits.
const (
	MaxModifiedExts      = 40
	MaxModifiedExtLength = 12
)

var extName = regexp.MustCompile(`^[a-z0-9]+$`)

// CheckModifiedExts says in German why a list of extensions cannot be used,
// or returns nil.
func CheckModifiedExts(exts []string) error {
	if len(exts) == 0 {
		return fmt.Errorf("keine Endungen angegeben, mindestens eine ist nötig, etwa php")
	}
	if len(exts) > MaxModifiedExts {
		return fmt.Errorf("%d Endungen angegeben, erlaubt sind höchstens %d", len(exts), MaxModifiedExts)
	}
	for _, e := range exts {
		if len(e) > MaxModifiedExtLength || !extName.MatchString(e) {
			return fmt.Errorf("die Endung %q geht nicht: erlaubt sind bis zu %d Kleinbuchstaben und Ziffern, "+
				"ohne Punkt, etwa php oder js", e, MaxModifiedExtLength)
		}
	}
	return nil
}

// modifiedExts returns the list in force for this run.
func (o *Options) modifiedExts() []string {
	if o == nil || len(o.ModifiedExts) == 0 {
		return DefaultModifiedExts
	}
	return o.ModifiedExts
}

// countsAsModified reports whether a differing vendor file with extension ext
// is reported.
func countsAsModified(ext string, exts []string) bool {
	ext = strings.ToLower(ext)
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}
