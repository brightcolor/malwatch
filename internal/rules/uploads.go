package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultUploadDirs are the directories that hold nothing but user uploads, as
// the scanner knows them without --upload-dirs. The ISPConfig addon has the
// same list as the default of its setting (malwatch_config_defaults()).
//
// Only directories where a CMS never puts code of its own. The list once
// included media, assets, files and cache; Joomla ships thousands of
// legitimate PHP files below media alone, which drowned every real finding.
// Plural and lower case only: Joomla keeps its own update code under
// "src/View/Upload" and "tmpl/upload", and the singular form would flag all of
// it.
var DefaultUploadDirs = []string{"uploads", "attachments", "avatars", "thumbs", "userfiles", "user_uploads", "file_uploads"}

// The limits of a list of upload directories: so many names, each so long.
// The setting of the addon has the same limits (malwatch_upload_dirs_limits()).
const (
	MaxUploadDirs      = 16
	MaxUploadDirLength = 30
)

// uploadDirName is a directory name: letters, digits, dot, underscore and
// hyphen, not starting with a dot, so "." and ".." never pass.
var uploadDirName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// CheckUploadDirs says in German why a list of upload directories cannot be
// used, or returns nil.
func CheckUploadDirs(dirs []string) error {
	if len(dirs) == 0 {
		return fmt.Errorf("keine Upload-Ordner angegeben, mindestens ein Name ist nötig, etwa uploads")
	}
	if len(dirs) > MaxUploadDirs {
		return fmt.Errorf("%d Upload-Ordner angegeben, erlaubt sind höchstens %d", len(dirs), MaxUploadDirs)
	}
	for _, d := range dirs {
		if len(d) > MaxUploadDirLength || !uploadDirName.MatchString(d) {
			return fmt.Errorf("der Upload-Ordner %q geht nicht: erlaubt sind bis zu %d Zeichen aus Buchstaben, "+
				"Ziffern, Punkt, Unterstrich und Bindestrich, ohne Punkt am Anfang", d, MaxUploadDirLength)
		}
	}
	return nil
}

// ParseUploadDirs splits the values of --upload-dirs, each a comma separated
// list, into names, without spaces and empty entries.
func ParseUploadDirs(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// uploadPattern matches a path below one of dirs, as a whole path segment:
// "uploads" does not match "myuploads".
func uploadPattern(dirs []string) *regexp.Regexp {
	quoted := make([]string, len(dirs))
	for i, d := range dirs {
		quoted[i] = regexp.QuoteMeta(d)
	}
	return regexp.MustCompile(`/(?:` + strings.Join(quoted, "|") + `)/`)
}
