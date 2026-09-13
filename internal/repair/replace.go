package repair

import "github.com/brightcolor/malwatch/internal/quarantine"

// Replacement is what ReplaceDir and ReplaceCore need from a caller outside
// this package. An upgrade exchanges a plugin for a newer release the same
// way a repair exchanges it for the original of the installed one.
type Replacement struct {
	Root          string // the installation; nothing outside it is written
	QuarantineDir string
	Domain        string
	Origin        string // quarantine origin, e.g. "upgrade"
	Reason        string // quarantine reason of every entry filed
}

func (r Replacement) options() Options {
	return Options{
		Root: r.Root, QuarantineDir: r.QuarantineDir, Domain: r.Domain,
		Origin: r.Origin, Reason: r.Reason,
	}
}

// ReplaceDir files dir into quarantine and moves stagedDir into its place,
// with the owner, group and mode dir had. It returns the entry and the number
// of files now in dir.
//
// A failure after the entry was written still returns the entry: the old tree
// sits in the store then, and the caller needs its id to bring it back.
func ReplaceDir(r Replacement, dir, stagedDir string) (quarantine.Entry, int, error) {
	opts := r.options()
	mode, uid, gid, hadMode := captureMode(dir)
	entry, err := quarantineElement(opts, "replace", Element{Path: dir}, "Beim Ersetzen abgelegt")
	if err != nil {
		return quarantine.Entry{}, 0, err
	}
	if err := Swap(r.Root, dir, stagedDir); err != nil {
		return entry, 0, err
	}
	if hadMode {
		_ = applyOwnership(dir, uid, gid, mode)
	}
	return entry, countFiles(dir), nil
}

// ReplaceCore exchanges wp-admin, wp-includes and the loose root files of the
// installation at r.Root for the staged core, filing what it replaces into
// quarantine first. The ids come back in the order they were filed, after a
// failure as well.
func ReplaceCore(r Replacement, stagedDir string) (int, []string, error) {
	return repairCore(r.options(), "replace", stagedDir)
}
