package dump

import (
	"os"
	"path/filepath"
)

// SourceSize adds up the regular files below every root, as the estimate the
// space check works with.
//
// A root that is not there contributes nothing: the log directory is
// optional, and a website without one must not turn the estimate into an
// error. Symlinks count as nothing, because they go into the archive as
// links, without their target.
func SourceSize(roots ...string) (int64, error) {
	var total int64
	for _, root := range roots {
		if root == "" {
			continue
		}
		if _, err := os.Lstat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				total += info.Size()
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}
