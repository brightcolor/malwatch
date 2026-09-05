package repair

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

// Backup writes dir as a gzipped tar below destDir and returns its path.
//
// It runs before anything is deleted, for everything that is touched and not
// only for what cannot be fetched again: a version read wrongly off the disk
// costs as much as a paid plugin, and both are cheap to keep.
func Backup(dir, destDir, name string) (string, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", err
	}
	archive := filepath.Join(destDir, name+".tar.gz")
	fh, err := os.OpenFile(archive, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	gz := gzip.NewWriter(fh)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		// A symlink is stored as a link and never followed: following one
		// would pull whatever it points at into the archive.
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	if walkErr != nil {
		return "", walkErr
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return archive, nil
}

// BackupFile copies one file below destDir and returns its path.
//
// A single file is kept as a copy rather than as a tar: getting one file back
// should not need an unpacking step, and the whole point of keeping it is that
// a finding may turn out to be a false alarm.
func BackupFile(file, destDir, name string) (string, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	target := filepath.Join(destDir, name)
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		return "", err
	}
	return target, nil
}
