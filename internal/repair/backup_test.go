package repair

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func readArchive(t *testing.T, archive string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fh, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(body)
	}
	return out
}

func TestBackupCarriesTheFilesItArchived(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "includes", "mail.php"), []byte("<?php // mail"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	archive, err := Backup(src, dest, "contact-form-7")
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	names := readArchive(t, archive)
	if names["includes/mail.php"] != "<?php // mail" {
		t.Fatalf("the archive does not carry the file: %v", names)
	}
}

func TestBackupNamesTheArchiveAfterTheElement(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "x.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	// The operator has to find the archive by the name of what was lost.
	archive, err := Backup(src, dest, "plugin-elementor-pro")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(archive) != "plugin-elementor-pro.tar.gz" {
		t.Errorf("archive is called %q", filepath.Base(archive))
	}
}
