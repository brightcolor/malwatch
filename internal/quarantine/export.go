package quarantine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// DefaultPassword is the convention security people use when they send a
// sample: every unpacker understands it, and no scanner looks inside.
const DefaultPassword = "infected"

// Export reads one entry's tar archive and writes it back out as a
// ZipCrypto-protected zip at outFile, returning the file's size.
//
// Symlinks carry no bytes worth shipping in a sample sent off for analysis
// and have no portable representation in a zip anyway, so only directories
// and regular files make the trip.
func Export(storeRoot, id, outFile, password string) (int64, error) {
	dir, err := entryDir(storeRoot, id)
	if err != nil {
		return 0, err
	}
	payload := filepath.Join(dir, payloadName)

	fh, err := os.Open(payload)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return 0, err
	}
	defer gz.Close()

	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			err = exportDir(zw, hdr)
		case tar.TypeReg:
			err = exportFile(zw, hdr, tr, password)
		default:
			continue
		}
		if err != nil {
			return 0, err
		}
	}

	if err := zw.Close(); err != nil {
		return 0, err
	}
	info, err := out.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// exportDir writes a directory marker: a name ending in "/", no content, no
// encryption - there is nothing in it to protect.
func exportDir(zw *zip.Writer, hdr *tar.Header) error {
	name := hdr.Name
	if len(name) == 0 || name[len(name)-1] != '/' {
		name += "/"
	}
	_, err := zw.CreateHeader(&zip.FileHeader{
		Name:     name,
		Method:   zip.Store,
		Modified: hdr.ModTime,
	})
	return err
}

// exportFile buffers the plaintext, deflates it, runs the result through
// ZipCrypto and writes it as a raw zip entry: CreateRaw is what lets the
// already-encrypted bytes go in unchanged, since the normal Create path
// would deflate the plaintext itself and never touch encryption at all.
func exportFile(zw *zip.Writer, hdr *tar.Header, tr *tar.Reader, password string) error {
	plain, err := io.ReadAll(tr)
	if err != nil {
		return err
	}
	crc := crc32.ChecksumIEEE(plain)

	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.BestSpeed)
	if err != nil {
		return err
	}
	if _, err := fw.Write(plain); err != nil {
		return err
	}
	if err := fw.Close(); err != nil {
		return err
	}

	// Twelve header bytes: eleven random, the twelfth the high byte of the
	// CRC. Classic unzip tools use it as a quick password check before
	// trusting the rest of the stream.
	header := make([]byte, 12)
	if _, err := rand.Read(header[:11]); err != nil {
		return err
	}
	header[11] = byte(crc >> 24)

	keys := newZipKeys(password)
	encrypted := make([]byte, 0, len(header)+deflated.Len())
	for _, b := range header {
		encrypted = append(encrypted, keys.encryptByte(b))
	}
	for _, b := range deflated.Bytes() {
		encrypted = append(encrypted, keys.encryptByte(b))
	}

	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               hdr.Name,
		Method:             zip.Deflate,
		Flags:              0x1,
		CRC32:              crc,
		CompressedSize64:   uint64(len(encrypted)),
		UncompressedSize64: uint64(len(plain)),
		Modified:           hdr.ModTime,
	})
	if err != nil {
		return err
	}
	_, err = w.Write(encrypted)
	return err
}
