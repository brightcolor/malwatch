package quarantine

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// DefaultPassword is the convention security people use when they send a
// sample: every unpacker understands it, and no scanner looks inside.
const DefaultPassword = "infected"

// ExportOptions shape the ZIP of a sample.
type ExportOptions struct {
	Password string
	Space    Space
}

// ExportResult says what became of one id: Err is nil when the entry is in
// the archive.
type ExportResult struct {
	ID  string
	Err error
}

// exportItem is an entry on its way into the archive.
type exportItem struct {
	id, payload string
}

// Export packs the entries named by ids into one ZipCrypto-protected ZIP at
// outFile, each below a directory named after its id: two websites can each
// have quarantined "wp-content/uploads/shell.php", and the archive keeps
// both.
//
// Every payload is read to its end first. An entry that is missing or
// unreadable gets its reason in the result and stays out of the archive; the
// others go in. Before the first byte, Export checks that the filesystem of
// outFile holds the archive, the scratch file of its largest file and the
// reserve of space. A *SpaceError, or any other error, means there is no
// archive: a half-written one is removed again. Without a readable entry no
// archive is written either.
//
// Files are streamed: each is deflated into a scratch file next to the
// archive, which yields the CRC and the sizes the ZIP header needs ahead of
// the content, and then enciphered on its way into the archive. Memory use
// stays the same whatever the size of a file.
//
// Symlinks carry no bytes worth shipping in a sample sent off for analysis
// and have no portable representation in a zip anyway, so only directories
// and regular files make the trip.
func Export(storeRoot string, ids []string, outFile string, opts ExportOptions) ([]ExportResult, error) {
	results := make([]ExportResult, len(ids))
	var items []exportItem
	var archive, scratch int64
	for i, id := range ids {
		results[i].ID = id
		dir, err := entryDir(storeRoot, id)
		if err != nil {
			results[i].Err = err
			continue
		}
		payload := filepath.Join(dir, payloadName)
		t, err := payloadTally(payload)
		if err != nil {
			if os.IsNotExist(err) {
				results[i].Err = fmt.Errorf("quarantäne-eintrag %s nicht gefunden", id)
			} else {
				results[i].Err = fmt.Errorf("quarantäne-archiv %s ist unlesbar: %w", payload, err)
			}
			continue
		}
		items = append(items, exportItem{id: id, payload: payload})
		archive += zipBound(t, int64(len(id)+1))
		if b := deflateBound(t.biggest); b > scratch {
			scratch = b
		}
	}
	if len(items) == 0 {
		return results, nil
	}

	outDir := filepath.Dir(outFile)
	l := ledger{space: opts.Space}
	out, err := l.on(outDir)
	if err != nil {
		return results, err
	}
	out.write(roundUp(archive+zipEndBytes, out.block()))
	out.write(roundUp(scratch, out.block()))
	if err := l.check("Es wurde kein ZIP geschrieben."); err != nil {
		return results, err
	}

	// The spool directory of the panel need not exist yet: unlike the runs
	// directory a result file lands in, nothing creates it ahead of the call
	// that first writes into it.
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return results, err
	}
	return results, writeExport(outFile, items, opts.Password)
}

// writeExport writes items into a new ZIP at outFile. Any error removes the
// file again.
func writeExport(outFile string, items []exportItem, password string) error {
	fh, err := os.OpenFile(outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	scratch, err := os.CreateTemp(filepath.Dir(outFile), ".malwatch-export-*")
	if err != nil {
		fh.Close()
		os.Remove(outFile)
		return err
	}
	defer func() {
		scratch.Close()
		os.Remove(scratch.Name())
	}()

	w := &exportWriter{zw: zip.NewWriter(fh), scratch: scratch, password: password}
	for _, item := range items {
		if err = w.entry(item.payload, item.id+"/"); err != nil {
			err = fmt.Errorf("Export von %s: %w", item.id, err)
			break
		}
	}
	if err == nil {
		err = w.zw.Close()
	}
	if closeErr := fh.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(outFile)
	}
	return err
}

// exportWriter writes entries into one ZIP, through one scratch file it
// reuses for every file.
type exportWriter struct {
	zw       *zip.Writer
	scratch  *os.File
	password string
}

// entry copies the directories and regular files of the payload into the
// archive, every name below prefix.
func (w *exportWriter) entry(payload, prefix string) error {
	fh, err := os.Open(payload)
	if err != nil {
		return err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			err = w.dir(prefix+hdr.Name, hdr)
		case tar.TypeReg:
			err = w.file(prefix+hdr.Name, hdr, tr)
		default:
			continue
		}
		if err != nil {
			return err
		}
	}
}

// dir writes a directory marker: a name ending in "/", no content, no
// encryption - there is nothing in it to protect.
func (w *exportWriter) dir(name string, hdr *tar.Header) error {
	if len(name) == 0 || name[len(name)-1] != '/' {
		name += "/"
	}
	_, err := w.zw.CreateHeader(&zip.FileHeader{
		Name:     name,
		Method:   zip.Store,
		Modified: hdr.ModTime,
	})
	return err
}

// file deflates content into the scratch file while it sums up the CRC, then
// writes the entry: header with CRC and sizes, the twelve bytes of the
// ZipCrypto header, the deflated bytes enciphered. CreateRaw is what lets
// the enciphered bytes go in as they are; the normal Create path would
// deflate the plaintext itself and never encipher it.
func (w *exportWriter) file(name string, hdr *tar.Header, content io.Reader) error {
	if err := w.scratch.Truncate(0); err != nil {
		return err
	}
	if _, err := w.scratch.Seek(0, io.SeekStart); err != nil {
		return err
	}

	sum := crc32.NewIEEE()
	fw, err := flate.NewWriter(w.scratch, flate.BestSpeed)
	if err != nil {
		return err
	}
	plain, err := io.Copy(fw, io.TeeReader(content, sum))
	if err != nil {
		return err
	}
	if err := fw.Close(); err != nil {
		return err
	}
	deflated, err := w.scratch.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := w.scratch.Seek(0, io.SeekStart); err != nil {
		return err
	}
	crc := sum.Sum32()

	// Twelve header bytes: eleven random, the twelfth the high byte of the
	// CRC. Classic unzip tools use it as a quick password check before
	// trusting the rest of the stream.
	header := make([]byte, zipCryptoHeader)
	if _, err := rand.Read(header[:zipCryptoHeader-1]); err != nil {
		return err
	}
	header[zipCryptoHeader-1] = byte(crc >> 24)

	raw, err := w.zw.CreateRaw(&zip.FileHeader{
		Name:               name,
		Method:             zip.Deflate,
		Flags:              0x1,
		CRC32:              crc,
		CompressedSize64:   uint64(zipCryptoHeader + deflated),
		UncompressedSize64: uint64(plain),
		Modified:           hdr.ModTime,
	})
	if err != nil {
		return err
	}
	cw := &cipherWriter{w: raw, keys: newZipKeys(w.password)}
	if _, err := cw.Write(header); err != nil {
		return err
	}
	copied, err := io.Copy(cw, w.scratch)
	if err != nil {
		return err
	}
	if copied != deflated {
		return fmt.Errorf("%s: %d von %d gepackten Bytes kamen im ZIP an", name, copied, deflated)
	}
	return nil
}

// cipherWriter enciphers what it is given with ZipCrypto and hands it on.
type cipherWriter struct {
	w    io.Writer
	keys *zipKeys
	buf  []byte
}

func (c *cipherWriter) Write(p []byte) (int, error) {
	if cap(c.buf) < len(p) {
		c.buf = make([]byte, len(p))
	}
	out := c.buf[:len(p)]
	for i, b := range p {
		out[i] = c.keys.encryptByte(b)
	}
	return c.w.Write(out)
}
