package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/sigs"
)

// signatureSources are the files fetched by "malwatch update".
//
// The signatures come from Linux Malware Detect, which publishes them for
// free use. malwatch ships no signatures of its own, so a fresh install has
// to run update once before the signature stage does anything.
var signatureSources = []struct {
	name string
	url  string
	// required marks a file the update cannot do without.
	required bool
}{
	{name: "rfxn.hdb", url: "https://cdn.rfxn.com/downloads/rfxn.hdb", required: true},
	{name: "rfxn.ndb", url: "https://cdn.rfxn.com/downloads/rfxn.ndb", required: true},
	{name: "version", url: "https://cdn.rfxn.com/downloads/maldet.sigs.ver", required: false},
}

func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("sig-dir", defaultSigDir, "")
	quiet := fs.Bool("quiet", false, "")
	timeout := fs.Int("timeout", 120, "")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}

	if err := os.MkdirAll(*dir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "Signaturverzeichnis %s nicht anlegbar: %v\n", *dir, err)
		return report.ExitError
	}

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	failed := false
	for _, src := range signatureSources {
		target := filepath.Join(*dir, src.name)
		if err := download(client, src.url, target); err != nil {
			if src.required {
				fmt.Fprintf(os.Stderr, "%s konnte nicht geladen werden: %v\n", src.name, err)
				failed = true
			}
			continue
		}
		if !*quiet {
			fmt.Printf("%s aktualisiert\n", src.name)
		}
	}
	if failed {
		return report.ExitError
	}

	// Load what was just written. A file that downloads but does not parse
	// would otherwise look like a successful update and scan nothing.
	db, err := sigs.Load(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Die geladenen Signaturen sind unbrauchbar: %v\n", err)
		return report.ExitError
	}
	if db.Empty() {
		fmt.Fprintln(os.Stderr, "Die geladenen Signaturdateien enthalten keine verwertbaren Einträge.")
		return report.ExitError
	}
	if !*quiet {
		fmt.Printf("Signaturen: %s\n", db.Describe())
		if db.Unsupported > 0 {
			fmt.Printf("%d Muster mit nicht unterstützten Platzhaltern wurden übergangen.\n", db.Unsupported)
		}
	}
	return 0
}

// download writes the URL to target, replacing it only after a complete
// transfer. A connection that drops halfway must not leave a truncated
// signature file behind, which would silently shrink the detection.
func download(client *http.Client, url, target string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "malwatch")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	written, err := io.Copy(f, io.LimitReader(resp.Body, 256*1024*1024))
	closeErr := f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}
	if written == 0 {
		os.Remove(tmp)
		return fmt.Errorf("leere Antwort")
	}
	// Content-Length is advisory, but when the server sent one a short read
	// means a truncated file.
	if resp.ContentLength > 0 && written != resp.ContentLength {
		os.Remove(tmp)
		return fmt.Errorf("unvollständig übertragen (%d von %d Bytes)", written, resp.ContentLength)
	}
	return os.Rename(tmp, target)
}
