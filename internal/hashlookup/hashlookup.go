// Package hashlookup asks a database of known files, such as CIRCL hashlookup,
// whether files are ordinary copies of published software.
//
// Only sums leave the server, never content: a batch of SHA-1 sums goes out,
// the entries the database knows come back. The database collects the files
// of Linux distributions and the NIST software reference library, so it knows
// many libraries that plugins bundle - PHP_CodeSniffer, Zend, PHPMailer - in
// the versions the distributions ship.
package hashlookup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultURL is the public service of CIRCL. The ISPConfig addon has it as
// the default of its setting (malwatch_config hashlookup_url).
const DefaultURL = "https://hashlookup.circl.lu"

// maxBatch is how many sums go out in one request.
const maxBatch = 100

// CheckURL says in German why an address cannot be used, or returns nil.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(raw) > 200 {
		return fmt.Errorf("%q ist keine https-Adresse wie %s", raw, DefaultURL)
	}
	return nil
}

// File is one file by its sums, lower case hex.
type File struct {
	SHA1   string
	SHA256 string
}

// Client talks to one database.
type Client struct {
	base   string
	client *http.Client
}

// New returns a client for the database at base. transport nil is the
// default network.
func New(base string, timeout time.Duration, transport http.RoundTripper) *Client {
	return &Client{base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: timeout, Transport: transport}}
}

// Known returns the files the database knows as ordinary files, by SHA-256,
// with the name it knows them by. An entry has to carry the same SHA-256 as
// the file, and an entry marked as malicious confirms nothing.
func (c *Client) Known(files []File) (map[string]string, error) {
	want := map[string]string{}
	var batch []string
	out := map[string]string{}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		entries, err := c.bulk(batch)
		batch = batch[:0]
		if err != nil {
			return err
		}
		for _, e := range entries {
			sha1, _ := e["SHA-1"].(string)
			sha256, _ := e["SHA-256"].(string)
			name, _ := e["FileName"].(string)
			if _, bad := e["KnownMalicious"]; bad {
				continue
			}
			if want[strings.ToLower(sha1)] != "" && want[strings.ToLower(sha1)] == strings.ToLower(sha256) {
				out[strings.ToLower(sha256)] = name
			}
		}
		return nil
	}
	for _, f := range files {
		if f.SHA1 == "" || f.SHA256 == "" {
			continue
		}
		want[strings.ToLower(f.SHA1)] = strings.ToLower(f.SHA256)
		batch = append(batch, strings.ToUpper(f.SHA1))
		if len(batch) == maxBatch {
			if err := flush(); err != nil {
				return out, err
			}
		}
	}
	return out, flush()
}

// bulk asks for one batch of SHA-1 sums.
func (c *Client) bulk(sums []string) ([]map[string]any, error) {
	body, err := json.Marshal(map[string][]string{"hashes": sums})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/bulk/sha1", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "malwatch")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("Antwort nicht lesbar: %w", err)
	}
	return entries, nil
}
