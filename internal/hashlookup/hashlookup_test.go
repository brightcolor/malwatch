package hashlookup

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A database of known files answers a batch of SHA-1 sums with the entries it
// has. A file counts as known when the entry carries the same SHA-256 as well
// and nothing marks it as malicious.
func TestKnownConfirmsOnlyOrdinaryFilesWithBothSums(t *testing.T) {
	var asked []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bulk/sha1" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Hashes []string `json:"hashes"`
		}
		_ = json.Unmarshal(body, &req)
		asked = append(asked, req.Hashes...)
		_, _ = w.Write([]byte(`[
			{"FileName":"usr/share/php/lib/a.inc","SHA-1":"AAAA","SHA-256":"A256"},
			{"FileName":"x/other.php","SHA-1":"BBBB","SHA-256":"FFFF"},
			{"FileName":"tools/shell.php","SHA-1":"CCCC","SHA-256":"C256","KnownMalicious":"example-feed"}
		]`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, srv.Client().Transport)
	known, err := c.Known([]File{
		{SHA1: "aaaa", SHA256: "a256"},
		{SHA1: "bbbb", SHA256: "b256"},
		{SHA1: "cccc", SHA256: "c256"},
		{SHA1: "dddd", SHA256: "d256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if known["a256"] != "usr/share/php/lib/a.inc" {
		t.Errorf("bekannte Datei nicht bestätigt: %v", known)
	}
	for _, sum := range []string{"b256", "c256", "d256"} {
		if _, ok := known[sum]; ok {
			t.Errorf("%s bestätigt: %v", sum, known)
		}
	}
	if strings.Join(asked, ",") != "AAAA,BBBB,CCCC,DDDD" {
		t.Errorf("gefragt wurde nach %v", asked)
	}
}

func TestNewRefusesAddressesThatAreNotHTTPS(t *testing.T) {
	for _, raw := range []string{"http://hashlookup.circl.lu", "ftp://x", "hashlookup.circl.lu", ""} {
		if err := CheckURL(raw); err == nil {
			t.Errorf("%q angenommen", raw)
		}
	}
	if err := CheckURL(DefaultURL); err != nil {
		t.Errorf("Vorgabe abgelehnt: %v", err)
	}
}
