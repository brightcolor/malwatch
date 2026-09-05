package vendorfiles

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoreAcceptsALocalisedBaseWithoutAVerb(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write(zipOf(t, map[string]string{"wordpress/wp-login.php": "<?php"}))
	}))
	defer srv.Close()

	// One address for every source is what the acceptance test passes. The
	// URL must stay a URL rather than carry a formatting complaint.
	f := NewFetcher(BaseURLs{Core: srv.URL + "/", LocalisedCore: srv.URL + "/"}, 10*time.Second)
	if _, err := f.Core("6.6.2", "de_DE", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(asked, "%!") {
		t.Fatalf("the address carries a formatting complaint: %q", asked)
	}
	if asked != "/wordpress-6.6.2-de_DE.zip" {
		t.Errorf("asked for %q", asked)
	}
}
