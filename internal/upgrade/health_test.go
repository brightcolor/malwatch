package upgrade

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// connectTo is the host:port an httptest server listens on.
func connectTo(srv *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
}

func TestProberConnectsToTheGivenAddressUnderTheSiteName(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	got := NewProber(connectTo(srv), 5*time.Second).Get("http://beispiel.de/")
	if got.Status != 200 || got.Empty {
		t.Fatalf("probe = %+v", got)
	}
	if host != "beispiel.de" {
		t.Errorf("Host = %q, want beispiel.de", host)
	}
}

func TestProberSendsTheSiteNameOverTLSWithoutVerifying(t *testing.T) {
	var sni string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni = r.TLS.ServerName
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	got := NewProber(connectTo(srv), 5*time.Second).Get("https://beispiel.de/")
	if got.Status != 200 {
		t.Fatalf("probe = %+v", got)
	}
	if sni != "beispiel.de" {
		t.Errorf("SNI = %q, want beispiel.de", sni)
	}
}

func TestProberFollowsItsOwnSiteAndStopsAtAnother(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "beispiel.de":
			http.Redirect(w, r, "http://www.beispiel.de/", http.StatusMovedPermanently)
		case r.Host == "www.beispiel.de" && r.URL.Path == "/":
			_, _ = w.Write([]byte("ok"))
		default:
			http.Redirect(w, r, "http://anderswo.example/", http.StatusFound)
		}
	}))
	defer srv.Close()
	p := NewProber(connectTo(srv), 5*time.Second)

	if got := p.Get("http://beispiel.de/"); got.Status != 200 {
		t.Errorf("the redirect to the www name was not followed: %+v", got)
	}
	if got := p.Get("http://www.beispiel.de/wp-login.php"); got.Status != 302 {
		t.Errorf("a redirect to another site has to be the answer: %+v", got)
	}
}

func TestProberWithoutAnAnswerReportsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	got := NewProber(connectTo(srv), 100*time.Millisecond).Get("http://beispiel.de/")
	if got.Status != 0 || got.Err == "" {
		t.Errorf("probe = %+v, want no answer", got)
	}
}

func TestProberCallsAWhitespacePageEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("\n  \n"))
	}))
	defer srv.Close()
	if got := NewProber(connectTo(srv), 5*time.Second).Get("http://beispiel.de/"); !got.Empty {
		t.Errorf("probe = %+v, want empty", got)
	}
}

func TestBrokenJudgesOnlyWhatAnsweredBefore(t *testing.T) {
	ok := Probe{Status: 200}
	cases := []struct {
		name          string
		before, after Probe
		broken        bool
	}{
		{"500 after 200", ok, Probe{Status: 500}, true},
		{"no answer after 200", ok, Probe{Err: "Zeitüberschreitung"}, true},
		{"empty after content", ok, Probe{Status: 200, Empty: true}, true},
		{"redirect after 200", ok, Probe{Status: 302}, false},
		{"403 after 200", ok, Probe{Status: 403}, false},
		{"500 after 500", Probe{Status: 500}, Probe{Status: 500}, false},
		{"500 after no answer", Probe{Err: "x"}, Probe{Status: 500}, false},
		{"empty after empty", Probe{Status: 200, Empty: true}, Probe{Status: 200, Empty: true}, false},
	}
	for _, c := range cases {
		if got := Broken(c.before, c.after) != ""; got != c.broken {
			t.Errorf("%s: broken = %v, want %v", c.name, got, c.broken)
		}
	}
}

func TestSiteBrokenNamesThePage(t *testing.T) {
	before := []Probe{{Status: 200}, {Status: 200}}
	after := []Probe{{Status: 200}, {Status: 500}}
	if got := siteBroken(before, after); got != "Anmeldeseite: Antwort 500" {
		t.Errorf("siteBroken = %q", got)
	}
}
