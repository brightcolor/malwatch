package cms

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeWordPressOrg answers the wordpress.org endpoints the lookup asks.
func fakeWordPressOrg(t *testing.T) *Lookup {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/plugins/info/1.2/"):
			if r.URL.Query().Get("request[slug]") == "bezahlt" {
				_, _ = w.Write([]byte(`{"error":"Plugin not found."}`))
				return
			}
			_, _ = w.Write([]byte(`{"version":"5.3.3","requires":"6.2","requires_php":"7.2"}`))
		case strings.HasPrefix(r.URL.Path, "/themes/info/1.2/"):
			_, _ = w.Write([]byte(`{"version":"1.2","requires":false,"requires_php":false}`))
		case r.URL.Path == "/core/stable-check/1.0/":
			_, _ = w.Write([]byte(`{"6.4.2":"insecure","6.4.4":"insecure","6.4.5":"outdated","6.5.3":"outdated","7.1":"latest"}`))
		case r.URL.Path == "/core/version-check/1.7/":
			_, _ = w.Write([]byte(`{"offers":[{"version":"7.1","current":"7.1","php_version":"7.4"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	l := NewLookup(NewCache("", time.Hour), 5*time.Second)
	l.wporg = srv.URL
	return l
}

func TestLatestPluginInfoCarriesTheRequirements(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got := l.LatestPluginInfo("plugin", "akismet"); got != (PluginInfo{Version: "5.3.3", RequiresWP: "6.2", RequiresPHP: "7.2"}) {
		t.Errorf("plugin = %+v", got)
	}
	if got := l.LatestPluginInfo("theme", "twentytwentyfour"); got != (PluginInfo{Version: "1.2"}) {
		t.Errorf("theme with false requirements = %+v", got)
	}
	if got := l.LatestPlugin("plugin", "bezahlt"); got != "" {
		t.Errorf("a plugin wordpress.org does not list = %q", got)
	}
	// The second call comes from the cache and says the same.
	if got := l.LatestPluginInfo("plugin", "akismet"); got.RequiresPHP != "7.2" {
		t.Errorf("cached plugin = %+v", got)
	}
}

func TestWordPressBranchLatestStaysOnTheBranch(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got := l.WordPressBranchLatest("6.4.2"); got != "6.4.5" {
		t.Errorf("newest on the branch of 6.4.2 = %q, want 6.4.5", got)
	}
	if got := l.WordPressBranchLatest("6.5.3"); got != "" {
		t.Errorf("the newest of its branch has nothing newer: %q", got)
	}
	if got := l.WordPressRequiresPHP(); got != "7.4" {
		t.Errorf("requires php = %q", got)
	}
}
