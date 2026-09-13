package knownfiles

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestA404SaysTheListIsNotPublished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	f := NewFetcher("", 5*time.Second)

	if _, err := f.load("plugin-x", srv.URL+"/x.json"); !errors.Is(err, ErrNotPublished) {
		t.Fatalf("err = %v, want ErrNotPublished", err)
	}
	if _, err := f.load("plugin-y", "http://127.0.0.1:1/y.json"); err == nil || errors.Is(err, ErrNotPublished) {
		t.Errorf("an unreachable server reads as not published: %v", err)
	}
}
