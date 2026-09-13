package upgrade

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Probe is what one page answered.
type Probe struct {
	Status int    // 0 without an answer
	Empty  bool   // a 200 whose body held nothing but whitespace
	Err    string // why there was no answer
}

// PageProber fetches a page of the site. *Prober is the real one; the tests
// script the answers.
type PageProber interface {
	Get(url string) Probe
}

// Prober asks the web server on this machine for a page of the website.
type Prober struct {
	client *http.Client
}

// NewProber returns a prober that connects to connect - "host" or
// "host:port" - whatever name an address carries, and sends that name as Host
// and SNI. An empty connect means 127.0.0.1. The certificate stays unverified:
// the check judges the answer of the site.
func NewProber(connect string, timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if connect == "" {
		connect = "127.0.0.1"
	}
	host, port, err := net.SplitHostPort(connect)
	if err != nil {
		host, port = strings.Trim(connect, "[]"), ""
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, addrPort, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if port != "" {
				addrPort = port
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, addrPort))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &Prober{client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: sameSite}}
}

// sameSite follows a redirect to the same name or its www variant, up to five
// times. Anything else ends the check, with the redirect as the answer.
func sameSite(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return http.ErrUseLastResponse
	}
	first := strings.TrimPrefix(strings.ToLower(via[0].URL.Hostname()), "www.")
	next := strings.TrimPrefix(strings.ToLower(req.URL.Hostname()), "www.")
	if first != next {
		return http.ErrUseLastResponse
	}
	return nil
}

// Get fetches url and reads at most 2 MB of the answer.
func (p *Prober) Get(url string) Probe {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Probe{Err: err.Error()}
	}
	req.Header.Set("User-Agent", "malwatch-upgrade")
	resp, err := p.client.Do(req)
	if err != nil {
		return Probe{Err: shortError(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return Probe{
		Status: resp.StatusCode,
		Empty:  resp.StatusCode == http.StatusOK && len(bytes.TrimSpace(body)) == 0,
	}
}

// shortError keeps the part of a transport error a person can act on.
func shortError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "Zeitüberschreitung"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

// Broken compares one page before and after an exchange and returns why the
// page counts as broken, or "". A page that answered with 500 or more before,
// or gave no answer at all, says nothing afterwards.
func Broken(before, after Probe) string {
	if !Judgeable(before) {
		return ""
	}
	switch {
	case after.Status == 0:
		return "keine Antwort (" + after.Err + ")"
	case after.Status >= 500:
		return fmt.Sprintf("Antwort %d", after.Status)
	case after.Empty && !before.Empty:
		return "leere Seite"
	}
	return ""
}

// Judgeable reports whether the answer of a page before an exchange lets a
// check afterwards mean something.
func Judgeable(before Probe) bool {
	return before.Status > 0 && before.Status < 500
}

// pageNames are the two pages every check looks at, in this order.
var pageNames = []string{"Startseite", "Anmeldeseite"}

// pageURLs returns the addresses of both pages below the URL of an
// installation, which ends in a slash (LoadPlan sees to that).
func pageURLs(base string) []string {
	return []string{base, base + "wp-login.php"}
}

// probeSite fetches both pages.
func probeSite(p PageProber, base string) []Probe {
	urls := pageURLs(base)
	out := make([]Probe, len(urls))
	for i, u := range urls {
		out[i] = p.Get(u)
	}
	return out
}

// siteBroken returns why the site counts as broken after an exchange, naming
// the page, or "" when neither page does.
func siteBroken(before, after []Probe) string {
	for i := range before {
		if i >= len(after) || i >= len(pageNames) {
			break
		}
		if reason := Broken(before[i], after[i]); reason != "" {
			return pageNames[i] + ": " + reason
		}
	}
	return ""
}
