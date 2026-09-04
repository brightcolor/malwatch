// Package clamav drives an installed ClamAV as an optional extra stage.
// malwatch works without it; where it is present its signature set is a
// worthwhile second opinion.
package clamav

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"
)

// Hit is one file ClamAV considers infected.
type Hit struct {
	Path      string
	Signature string
}

// Scanner is a detected ClamAV installation.
type Scanner struct {
	binary  string
	daemon  bool
	version string
}

// Detect looks for clamdscan first: it reuses the daemon's loaded signature
// set instead of loading several hundred megabytes per run.
func Detect() *Scanner {
	for _, cand := range []struct {
		name   string
		daemon bool
	}{
		{"clamdscan", true},
		{"clamscan", false},
	} {
		path, err := exec.LookPath(cand.name)
		if err != nil {
			continue
		}
		return &Scanner{binary: path, daemon: cand.daemon, version: probeVersion(path)}
	}
	return &Scanner{}
}

// Available reports whether ClamAV can be used.
func (s *Scanner) Available() bool { return s != nil && s.binary != "" }

// Describe returns a short label for the report.
func (s *Scanner) Describe() string {
	if !s.Available() {
		return "nicht installiert"
	}
	v := s.version
	if v == "" {
		v = "unbekannte Version"
	}
	if s.daemon {
		return v + " (Dienst)"
	}
	return v
}

func probeVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

// Scan runs ClamAV over the given paths and returns the infected files.
//
// A non-zero exit status is expected: ClamAV returns 1 when it found
// something. Only status 2 and above is a real failure.
func (s *Scanner) Scan(paths, excludes []string) ([]Hit, error) {
	if !s.Available() {
		return nil, nil
	}

	args := []string{"--infected", "--no-summary"}
	if s.daemon {
		// Without this the daemon reads the files itself and cannot see
		// anything a customer directory does not grant it.
		args = append(args, "--fdpass", "--multiscan")
	} else {
		args = append(args, "--recursive")
		for _, pattern := range excludes {
			args = append(args, "--exclude="+globToRegexp(pattern))
		}
	}
	args = append(args, paths...)

	cmd := exec.Command(s.binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var hits []Hit
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if hit, ok := parseLine(sc.Text()); ok {
			hits = append(hits, hit)
		}
	}

	err = cmd.Wait()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			// Exit 1 means "virus found", which is not an error here.
			return hits, nil
		}
		return hits, err
	}
	return hits, nil
}

// parseLine reads a line of the form "/path/to/file: Signature FOUND".
func parseLine(line string) (Hit, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasSuffix(line, " FOUND") {
		return Hit{}, false
	}
	body := strings.TrimSuffix(line, " FOUND")
	// A file name may contain a colon, so the last one wins.
	idx := strings.LastIndex(body, ": ")
	if idx <= 0 {
		return Hit{}, false
	}
	return Hit{
		Path:      body[:idx],
		Signature: strings.TrimSpace(body[idx+2:]),
	}, true
}

// globToRegexp converts an exclude glob into the regular expression that
// clamscan expects. It is deliberately conservative: an unconvertible
// pattern becomes one that matches nothing rather than everything.
func globToRegexp(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
