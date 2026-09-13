package vulns

import (
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

func TestCVSS3ScoreMatchesThePublishedNumbers(t *testing.T) {
	// Each pair appears in a vulnerability database with both the vector and
	// the score, so the expected number is the one the database printed.
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
	}
	for _, c := range cases {
		got, ok := cvss3Score(c.vector)
		if !ok {
			t.Errorf("%s: not readable", c.vector)
			continue
		}
		if got != c.want {
			t.Errorf("%s: score %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSS3ScoreRefusesWhatItCannotRead(t *testing.T) {
	for _, vector := range []string{
		"",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", // no scope
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		if _, ok := cvss3Score(vector); ok {
			t.Errorf("%q was read as a valid CVSS 3 vector", vector)
		}
	}
}

func TestSeverityBands(t *testing.T) {
	cases := map[float64]report.Severity{
		10.0: report.SeverityCritical,
		9.0:  report.SeverityCritical,
		8.9:  report.SeverityHigh,
		7.0:  report.SeverityHigh,
		6.9:  report.SeverityMedium,
		4.0:  report.SeverityMedium,
		3.9:  report.SeverityLow,
		0.1:  report.SeverityLow,
		0:    "",
	}
	for score, want := range cases {
		if got := severityFromScore(score); got != want {
			t.Errorf("score %.1f: %q, want %q", score, got, want)
		}
	}
}

func TestSeverityWords(t *testing.T) {
	cases := map[string]report.Severity{
		"CRITICAL": report.SeverityCritical,
		"c":        report.SeverityCritical,
		"High":     report.SeverityHigh,
		"MODERATE": report.SeverityMedium,
		"m":        report.SeverityMedium,
		"Low":      report.SeverityLow,
		"none":     "",
		"":         "",
	}
	for word, want := range cases {
		if got := severityFromWord(word); got != want {
			t.Errorf("%q: %q, want %q", word, got, want)
		}
	}
}
