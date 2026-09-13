package vulns

import (
	"math"
	"strings"

	"github.com/brightcolor/malwatch/internal/report"
)

// cvss3Score computes the CVSS 3.x base score from a vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
//
// The GitHub advisories publish the vector and leave the number out, while
// the WordPress data carries both. Working the number out here puts every
// advisory on the same scale, whichever database it came from.
//
// A vector this cannot read gives ok=false. Version 4 vectors are among them:
// their score comes out of a lookup table of several hundred rows, and the
// advisories that carry only a version 4 vector also carry a rating in words.
func cvss3Score(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		metrics[k] = v
	}

	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	// Privileges weigh less once the flaw reaches beyond its own component.
	privileges := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		privileges = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	impactTable := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	values := []struct {
		key   string
		table map[string]float64
	}{
		{"AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}},
		{"AC", map[string]float64{"L": 0.77, "H": 0.44}},
		{"PR", privileges},
		{"UI", map[string]float64{"N": 0.85, "R": 0.62}},
		{"C", impactTable},
		{"I", impactTable},
		{"A", impactTable},
	}
	read := make([]float64, len(values))
	for i, v := range values {
		f, ok := v.table[metrics[v.key]]
		if !ok {
			return 0, false
		}
		read[i] = f
	}
	av, ac, pr, ui, c, in, a := read[0], read[1], read[2], read[3], read[4], read[5], read[6]

	iss := 1 - (1-c)*(1-in)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return roundUp(math.Min(impact+exploitability, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
}

// roundUp rounds up to one decimal the way CVSS 3.1 prescribes it: on
// integers, so that 4.000000000000001 stays 4.0 and does not become 4.1.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// severityFromScore maps a score onto the rating bands of the CVSS
// specification. A score of zero has no rating.
func severityFromScore(score float64) report.Severity {
	switch {
	case score >= 9.0:
		return report.SeverityCritical
	case score >= 7.0:
		return report.SeverityHigh
	case score >= 4.0:
		return report.SeverityMedium
	case score > 0:
		return report.SeverityLow
	}
	return ""
}

// severityFromWord reads a rating written out by a database: "critical",
// "HIGH", "Moderate", or the single letters one of them uses.
func severityFromWord(word string) report.Severity {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "critical", "c":
		return report.SeverityCritical
	case "high", "h", "important":
		return report.SeverityHigh
	case "medium", "moderate", "m":
		return report.SeverityMedium
	case "low", "l":
		return report.SeverityLow
	}
	return ""
}
