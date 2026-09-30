package scanner

import (
	"sync"

	"github.com/brightcolor/malwatch/internal/report"
	"github.com/brightcolor/malwatch/internal/rules"
)

// The sources that confirm the content of a file with findings, as the report
// counts them (report.Report.Verified).
const (
	verifiedCopy = "Kopie einer geprüften Herstellerdatei"
)

// verifiedCount counts confirmed files per source across the workers.
type verifiedCount struct {
	mu sync.Mutex
	m  map[string]int
}

// count notes one file confirmed by source.
func (o *Options) count(source string) {
	if o == nil || o.verified == nil {
		return
	}
	o.verified.mu.Lock()
	o.verified.m[source]++
	o.verified.mu.Unlock()
}

// keepPlace keeps the findings about where a file lies and about how it
// differs from the vendor's release, and drops those about its content: the
// content is confirmed.
func keepPlace(out []report.Finding) []report.Finding {
	kept := out[:0]
	for _, f := range out {
		if f.Engine == "herstellerdateien" {
			kept = append(kept, f)
			continue
		}
		if r := rules.ByID(f.Rule); r != nil && r.ByPlace {
			kept = append(kept, f)
		}
	}
	return kept
}
