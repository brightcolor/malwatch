// Package quarantine keeps files a scan or a repair took off a website: an
// on-disk store they can be listed from, brought back to their exact spot,
// or shipped out as a password-protected sample for someone else to look at.
package quarantine

// Entry is one quarantined file or directory, as recorded in meta.json next
// to its payload.
type Entry struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"` // RFC3339, UTC
	Domain       string `json:"domain"`
	Root         string `json:"root"`
	RelPath      string `json:"rel_path"` // slash-separated, relative to Root
	EntryKind    string `json:"entry_kind"`
	Origin       string `json:"origin"`
	Reason       string `json:"reason"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Files        int    `json:"files"`
	Bytes        int64  `json:"bytes"`
	ArchiveBytes int64  `json:"archive_bytes"`
}

// Source describes what is about to be taken out of a website.
type Source struct {
	Root     string // web root, absolute
	RelPath  string // relative to Root, slash-separated
	Domain   string
	Origin   string
	Reason   string
	RuleID   string
	Severity string
}

// TotalBytes adds up the original size every entry had before it was
// archived - what quarantine is holding, not what it costs on disk once
// compressed.
func TotalBytes(entries []Entry) int64 {
	var total int64
	for _, e := range entries {
		total += e.Bytes
	}
	return total
}
