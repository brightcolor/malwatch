// Package progress publishes what a long run is currently doing, so the panel
// can show it while it happens instead of only afterwards.
package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// interval throttles the writes. One document per file would be a thousand
// writes for a single plugin; twice a second is more often than the panel
// polls.
const interval = 500 * time.Millisecond

// LogEntry is one line of what happened. The same entries end up in the
// report, so the running view and the permanent log share one mechanism.
type LogEntry struct {
	Time  time.Time `json:"t"`
	Level string    `json:"level"`
	Text  string    `json:"text"`
}

type element struct {
	Kind    string `json:"kind"`
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

type document struct {
	Schema        int        `json:"schema"`
	Kind          string     `json:"kind"`
	StartedAt     time.Time  `json:"started_at"`
	Phase         string     `json:"phase"`
	PhaseIndex    int        `json:"phase_index"`
	PhaseTotal    int        `json:"phase_total"`
	ElementsDone  int        `json:"elements_done"`
	ElementsTotal int        `json:"elements_total"`
	Element       *element   `json:"element,omitempty"`
	FilesDone     int        `json:"files_done"`
	FilesTotal    int        `json:"files_total"`
	File          string     `json:"file,omitempty"`
	Log           []LogEntry `json:"log"`
}

// Writer keeps the document and writes it out, throttled.
type Writer struct {
	mu      sync.Mutex
	path    string
	doc     document
	written time.Time
}

// New starts a progress file. An empty path returns a writer that keeps the
// log in memory and writes nothing, so callers need no conditionals.
func New(path, kind string) (*Writer, error) {
	w := &Writer{path: path}
	w.doc = document{Schema: 1, Kind: kind, StartedAt: time.Now().UTC(), Log: []LogEntry{}}
	if path == "" {
		return w, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return w, w.Flush()
}

// Phase records which of the run's phases is active.
func (w *Writer) Phase(index, total int, name string) {
	w.mu.Lock()
	w.doc.Phase, w.doc.PhaseIndex, w.doc.PhaseTotal = name, index, total
	w.mu.Unlock()
	w.maybeWrite()
}

// Element records which unit is being worked on. It clears the file counters,
// which belong to the element that just ended.
func (w *Writer) Element(kind, slug, version string, done, total int) {
	w.mu.Lock()
	w.doc.Element = &element{Kind: kind, Slug: slug, Version: version}
	w.doc.ElementsDone, w.doc.ElementsTotal = done, total
	w.doc.FilesDone, w.doc.FilesTotal, w.doc.File = 0, 0, ""
	w.mu.Unlock()
	w.maybeWrite()
}

// File records the position within the current element.
func (w *Writer) File(rel string, done, total int) {
	w.mu.Lock()
	w.doc.File, w.doc.FilesDone, w.doc.FilesTotal = rel, done, total
	w.mu.Unlock()
	w.maybeWrite()
}

// Log appends a line. level is one of ok, info, warn or error.
func (w *Writer) Log(level, format string, args ...any) {
	w.mu.Lock()
	w.doc.Log = append(w.doc.Log, LogEntry{
		Time: time.Now().UTC(), Level: level, Text: fmt.Sprintf(format, args...),
	})
	w.mu.Unlock()
	// A log line is a state change worth publishing at once.
	_ = w.Flush()
}

// Entries returns a copy of the log, for the report.
func (w *Writer) Entries() []LogEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]LogEntry, len(w.doc.Log))
	copy(out, w.doc.Log)
	return out
}

func (w *Writer) maybeWrite() {
	w.mu.Lock()
	due := time.Since(w.written) >= interval
	w.mu.Unlock()
	if due {
		_ = w.Flush()
	}
}

// Flush writes the document out, complete or not at all.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "" {
		return nil
	}
	raw, err := json.Marshal(w.doc)
	if err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.path); err != nil {
		return err
	}
	w.written = time.Now()
	return nil
}

// Close writes the final state.
func (w *Writer) Close() error { return w.Flush() }
