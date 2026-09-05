package progress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestAReaderNeverSeesHalfADocument(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Replacing a file another process holds open is a POSIX property.
		// Windows refuses the rename, which says nothing about the design:
		// the scanner runs on Linux, and so does CI, where this test guards
		// the property that matters.
		t.Skip("rename over an open file is refused on Windows")
	}
	path := filepath.Join(t.TempDir(), "job.progress")
	w, err := New(path, "repair")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// The panel polls this file while it is being rewritten. Writing in place
	// would hand it a truncated document; write-then-rename cannot.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) == 0 {
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Errorf("the reader saw invalid JSON: %v", err)
				return
			}
		}
	}()

	for i := 1; i <= 500; i++ {
		w.File("wp-includes/file.php", i, 500)
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestTheDocumentCarriesTheCurrentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.progress")
	w, err := New(path, "repair")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	w.Phase(5, 5, "swap")
	w.Element("plugin", "contact-form-7", "5.9.8", 9, 14)
	w.File("wp-content/plugins/contact-form-7/includes/mail.php", 412, 1284)
	w.Log("ok", "ersetzt %s %s", "akismet", "5.3.3")
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema    int    `json:"schema"`
		Kind      string `json:"kind"`
		Phase     string `json:"phase"`
		FilesDone int    `json:"files_done"`
		Element   struct {
			Slug string `json:"slug"`
		} `json:"element"`
		Log []struct {
			Text string `json:"text"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Kind != "repair" || doc.Phase != "swap" {
		t.Errorf("head is wrong: %+v", doc)
	}
	if doc.FilesDone != 412 || doc.Element.Slug != "contact-form-7" {
		t.Errorf("position is wrong: %+v", doc)
	}
	if len(doc.Log) != 1 || doc.Log[0].Text != "ersetzt akismet 5.3.3" {
		t.Errorf("log is wrong: %+v", doc.Log)
	}
}

func TestAnEmptyPathIsAWriterThatDoesNothing(t *testing.T) {
	// Callers should not need a conditional around every progress call.
	w, err := New("", "scan")
	if err != nil {
		t.Fatal(err)
	}
	w.Phase(1, 5, "detect")
	w.Log("info", "nothing is written")
	if err := w.Close(); err != nil {
		t.Fatalf("a writer without a path must stay quiet: %v", err)
	}
	if len(w.Entries()) != 1 {
		t.Errorf("the log is kept in memory even without a file: %v", w.Entries())
	}
}
