package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brightcolor/malwatch/internal/report"
)

// timeline records page checks and waits in the order they happen.
type timeline struct {
	mu     sync.Mutex
	events []string
	inner  PageProber
}

func (tl *timeline) add(event string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.events = append(tl.events, event)
}

func (tl *timeline) Get(url string) Probe {
	tl.add("probe")
	return tl.inner.Get(url)
}

func (tl *timeline) String() string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return strings.Join(tl.events, ",")
}

// PHP keeps running the compiled old release until OPcache looks at the file
// again. The check after the exchange has to come after that moment, and the
// wait runs while WordPress still shows its maintenance page.
func TestTheCheckWaitsUntilPHPReadsTheNewFiles(t *testing.T) {
	root := site(t)
	tl := &timeline{inner: healthy()}
	opts := options(t, root, onePlan(root, planAkismet), tl, &recorder{})
	opts.Settle = 3 * time.Second
	opts.Sleep = func(d time.Duration) {
		state := "maintenance"
		if _, err := os.Stat(filepath.Join(root, ".maintenance")); err != nil {
			state = "live"
		}
		tl.add("wait " + d.String() + " " + state)
	}

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Elements[0].Outcome != report.UpgradeUpdated {
		t.Fatalf("element = %+v", rep.Elements[0])
	}
	if got, want := tl.String(), "probe,probe,wait 3s maintenance,probe,probe"; got != want {
		t.Errorf("timeline = %s, want %s", got, want)
	}
}

func TestTheCheckAfterARollbackWaitsAsWell(t *testing.T) {
	root := site(t)
	tl := &timeline{inner: &scripted{answers: map[string][]Probe{siteURL: {{Status: 200}, {Status: 500}, {Status: 200}}}}}
	opts := options(t, root, onePlan(root, planAkismet), tl, &recorder{})
	opts.Settle = 3 * time.Second
	opts.Sleep = func(d time.Duration) { tl.add("wait " + d.String()) }

	rep, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Elements[0].Outcome != report.UpgradeRolledBack {
		t.Fatalf("element = %+v", rep.Elements[0])
	}
	if got, want := tl.String(), "probe,probe,wait 3s,probe,probe,wait 3s,probe,probe"; got != want {
		t.Errorf("timeline = %s, want %s", got, want)
	}
}

func TestASettleOfZeroWaitsNothing(t *testing.T) {
	root := site(t)
	waited := false
	opts := options(t, root, onePlan(root, planAkismet), healthy(), &recorder{})
	opts.Sleep = func(time.Duration) { waited = true }

	if _, err := Run(opts); err != nil {
		t.Fatal(err)
	}
	if waited {
		t.Error("a run with Settle 0 waited")
	}
}
