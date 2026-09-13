package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"sync"
	"testing"
)

// recorder is an Executor that writes down every command and answers from a
// script: what a subcommand prints, and the error a subcommand returns.
type recorder struct {
	mu       sync.Mutex
	commands []Command
	stdins   []string
	stdout   map[string]string // "db export" -> printed text
	fail     map[string]error  // "core update-db" -> returned error
}

func (r *recorder) Run(ctx context.Context, c Command) error {
	in := ""
	if c.Stdin != nil {
		raw, _ := io.ReadAll(c.Stdin)
		in = string(raw)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, c)
	r.stdins = append(r.stdins, in)
	sub := subcommand(c)
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, r.stdout[sub])
	}
	return r.fail[sub]
}

// subcommand is "db export" for the arguments of a WP-CLI command.
func subcommand(c Command) string {
	var words []string
	for _, a := range c.Args[1:] {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(words) > 2 {
		words = words[:2]
	}
	return strings.Join(words, " ")
}

func (r *recorder) subcommands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.commands {
		out = append(out, subcommand(c))
	}
	return out
}

func TestWPCLIRunsAsTheSiteUserWithItsPHP(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"db export": "-- dump"}}
	cli := WPCLI{Exec: rec, User: "web12", Group: "client3", PHP: "/usr/bin/php8.2", Binary: "/usr/local/bin/wp"}
	install := "/var/www/clients/client3/web12/web"
	ctx := context.Background()

	var dump bytes.Buffer
	if err := cli.ExportDB(ctx, install, &dump); err != nil {
		t.Fatal(err)
	}
	if err := cli.UpdateDB(ctx, install); err != nil {
		t.Fatal(err)
	}
	if err := cli.ImportDB(ctx, install, strings.NewReader("-- dump")); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(rec.subcommands(), ","); got != "db export,core update-db,db import" {
		t.Errorf("commands = %s", got)
	}
	c := rec.commands[0]
	if c.User != "web12" || c.Group != "client3" || c.Binary != "/usr/bin/php8.2" || c.Args[0] != "/usr/local/bin/wp" {
		t.Errorf("command = %+v", c)
	}
	joined := strings.Join(c.Args, " ")
	for _, want := range []string{"--path=" + install, "--skip-plugins", "--skip-themes"} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments lack %s: %s", want, joined)
		}
	}
	if dump.String() != "-- dump" || rec.stdins[2] != "-- dump" {
		t.Errorf("export %q, import read %q", dump.String(), rec.stdins[2])
	}
}

func TestParseRunAsRefusesRoot(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		switch name {
		case "web12":
			return &user.User{Username: "web12", Uid: "5012"}, nil
		case "toor":
			return &user.User{Username: "toor", Uid: "0"}, nil
		}
		return nil, errors.New("unknown user")
	}
	if name, group, err := ParseRunAs("web12:client3", lookup); err != nil || name != "web12" || group != "client3" {
		t.Errorf("web12:client3 = %q %q %v", name, group, err)
	}
	for _, spec := range []string{"", "root", "root:root", "toor:toor", "web12;rm", "niemand:client3"} {
		if _, _, err := ParseRunAs(spec, lookup); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

// TestHelperEcho copies stdin to stdout and writes a line to stderr, standing
// in for a program the SystemExecutor starts. Outside that test it does nothing.
func TestHelperEcho(t *testing.T) {
	if os.Getenv("MALWATCH_HELPER_ECHO") != "1" {
		return
	}
	raw, _ := io.ReadAll(os.Stdin)
	fmt.Print(string(raw))
	fmt.Fprintln(os.Stderr, "letzte Zeile")
	if os.Getenv("MALWATCH_HELPER_FAIL") == "1" {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestSystemExecutorConnectsStdinStdoutAndNamesTheError(t *testing.T) {
	var out bytes.Buffer
	err := SystemExecutor{}.Run(context.Background(), Command{
		Binary: os.Args[0], Args: []string{"-test.run=TestHelperEcho", "--"},
		Env: []string{"MALWATCH_HELPER_ECHO=1"}, Stdin: strings.NewReader("hallo"), Stdout: &out,
	})
	if err != nil || out.String() != "hallo" {
		t.Fatalf("out = %q, err = %v", out.String(), err)
	}

	err = SystemExecutor{}.Run(context.Background(), Command{
		Binary: os.Args[0], Args: []string{"-test.run=TestHelperEcho", "--"},
		Env: []string{"MALWATCH_HELPER_ECHO=1", "MALWATCH_HELPER_FAIL=1"},
	})
	if err == nil || !strings.Contains(err.Error(), "letzte Zeile") {
		t.Errorf("err = %v, want the last line of stderr", err)
	}
}
