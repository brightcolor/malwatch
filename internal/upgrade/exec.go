package upgrade

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
)

// Command is one program the upgrade runs for a website.
type Command struct {
	User   string // run as this user; empty runs as the caller
	Group  string // with this group; empty takes the user's own
	Binary string
	Args   []string
	Env    []string  // added to a small environment of its own
	Stdin  io.Reader // nil reads nothing
	Stdout io.Writer // nil discards
}

// Executor runs a command. SystemExecutor is the real one; the tests record.
type Executor interface {
	Run(ctx context.Context, cmd Command) error
}

// SystemExecutor runs commands on this machine, through runuser when the
// command names another user than the one running malwatch.
type SystemExecutor struct{}

// Run starts the command and waits for it. An error names the last line the
// program wrote to stderr.
func (SystemExecutor) Run(ctx context.Context, c Command) error {
	name, args := c.Binary, c.Args
	if c.User != "" && !isCurrentUser(c.User) {
		name = "runuser"
		args = []string{"-u", c.User}
		if c.Group != "" {
			args = append(args, "-g", c.Group)
		}
		args = append(args, "--", c.Binary)
		args = append(args, c.Args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(baseEnv(), c.Env...)
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	stderr := &tailBuffer{max: 8192}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if line := lastLine(stderr.buf.String()); line != "" {
			return fmt.Errorf("%s: %w: %s", c.Binary, err, line)
		}
		return fmt.Errorf("%s: %w", c.Binary, err)
	}
	return nil
}

// baseEnv is the environment a website command starts from. The environment
// of the root process stays behind: WP-CLI loads the mu-plugins of the site,
// and whatever sits in root's environment would be theirs to read.
func baseEnv() []string {
	if runtime.GOOS == "windows" {
		return os.Environ() // tests only; the upgrade runs on Linux
	}
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
}

func isCurrentUser(name string) bool {
	u, err := user.Current()
	return err == nil && u.Username == name
}

// tailBuffer keeps the last max bytes a program writes.
type tailBuffer struct {
	buf bytes.Buffer
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf.Write(p)
	if over := t.buf.Len() - t.max; over > 0 {
		t.buf.Next(over)
	}
	return len(p), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// WPCLI runs WP-CLI for an installation as the user of the website and with
// its PHP. Plugins and themes stay unloaded; WP-CLI loads the mu-plugins of
// the installation all the same, it has no switch for them.
type WPCLI struct {
	Exec   Executor
	User   string
	Group  string
	PHP    string
	Binary string
}

func (w WPCLI) command(install string, stdin io.Reader, stdout io.Writer, args ...string) Command {
	full := append([]string{w.Binary, "--path=" + install, "--skip-plugins", "--skip-themes", "--skip-packages"}, args...)
	return Command{
		User: w.User, Group: w.Group, Binary: w.PHP, Args: full,
		Env: []string{
			"HOME=/tmp",
			"WP_CLI_CACHE_DIR=/tmp/malwatch-wp-cli-" + w.User,
			"WP_CLI_CONFIG_PATH=/dev/null",
			"WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
		},
		Stdin:  stdin,
		Stdout: stdout,
	}
}

// ExportDB writes the database of the installation to out.
func (w WPCLI) ExportDB(ctx context.Context, install string, out io.Writer) error {
	return w.Exec.Run(ctx, w.command(install, nil, out, "db", "export", "-"))
}

// ImportDB loads in into the database of the installation.
func (w WPCLI) ImportDB(ctx context.Context, install string, in io.Reader) error {
	return w.Exec.Run(ctx, w.command(install, in, nil, "db", "import", "-"))
}

// UpdateDB raises the database to the core that is now in the installation.
func (w WPCLI) UpdateDB(ctx context.Context, install string) error {
	return w.Exec.Run(ctx, w.command(install, nil, nil, "core", "update-db"))
}

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ParseRunAs splits "user:group" and refuses root and every account with UID
// 0. lookup is user.Lookup outside the tests.
func ParseRunAs(spec string, lookup func(string) (*user.User, error)) (name, group string, err error) {
	name, group, _ = strings.Cut(strings.TrimSpace(spec), ":")
	if name == "" {
		return "", "", fmt.Errorf("--run-as braucht den Benutzer der Website, etwa web12:client3")
	}
	if !accountRe.MatchString(name) || (group != "" && !accountRe.MatchString(group)) {
		return "", "", fmt.Errorf("--run-as=%q nennt keinen gültigen Benutzer", spec)
	}
	if name == "root" {
		return "", "", fmt.Errorf("--run-as=root wird abgewiesen: WP-CLI führt Code der Website aus")
	}
	u, err := lookup(name)
	if err != nil {
		return "", "", fmt.Errorf("Benutzer %s ist unbekannt: %w", name, err)
	}
	if u.Uid == "0" {
		return "", "", fmt.Errorf("--run-as=%s hat die UID 0 und wird abgewiesen", name)
	}
	return name, group, nil
}
