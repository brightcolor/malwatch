// Package phpinfo asks a PHP binary which version it is. The binary runs with
// -r and no script, so no code of a website runs.
package phpinfo

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// command starts the binary. The tests replace it with a helper process.
var command = exec.CommandContext

var versionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?`)

// Version runs "<binary> -r 'echo PHP_VERSION;'" and returns the version
// without a distribution suffix such as "-1+ubuntu22.04".
func Version(binary string, timeout time.Duration) (string, error) {
	if binary == "" {
		return "", fmt.Errorf("kein PHP-Binary angegeben")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := command(ctx, binary, "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", binary, err)
	}
	text := strings.TrimSpace(string(out))
	v := versionRe.FindString(text)
	if v == "" {
		if len(text) > 80 {
			text = text[:80]
		}
		return "", fmt.Errorf("%s nannte keine PHP-Version: %q", binary, text)
	}
	return v, nil
}
