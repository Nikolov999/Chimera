package kernel

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func run(ctx context.Context, name string, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if m := strings.TrimSpace(string(b)); m != "" {
			return "", fmt.Errorf("%w: %s", err, m)
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
func parseKV(text string) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}
func commandAvailable(name string) bool { _, err := exec.LookPath(name); return err == nil }
func capState(name string, available bool, source, detail string) Capability {
	state := "UNAVAILABLE"
	if available {
		state = "AVAILABLE"
	}
	return Capability{Name: name, State: state, Source: source, Detail: detail}
}
