package software

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
		if msg := strings.TrimSpace(string(b)); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func commandAvailable(name string) bool { _, err := exec.LookPath(name); return err == nil }

func tabLines(text string, minFields int) [][]string {
	out := make([][]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < minFields {
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		out = append(out, parts)
		if len(out) >= maxInventoryItems {
			break
		}
	}
	return out
}
