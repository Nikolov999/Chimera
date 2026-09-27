//go:build linux

package software

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformInfrastructureActivity(ctx context.Context) ([]infrastructureActivity, []SourceStatus) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, []SourceStatus{{ID: "linux-proc-processes", State: evidence.StateUnavailable, Source: "/proc process metadata", Reason: err.Error()}}
	}
	out := make([]infrastructureActivity, 0)
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		raw, err := os.ReadFile(filepath.Join(base, "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(raw))
		if name == "" {
			continue
		}
		path := ""
		if p, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
			path = strings.TrimSpace(p)
		}
		out = append(out, infrastructureActivity{Kind: "process", Name: name, Path: path})
		if len(out) >= 65536 {
			break
		}
	}
	return out, []SourceStatus{{ID: "linux-proc-processes", State: evidence.StateObserved, Source: "/proc process metadata", ItemCount: len(out)}}
}
