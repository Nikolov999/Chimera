//go:build darwin

package processes

import (
	"context"
	"os"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectRuntimeEnvironmentPlatform(ctx context.Context, items []Process) ([]RuntimeEnvironmentContext, environmentProviderStats) {
	stats := environmentProviderStats{ID: "darwin-process-environment", State: evidence.StateDegraded, Source: "current-process environment exposed to Go runtime", Reason: "cross-process environment values are not collected because the available process interfaces can expose sensitive argv/environment contents; Chimera retains only current-process redacted metadata"}
	out := make([]RuntimeEnvironmentContext, 0, len(items))
	self := os.Getpid()
	for _, p := range items {
		if ctx.Err() != nil {
			stats.Reason = ctx.Err().Error()
			break
		}
		if p.PID == self {
			c := inspectEnvironmentEntries(os.Environ(), "darwin", "current-process environment names and redacted classification metadata")
			c.PID = p.PID
			out = append(out, c)
			stats.Count++
			continue
		}
		out = append(out, RuntimeEnvironmentContext{PID: p.PID, Platform: "darwin", State: "UNKNOWN", Posture: "UNKNOWN", ValuesRedacted: true, Source: "macOS process environment metadata", Confidence: evidence.ConfidenceExact, Reason: "cross-process environment intentionally not collected to avoid exposing argv/environment values"})
		stats.Missing++
	}
	if stats.Count == 0 {
		stats.State = evidence.StateUnavailable
	}
	return out, stats
}
