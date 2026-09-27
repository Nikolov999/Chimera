//go:build windows

package processes

import (
	"context"
	"os"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectRuntimeEnvironmentPlatform(ctx context.Context, items []Process) ([]RuntimeEnvironmentContext, environmentProviderStats) {
	stats := environmentProviderStats{ID: "windows-process-environment", State: evidence.StateDegraded, Source: "current-process environment via Win32 process environment block exposed to Go runtime", Reason: "cross-process environment inspection would require reading another process environment block; Chimera intentionally does not read process memory"}
	out := make([]RuntimeEnvironmentContext, 0, len(items))
	self := os.Getpid()
	for _, p := range items {
		if ctx.Err() != nil {
			stats.Reason = ctx.Err().Error()
			break
		}
		if p.PID == self {
			c := inspectEnvironmentEntries(os.Environ(), "windows", "current-process environment names and redacted classification metadata")
			c.PID = p.PID
			out = append(out, c)
			stats.Count++
			continue
		}
		out = append(out, RuntimeEnvironmentContext{PID: p.PID, Platform: "windows", State: "UNKNOWN", Posture: "UNKNOWN", ValuesRedacted: true, Source: "Windows process environment metadata", Confidence: evidence.ConfidenceExact, Reason: "cross-process environment not collected because Chimera does not read process memory"})
		stats.Missing++
	}
	if stats.Count == 0 {
		stats.State = evidence.StateUnavailable
	}
	return out, stats
}
