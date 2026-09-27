//go:build !linux && !windows && !darwin

package processes

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectRuntimeEnvironmentPlatform(ctx context.Context, items []Process) ([]RuntimeEnvironmentContext, environmentProviderStats) {
	out := make([]RuntimeEnvironmentContext, 0, len(items))
	for _, p := range items {
		out = append(out, RuntimeEnvironmentContext{PID: p.PID, Platform: "unsupported", State: "UNSUPPORTED", Posture: "UNKNOWN", ValuesRedacted: true, Source: "platform process environment metadata", Confidence: evidence.ConfidenceExact, Reason: "process environment provider is not implemented for this platform"})
	}
	return out, environmentProviderStats{ID: "process-environment-unsupported", State: evidence.StateUnsupported, Source: "platform process environment metadata", Reason: "process environment provider is not implemented for this platform"}
}
