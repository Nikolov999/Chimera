//go:build !linux && !windows && !darwin

package processes

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectIsolationPlatform(ctx context.Context, items []Process) ([]IsolationContext, isolationProviderStats) {
	out := make([]IsolationContext, 0, len(items))
	for _, p := range items {
		out = append(out, IsolationContext{PID: p.PID, Platform: "unsupported", State: "UNSUPPORTED", IsolationState: "UNKNOWN", AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "UNKNOWN", Source: "platform process-isolation metadata", Confidence: evidence.ConfidenceExact, Reason: "process-isolation provider is not implemented for this platform"})
	}
	return out, isolationProviderStats{ID: "process-isolation-unsupported", State: evidence.StateUnsupported, Source: "platform process-isolation metadata", Reason: "process-isolation provider is not implemented for this platform"}
}
