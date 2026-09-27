//go:build !linux && !windows && !darwin

package processes

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectExecutionMemoryPlatform(_ context.Context, items []Process) ([]ExecutionMemoryContext, memoryProviderStats) {
	out := make([]ExecutionMemoryContext, 0, len(items))
	for _, p := range items {
		out = append(out, ExecutionMemoryContext{PID: p.PID, State: "UNSUPPORTED", Source: "platform executable-memory metadata", Confidence: evidence.ConfidenceExact, Reason: "unsupported platform"})
	}
	return out, memoryProviderStats{ID: "platform-executable-memory", State: evidence.StateUnsupported, Source: "platform executable-memory metadata", Reason: "unsupported platform"}
}
