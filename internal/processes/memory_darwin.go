//go:build darwin

package processes

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectExecutionMemoryPlatform(_ context.Context, items []Process) ([]ExecutionMemoryContext, memoryProviderStats) {
	out := make([]ExecutionMemoryContext, 0, len(items))
	for _, p := range items {
		out = append(out, ExecutionMemoryContext{
			PID: p.PID, Platform: "darwin", State: "UNSUPPORTED",
			Source: "macOS executable-memory metadata provider", Confidence: evidence.ConfidenceExact,
			Reason: "does not invoke task_for_pid or read process memory; no stable unprivileged per-process VM-protection provider is used on macOS",
		})
	}
	return out, memoryProviderStats{
		ID: "darwin-executable-memory", State: evidence.StateUnsupported, Source: "macOS executable-memory metadata provider",
		Reason: "safe unprivileged per-process executable-memory protection metadata is not available through the current read-only provider",
	}
}
