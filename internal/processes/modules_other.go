//go:build !linux && !windows && !darwin

package processes

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectLoadedModulesPlatform(_ context.Context, items []Process) ([]LoadedModuleContext, moduleProviderStats) {
	out := make([]LoadedModuleContext, 0, len(items))
	for _, p := range items {
		out = append(out, LoadedModuleContext{PID: p.PID, State: "UNSUPPORTED", Source: "platform loaded-module metadata", Confidence: evidence.ConfidenceExact, Reason: "loaded-module collection is not supported on this platform"})
	}
	return out, moduleProviderStats{ID: "loaded-modules", State: evidence.StateUnsupported, Source: "platform loaded-module metadata", Reason: "loaded-module collection is not supported on this platform"}
}
