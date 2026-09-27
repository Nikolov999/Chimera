//go:build !linux && !windows && !darwin

package kernel

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMemoryMitigations(context.Context, Inventory) []MitigationAssessment {
	return []MitigationAssessment{
		unavailableMitigation("platform.aslr", "Platform ASLR posture", evidence.StateUnsupported, "platform mitigation provider", "unsupported platform", "supports Windows, Linux, and macOS", evidence.ConfidenceHigh),
	}
}
