//go:build !linux && !windows && !darwin

package kernel

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectDebugExposure(context.Context, Inventory) []DebugExposureAssessment {
	return []DebugExposureAssessment{
		unavailableDebugExposure("platform.kernel_debug_exposure", "Platform kernel/debug exposure", evidence.StateUnsupported, "platform debug-exposure provider", "unsupported platform", "supports Windows, Linux, and macOS", evidence.ConfidenceHigh),
	}
}
