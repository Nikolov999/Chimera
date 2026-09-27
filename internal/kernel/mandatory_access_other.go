//go:build !linux && !windows && !darwin

package kernel

import (
	"context"
	"runtime"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMandatoryAccessPlatform(context.Context, Inventory) []MandatoryAccessAssessment {
	return []MandatoryAccessAssessment{
		unavailableMandatoryAccess("platform.mandatory_access", "Platform mandatory access control", "platform", evidence.StateUnsupported, "platform mandatory-access provider", runtime.GOOS, "mandatory-access collection is not implemented for this platform", evidence.ConfidenceExact),
	}
}
