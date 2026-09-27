//go:build !linux && !windows && !darwin

package kernel

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectIntegrityControls(context.Context, Inventory) []ControlAssessment {
	return []ControlAssessment{
		unavailableControl("platform.code_integrity", "Platform code-integrity posture", evidence.StateUnsupported, "platform integrity provider", "unsupported platform", "supports Windows, Linux, and macOS", evidence.ConfidenceHigh),
	}
}
