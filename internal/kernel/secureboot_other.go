//go:build !linux && !windows && !darwin

package kernel

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSecureBoot(context.Context, Inventory) SecureBootAssessment {
	return unavailableSecureBoot(evidence.StateUnsupported, "platform Secure Boot provider", "platform firmware metadata", "Secure Boot assessment is not implemented on this operating system", evidence.ConfidenceExact)
}
