//go:build !linux && !darwin && !windows

package services

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPathIntegrity(_ context.Context, inv *Inventory) {
	addSource(inv, "service-path-integrity", evidence.StateNotApplicable, "platform service path metadata", 0, "service path-integrity correlation is not implemented for this platform")
}
