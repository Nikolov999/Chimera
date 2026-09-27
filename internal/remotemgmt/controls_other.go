//go:build !linux && !windows && !darwin

package remotemgmt

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
	"runtime"
)

func collectPlatformControls(ctx context.Context) []Control {
	_ = ctx
	return []Control{{Family: "REMOTE_MANAGEMENT", Name: "platform configuration", State: evidence.StateUnsupported, Source: "platform remote-management provider", Confidence: evidence.ConfidenceLow, Reason: "remote-management configuration collection is not implemented for " + runtime.GOOS}}
}
