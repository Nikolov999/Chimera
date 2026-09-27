//go:build !linux && !windows && !darwin

package kernel

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectLoadedModulesPlatform(context.Context, Inventory) []ModuleAssessment {
	return []ModuleAssessment{{
		ID: "platform.loaded_modules", Name: "Platform loaded kernel modules/drivers", Kind: "kernel-module-set",
		CollectionState: evidence.StateUnsupported, LoadState: "UNKNOWN", Provider: "platform loaded-module provider", Source: "unsupported platform",
		SignatureState: "UNKNOWN", TrustState: "UNKNOWN", BackingState: "UNKNOWN", Confidence: evidence.ConfidenceHigh,
		Reason: "supports Windows, Linux, and macOS",
	}}
}
