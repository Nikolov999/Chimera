//go:build !linux && !windows && !darwin

package software

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func resolvePlatformOwnership(ctx context.Context, path string, items []Item) ownershipResult {
	_ = ctx
	_ = path
	_ = items
	return ownershipResult{Ownership: OwnershipUnknown, Provider: "platform ownership resolver", ProviderState: evidence.StateUnsupported, Method: "unsupported", Reason: "package/application binary attribution is unsupported on this platform", Confidence: evidence.ConfidenceLow}
}
