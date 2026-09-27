//go:build !linux && !windows && !darwin

package services

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-services", evidence.StateUnsupported, "platform service manager", 0, "service inventory is not implemented for this operating system")
}
