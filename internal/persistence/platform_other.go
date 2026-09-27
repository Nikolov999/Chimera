//go:build !linux && !windows && !darwin

package persistence

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-startup", evidence.StateUnsupported, "platform persistence startup provider", 0, "platform-specific persistence inventory is unsupported")
}
