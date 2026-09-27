//go:build !linux && !windows && !darwin

package software

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-software", evidence.StateUnsupported, "platform software inventory", 0, "supports Windows, Linux, and macOS")
}
