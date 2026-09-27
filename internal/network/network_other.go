//go:build !linux && !windows && !darwin

package network

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-sockets", evidence.StateUnsupported, "platform local socket provider", 0, "supports Windows, Linux, and macOS")
}
