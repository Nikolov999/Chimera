//go:build !linux && !darwin && !windows

package accounts

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
	"runtime"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-accounts", evidence.StateUnsupported, "platform local account provider", 0, "local account inventory is not implemented for "+runtime.GOOS)
}
