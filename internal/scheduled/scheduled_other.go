//go:build !linux && !windows && !darwin

package scheduled

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	_ = ctx
	addSource(inv, "scheduled-platform", evidence.StateUnsupported, "platform scheduled execution", 0, "scheduled execution inventory is unsupported on this platform")
}
