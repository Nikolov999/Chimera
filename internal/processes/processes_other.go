//go:build !linux && !darwin && !windows

package processes

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addSource(inv, "platform-processes", evidence.StateUnsupported, "platform process metadata", 0, "process inventory is not implemented for this operating system")
}
