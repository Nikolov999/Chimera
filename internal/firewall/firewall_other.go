//go:build !linux && !windows && !darwin

package firewall

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(_ context.Context, inv *Inventory) {
	addProvider(inv, ProviderStatus{ID: "platform-firewall", Name: "Platform firewall", State: evidence.StateUnsupported, Enabled: "UNKNOWN", Source: "platform support matrix", Reason: "firewall inventory is supported on Windows, Linux, and macOS"})
}
