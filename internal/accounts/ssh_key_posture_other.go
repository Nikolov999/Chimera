//go:build !linux && !darwin && !windows

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSSHKeyPosture(_ context.Context, inv *Inventory) {
	inv.SSHKeyPosture = SSHKeyPosture{State: evidence.StateNotApplicable, Source: "local SSH key/authorized_keys metadata provider", Reason: "SSH key/authorized_keys assessment is not supported on this platform"}
}
