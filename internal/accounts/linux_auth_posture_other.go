//go:build !linux

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectLinuxAuthPosture(_ context.Context, inv *Inventory) {
	inv.LinuxAuthPosture = LinuxAuthPosture{
		State:  evidence.StateNotApplicable,
		Source: "Linux PAM/login policy provider",
		Reason: "Linux PAM/login policy assessment is not applicable on " + inv.Platform,
		LoginPolicy: LinuxLoginPolicy{
			State: evidence.StateNotApplicable, Source: "/etc/login.defs", Confidence: evidence.ConfidenceExact,
			Reason: "Linux login policy is not applicable on this platform",
		},
	}
}
