//go:build !linux

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSudoPosture(_ context.Context, inv *Inventory) {
	inv.SudoPosture = SudoPosture{
		State:  evidence.StateNotApplicable,
		Source: "Linux sudoers posture provider",
		Reason: "Linux sudo/sudoers assessment is not applicable on " + inv.Platform,
	}
}
