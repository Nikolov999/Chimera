//go:build !darwin

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMacOSAuthorizationPosture(_ context.Context, inv *Inventory) {
	inv.MacOSAuthorizationPosture = MacOSAuthorizationPosture{
		State:  evidence.StateNotApplicable,
		Source: "macOS local authorization provider",
		Reason: "macOS local authorization assessment is not applicable on " + inv.Platform,
		FileVault: SecurityControl{
			ID: "filevault", Name: "FileVault disk encryption", State: evidence.StateNotApplicable,
			Source: "fdesetup status", Confidence: evidence.ConfidenceExact,
			Reason: "FileVault is not applicable on this platform",
		},
	}
}
