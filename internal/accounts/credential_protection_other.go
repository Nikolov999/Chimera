//go:build !windows

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectCredentialProtection(_ context.Context, inv *Inventory) {
	inv.CredentialProtection = CredentialProtection{
		State:  evidence.StateNotApplicable,
		Source: "Windows credential-protection provider",
		Reason: "Windows credential-protection assessment is not applicable on " + inv.Platform,
	}
}
