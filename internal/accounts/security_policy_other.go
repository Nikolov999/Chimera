//go:build !windows

package accounts

import (
	"context"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSecurityPolicy(_ context.Context, inv *Inventory) {
	inv.SecurityPolicy = SecurityPolicy{
		State:  evidence.StateNotApplicable,
		Source: "Windows UAC/local security policy provider",
		Reason: "Windows UAC/local-security-policy assessment is not applicable on " + inv.Platform,
	}
}
