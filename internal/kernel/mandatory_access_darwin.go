//go:build darwin

package kernel

import (
	"context"
	"os"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMandatoryAccessPlatform(ctx context.Context, _ Inventory) []MandatoryAccessAssessment {
	return []MandatoryAccessAssessment{
		collectDarwinSIP(ctx),
		collectDarwinSandboxInfrastructure(),
	}
}

func collectDarwinSIP(ctx context.Context) MandatoryAccessAssessment {
	const id = "macos.sip"
	const name = "macOS System Integrity Protection"
	const provider = "csrutil"
	const source = "csrutil status"
	if !commandAvailable("csrutil") {
		return unavailableMandatoryAccess(id, name, "SIP", evidence.StateUnsupported, provider, source, "csrutil is unavailable, so System Integrity Protection state cannot be queried", evidence.ConfidenceHigh)
	}
	out, err := run(ctx, "csrutil", "status")
	if err != nil {
		return unavailableMandatoryAccess(id, name, "SIP", evidence.StateUnavailable, provider, source, "System Integrity Protection state could not be queried: "+err.Error(), evidence.ConfidenceLow)
	}
	state, mode, enabled, ok := parseCSRUtilStatus(out)
	if !ok {
		return unavailableMandatoryAccess(id, name, "SIP", evidence.StateDegraded, provider, source, "csrutil returned unrecognized status output", evidence.ConfidenceLow)
	}
	return observedMandatoryAccess(id, name, "SIP", state, mode, provider, source, enabled, evidence.ConfidenceHigh)
}

func collectDarwinSandboxInfrastructure() MandatoryAccessAssessment {
	const id = "macos.sandbox.infrastructure"
	const name = "macOS application sandbox policy infrastructure"
	const provider = "macOS Seatbelt/Sandbox local policy surface"
	const source = "/System/Library/Sandbox/Profiles"
	if st, err := os.Stat("/System/Library/Sandbox/Profiles"); err == nil && st.IsDir() {
		return observedMandatoryAccess(id, name, "Seatbelt/Sandbox", "AVAILABLE", "system sandbox policy infrastructure present; per-process enforcement is not inferred", provider, source, nil, evidence.ConfidenceHigh)
	} else if os.IsPermission(err) {
		return unavailableMandatoryAccess(id, name, "Seatbelt/Sandbox", evidence.StateDenied, provider, source, "sandbox policy infrastructure path is permission-restricted", evidence.ConfidenceMedium)
	}
	return unavailableMandatoryAccess(id, name, "Seatbelt/Sandbox", evidence.StateUnavailable, provider, source, "system sandbox policy infrastructure was not observable; no global enforcement conclusion is made", evidence.ConfidenceLow)
}
