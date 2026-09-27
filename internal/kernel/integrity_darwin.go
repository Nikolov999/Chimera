//go:build darwin

package kernel

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectIntegrityControls(ctx context.Context, _ Inventory) []ControlAssessment {
	return []ControlAssessment{collectDarwinAMFIPosture(ctx)}
}

func collectDarwinAMFIPosture(ctx context.Context) ControlAssessment {
	const id = "macos.amfi_boot_policy"
	const name = "macOS AMFI boot-policy posture"
	const provider = "macOS kernel boot arguments"
	const source = "sysctl -n kern.bootargs"
	if !commandAvailable("sysctl") {
		return unavailableControl(id, name, evidence.StateUnsupported, provider, source, "sysctl is unavailable, so AMFI-relevant boot policy cannot be inspected", evidence.ConfidenceHigh)
	}
	out, err := run(ctx, "sysctl", "-n", "kern.bootargs")
	if err != nil {
		return unavailableControl(id, name, evidence.StateUnavailable, provider, source, "kernel boot arguments could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	bypasses := darwinAMFIBypassArgs(out)
	if len(bypasses) > 0 {
		return observedControl(id, name, "BYPASS_REQUESTED", strings.Join(bypasses, ", "), provider, source, boolPtr(false), evidence.ConfidenceHigh)
	}
	// Absence of known disabling boot arguments is defensible evidence, but it
	// is not treated as proof of every AMFI subsystem's runtime state.
	return observedControl(id, name, "NO_BOOT_ARG_BYPASS_OBSERVED", "no known AMFI/code-signing disable boot arguments", provider, source, nil, evidence.ConfidenceMedium)
}

func darwinAMFIBypassArgs(text string) []string {
	known := map[string]struct{}{
		"amfi_get_out_of_my_way=1":   {},
		"amfi_allow_any_signature=1": {},
		"cs_enforcement_disable=1":   {},
	}
	var out []string
	for _, token := range strings.Fields(strings.TrimSpace(text)) {
		normalized := strings.ToLower(strings.TrimSpace(token))
		if _, ok := known[normalized]; ok {
			out = append(out, normalized)
		}
	}
	return out
}
