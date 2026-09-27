//go:build darwin

package kernel

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMemoryMitigations(ctx context.Context, _ Inventory) []MitigationAssessment {
	return []MitigationAssessment{
		collectDarwinASLRBootPolicy(ctx),
		collectDarwinSystemPIE(ctx),
	}
}

func collectDarwinASLRBootPolicy(ctx context.Context) MitigationAssessment {
	const id = "macos.aslr_boot_policy"
	const name = "macOS ASLR boot-policy overrides"
	const provider = "macOS kernel boot arguments"
	const source = "sysctl -n kern.bootargs"
	if !commandAvailable("sysctl") {
		return unavailableMitigation(id, name, evidence.StateUnsupported, provider, source, "sysctl is unavailable, so ASLR-relevant boot arguments cannot be inspected", evidence.ConfidenceHigh)
	}
	out, err := run(ctx, "sysctl", "-n", "kern.bootargs")
	if err != nil {
		return unavailableMitigation(id, name, evidence.StateUnavailable, provider, source, "kernel boot arguments could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	var overrides []string
	for _, token := range strings.Fields(strings.ToLower(out)) {
		token = strings.TrimSpace(token)
		if token == "slide=0" || token == "noaslr" || token == "disable_aslr=1" {
			overrides = append(overrides, token)
		}
	}
	if len(overrides) > 0 {
		return observedMitigation(id, name, "DISABLE_OVERRIDE_OBSERVED", strings.Join(overrides, ", "), provider, source, boolPtr(false), evidence.ConfidenceHigh)
	}
	return observedMitigation(id, name, "NO_DISABLE_OVERRIDE_OBSERVED", "no recognized ASLR-disabling boot argument", provider, source, nil, evidence.ConfidenceMedium)
}

func collectDarwinSystemPIE(ctx context.Context) MitigationAssessment {
	const id = "macos.system_binary_pie"
	const name = "macOS system executable PIE posture"
	const provider = "Mach-O header flags"
	const source = "otool -hv /usr/bin/true"
	if !commandAvailable("otool") {
		return unavailableMitigation(id, name, evidence.StateUnsupported, provider, source, "otool is unavailable, so a local system-binary PIE check cannot be performed", evidence.ConfidenceHigh)
	}
	out, err := run(ctx, "otool", "-hv", "/usr/bin/true")
	if err != nil {
		return unavailableMitigation(id, name, evidence.StateUnavailable, provider, source, "system executable Mach-O header could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	upper := strings.ToUpper(out)
	if strings.Contains(upper, "PIE") {
		return observedMitigation(id, name, "PIE_ENABLED", "/usr/bin/true carries the Mach-O PIE flag", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	}
	return observedMitigation(id, name, "PIE_NOT_OBSERVED", "/usr/bin/true Mach-O header did not expose the PIE flag", provider, source, boolPtr(false), evidence.ConfidenceMedium)
}
