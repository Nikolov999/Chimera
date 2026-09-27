//go:build darwin

package kernel

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectDebugExposure(ctx context.Context, _ Inventory) []DebugExposureAssessment {
	return []DebugExposureAssessment{
		collectDarwinKernelDebugBootArgs(ctx),
		collectDarwinDeveloperToolSecurity(ctx),
	}
}

func collectDarwinKernelDebugBootArgs(ctx context.Context) DebugExposureAssessment {
	const id = "macos.kernel_debug_boot_args"
	const name = "macOS kernel-debug boot arguments"
	const provider = "macOS kernel boot arguments"
	const source = "sysctl -n kern.bootargs"
	if !commandAvailable("sysctl") {
		return unavailableDebugExposure(id, name, evidence.StateUnsupported, provider, source, "sysctl is unavailable, so kernel-debug boot arguments cannot be inspected", evidence.ConfidenceHigh)
	}
	raw, err := run(ctx, "sysctl", "-n", "kern.bootargs")
	if err != nil {
		return unavailableDebugExposure(id, name, evidence.StateUnavailable, provider, source, "kernel boot arguments could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	args := debugBootArguments(raw)
	if len(args) > 0 {
		return observedDebugExposure(id, name, "DEBUG_ARGUMENTS_OBSERVED", strings.Join(args, ", "), provider, source, boolPtr(true), evidence.ConfidenceHigh)
	}
	return observedDebugExposure(id, name, "NO_DEBUG_ARGUMENTS_OBSERVED", "no recognized KDP/kernel-debug boot arguments", provider, source, boolPtr(false), evidence.ConfidenceMedium)
}

func collectDarwinDeveloperToolSecurity(ctx context.Context) DebugExposureAssessment {
	const id = "macos.developer_tool_security"
	const name = "macOS developer-tool debugging authorization"
	const provider = "DevToolsSecurity"
	const source = "DevToolsSecurity -status"
	if !commandAvailable("DevToolsSecurity") {
		return unavailableDebugExposure(id, name, evidence.StateUnsupported, provider, source, "DevToolsSecurity is unavailable, so developer-tool authorization state cannot be inspected", evidence.ConfidenceHigh)
	}
	raw, err := run(ctx, "DevToolsSecurity", "-status")
	if err != nil {
		return unavailableDebugExposure(id, name, evidence.StateUnavailable, provider, source, "developer-tool authorization state could not be read: "+err.Error(), evidence.ConfidenceLow)
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "enabled"):
		return observedDebugExposure(id, name, "ENABLED", strings.TrimSpace(raw), provider, source, boolPtr(true), evidence.ConfidenceHigh)
	case strings.Contains(lower, "disabled"):
		return observedDebugExposure(id, name, "DISABLED", strings.TrimSpace(raw), provider, source, boolPtr(false), evidence.ConfidenceHigh)
	default:
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, "DevToolsSecurity returned an unrecognized status", evidence.ConfidenceLow)
	}
}
