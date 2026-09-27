//go:build darwin

package kernel

import (
	"context"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectSecureBoot(ctx context.Context, k Inventory) SecureBootAssessment {
	const provider = "macOS system_profiler Secure Boot metadata"
	const source = "system_profiler SPiBridgeDataType"
	if !commandAvailable("system_profiler") {
		return unavailableSecureBoot(evidence.StateUnsupported, provider, source, "system_profiler is unavailable, so local Secure Boot metadata cannot be queried", evidence.ConfidenceHigh)
	}
	out, err := run(ctx, "system_profiler", "SPiBridgeDataType")
	if err != nil {
		return unavailableSecureBoot(evidence.StateUnavailable, provider, source, "Secure Boot metadata provider failed: "+err.Error(), evidence.ConfidenceLow)
	}
	mode, ok := parseDarwinSecureBootMode(out)
	if !ok {
		// Apple silicon has a Secure Boot policy even though SPiBridgeDataType may
		// not expose it on every macOS release. Do not mislabel missing provider
		// output as NOT_APPLICABLE on arm64. Intel systems with no bridge data are
		// conservatively treated as hardware without this policy surface.
		if strings.EqualFold(k.Architecture, "arm64") || strings.TrimSpace(out) != "" {
			return unavailableSecureBoot(evidence.StateUnavailable, provider, source, "hardware is Secure-Boot-capable or exposes bridge metadata, but the local provider did not report a readable Secure Boot mode", evidence.ConfidenceMedium)
		}
		return unavailableSecureBoot(evidence.StateNotApplicable, provider, source, "Intel hardware did not expose a Secure Boot policy through the local bridge/security metadata provider", evidence.ConfidenceMedium)
	}
	normalized := strings.ToLower(mode)
	switch {
	case strings.Contains(normalized, "full security"):
		return observedSecureBoot(true, "Full Security", provider, source, evidence.ConfidenceHigh)
	case strings.Contains(normalized, "medium security") || strings.Contains(normalized, "reduced security"):
		// Secure boot remains enabled, but not at the strongest policy level.
		return observedSecureBoot(true, mode, provider, source, evidence.ConfidenceHigh)
	case strings.Contains(normalized, "no security") || strings.Contains(normalized, "disabled"):
		return observedSecureBoot(false, mode, provider, source, evidence.ConfidenceHigh)
	default:
		return unavailableSecureBoot(evidence.StateDegraded, provider, source, "provider returned an unrecognized Secure Boot mode: "+mode, evidence.ConfidenceLow)
	}
}

func parseDarwinSecureBootMode(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "secure boot" || key == "secure boot status" || key == "secure boot policy" {
			value := strings.TrimSpace(v)
			if value != "" {
				return value, true
			}
		}
	}
	return "", false
}
