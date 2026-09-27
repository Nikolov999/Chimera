//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsSecureBootResult struct {
	State   string `json:"state"`
	Enabled *bool  `json:"enabled"`
	Reason  string `json:"reason"`
}

func collectSecureBoot(ctx context.Context, k Inventory) SecureBootAssessment {
	const provider = "Confirm-SecureBootUEFI"
	const source = "PowerShell Confirm-SecureBootUEFI"
	if strings.EqualFold(k.BootMode, "BIOS") {
		return unavailableSecureBoot(evidence.StateNotApplicable, provider, source, "legacy BIOS firmware mode was observed; UEFI Secure Boot is not applicable", evidence.ConfidenceHigh)
	}
	if !commandAvailable("powershell.exe") {
		return unavailableSecureBoot(evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so the native Secure Boot provider cannot be queried", evidence.ConfidenceHigh)
	}
	script := `$ErrorActionPreference='Stop'; try { $v=Confirm-SecureBootUEFI; [pscustomobject]@{state='OBSERVED';enabled=[bool]$v;reason=''}|ConvertTo-Json -Compress } catch { $m=$_.Exception.Message; $s='UNAVAILABLE'; if($m -match '(?i)access.*denied|privilege'){ $s='DENIED' } elseif($m -match '(?i)not supported|unsupported|BIOS|UEFI'){ $s='NOT_APPLICABLE' }; [pscustomobject]@{state=$s;enabled=$null;reason=$m}|ConvertTo-Json -Compress }`
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return unavailableSecureBoot(evidence.StateUnavailable, provider, source, "Secure Boot provider failed: "+err.Error(), evidence.ConfidenceLow)
	}
	var r windowsSecureBootResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return unavailableSecureBoot(evidence.StateDegraded, provider, source, "Secure Boot provider returned invalid structured output: "+err.Error(), evidence.ConfidenceLow)
	}
	switch strings.ToUpper(strings.TrimSpace(r.State)) {
	case "OBSERVED":
		if r.Enabled == nil {
			return unavailableSecureBoot(evidence.StateDegraded, provider, source, "Secure Boot provider did not return an enabled/disabled value", evidence.ConfidenceLow)
		}
		return observedSecureBoot(*r.Enabled, "UEFI", provider, source, evidence.ConfidenceExact)
	case "DENIED":
		return unavailableSecureBoot(evidence.StateDenied, provider, source, fallbackReason(r.Reason, "permission denied while querying Secure Boot state"), evidence.ConfidenceHigh)
	case "NOT_APPLICABLE":
		return unavailableSecureBoot(evidence.StateNotApplicable, provider, source, fallbackReason(r.Reason, "platform firmware does not expose UEFI Secure Boot"), evidence.ConfidenceHigh)
	default:
		return unavailableSecureBoot(evidence.StateUnavailable, provider, source, fallbackReason(r.Reason, "Secure Boot state was unavailable"), evidence.ConfidenceMedium)
	}
}

func fallbackReason(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}
