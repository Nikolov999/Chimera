//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsIntegrityResult struct {
	CIStatus       *int  `json:"ci_status"`
	HVCIConfigured *bool `json:"hvci_configured"`
	HVCIRunning    *bool `json:"hvci_running"`
}

func collectIntegrityControls(ctx context.Context, _ Inventory) []ControlAssessment {
	controls := collectWindowsDeviceGuard(ctx)
	controls = append(controls, collectWindowsTestSigning(ctx))
	return controls
}

func collectWindowsDeviceGuard(ctx context.Context) []ControlAssessment {
	const ciID = "windows.code_integrity_policy"
	const ciName = "Windows code integrity policy"
	const hvciID = "windows.hvci"
	const hvciName = "Windows Hypervisor-Enforced Code Integrity"
	const provider = "Win32_DeviceGuard and DeviceGuard registry policy"
	const source = "root\\Microsoft\\Windows\\DeviceGuard:Win32_DeviceGuard; HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"

	if !commandAvailable("powershell.exe") {
		return []ControlAssessment{
			unavailableControl(ciID, ciName, evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so local Device Guard code-integrity metadata cannot be queried", evidence.ConfidenceHigh),
			unavailableControl(hvciID, hvciName, evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so local HVCI metadata cannot be queried", evidence.ConfidenceHigh),
		}
	}

	script := `$ErrorActionPreference='Stop'; $dg=$null; try{$dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop}catch{}; $ci=$null; $running=$null; if($null -ne $dg){if($null -ne $dg.CodeIntegrityPolicyEnforcementStatus){$ci=[int]$dg.CodeIntegrityPolicyEnforcementStatus}; if($null -ne $dg.SecurityServicesRunning){$running=[bool](@($dg.SecurityServicesRunning) -contains 2)}}; $cfg=$null; try{$v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -ErrorAction Stop).Enabled; if($null -ne $v){$cfg=([int]$v -eq 1)}}catch{}; [pscustomobject]@{ci_status=$ci;hvci_configured=$cfg;hvci_running=$running}|ConvertTo-Json -Compress`
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		reason := "Device Guard provider failed: " + err.Error()
		return []ControlAssessment{
			unavailableControl(ciID, ciName, evidence.StateUnavailable, provider, source, reason, evidence.ConfidenceLow),
			unavailableControl(hvciID, hvciName, evidence.StateUnavailable, provider, source, reason, evidence.ConfidenceLow),
		}
	}
	var r windowsIntegrityResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		reason := "Device Guard provider returned invalid structured output: " + err.Error()
		return []ControlAssessment{
			unavailableControl(ciID, ciName, evidence.StateDegraded, provider, source, reason, evidence.ConfidenceLow),
			unavailableControl(hvciID, hvciName, evidence.StateDegraded, provider, source, reason, evidence.ConfidenceLow),
		}
	}

	ci := unavailableControl(ciID, ciName, evidence.StateUnavailable, provider, source, "Win32_DeviceGuard did not expose CodeIntegrityPolicyEnforcementStatus", evidence.ConfidenceMedium)
	if r.CIStatus != nil {
		switch *r.CIStatus {
		case 0:
			ci = observedControl(ciID, ciName, "DISABLED", "off", provider, source, boolPtr(false), evidence.ConfidenceHigh)
		case 1:
			ci = observedControl(ciID, ciName, "AUDIT", "audit", provider, source, boolPtr(false), evidence.ConfidenceHigh)
		case 2:
			ci = observedControl(ciID, ciName, "ENFORCED", "enforcement", provider, source, boolPtr(true), evidence.ConfidenceHigh)
		default:
			ci = unavailableControl(ciID, ciName, evidence.StateDegraded, provider, source, "Win32_DeviceGuard returned an unrecognized code-integrity policy status", evidence.ConfidenceLow)
		}
	}

	hvci := unavailableControl(hvciID, hvciName, evidence.StateUnavailable, provider, source, "HVCI configured/running state was not exposed by local providers", evidence.ConfidenceMedium)
	if r.HVCIRunning != nil || r.HVCIConfigured != nil {
		running := r.HVCIRunning != nil && *r.HVCIRunning
		configured := r.HVCIConfigured != nil && *r.HVCIConfigured
		state := "DISABLED"
		mode := "configured=false; running=false"
		enabled := false
		switch {
		case running:
			state = "RUNNING"
			enabled = true
			mode = "configured=true-or-policy-managed; running=true"
		case configured:
			state = "CONFIGURED_NOT_RUNNING"
			mode = "configured=true; running=false"
		default:
			mode = "configured=false; running=false-or-unreported"
		}
		hvci = observedControl(hvciID, hvciName, state, mode, provider, source, boolPtr(enabled), evidence.ConfidenceHigh)
	}
	return []ControlAssessment{ci, hvci}
}

func collectWindowsTestSigning(ctx context.Context) ControlAssessment {
	const id = "windows.test_signing"
	const name = "Windows test-signing boot policy"
	const provider = "Windows Boot Configuration Data"
	const source = "bcdedit /enum {current}"
	if !commandAvailable("bcdedit.exe") && !commandAvailable("bcdedit") {
		return unavailableControl(id, name, evidence.StateUnsupported, provider, source, "bcdedit is unavailable, so test-signing policy cannot be inspected", evidence.ConfidenceHigh)
	}
	exe := "bcdedit.exe"
	if !commandAvailable(exe) {
		exe = "bcdedit"
	}
	out, err := run(ctx, exe, "/enum", "{current}")
	if err != nil {
		state := evidence.StateUnavailable
		if strings.Contains(strings.ToLower(err.Error()), "access is denied") || strings.Contains(strings.ToLower(err.Error()), "access denied") {
			state = evidence.StateDenied
		}
		return unavailableControl(id, name, state, provider, source, "test-signing boot policy could not be read: "+err.Error(), evidence.ConfidenceMedium)
	}
	enabled, found := parseBCDTestSigning(out)
	if !found {
		// An absent testsigning element means the current loader is using its
		// default (off) setting. Preserve this as high-confidence local BCD
		// evidence rather than inventing a provider failure.
		return observedControl(id, name, "DISABLED", "default/element absent", provider, source, boolPtr(false), evidence.ConfidenceHigh)
	}
	state := "DISABLED"
	if enabled {
		state = "ENABLED"
	}
	return observedControl(id, name, state, "explicit BCD element", provider, source, boolPtr(enabled), evidence.ConfidenceExact)
}

func parseBCDTestSigning(text string) (bool, bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "testsigning") {
			continue
		}
		if v, ok := parseBoolControl(fields[len(fields)-1]); ok {
			return v, true
		}
	}
	return false, false
}
