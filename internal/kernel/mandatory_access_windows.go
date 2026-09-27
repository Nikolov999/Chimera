//go:build windows

package kernel

import (
	"context"
	"encoding/json"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsIsolationResult struct {
	VBSStatus *int `json:"vbs_status"`
}

func collectMandatoryAccessPlatform(ctx context.Context, _ Inventory) []MandatoryAccessAssessment {
	return []MandatoryAccessAssessment{
		collectWindowsVBSIsolation(ctx),
		unavailableMandatoryAccess(
			"windows.appcontainer.scope",
			"Windows AppContainer isolation applicability",
			"AppContainer",
			evidence.StateNotApplicable,
			"Windows process-isolation architecture",
			"per-process AppContainer state",
			"Windows does not expose a single system-wide AppContainer enabled switch; per-process isolation posture belongs to the runtime isolation assessment",
			evidence.ConfidenceExact,
		),
	}
}

func collectWindowsVBSIsolation(ctx context.Context) MandatoryAccessAssessment {
	const id = "windows.vbs_isolation"
	const name = "Windows virtualization-based security isolation"
	const provider = "Win32_DeviceGuard"
	const source = "root\\Microsoft\\Windows\\DeviceGuard:Win32_DeviceGuard.VirtualizationBasedSecurityStatus"
	if !commandAvailable("powershell.exe") {
		return unavailableMandatoryAccess(id, name, "VBS", evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so VBS isolation status cannot be queried", evidence.ConfidenceHigh)
	}
	script := `$ErrorActionPreference='Stop'; $dg=$null; try{$dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop}catch{}; $s=$null; if($null -ne $dg -and $null -ne $dg.VirtualizationBasedSecurityStatus){$s=[int]$dg.VirtualizationBasedSecurityStatus}; [pscustomobject]@{vbs_status=$s}|ConvertTo-Json -Compress`
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return unavailableMandatoryAccess(id, name, "VBS", evidence.StateUnavailable, provider, source, "Device Guard isolation provider failed: "+err.Error(), evidence.ConfidenceLow)
	}
	var r windowsIsolationResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return unavailableMandatoryAccess(id, name, "VBS", evidence.StateDegraded, provider, source, "Device Guard isolation provider returned invalid structured output: "+err.Error(), evidence.ConfidenceLow)
	}
	if r.VBSStatus == nil {
		return unavailableMandatoryAccess(id, name, "VBS", evidence.StateUnavailable, provider, source, "Win32_DeviceGuard did not expose VirtualizationBasedSecurityStatus", evidence.ConfidenceMedium)
	}
	switch *r.VBSStatus {
	case 0:
		return observedMandatoryAccess(id, name, "VBS", "DISABLED", "not enabled", provider, source, boolPtr(false), evidence.ConfidenceHigh)
	case 1:
		return observedMandatoryAccess(id, name, "VBS", "CONFIGURED_NOT_RUNNING", "enabled but not running", provider, source, boolPtr(false), evidence.ConfidenceHigh)
	case 2:
		return observedMandatoryAccess(id, name, "VBS", "RUNNING", "enabled and running", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	default:
		return unavailableMandatoryAccess(id, name, "VBS", evidence.StateDegraded, provider, source, "Win32_DeviceGuard returned an unrecognized VBS status", evidence.ConfidenceLow)
	}
}
