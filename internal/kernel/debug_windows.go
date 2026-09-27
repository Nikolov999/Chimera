//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsDeveloperModeResult struct {
	AllowDevelopmentWithoutDevLicense *int `json:"allow_development_without_dev_license"`
}

func collectDebugExposure(ctx context.Context, _ Inventory) []DebugExposureAssessment {
	out := collectWindowsBCDDebugPolicy(ctx)
	out = append(out, collectWindowsDeveloperMode(ctx))
	return out
}

func collectWindowsBCDDebugPolicy(ctx context.Context) []DebugExposureAssessment {
	const provider = "Windows Boot Configuration Data"
	const source = "bcdedit /enum {current}"
	defs := []struct{ id, name, element string }{
		{"windows.kernel_debugging", "Windows kernel debugging", "debug"},
		{"windows.boot_debugging", "Windows boot debugging", "bootdebug"},
	}
	exe := "bcdedit.exe"
	if !commandAvailable(exe) {
		exe = "bcdedit"
	}
	if !commandAvailable(exe) {
		out := make([]DebugExposureAssessment, 0, len(defs))
		for _, d := range defs {
			out = append(out, unavailableDebugExposure(d.id, d.name, evidence.StateUnsupported, provider, source, "bcdedit is unavailable, so local debugging boot policy cannot be inspected", evidence.ConfidenceHigh))
		}
		return out
	}
	raw, err := run(ctx, exe, "/enum", "{current}")
	if err != nil {
		state := evidence.StateUnavailable
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "access is denied") || strings.Contains(lower, "access denied") {
			state = evidence.StateDenied
		}
		out := make([]DebugExposureAssessment, 0, len(defs))
		for _, d := range defs {
			out = append(out, unavailableDebugExposure(d.id, d.name, state, provider, source, "BCD debugging policy could not be read: "+err.Error(), evidence.ConfidenceMedium))
		}
		return out
	}
	out := make([]DebugExposureAssessment, 0, len(defs))
	for _, d := range defs {
		enabled, found := parseBCDBooleanElement(raw, d.element)
		mode := "default/element absent"
		if found {
			mode = "explicit BCD element"
		}
		state := "DISABLED"
		if enabled {
			state = "ENABLED"
		}
		conf := evidence.ConfidenceHigh
		if found {
			conf = evidence.ConfidenceExact
		}
		out = append(out, observedDebugExposure(d.id, d.name, state, mode, provider, source, boolPtr(enabled), conf))
	}
	return out
}

func collectWindowsDeveloperMode(ctx context.Context) DebugExposureAssessment {
	const id = "windows.developer_mode"
	const name = "Windows Developer Mode"
	const provider = "Windows AppModelUnlock policy"
	const source = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock:AllowDevelopmentWithoutDevLicense`
	if !commandAvailable("powershell.exe") {
		return unavailableDebugExposure(id, name, evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so Developer Mode policy cannot be queried", evidence.ConfidenceHigh)
	}
	script := `$ErrorActionPreference='Stop'; $v=$null; try{$p=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name AllowDevelopmentWithoutDevLicense -ErrorAction Stop; if($null -ne $p.AllowDevelopmentWithoutDevLicense){$v=[int]$p.AllowDevelopmentWithoutDevLicense}}catch [System.Management.Automation.ItemNotFoundException]{} catch [System.Management.Automation.PSArgumentException]{}; [pscustomobject]@{allow_development_without_dev_license=$v}|ConvertTo-Json -Compress`
	raw, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return unavailableDebugExposure(id, name, evidence.StateUnavailable, provider, source, "Developer Mode provider failed: "+err.Error(), evidence.ConfidenceLow)
	}
	var r windowsDeveloperModeResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, "Developer Mode provider returned invalid structured output: "+err.Error(), evidence.ConfidenceLow)
	}
	if r.AllowDevelopmentWithoutDevLicense == nil {
		return observedDebugExposure(id, name, "DISABLED_OR_NOT_CONFIGURED", "policy value absent", provider, source, boolPtr(false), evidence.ConfidenceHigh)
	}
	switch *r.AllowDevelopmentWithoutDevLicense {
	case 0:
		return observedDebugExposure(id, name, "DISABLED", "AllowDevelopmentWithoutDevLicense=0", provider, source, boolPtr(false), evidence.ConfidenceExact)
	case 1:
		return observedDebugExposure(id, name, "ENABLED", "AllowDevelopmentWithoutDevLicense=1", provider, source, boolPtr(true), evidence.ConfidenceExact)
	default:
		return unavailableDebugExposure(id, name, evidence.StateDegraded, provider, source, "Developer Mode policy returned an unrecognized value", evidence.ConfidenceLow)
	}
}
