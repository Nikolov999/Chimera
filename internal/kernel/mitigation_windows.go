//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsMitigationSettings struct {
	BottomUp         string `json:"bottom_up"`
	ForceRelocate    string `json:"force_relocate"`
	HighEntropy      string `json:"high_entropy"`
	DisallowStripped string `json:"disallow_stripped"`
	CFGEnable        string `json:"cfg_enable"`
	CFGStrict        string `json:"cfg_strict"`
	SEHOPEnable      string `json:"sehop_enable"`
}

func collectMemoryMitigations(ctx context.Context, _ Inventory) []MitigationAssessment {
	out := []MitigationAssessment{collectWindowsDEP(ctx)}
	out = append(out, collectWindowsSystemMitigations(ctx)...)
	return out
}

func collectWindowsDEP(ctx context.Context) MitigationAssessment {
	const id = "windows.dep"
	const name = "Windows Data Execution Prevention"
	const provider = "Win32_OperatingSystem DataExecutionPrevention_SupportPolicy"
	const source = "root\\cimv2:Win32_OperatingSystem"
	if !commandAvailable("powershell.exe") {
		return unavailableMitigation(id, name, evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so the local DEP system policy cannot be queried", evidence.ConfidenceHigh)
	}
	script := `$ErrorActionPreference='Stop'; $o=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; if($null -eq $o.DataExecutionPrevention_SupportPolicy){'null'}else{[string][int]$o.DataExecutionPrevention_SupportPolicy}`
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return unavailableMitigation(id, name, evidence.StateUnavailable, provider, source, "DEP provider failed: "+err.Error(), evidence.ConfidenceLow)
	}
	switch strings.TrimSpace(out) {
	case "0":
		return observedMitigation(id, name, "DISABLED", "AlwaysOff", provider, source, boolPtr(false), evidence.ConfidenceHigh)
	case "1":
		return observedMitigation(id, name, "ENABLED", "AlwaysOn", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	case "2":
		return observedMitigation(id, name, "ENABLED", "OptIn", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	case "3":
		return observedMitigation(id, name, "ENABLED", "OptOut", provider, source, boolPtr(true), evidence.ConfidenceHigh)
	default:
		return unavailableMitigation(id, name, evidence.StateDegraded, provider, source, "DEP provider returned an unrecognized policy value", evidence.ConfidenceLow)
	}
}

func collectWindowsSystemMitigations(ctx context.Context) []MitigationAssessment {
	const provider = "Windows Get-ProcessMitigation system policy"
	const source = "Get-ProcessMitigation -System"
	ids := []struct{ id, name string }{
		{"windows.aslr", "Windows system ASLR policy"},
		{"windows.cfg", "Windows Control Flow Guard policy"},
		{"windows.sehop", "Windows SEH overwrite protection policy"},
	}
	if !commandAvailable("powershell.exe") {
		out := make([]MitigationAssessment, 0, len(ids))
		for _, x := range ids {
			out = append(out, unavailableMitigation(x.id, x.name, evidence.StateUnsupported, provider, source, "PowerShell is unavailable, so system process-mitigation policy cannot be queried", evidence.ConfidenceHigh))
		}
		return out
	}
	script := `$ErrorActionPreference='Stop'; $m=Get-ProcessMitigation -System -ErrorAction Stop; function S($v){if($null -eq $v){return ''}; return [string]$v}; [pscustomobject]@{bottom_up=(S $m.ASLR.BottomUp);force_relocate=(S $m.ASLR.ForceRelocateImages);high_entropy=(S $m.ASLR.HighEntropy);disallow_stripped=(S $m.ASLR.DisallowStripped);cfg_enable=(S $m.CFG.Enable);cfg_strict=(S $m.CFG.StrictMode);sehop_enable=(S $m.SEHOP.Enable)}|ConvertTo-Json -Compress`
	raw, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		out := make([]MitigationAssessment, 0, len(ids))
		for _, x := range ids {
			out = append(out, unavailableMitigation(x.id, x.name, evidence.StateUnavailable, provider, source, "system process-mitigation provider failed: "+err.Error(), evidence.ConfidenceLow))
		}
		return out
	}
	var m windowsMitigationSettings
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		out := make([]MitigationAssessment, 0, len(ids))
		for _, x := range ids {
			out = append(out, unavailableMitigation(x.id, x.name, evidence.StateDegraded, provider, source, "system mitigation provider returned invalid structured output: "+err.Error(), evidence.ConfidenceLow))
		}
		return out
	}
	aslr := map[string]string{
		"BottomUp": m.BottomUp, "DisallowStripped": m.DisallowStripped,
		"ForceRelocateImages": m.ForceRelocate, "HighEntropy": m.HighEntropy,
	}
	aslrState, aslrEnabled, aslrMode := aggregateMitigationSettings(aslr)
	cfgState, cfgEnabled, cfgMode := aggregateMitigationSettings(map[string]string{"Enable": m.CFGEnable, "StrictMode": m.CFGStrict})
	sehopState, sehopEnabled, sehopMode := aggregateMitigationSettings(map[string]string{"Enable": m.SEHOPEnable})
	return []MitigationAssessment{
		observedMitigation("windows.aslr", "Windows system ASLR policy", aslrState, aslrMode, provider, source, aslrEnabled, evidence.ConfidenceHigh),
		observedMitigation("windows.cfg", "Windows Control Flow Guard policy", cfgState, cfgMode, provider, source, cfgEnabled, evidence.ConfidenceHigh),
		observedMitigation("windows.sehop", "Windows SEH overwrite protection policy", sehopState, sehopMode, provider, source, sehopEnabled, evidence.ConfidenceHigh),
	}
}
