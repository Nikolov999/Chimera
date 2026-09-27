//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type winInstalledDriverCandidate struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	State       string `json:"State"`
	Path        string `json:"Path"`
	Version     string `json:"Version"`
	Exists      *bool  `json:"Exists"`
}

func collectInstalledVulnerableDriverCandidatesPlatform(ctx context.Context, entries []driverIntelEntry) ([]driverCandidate, evidence.State, string, string) {
	if len(entries) == 0 {
		return nil, evidence.StateNotApplicable, "no Windows entries exist in the pinned seed", "embedded driver intelligence"
	}
	if !commandAvailable("powershell.exe") {
		return nil, evidence.StateUnavailable, "powershell.exe is unavailable; installed Win32_SystemDriver candidates could not be collected", "Win32_SystemDriver"
	}
	aliases := make([]string, 0, 16)
	for _, e := range entries {
		aliases = append(aliases, e.ServiceNames...)
		aliases = append(aliases, e.FileNames...)
	}
	// The provider reads service/driver metadata only. Filtering is repeated in
	// Go with exact normalized identity matching; PowerShell filtering here is
	// merely a bounded collection optimization.
	quoted := make([]string, 0, len(aliases))
	for _, a := range aliases {
		quoted = append(quoted, "'"+strings.ReplaceAll(strings.ToLower(a), "'", "''")+"'")
	}
	ps := `$ErrorActionPreference='SilentlyContinue'; $aliases=@(` + strings.Join(quoted, ",") + `); $rows=@(); Get-CimInstance Win32_SystemDriver | ForEach-Object { $d=$_; $p=[string]$d.PathName; if($p -match '^\\SystemRoot\\'){ $p=Join-Path $env:SystemRoot $p.Substring(12) }; if($p -match '^System32\\'){ $p=Join-Path $env:SystemRoot $p }; if($p -match '^"([^"]+)"'){ $p=$matches[1] } else { $p=($p -split '\\s+')[0] }; if($p -match '^\\\?\?\\'){ $p=$p.Substring(4) }; $base=[IO.Path]::GetFileName($p).ToLowerInvariant(); if($aliases -contains ([string]$d.Name).ToLowerInvariant() -or $aliases -contains $base){ $exists=$null; $ver=''; if($p){try{$exists=Test-Path -LiteralPath $p}catch{}; if($exists){try{$ver=(Get-Item -LiteralPath $p).VersionInfo.FileVersion}catch{}}}; $rows += [pscustomobject]@{Name=[string]$d.Name;DisplayName=[string]$d.DisplayName;State=[string]$d.State;Path=$p;Version=$ver;Exists=$exists} } }; @($rows)|ConvertTo-Json -Compress -Depth 3`
	s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err != nil {
		return nil, evidence.StateUnavailable, "installed Win32_SystemDriver collection failed: " + err.Error(), "Win32_SystemDriver"
	}
	if strings.TrimSpace(s) == "" || strings.TrimSpace(s) == "null" || strings.TrimSpace(s) == "[]" {
		return nil, evidence.StateObserved, "no installed driver identities matched the pinned aliases", "Win32_SystemDriver"
	}
	var rows []winInstalledDriverCandidate
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		var one winInstalledDriverCandidate
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return nil, evidence.StateDegraded, "installed-driver JSON decode failed: " + err.Error(), "Win32_SystemDriver"
		}
		rows = []winInstalledDriverCandidate{one}
	} else if err := json.Unmarshal([]byte(s), &rows); err != nil {
		return nil, evidence.StateDegraded, "installed-driver JSON decode failed: " + err.Error(), "Win32_SystemDriver"
	}
	out := make([]driverCandidate, 0, len(rows))
	for _, r := range rows {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = strings.TrimSpace(r.DisplayName)
		}
		loaded := strings.EqualFold(strings.TrimSpace(r.State), "running")
		installed := true // Win32_SystemDriver registration itself is installed-state evidence.
		out = append(out, driverCandidate{Name: name, Path: strings.TrimSpace(r.Path), Version: strings.TrimSpace(r.Version), Installed: installed, Loaded: loaded, CollectionState: evidence.StateObserved, Source: "Win32_SystemDriver installed-driver inventory", ExposureState: exposureFromLoad(loaded), ExposureReason: exposureReasonFromLoad(loaded), Confidence: evidence.ConfidenceHigh})
	}
	return out, evidence.StateObserved, "", "Win32_SystemDriver"
}
