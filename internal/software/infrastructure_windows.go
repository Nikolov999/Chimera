//go:build windows

package software

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsInfrastructureSnapshot struct {
	Processes []struct {
		Name string `json:"Name"`
		Path string `json:"Path"`
	} `json:"Processes"`
	Services []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Path        string `json:"Path"`
	} `json:"Services"`
}

func collectPlatformInfrastructureActivity(ctx context.Context) ([]infrastructureActivity, []SourceStatus) {
	if !commandAvailable("powershell.exe") {
		return nil, []SourceStatus{{ID: "windows-process-service-metadata", State: evidence.StateUnavailable, Source: "Windows PowerShell local process/service metadata", Reason: "powershell.exe not available"}}
	}
	const script = `$p=@(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {$q=''; try {$q=[string]$_.Path} catch {}; [pscustomobject]@{Name=[string]$_.ProcessName;Path=$q}}); $s=@(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | ForEach-Object {$raw=[Environment]::ExpandEnvironmentVariables([string]$_.PathName); $ep=''; if($raw -match '^\s*"([^"]+)"'){$ep=$matches[1]} elseif($raw -match '^\s*([^\s]+)'){$ep=$matches[1]}; [pscustomobject]@{Name=[string]$_.Name;DisplayName=[string]$_.DisplayName;Path=$ep}}); [pscustomobject]@{Processes=$p;Services=$s} | ConvertTo-Json -Compress -Depth 4`
	text, err := runRuntimeProbe(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, []SourceStatus{{ID: "windows-process-service-metadata", State: infrastructureStateForError(ctx, err), Source: "Windows PowerShell local process/service metadata", Reason: err.Error()}}
	}
	var snap windowsInfrastructureSnapshot
	if err := json.Unmarshal([]byte(text), &snap); err != nil {
		return nil, []SourceStatus{{ID: "windows-process-service-metadata", State: evidence.StateDegraded, Source: "Windows PowerShell local process/service metadata", Reason: "parse provider output: " + err.Error()}}
	}
	out := make([]infrastructureActivity, 0, len(snap.Processes)+len(snap.Services)*2)
	for _, p := range snap.Processes {
		if strings.TrimSpace(p.Name) != "" {
			out = append(out, infrastructureActivity{Kind: "process", Name: p.Name, Path: p.Path})
		}
	}
	for _, s := range snap.Services {
		if strings.TrimSpace(s.Name) != "" {
			out = append(out, infrastructureActivity{Kind: "service", Name: s.Name, Path: s.Path})
		}
		if strings.TrimSpace(s.DisplayName) != "" && !strings.EqualFold(s.Name, s.DisplayName) {
			out = append(out, infrastructureActivity{Kind: "service", Name: s.DisplayName, Path: s.Path})
		}
	}
	return out, []SourceStatus{{ID: "windows-process-service-metadata", State: evidence.StateObserved, Source: "Windows PowerShell local process/service metadata", ItemCount: len(out)}}
}
