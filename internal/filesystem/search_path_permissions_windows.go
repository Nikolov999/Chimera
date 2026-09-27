//go:build windows

package filesystem

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

type windowsSearchPathWire struct {
	CandidateID     string   `json:"candidate_id"`
	Path            string   `json:"path"`
	State           string   `json:"state"`
	Exists          bool     `json:"exists"`
	Directory       bool     `json:"directory"`
	Owner           string   `json:"owner"`
	BroadlyWritable bool     `json:"broadly_writable"`
	WritePrincipals []string `json:"write_principals"`
	Reason          string   `json:"reason"`
}

type windowsSearchCandidateWire struct {
	CandidateID string   `json:"candidate_id"`
	Path        string   `json:"path"`
	Contexts    []string `json:"contexts"`
	Source      string   `json:"source"`
}

const windowsSearchPathScript = `$ErrorActionPreference='Stop'
$items=@(); try {$items=@(ConvertFrom-Json $env:CHIMERA_SEARCH_PATHS_JSON -ErrorAction Stop)} catch { Write-Error ('[chimera-stage:windows-search-path-input] ' + $_.Exception.Message); exit 40 }
$broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$mask=` + windowsacl.PowerShellMutatingMaskExpression + `
foreach($i in $items){
 $id=[string]$i.candidate_id
 $p=[string]$i.path
 if([string]::IsNullOrWhiteSpace($p)){continue}
 if(-not (Test-Path -LiteralPath $p)){
   [pscustomobject]@{candidate_id=$id;path=$p;state='OBSERVED';exists=$false;directory=$false;owner='';broadly_writable=$false;write_principals=@();reason='search directory does not exist on this host'} | ConvertTo-Json -Compress
   continue
 }
 try {
  $isdir=Test-Path -LiteralPath $p -PathType Container
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
  $allow=@{};$deny=@{};$names=@{}
  foreach($ace in @($acl.Access)){
   $sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}
   if($broadSids -notcontains $sid){continue}
   if(([int64]$ace.FileSystemRights -band [int64]$mask) -eq 0){continue}
   if([string]$ace.AccessControlType -eq 'Deny'){$deny[$sid]=$true}else{$allow[$sid]=$true;$names[$sid]=[string]$ace.IdentityReference}
  }
  $writers=@();foreach($sid in $allow.Keys){if(-not $deny.ContainsKey($sid)){$writers+=$names[$sid]}}
  [pscustomobject]@{candidate_id=$id;path=$p;state='OBSERVED';exists=$true;directory=$isdir;owner=[string]$acl.Owner;broadly_writable=($writers.Count -gt 0);write_principals=@($writers);reason=''} | ConvertTo-Json -Compress
 } catch {
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{candidate_id=$id;path=$p;state=$st;exists=$true;directory=$false;owner='';broadly_writable=$false;write_principals=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress
 }
}`

func collectPlatformSearchPaths(ctx context.Context, candidates []searchPathCandidate, capability PermissionCapability) ([]SearchPathRecord, SourceStatus, []string) {
	ps, err := windowsFilesystemPowerShellPath()
	if err != nil {
		return nil, SourceStatus{ID: "privileged-search-paths", State: evidence.StateUnavailable, Source: "Windows PowerShell Get-Acl privileged search-path inventory", Reason: "PowerShell not found"}, []string{"privileged search-path DACL inventory unavailable: PowerShell not found"}
	}
	wire := make([]windowsSearchCandidateWire, 0, len(candidates))
	byID := make(map[string]searchPathCandidate, len(candidates))
	byPath := make(map[string]searchPathCandidate, len(candidates))
	for _, c := range candidates {
		id := stableSearchPathID(c.Path)
		wire = append(wire, windowsSearchCandidateWire{CandidateID: id, Path: c.Path, Contexts: c.Contexts, Source: c.Source})
		byID[id] = c
		byPath[platformPathKey(c.Path)] = c
	}
	rawItems, _ := json.Marshal(wire)
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsSearchPathScript)
	cmd.Env = append(os.Environ(), "CHIMERA_SEARCH_PATHS_JSON="+string(rawItems))
	raw, runErr := cmd.Output()
	// Preserve any completed candidate rows when the bounded enrichment stage is
	// cancelled; search-path base discovery remains independently trustworthy.
	out := []SearchPathRecord{}
	unresolved := 0
	malformed := 0
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var w windowsSearchPathWire
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			malformed++
			continue
		}
		c, correlated := byID[strings.TrimSpace(w.CandidateID)]
		if !correlated {
			candidatePath := strings.TrimSpace(w.Path)
			if candidatePath != "" {
				c, correlated = byPath[platformPathKey(candidatePath)]
			}
		}
		p := strings.TrimSpace(w.Path)
		if p == "" && correlated {
			p = c.Path
		}
		if p == "" {
			malformed++
			continue
		}
		p = filepath.Clean(p)
		st := evidence.State(strings.ToUpper(strings.TrimSpace(w.State)))
		reason := strings.TrimSpace(w.Reason)
		if st == "" {
			st = evidence.StateDegraded
			reason = appendFilesystemReason(reason, "provider record did not include a state")
		}
		contexts := append([]string(nil), c.Contexts...)
		sources := []string{c.Source}
		if !correlated {
			st = evidence.StateDegraded
			contexts = []string{"UNKNOWN_CONTEXT"}
			sources = []string{"Windows PowerShell search-path provider output without candidate correlation"}
			reason = appendFilesystemReason(reason, "provider record could not be correlated to its discovery candidate")
		}
		permissionModel := strings.TrimSpace(capability.Model)
		if permissionModel == "" {
			permissionModel = "WINDOWS_DACL"
		}
		rec := SearchPathRecord{ID: stableSearchPathID(p), Path: p, State: st, Exists: w.Exists, Directory: w.Directory,
			OwnerID: strings.TrimSpace(w.Owner), PermissionModel: permissionModel, BroadlyWritable: w.BroadlyWritable,
			UntrustedWrite: w.BroadlyWritable, WritePrincipals: append([]string(nil), w.WritePrincipals...), Contexts: contexts,
			DiscoverySources: sources, CollectionSource: "Windows PowerShell Get-Acl directory DACL metadata", Confidence: evidence.ConfidenceHigh, Reason: reason}
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		malformed++
	}
	state := evidence.StateObserved
	reasons := []string{}
	degraded := []string(nil)
	if unresolved > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("permission metadata unresolved for %d privileged search-path record(s)", unresolved))
	}
	if malformed > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("quarantined %d malformed privileged search-path provider record(s)", malformed))
	}
	if runErr != nil {
		runReason := windowsFilesystemProviderReason(ctx, "windows-search-path-acl", runErr)
		if len(out) == 0 {
			state = stateForWindowsFilesystemErr(ctx, runErr)
		} else {
			state = evidence.StateDegraded
		}
		reasons = append(reasons, runReason)
		degraded = append(degraded, fmt.Sprintf("privileged search-path DACL enrichment preserved %d completed record(s): %s", len(out), runReason))
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	if reason != "" && len(degraded) == 0 {
		degraded = append(degraded, "privileged search-path DACL inventory degraded: "+reason)
	}
	return out, SourceStatus{ID: "privileged-search-paths", State: state, Source: "Windows PowerShell Get-Acl privileged search-path inventory", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func windowsFilesystemPowerShellPath() (string, error) {
	for _, name := range []string{"powershell.exe", "powershell", "pwsh.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("PowerShell executable was not found")
}

func windowsFilesystemProviderReason(ctx context.Context, stage string, err error) string {
	detail := ""
	if ee, ok := err.(*exec.ExitError); ok {
		detail = string(ee.Stderr)
	}
	return windowsFilesystemProviderReasonWithDetail(ctx, stage, err, detail)
}

func windowsFilesystemProviderReasonWithDetail(ctx context.Context, stage string, err error, stderr string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		stage = "windows-filesystem-provider"
	}
	if ctx != nil && ctx.Err() != nil {
		return stage + ": " + ctx.Err().Error()
	}
	reason := stage + " failed"
	if ee, ok := err.(*exec.ExitError); ok {
		reason += fmt.Sprintf(" (exit code %d)", ee.ExitCode())
	} else if err != nil {
		reason += ": " + boundedFilesystemProviderDetail(err.Error())
	}
	if detail := boundedFilesystemProviderDetail(stderr); detail != "" {
		reason += ": " + detail
	}
	return reason
}

func boundedFilesystemProviderDetail(s string) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	const max = 2048
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func stateForWindowsFilesystemErr(ctx context.Context, err error) evidence.State {
	detail := ""
	if ee, ok := err.(*exec.ExitError); ok {
		detail = string(ee.Stderr)
	}
	return stateForWindowsFilesystemErrWithDetail(ctx, err, detail)
}

func stateForWindowsFilesystemErrWithDetail(ctx context.Context, err error, detail string) evidence.State {
	if ctx != nil && ctx.Err() != nil {
		return evidence.StateDegraded
	}
	s := strings.ToLower(strings.TrimSpace(detail))
	if err != nil {
		s += " " + strings.ToLower(err.Error())
	}
	if strings.Contains(s, "access") || strings.Contains(s, "denied") || strings.Contains(s, "unauthorized") {
		return evidence.StateDenied
	}
	return evidence.StateUnavailable
}

func appendFilesystemReason(reason, addition string) string {
	reason = strings.TrimSpace(reason)
	addition = strings.TrimSpace(addition)
	if reason == "" {
		return addition
	}
	if addition == "" {
		return reason
	}
	return reason + "; " + addition
}
