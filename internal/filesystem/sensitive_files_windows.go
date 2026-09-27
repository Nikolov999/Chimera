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

type windowsSensitiveWire struct {
	Path              string   `json:"path"`
	State             string   `json:"state"`
	Exists            bool     `json:"exists"`
	Directory         bool     `json:"directory"`
	Owner             string   `json:"owner"`
	BroadlyWritable   bool     `json:"broadly_writable"`
	BroadlyAccessible bool     `json:"broadly_accessible"`
	WritePrincipals   []string `json:"write_principals"`
	ReadPrincipals    []string `json:"read_principals"`
	Reason            string   `json:"reason"`
}

type windowsSensitiveCandidateWire struct {
	Path string `json:"path"`
}

const windowsSensitiveScript = `$ErrorActionPreference='Stop'
$items=@(); try {$items=@(ConvertFrom-Json $env:CHIMERA_SENSITIVE_PATHS_JSON)} catch {}
$broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$writeMask=` + windowsacl.PowerShellMutatingMaskExpression + `
$readMask=[System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::FullControl -bor [System.Security.AccessControl.FileSystemRights]::ListDirectory
foreach($i in $items){
 $p=[string]$i.path
 if([string]::IsNullOrWhiteSpace($p)){continue}
 if(-not (Test-Path -LiteralPath $p)){
  [pscustomobject]@{path=$p;state='OBSERVED';exists=$false;directory=$false;owner='';broadly_writable=$false;broadly_accessible=$false;write_principals=@();read_principals=@();reason='path does not exist on this host'} | ConvertTo-Json -Compress
  continue
 }
 try {
  $isdir=Test-Path -LiteralPath $p -PathType Container
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
  $allowW=@{};$denyW=@{};$allowR=@{};$denyR=@{};$names=@{}
  foreach($ace in @($acl.Access)){
   $sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}
   if($broadSids -notcontains $sid){continue}
   $names[$sid]=[string]$ace.IdentityReference
   if(([int64]$ace.FileSystemRights -band [int64]$writeMask) -ne 0){if([string]$ace.AccessControlType -eq 'Deny'){$denyW[$sid]=$true}else{$allowW[$sid]=$true}}
   if(([int64]$ace.FileSystemRights -band [int64]$readMask) -ne 0){if([string]$ace.AccessControlType -eq 'Deny'){$denyR[$sid]=$true}else{$allowR[$sid]=$true}}
  }
  $writers=@();foreach($sid in $allowW.Keys){if(-not $denyW.ContainsKey($sid)){$writers+=$names[$sid]}}
  $readers=@();foreach($sid in $allowR.Keys){if(-not $denyR.ContainsKey($sid)){$readers+=$names[$sid]}}
  [pscustomobject]@{path=$p;state='OBSERVED';exists=$true;directory=$isdir;owner=[string]$acl.Owner;broadly_writable=($writers.Count -gt 0);broadly_accessible=($readers.Count -gt 0);write_principals=@($writers);read_principals=@($readers);reason=''} | ConvertTo-Json -Compress
 } catch {
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{path=$p;state=$st;exists=$true;directory=$false;owner='';broadly_writable=$false;broadly_accessible=$false;write_principals=@();read_principals=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress
 }
}`

func collectPlatformSensitiveFiles(ctx context.Context, capability PermissionCapability) ([]SensitiveFileRecord, SourceStatus, []string) {
	candidates, degraded := expandSensitiveCandidates(platformSensitiveCandidates())
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		ps, err = exec.LookPath("pwsh.exe")
	}
	if err != nil {
		return nil, SourceStatus{ID: "sensitive-file-permissions", State: evidence.StateUnavailable, Source: "Windows PowerShell Get-Acl sensitive-path inventory", Reason: "PowerShell not found"}, append(degraded, "sensitive-file DACL inventory unavailable: PowerShell not found")
	}
	wire := make([]windowsSensitiveCandidateWire, 0, len(candidates))
	byPath := map[string]sensitiveCandidate{}
	for _, c := range candidates {
		wire = append(wire, windowsSensitiveCandidateWire{Path: c.Path})
		byPath[strings.ToLower(filepath.Clean(c.Path))] = c
	}
	const batchSize = 48
	var rawBuilder strings.Builder
	runIssues := []string{}
	for offset := 0; offset < len(wire); offset += batchSize {
		if ctx != nil && ctx.Err() != nil {
			runIssues = append(runIssues, "windows-sensitive-file-dacl-inventory: "+ctx.Err().Error())
			break
		}
		end := offset + batchSize
		if end > len(wire) {
			end = len(wire)
		}
		rawItems, marshalErr := json.Marshal(wire[offset:end])
		if marshalErr != nil {
			runIssues = append(runIssues, "windows-sensitive-file-dacl-inventory input encode: "+marshalErr.Error())
			continue
		}
		cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsSensitiveScript)
		cmd.Env = append(os.Environ(), "CHIMERA_SENSITIVE_PATHS_JSON="+string(rawItems))
		batchRaw, runErr := cmd.Output()
		if len(batchRaw) > 0 {
			rawBuilder.Write(batchRaw)
			rawBuilder.WriteByte('\n')
		}
		if runErr != nil {
			runIssues = append(runIssues, windowsFilesystemProviderReason(ctx, "windows-sensitive-file-dacl-inventory", runErr))
			if ctx != nil && ctx.Err() != nil {
				break
			}
		}
	}
	// Fix51 parses every completed batch, including JSON lines emitted before a
	// bounded stage is cancelled. A slow tail cannot erase earlier ACL evidence.
	out := []SensitiveFileRecord{}
	unresolved := 0
	seenPaths := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(rawBuilder.String()))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var w windowsSensitiveWire
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			degraded = append(degraded, "sensitive-file DACL output contained an invalid record")
			continue
		}
		p := filepath.Clean(strings.TrimSpace(w.Path))
		key := strings.ToLower(p)
		c, ok := byPath[key]
		if !ok {
			continue
		}
		seenPaths[key] = struct{}{}
		st := evidence.State(strings.ToUpper(strings.TrimSpace(w.State)))
		if st == "" {
			st = evidence.StateUnavailable
		}
		ownerState := SensitiveOwnerUnknown
		expectedOwner := ""
		if c.Scope == "SYSTEM" {
			expectedOwner = "SYSTEM/Administrators/TrustedInstaller"
			if st == evidence.StateObserved && w.Exists {
				if windowsPrivilegedOwner(w.Owner) {
					ownerState = SensitiveOwnerExpected
				} else if strings.TrimSpace(w.Owner) != "" {
					ownerState = SensitiveOwnerUnexpected
				}
			}
		} else if c.Scope == "APPLICATION" {
			ownerState = SensitiveOwnerNotApplicable
		}
		rec := SensitiveFileRecord{
			ID: stableSensitiveFileID(c.Kind, p), Kind: c.Kind, Scope: c.Scope, Path: p, AccessPolicy: c.AccessPolicy,
			State: st, Exists: w.Exists, Directory: w.Directory, OwnerID: strings.TrimSpace(w.Owner), ExpectedOwnerID: expectedOwner, OwnerState: ownerState,
			PermissionModel: capability.Model, BroadlyWritable: w.BroadlyWritable, UntrustedWrite: w.BroadlyWritable,
			BroadlyAccessible: w.BroadlyAccessible, UntrustedAccess: w.BroadlyAccessible,
			WritePrincipals: append([]string(nil), w.WritePrincipals...), ReadPrincipals: append([]string(nil), w.ReadPrincipals...),
			DiscoverySource: c.Source, CollectionSource: "Windows PowerShell Get-Acl sensitive-path DACL metadata", Confidence: evidence.ConfidenceHigh, Reason: strings.TrimSpace(w.Reason),
		}
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		degraded = append(degraded, "sensitive-file DACL parsing degraded: "+err.Error())
	}
	state := evidence.StateObserved
	reasons := []string{}
	if unresolved > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("sensitive-file DACL inventory completed with %d unresolved record(s)", unresolved))
	}
	missing := len(byPath) - len(seenPaths)
	if missing > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("sensitive-file DACL enrichment completed %d of %d candidate(s)", len(seenPaths), len(byPath)))
	}
	if len(runIssues) > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, runIssues...)
		degraded = append(degraded, fmt.Sprintf("sensitive-file DACL enrichment preserved %d completed record(s) across bounded batches: %s", len(out), strings.Join(uniqueSorted(runIssues), "; ")))
	}
	if len(degraded) > 0 && state == evidence.StateObserved {
		state = evidence.StateDegraded
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	return out, SourceStatus{ID: "sensitive-file-permissions", State: state, Source: "Windows PowerShell Get-Acl sensitive-path inventory", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func windowsPrivilegedOwner(owner string) bool {
	o := strings.ToLower(strings.TrimSpace(owner))
	return o == "s-1-5-18" || o == "s-1-5-32-544" || strings.Contains(o, "trustedinstaller") || strings.HasSuffix(o, `\system`) || strings.HasSuffix(o, `\administrators`) || strings.Contains(o, "builtin\\administrators")
}
