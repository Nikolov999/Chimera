//go:build windows

package filesystem

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/windowsacl"
)

type windowsACLGrantWire struct {
	Principal      string   `json:"principal"`
	PrincipalID    string   `json:"principal_id"`
	PrincipalClass string   `json:"principal_class"`
	Access         string   `json:"access"`
	Rights         []string `json:"rights"`
	Inherited      bool     `json:"inherited"`
	Effective      bool     `json:"effective"`
	Broad          bool     `json:"broad"`
	Trusted        bool     `json:"trusted"`
	WriteLike      bool     `json:"write_like"`
	ControlLike    bool     `json:"control_like"`
}

type windowsACLBoundaryWire struct {
	Path      string                `json:"path"`
	State     string                `json:"state"`
	Exists    bool                  `json:"exists"`
	Directory bool                  `json:"directory"`
	Owner     string                `json:"owner"`
	Grants    []windowsACLGrantWire `json:"grants"`
	Reason    string                `json:"reason"`
}

type windowsACLBoundaryCandidateWire struct {
	Path string `json:"path"`
}

const windowsACLBoundaryScript = `$ErrorActionPreference='Stop'
$raw=[Console]::In.ReadToEnd(); $items=@(); try {$items=@(ConvertFrom-Json $raw)} catch {}
$broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$trustedExact=@('S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-32-544')
$writeMask=` + windowsacl.PowerShellMutatingMaskExpression + `
$controlMask=` + windowsacl.PowerShellControlMaskExpression + `
foreach($i in $items){
 $p=[string]$i.path; if([string]::IsNullOrWhiteSpace($p)){continue}
 if(-not (Test-Path -LiteralPath $p)){
  [pscustomobject]@{path=$p;state='OBSERVED';exists=$false;directory=$false;owner='';grants=@();reason='path does not exist on this host'} | ConvertTo-Json -Compress -Depth 8
  continue
 }
 try {
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop; $isdir=Test-Path -LiteralPath $p -PathType Container
  $deny=@{}
  foreach($ace in @($acl.Access)){
   if([string]$ace.AccessControlType -ne 'Deny'){continue}
   $sid=''; try {$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value} catch {$sid=[string]$ace.IdentityReference}
   $v=[int64]$ace.FileSystemRights; if($deny.ContainsKey($sid)){$deny[$sid]=([int64]$deny[$sid] -bor $v)}else{$deny[$sid]=$v}
  }
  $grants=@()
  foreach($ace in @($acl.Access)){
   $sid=''; try {$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value} catch {$sid=[string]$ace.IdentityReference}
   $v=[int64]$ace.FileSystemRights; $effectiveRights=$v; $effective=$true
   if([string]$ace.AccessControlType -eq 'Allow' -and $deny.ContainsKey($sid)){$effectiveRights=($v -band (-bnot ([int64]$deny[$sid])));$effective=($effectiveRights -ne 0)}
   $broad=($broadSids -contains $sid)
   $trusted=($trustedExact -contains $sid) -or $sid.StartsWith('S-1-5-80-')
   $pc=if($broad){'BROAD_PRINCIPAL'}elseif($trusted){'TRUSTED_SYSTEM'}else{'NAMED_PRINCIPAL'}
   $rights=@(([string]$ace.FileSystemRights -split ',') | ForEach-Object {$_.Trim().ToUpperInvariant()} | Where-Object {$_})
   $writeLike=(($effectiveRights -band $writeMask) -ne 0); $controlLike=(($effectiveRights -band $controlMask) -ne 0)
   $grants += [pscustomobject]@{principal=[string]$ace.IdentityReference;principal_id=$sid;principal_class=$pc;access=([string]$ace.AccessControlType).ToUpperInvariant();rights=$rights;inherited=[bool]$ace.IsInherited;effective=[bool]$effective;broad=[bool]$broad;trusted=[bool]$trusted;write_like=[bool]$writeLike;control_like=[bool]$controlLike}
  }
  [pscustomobject]@{path=$p;state='OBSERVED';exists=$true;directory=$isdir;owner=[string]$acl.Owner;grants=@($grants);reason=''} | ConvertTo-Json -Compress -Depth 8
 } catch {
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{path=$p;state=$st;exists=$true;directory=$false;owner='';grants=@();reason=[string]$_.Exception.Message} | ConvertTo-Json -Compress -Depth 8
 }
}`

func collectPlatformACLBoundaries(ctx context.Context, candidates []aclBoundaryCandidate) ([]ACLBoundaryRecord, SourceStatus, []string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		ps, err = exec.LookPath("pwsh.exe")
	}
	if err != nil {
		return nil, SourceStatus{ID: "acl-boundaries", State: evidence.StateUnavailable, Source: "Windows native DACL metadata via PowerShell Get-Acl", Reason: "PowerShell not found"}, []string{"Windows ACL boundary inventory unavailable: PowerShell not found"}
	}

	wire := make([]windowsACLBoundaryCandidateWire, 0, len(candidates))
	byPath := map[string]aclBoundaryCandidate{}
	for _, c := range candidates {
		wire = append(wire, windowsACLBoundaryCandidateWire{Path: c.Path})
		byPath[strings.ToLower(filepath.Clean(c.Path))] = c
	}
	const batchSize = 40
	var rawBuilder strings.Builder
	runIssues := []string{}
	for offset := 0; offset < len(wire); offset += batchSize {
		if ctx != nil && ctx.Err() != nil {
			runIssues = append(runIssues, "windows-acl-boundary-inventory: "+ctx.Err().Error())
			break
		}
		end := offset + batchSize
		if end > len(wire) {
			end = len(wire)
		}
		rawItems, marshalErr := json.Marshal(wire[offset:end])
		if marshalErr != nil {
			runIssues = append(runIssues, "windows-acl-boundary-inventory input encode: "+marshalErr.Error())
			continue
		}
		cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsACLBoundaryScript)
		cmd.Stdin = strings.NewReader(string(rawItems))
		batchRaw, runErr := cmd.Output()
		if len(batchRaw) > 0 {
			rawBuilder.Write(batchRaw)
			rawBuilder.WriteByte('\n')
		}
		if runErr != nil {
			runIssues = append(runIssues, windowsFilesystemProviderReason(ctx, "windows-acl-boundary-inventory", runErr))
			if ctx != nil && ctx.Err() != nil {
				break
			}
		}
	}
	// Fix51 retains complete JSON lines from completed batches if the bounded
	// high-impact ACL stage expires later in the candidate set.
	out := []ACLBoundaryRecord{}
	degraded := []string{}
	unresolved := 0
	seenPaths := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(rawBuilder.String()))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var w windowsACLBoundaryWire
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			degraded = append(degraded, "Windows ACL output contained an invalid record")
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
		rec := ACLBoundaryRecord{
			ID: stableACLBoundaryID(p), Path: p, Contexts: append([]string(nil), c.Contexts...), State: st,
			Exists: w.Exists, Directory: w.Directory, OwnerID: strings.TrimSpace(w.Owner), ACLModel: "NTFS_DACL",
			HasExtendedACL: len(w.Grants) > 0, DiscoverySources: append([]string(nil), c.Sources...),
			CollectionSource: "Windows security descriptor DACL via PowerShell Get-Acl", Confidence: evidence.ConfidenceHigh, Reason: strings.TrimSpace(w.Reason),
		}
		for _, g := range w.Grants {
			rec.Grants = append(rec.Grants, ACLGrant{
				Principal: g.Principal, PrincipalID: g.PrincipalID, PrincipalClass: g.PrincipalClass,
				Access: g.Access, Rights: append([]string(nil), g.Rights...), Inherited: g.Inherited,
				Effective: g.Effective, Broad: g.Broad, Trusted: g.Trusted, WriteLike: g.WriteLike, ControlLike: g.ControlLike,
			})
		}
		classifyACLBoundary(&rec)
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		degraded = append(degraded, "Windows ACL output parsing degraded: "+err.Error())
	}
	state := evidence.StateObserved
	reasons := []string{}
	if unresolved > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("Windows ACL boundary inventory completed with %d unresolved record(s)", unresolved))
	}
	missing := len(byPath) - len(seenPaths)
	if missing > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("Windows ACL boundary enrichment completed %d of %d candidate(s)", len(seenPaths), len(byPath)))
	}
	if len(runIssues) > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, runIssues...)
		degraded = append(degraded, fmt.Sprintf("Windows ACL boundary enrichment preserved %d completed record(s) across bounded batches: %s", len(out), strings.Join(uniqueSorted(runIssues), "; ")))
	}
	if len(degraded) > 0 && state == evidence.StateObserved {
		state = evidence.StateDegraded
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	return out, SourceStatus{ID: "acl-boundaries", State: state, Source: "Windows native DACL metadata via PowerShell Get-Acl on selected high-impact paths", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}
