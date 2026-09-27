//go:build windows

package filesystem

import (
	"bufio"
	"bytes"
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

type windowsTempWire struct {
	Kind                  string   `json:"kind"`
	CandidateID           string   `json:"candidate_id"`
	Path                  string   `json:"path"`
	State                 string   `json:"state"`
	Exists                bool     `json:"exists"`
	Directory             bool     `json:"directory"`
	Owner                 string   `json:"owner"`
	TrustedOwner          bool     `json:"trusted_owner"`
	OwnerTrustKnown       bool     `json:"owner_trust_known"`
	BroadCreate           bool     `json:"broad_create"`
	BroadControl          bool     `json:"broad_control"`
	WritePrincipals       []string `json:"write_principals"`
	ParentPath            string   `json:"parent_path"`
	ParentState           string   `json:"parent_state"`
	ParentOwner           string   `json:"parent_owner"`
	ParentTrustedOwner    bool     `json:"parent_trusted_owner"`
	ParentOwnerTrustKnown bool     `json:"parent_owner_trust_known"`
	ParentBroadCreate     bool     `json:"parent_broad_create"`
	ParentBroadControl    bool     `json:"parent_broad_control"`
	Reason                string   `json:"reason"`
}

const windowsTempSecurityScript = `$ErrorActionPreference='Stop'
` + windowsCandidateEnvelopePowerShell + `
$items=@()
try{$items=@(Read-ChimeraCandidateEnvelope -Json $env:CHIMERA_TEMP_PATHS_JSON -Label 'temporary-directory')}catch{
 [pscustomobject]@{kind='provider_error';candidate_id='';path='';state='UNAVAILABLE';exists=$false;directory=$false;owner='';trusted_owner=$false;owner_trust_known=$false;broad_create=$false;broad_control=$false;write_principals=@();parent_path='';parent_state='';parent_owner='';parent_trusted_owner=$false;parent_owner_trust_known=$false;parent_broad_create=$false;parent_broad_control=$false;reason=('decode temporary-directory candidate envelope: '+[string]$_.Exception.Message)} | ConvertTo-Json -Compress
 exit 0
}
$broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$trustedOwners=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$createMask=` + windowsacl.PowerShellCreateMaskExpression + `
$controlMask=` + windowsacl.PowerShellControlMaskExpression + `
function Inspect-Path([string]$p){
 if([string]::IsNullOrWhiteSpace($p)){return $null}
 try{
  if(-not (Test-Path -LiteralPath $p -ErrorAction Stop)){return [pscustomobject]@{path=$p;state='OBSERVED';exists=$false;directory=$false;owner='';trusted_owner=$false;owner_trust_known=$false;broad_create=$false;broad_control=$false;writers=@();reason='path does not exist on this host'}}
  $isdir=Test-Path -LiteralPath $p -PathType Container -ErrorAction Stop
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
  $ownerSid='';try{$ownerSid=([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{try{$ownerSid=([System.Security.Principal.SecurityIdentifier]$acl.Owner).Value}catch{}}
  $allowCreate=@{};$denyCreate=@{};$allowControl=@{};$denyControl=@{};$names=@{}
  foreach($ace in @($acl.Access)){
   $sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}
   if($broadSids -notcontains $sid){continue}
   $names[$sid]=[string]$ace.IdentityReference
   $isDeny=([string]$ace.AccessControlType -eq 'Deny')
   if(([int64]$ace.FileSystemRights -band [int64]$createMask) -ne 0){if($isDeny){$denyCreate[$sid]=$true}else{$allowCreate[$sid]=$true}}
   if(([int64]$ace.FileSystemRights -band [int64]$controlMask) -ne 0){if($isDeny){$denyControl[$sid]=$true}else{$allowControl[$sid]=$true}}
  }
  $writers=@();$bc=$false;$bctl=$false
  foreach($sid in $allowCreate.Keys){if(-not $denyCreate.ContainsKey($sid)){$bc=$true;$writers+=$names[$sid]}}
  foreach($sid in $allowControl.Keys){if(-not $denyControl.ContainsKey($sid)){$bctl=$true;$writers+=$names[$sid]}}
  return [pscustomobject]@{path=$p;state='OBSERVED';exists=$true;directory=$isdir;owner=[string]$acl.Owner;trusted_owner=($trustedOwners -contains $ownerSid);owner_trust_known=(-not [string]::IsNullOrWhiteSpace($ownerSid));broad_create=$bc;broad_control=$bctl;writers=@($writers|Sort-Object -Unique);reason=''}
 }catch{
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  return [pscustomobject]@{path=$p;state=$st;exists=$true;directory=$false;owner='';trusted_owner=$false;owner_trust_known=$false;broad_create=$false;broad_control=$false;writers=@();reason=[string]$_.Exception.Message}
 }
}
foreach($i in $items){
 $id=[string]$i.candidate_id
 $inputPath=[string]$i.path
 $r=Inspect-Path $inputPath
 if($null -eq $r){
  [pscustomobject]@{kind='temporary_directory';candidate_id=$id;path=$inputPath;state='UNAVAILABLE';exists=$false;directory=$false;owner='';trusted_owner=$false;owner_trust_known=$false;broad_create=$false;broad_control=$false;write_principals=@();parent_path='';parent_state='';parent_owner='';parent_trusted_owner=$false;parent_owner_trust_known=$false;parent_broad_create=$false;parent_broad_control=$false;reason='candidate path could not be inspected'} | ConvertTo-Json -Compress
  continue
 }
 $parent='';try{$parent=[System.IO.Directory]::GetParent($inputPath).FullName}catch{}
 $pr=if($parent){Inspect-Path $parent}else{$null}
 [pscustomobject]@{kind='temporary_directory';candidate_id=$id;path=$r.path;state=$r.state;exists=$r.exists;directory=$r.directory;owner=$r.owner;trusted_owner=$r.trusted_owner;owner_trust_known=$r.owner_trust_known;broad_create=$r.broad_create;broad_control=$r.broad_control;write_principals=@($r.writers);parent_path=$parent;parent_state=if($pr){$pr.state}else{''};parent_owner=if($pr){$pr.owner}else{''};parent_trusted_owner=if($pr){$pr.trusted_owner}else{$false};parent_owner_trust_known=if($pr){$pr.owner_trust_known}else{$false};parent_broad_create=if($pr){$pr.broad_create}else{$false};parent_broad_control=if($pr){$pr.broad_control}else{$false};reason=$r.reason} | ConvertTo-Json -Compress
}`

func collectPlatformTempDirectories(ctx context.Context, candidates []tempDirectoryCandidate, capability PermissionCapability) ([]TempDirectoryRecord, SourceStatus, []string) {
	const source = "Windows PowerShell Get-Acl temporary-directory and parent DACL metadata"
	if len(candidates) == 0 {
		return nil, SourceStatus{ID: "temporary-directory-security", State: evidence.StateObserved, Source: source, ItemCount: 0}, nil
	}
	ps, err := windowsFilesystemPowerShellPath()
	if err != nil {
		return nil, SourceStatus{ID: "temporary-directory-security", State: evidence.StateUnavailable, Source: source, Reason: "PowerShell not found"}, []string{"temporary-directory DACL inventory unavailable: PowerShell not found"}
	}
	wire := make([]windowsCandidateEnvelopeItem, 0, len(candidates))
	byID := make(map[string]tempDirectoryCandidate, len(candidates))
	for _, c := range candidates {
		id := stableTempDirectoryID(c.Path)
		wire = append(wire, windowsCandidateEnvelopeItem{CandidateID: id, Path: c.Path})
		byID[id] = c
	}
	rawItems, marshalErr := marshalWindowsCandidateEnvelope(wire)
	if marshalErr != nil {
		reason := "temporary-directory candidate input contract: " + marshalErr.Error()
		return nil, SourceStatus{ID: "temporary-directory-security", State: evidence.StateUnavailable, Source: source, Reason: reason}, []string{"temporary-directory DACL inventory unavailable: " + reason}
	}
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsTempSecurityScript)
	cmd.Env = append(os.Environ(), "CHIMERA_TEMP_PATHS_JSON="+string(rawItems))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	out := []TempDirectoryRecord{}
	unresolved := 0
	malformed := 0
	providerFaults := []string{}
	seen := make(map[string]struct{}, len(byID))
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var w windowsTempWire
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			malformed++
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(w.Kind))
		if kind == "provider_error" {
			providerFaults = append(providerFaults, fallback(strings.TrimSpace(w.Reason), "temporary-directory provider input contract failed"))
			continue
		}
		if kind != "" && kind != "temporary_directory" {
			malformed++
			continue
		}
		candidateID := strings.TrimSpace(w.CandidateID)
		c, correlated := byID[candidateID]
		if !correlated {
			malformed++
			continue
		}
		if _, duplicate := seen[candidateID]; duplicate {
			malformed++
			continue
		}
		providerPath := strings.TrimSpace(w.Path)
		if providerPath == "" || platformPathKey(providerPath) != platformPathKey(c.Path) {
			malformed++
			continue
		}
		seen[candidateID] = struct{}{}
		p := filepath.Clean(c.Path)
		st := evidence.State(strings.ToUpper(strings.TrimSpace(w.State)))
		if !validWindowsCandidateEvidenceState(st) {
			st = evidence.StateDegraded
			w.Reason = appendTempReason(w.Reason, "provider record contained an invalid state")
		}
		pst := evidence.State(strings.ToUpper(strings.TrimSpace(w.ParentState)))
		if pst != "" && !validWindowsCandidateEvidenceState(pst) {
			pst = evidence.StateDegraded
			w.Reason = appendTempReason(w.Reason, "parent provider record contained an invalid state")
		}
		r := TempDirectoryRecord{
			ID: stableTempDirectoryID(p), Path: p, Scope: c.Scope, Shared: c.Shared, State: st, Exists: w.Exists, Directory: w.Directory,
			OwnerID: strings.TrimSpace(w.Owner), PermissionModel: capability.Model, BroadCreate: w.BroadCreate, BroadControl: w.BroadControl,
			BroadlyWritable: w.BroadCreate || w.BroadControl, TrustedOwner: w.TrustedOwner, TrustedOwnerKnown: w.OwnerTrustKnown, UnsafeOwnership: c.Shared && w.Exists && w.OwnerTrustKnown && !w.TrustedOwner,
			UnsafePermissions: w.BroadControl || (!c.Shared && w.BroadCreate), ParentPath: strings.TrimSpace(w.ParentPath), ParentState: pst,
			ParentOwnerID: strings.TrimSpace(w.ParentOwner), ParentBroadlyWritable: w.ParentBroadCreate || w.ParentBroadControl,
			ParentTrustedOwner: w.ParentTrustedOwner, ParentTrustKnown: w.ParentOwnerTrustKnown,
			ParentUnsafe:    w.ParentBroadControl || (!c.Shared && w.ParentBroadCreate) || (c.Shared && w.ParentPath != "" && w.ParentOwnerTrustKnown && !w.ParentTrustedOwner),
			WritePrincipals: append([]string(nil), w.WritePrincipals...), DiscoverySources: append([]string(nil), c.Sources...),
			CollectionSource: source, Confidence: evidence.ConfidenceHigh, Reason: strings.TrimSpace(w.Reason),
		}
		if r.State == evidence.StateObserved && r.Exists && !r.Directory {
			r.UnsafePermissions = true
			r.Reason = appendTempReason(r.Reason, "temporary-area candidate is not a directory")
		}
		out = append(out, r)
		if r.State != evidence.StateObserved || (r.ParentState != "" && r.ParentState != evidence.StateObserved) || (r.Shared && !r.TrustedOwnerKnown) || (r.Shared && r.ParentPath != "" && !r.ParentTrustKnown) {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		malformed++
	}

	missing := len(byID) - len(seen)
	state := evidence.StateObserved
	reasons := []string{}
	limitations := []string{}
	if unresolved > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("security metadata unresolved for %d temporary-directory boundary record(s)", unresolved))
	}
	if malformed > 0 {
		state = evidence.StateDegraded
		reasons = append(reasons, fmt.Sprintf("quarantined %d unmatched, duplicate, or malformed temporary-directory provider record(s)", malformed))
		limitations = append(limitations, fmt.Sprintf("temporary-directory DACL inventory degraded: quarantined %d unmatched, duplicate, or malformed provider record(s)", malformed))
	}
	if missing > 0 {
		if len(out) == 0 {
			state = evidence.StateUnavailable
		} else {
			state = evidence.StateDegraded
		}
		contractReason := fmt.Sprintf("provider contract violation: submitted=%d correlated=%d missing=%d", len(byID), len(seen), missing)
		reasons = append(reasons, contractReason)
		limitations = append(limitations, "temporary-directory DACL inventory degraded: "+contractReason)
	}
	for _, fault := range providerFaults {
		if len(out) == 0 {
			state = evidence.StateUnavailable
		} else {
			state = evidence.StateDegraded
		}
		reasons = append(reasons, "provider input contract failed: "+fault)
		limitations = append(limitations, "temporary-directory DACL inventory unavailable: "+fault)
	}
	if runErr != nil {
		reason := windowsFilesystemProviderReasonWithDetail(ctx, "windows-temporary-directory-dacl-inventory", runErr, stderr.String())
		if len(out) == 0 {
			state = stateForWindowsFilesystemErrWithDetail(ctx, runErr, stderr.String())
		} else {
			state = evidence.StateDegraded
		}
		reasons = append(reasons, reason)
		limitations = append(limitations, "temporary-directory DACL inventory degraded: "+reason)
	}
	if len(out) == 0 && len(byID) > 0 && len(reasons) == 0 {
		state = evidence.StateUnavailable
		reasons = append(reasons, "no temporary-directory records were returned")
		limitations = append(limitations, "temporary-directory DACL inventory unavailable: provider returned no candidate records")
	}
	reason := strings.Join(uniqueSorted(reasons), "; ")
	return out, SourceStatus{ID: "temporary-directory-security", State: state, Source: source, ItemCount: len(out), Reason: reason}, uniqueSorted(limitations)
}
