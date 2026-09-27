//go:build windows

package persistence

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

type windowsPersistencePathWire struct {
	Path                    string   `json:"path"`
	State                   string   `json:"state"`
	Exists                  bool     `json:"exists"`
	Directory               bool     `json:"directory"`
	Owner                   string   `json:"owner"`
	OwnerSID                string   `json:"owner_sid"`
	OwnerTrust              string   `json:"owner_trust"`
	DACLState               string   `json:"dacl_state"`
	BroadlyWritable         bool     `json:"broadly_writable"`
	UntrustedWritable       bool     `json:"untrusted_writable"`
	InheritedUntrustedWrite bool     `json:"inherited_untrusted_write"`
	WritePrincipals         []string `json:"write_principals"`
	Reason                  string   `json:"reason"`
}

const windowsPersistencePathScript = `$ErrorActionPreference='Stop'
$paths=@();try{$paths=@(ConvertFrom-Json $env:CHIMERA_PERSISTENCE_PATHS_JSON)}catch{}
$lowTrustSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-7')
$trustedOwnerSids=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$mask=` + windowsacl.PowerShellMutatingMaskExpression + `
foreach($p in $paths){
 if([string]::IsNullOrWhiteSpace([string]$p)){continue}
 if(-not (Test-Path -LiteralPath $p)){[pscustomobject]@{path=[string]$p;state='OBSERVED';exists=$false;directory=$false;owner='';owner_sid='';owner_trust='UNKNOWN';dacl_state='NOT_APPLICABLE';broadly_writable=$false;untrusted_writable=$false;inherited_untrusted_write=$false;write_principals=@();reason='path does not exist'}|ConvertTo-Json -Compress;continue}
 try{
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop;$allow=@{};$deny=@{};$inheritedAllow=@{}
  $ownerSid='';try{$ownerSid=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value}catch{}
  $ownerTrust=if([string]::IsNullOrWhiteSpace($ownerSid)){'UNKNOWN'}elseif($trustedOwnerSids -contains $ownerSid){'TRUSTED'}else{'UNTRUSTED'}
  foreach($ace in @($acl.Access)){$sid='';try{$sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{};if($lowTrustSids -notcontains $sid){continue};if(([int64]$ace.FileSystemRights -band [int64]$mask) -eq 0){continue};if([string]$ace.AccessControlType -eq 'Deny'){$deny[$sid]=$true}else{$allow[$sid]=$true;if([bool]$ace.IsInherited){$inheritedAllow[$sid]=$true}}}
  $writers=@();$inherited=$false;foreach($sid in $allow.Keys){if(-not $deny.ContainsKey($sid)){$writers+=$sid;if($inheritedAllow.ContainsKey($sid)){$inherited=$true}}}
  $writers=@($writers|Sort-Object -Unique);$weak=($writers.Count -gt 0);$why=if($weak){'lower-trust DACL write grant: '+($writers -join ', ')}else{''}
  [pscustomobject]@{path=[string]$p;state='OBSERVED';exists=$true;directory=(Test-Path -LiteralPath $p -PathType Container);owner=[string]$acl.Owner;owner_sid=$ownerSid;owner_trust=$ownerTrust;dacl_state='OBSERVED';broadly_writable=$weak;untrusted_writable=$weak;inherited_untrusted_write=$inherited;write_principals=$writers;reason=$why}|ConvertTo-Json -Compress
 }catch{$st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'};[pscustomobject]@{path=[string]$p;state=$st;exists=$true;directory=$false;owner='';owner_sid='';owner_trust='UNKNOWN';dacl_state=$st;broadly_writable=$false;untrusted_writable=$false;inherited_untrusted_write=$false;write_principals=@();reason=[string]$_.Exception.Message}|ConvertTo-Json -Compress}
}`

func assessPlatformPathIntegrity(ctx context.Context, inv *Inventory) {
	paths := map[string]string{}
	for i := range inv.Entries {
		e := &inv.Entries[i]
		privileged, basis := privilegedContext(e.PrivilegeContext)
		if e.PathIntegrity.PrivilegeBasis == "" || e.PathIntegrity.PrivilegeBasis == "UNKNOWN" {
			e.PathIntegrity.Privileged, e.PathIntegrity.PrivilegeBasis = privileged, basis
		}
		addWindowsCandidate(paths, e.ExecutablePath, true)
		addWindowsCandidate(paths, e.ReferencedScriptPath, false)
		addWindowsCandidate(paths, e.DefinitionPath, false)
	}
	postures, state, reason := collectWindowsPersistencePaths(ctx, paths)
	for i := range inv.Entries {
		fillWindowsPathIntegrity(&inv.Entries[i], postures)
	}
	addSource(inv, "persistence-path-integrity", state, "provider-native metadata plus Windows PowerShell Get-Acl persistence path assessment", len(postures), reason)
}

func addWindowsCandidate(paths map[string]string, path string, executable bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if executable && !filepath.IsAbs(path) {
		if resolved, err := exec.LookPath(path); err == nil {
			path = resolved
		} else {
			return
		}
	}
	if !filepath.IsAbs(path) {
		return
	}
	clean := filepath.Clean(path)
	paths[strings.ToLower(clean)] = clean
	dir := filepath.Dir(clean)
	if dir != "." && dir != clean {
		paths[strings.ToLower(dir)] = dir
	}
}

func collectWindowsPersistencePaths(ctx context.Context, candidates map[string]string) (map[string]PathPosture, evidence.State, string) {
	out := map[string]PathPosture{}
	if len(candidates) == 0 {
		return out, evidence.StateNotApplicable, "no absolute persistence paths were available for DACL assessment"
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		ps, err = exec.LookPath("pwsh.exe")
	}
	if err != nil {
		return out, evidence.StateUnavailable, "PowerShell was not available for local DACL assessment"
	}
	vals := make([]string, 0, len(candidates))
	for _, p := range candidates {
		vals = append(vals, p)
	}
	rawVals, _ := json.Marshal(vals)
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsPersistencePathScript)
	cmd.Env = append(os.Environ(), "CHIMERA_PERSISTENCE_PATHS_JSON="+string(rawVals))
	raw, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return out, evidence.StateUnavailable, ctx.Err().Error()
		}
		return out, evidence.StateUnavailable, err.Error()
	}
	unresolved := 0
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var w windowsPersistencePathWire
		if json.Unmarshal([]byte(strings.TrimSpace(scanner.Text())), &w) != nil {
			continue
		}
		p := filepath.Clean(strings.TrimSpace(w.Path))
		st := persistenceState(w.State)
		rec := normalizePathPosture(PathPosture{
			Path: p, State: st, Exists: w.Exists, Directory: w.Directory,
			OwnerID: strings.TrimSpace(w.OwnerSID), OwnerPrincipal: strings.TrimSpace(w.Owner), OwnerTrust: strings.TrimSpace(w.OwnerTrust),
			PermissionModel: "Windows NTFS DACL lower-trust write grants", DACLState: strings.TrimSpace(w.DACLState),
			BroadlyWritable: w.BroadlyWritable, UntrustedWrite: w.UntrustedWritable, InheritedUntrustedWrite: w.InheritedUntrustedWrite,
			WritePrincipals: append([]string(nil), w.WritePrincipals...), CollectionSource: "Windows PowerShell Get-Acl persistence path metadata",
			Confidence: evidence.ConfidenceHigh, Reason: strings.TrimSpace(w.Reason),
		})
		out[strings.ToLower(p)] = rec
		if st != evidence.StateObserved {
			unresolved++
		}
	}
	if err := scanner.Err(); err != nil {
		return out, evidence.StateDegraded, err.Error()
	}
	if unresolved > 0 {
		return out, evidence.StateDegraded, fmt.Sprintf("DACL metadata unresolved for %d persistence path(s)", unresolved)
	}
	return out, evidence.StateObserved, ""
}

func fillWindowsPathIntegrity(e *Entry, byPath map[string]PathPosture) {
	p := e.PathIntegrity
	p.Executable = fillWindowsPosture(p.Executable, e.ExecutablePath, true, byPath)
	p.ExecutableDirectory = fillWindowsDirectory(p.ExecutableDirectory, p.Executable.Path, byPath)
	p.ReferencedScript = fillWindowsPosture(p.ReferencedScript, e.ReferencedScriptPath, false, byPath)
	p.ReferencedScriptDirectory = fillWindowsDirectory(p.ReferencedScriptDirectory, p.ReferencedScript.Path, byPath)
	p.Definition = fillWindowsPosture(p.Definition, e.DefinitionPath, false, byPath)
	p.DefinitionDirectory = fillWindowsDirectory(p.DefinitionDirectory, p.Definition.Path, byPath)
	e.PathIntegrity = normalizePathIntegrity(p)
}
func fillWindowsPosture(existing PathPosture, path string, executable bool, byPath map[string]PathPosture) PathPosture {
	if existing.State == evidence.StateObserved {
		return existing
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return pathNotApplicable("Windows persistence path metadata")
	}
	if executable && !filepath.IsAbs(path) {
		if r, err := exec.LookPath(path); err == nil {
			path = r
		} else {
			return PathPosture{Path: path, State: evidence.StateUnavailable, CollectionSource: "Windows executable resolution", Confidence: evidence.ConfidenceMedium, Reason: "persistence executable could not be resolved through local PATH"}
		}
	}
	if !filepath.IsAbs(path) {
		return PathPosture{Path: path, State: evidence.StateUnavailable, CollectionSource: "Windows persistence path metadata", Confidence: evidence.ConfidenceMedium, Reason: "relative persistence path cannot be safely resolved"}
	}
	if r, ok := byPath[strings.ToLower(filepath.Clean(path))]; ok {
		return r
	}
	return PathPosture{Path: path, State: evidence.StateUnavailable, CollectionSource: "Windows PowerShell Get-Acl persistence path metadata", Confidence: evidence.ConfidenceMedium, Reason: "DACL record unavailable"}
}
func fillWindowsDirectory(existing PathPosture, path string, byPath map[string]PathPosture) PathPosture {
	if existing.State == evidence.StateObserved {
		return existing
	}
	if path == "" || !filepath.IsAbs(path) {
		return pathNotApplicable("Windows persistence path metadata")
	}
	d := filepath.Dir(path)
	if r, ok := byPath[strings.ToLower(filepath.Clean(d))]; ok {
		return r
	}
	return PathPosture{Path: d, State: evidence.StateUnavailable, Directory: true, CollectionSource: "Windows PowerShell Get-Acl persistence path metadata", Confidence: evidence.ConfidenceMedium, Reason: "directory DACL record unavailable"}
}
