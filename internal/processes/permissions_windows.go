//go:build windows

package processes

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsACLRule struct {
	SID      string `json:"sid"`
	Identity string `json:"identity"`
	Rights   string `json:"rights"`
	Type     string `json:"type"`
}

type windowsACLNode struct {
	Path     string           `json:"path"`
	Kind     string           `json:"kind"`
	State    string           `json:"state"`
	OwnerSID string           `json:"owner_sid"`
	Owner    string           `json:"owner"`
	Rules    []windowsACLRule `json:"rules"`
	Reason   string           `json:"reason"`
}

func collectPlatformPathPermissions(ctx context.Context, items []Process, platform string) []PathPermissionContext {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		return unknownPermissionContexts(items, platform, "PowerShell executable was not found for Windows ACL inspection")
	}

	script := `$ErrorActionPreference='SilentlyContinue'
$seen=@{}
$nodes=@()
function SidOf([object]$id){ try { return $id.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return '' } }
function AddNode([string]$p,[string]$kind){
 if([string]::IsNullOrWhiteSpace($p)){ return }
 $k=$p.ToLowerInvariant(); if($seen.ContainsKey($k)){ return }; $seen[$k]=$true
 try {
  $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
  $ownerSid=''; try { $ownerSid=SidOf $acl.Owner } catch {}
  if([string]::IsNullOrWhiteSpace($ownerSid)){ try { $ownerSid=([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {} }
  $rules=@(); foreach($r in $acl.Access){
   $sid=''; try { $sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
   $rules += [pscustomobject]@{sid=$sid;identity=[string]$r.IdentityReference;rights=[string]$r.FileSystemRights;type=[string]$r.AccessControlType}
  }
  $nodes += [pscustomobject]@{path=$item.FullName;kind=$kind;state='OBSERVED';owner_sid=$ownerSid;owner=[string]$acl.Owner;rules=$rules;reason=''}
 } catch {
  $nodes += [pscustomobject]@{path=$p;kind=$kind;state='UNKNOWN';owner_sid='';owner='';rules=@();reason=$_.Exception.Message}
 }
}
Get-CimInstance Win32_Process | ForEach-Object {
 $p=[string]$_.ExecutablePath; if([string]::IsNullOrWhiteSpace($p)){ return }
 AddNode $p 'EXECUTABLE'
 try { $d=[System.IO.Directory]::GetParent($p); $i=0; while($null -ne $d -and $i -lt 16){ AddNode $d.FullName 'DIRECTORY'; $d=$d.Parent; $i++ } } catch {}
}
$nodes | ConvertTo-Json -Compress -Depth 7`
	cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	raw, err := cmd.Output()
	if err != nil {
		return unknownPermissionContexts(items, platform, "Windows ACL collection failed: "+err.Error())
	}
	nodes := []windowsACLNode{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &nodes); err != nil {
			var one windowsACLNode
			if err2 := json.Unmarshal(raw, &one); err2 != nil {
				return unknownPermissionContexts(items, platform, "Windows ACL output decode failed: "+err.Error())
			}
			nodes = []windowsACLNode{one}
		}
	}
	index := map[string]windowsACLNode{}
	for _, n := range nodes {
		index[windowsPathKey(n.Path)] = n
	}

	out := make([]PathPermissionContext, 0, len(items))
	for _, p := range items {
		path := strings.TrimSpace(p.ExecutablePath)
		if path == "" {
			out = append(out, unknownPermissionContext(p, platform, "executable path unavailable"))
			continue
		}
		c := PathPermissionContext{ProcessID: p.ID, Platform: platform, PID: p.PID, Path: path, Source: "Windows NTFS ACL metadata via Get-Acl", Confidence: evidence.ConfidenceHigh}
		if n, ok := index[windowsPathKey(path)]; ok {
			c.Executable = windowsPermissionNode(n, p)
		} else {
			c.Executable = PermissionNode{Path: path, Kind: "EXECUTABLE", State: "UNKNOWN", ACLSource: "Windows NTFS ACL via Get-Acl", Reason: "ACL record not returned for executable"}
			c.Confidence = evidence.ConfidenceMedium
		}
		dir := filepath.Dir(path)
		seen := map[string]struct{}{}
		for i := 0; i < maxPermissionAncestors && dir != ""; i++ {
			key := windowsPathKey(dir)
			if _, ok := seen[key]; ok {
				break
			}
			seen[key] = struct{}{}
			if n, ok := index[key]; ok {
				c.Parents = append(c.Parents, windowsPermissionNode(n, p))
			} else {
				c.Parents = append(c.Parents, PermissionNode{Path: dir, Kind: "DIRECTORY", State: "UNKNOWN", ACLSource: "Windows NTFS ACL via Get-Acl", Reason: "ACL record not returned for parent directory"})
				c.Confidence = evidence.ConfidenceMedium
			}
			parent := filepath.Dir(dir)
			if strings.EqualFold(parent, dir) {
				break
			}
			dir = parent
		}
		if c.Executable.UntrustedWrite {
			c.Reasons = append(c.Reasons, "executable ACL grants write/modify control outside the trusted privileged boundary")
		}
		for _, n := range c.Parents {
			if n.UntrustedWrite {
				c.Reasons = append(c.Reasons, "parent directory ACL permits untrusted replacement/write access: "+n.Path)
			}
		}
		c = finalizePermissionContext(c)
		out = append(out, c)
	}
	return out
}

func windowsPermissionNode(raw windowsACLNode, p Process) PermissionNode {
	n := PermissionNode{Path: raw.Path, Kind: raw.Kind, State: strings.ToUpper(fallback(raw.State, "UNKNOWN")), OwnerID: raw.OwnerSID, Owner: raw.Owner, ACLSource: "Windows NTFS ACL via Get-Acl", Reason: raw.Reason}
	if n.State != "OBSERVED" {
		return n
	}
	for _, r := range raw.Rules {
		if !strings.EqualFold(strings.TrimSpace(r.Type), "Allow") || !windowsWriteRights(r.Rights) {
			continue
		}
		principal := fallback(strings.TrimSpace(r.SID), strings.TrimSpace(r.Identity))
		n.WritePrincipals = append(n.WritePrincipals, principal+":"+strings.TrimSpace(r.Rights))
		if windowsBroadSID(r.SID) {
			n.BroadWrite = true
		}
		if !windowsTrustedWriteSID(r.SID) {
			n.UntrustedWrite = true
		}
	}
	if p.Principal.Elevated && n.OwnerID != "" && !windowsTrustedWriteSID(n.OwnerID) {
		// The owner can normally alter a DACL even if no explicit write ACE is
		// present, making a non-trusted owner material to a privileged path.
		n.UntrustedWrite = true
		n.Reason = appendReason(n.Reason, "privileged path is owned by a principal outside SYSTEM/Administrators/TrustedInstaller")
	}
	return n
}

func windowsWriteRights(rights string) bool {
	r := strings.ToLower(rights)
	for _, token := range []string{"fullcontrol", "modify", "write", "writedata", "createfiles", "createdirectories", "appenddata", "delete", "deletechild", "changespermissions", "changepermissions", "takeownership"} {
		if strings.Contains(r, token) {
			return true
		}
	}
	return false
}

func windowsBroadSID(sid string) bool {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	switch sid {
	case "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4":
		return true
	}
	return false
}

func windowsTrustedWriteSID(sid string) bool {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if sid == "S-1-5-18" || sid == "S-1-5-32-544" {
		return true
	}
	// TrustedInstaller and service installer identities are service SIDs. We
	// only trust the canonical TrustedInstaller SID, not arbitrary service SIDs.
	return sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

func windowsPathKey(path string) string {
	return strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
}

func unknownPermissionContexts(items []Process, platform, reason string) []PathPermissionContext {
	out := make([]PathPermissionContext, 0, len(items))
	for _, p := range items {
		out = append(out, unknownPermissionContext(p, platform, reason))
	}
	return out
}
