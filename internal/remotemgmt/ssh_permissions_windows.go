//go:build windows

package remotemgmt

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type sshWindowsACL struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	Owner  string `json:"owner"`
	Broad  bool   `json:"broad"`
	Reason string `json:"reason"`
}

func sshFilePosture(ctx context.Context, path string) SSHFilePosture {
	p := SSHFilePosture{ID: sshFileID(path), Path: path, State: evidence.StateUnavailable, Source: "Windows NTFS ACL metadata via Get-Acl", PermissionBasis: "Windows DACL broad-principal write grants", Confidence: evidence.ConfidenceHigh}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		p.Reason = "powershell.exe unavailable for read-only ACL inspection"
		p.Confidence = evidence.ConfidenceLow
		return p
	}
	script := `$p=$args[0]; try { $i=Get-Item -LiteralPath $p -ErrorAction Stop; $a=Get-Acl -LiteralPath $p -ErrorAction Stop; $b=$false; foreach($x in $a.Access){ $id=[string]$x.IdentityReference; $r=[string]$x.FileSystemRights; if($x.AccessControlType -eq 'Allow' -and ($id -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users') -and ($r -match '(?i)Write|Modify|FullControl|TakeOwnership|ChangePermissions')){$b=$true} }; [pscustomobject]@{path=$p;state='OBSERVED';owner=[string]$a.Owner;broad=$b;reason=''}|ConvertTo-Json -Compress } catch { [pscustomobject]@{path=$p;state='UNAVAILABLE';owner='';broad=$false;reason=[string]$_.Exception.Message}|ConvertTo-Json -Compress }`
	b, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script, path).CombinedOutput()
	if err != nil {
		p.Reason = "ACL provider failed"
		p.Confidence = evidence.ConfidenceLow
		return p
	}
	var row sshWindowsACL
	if err := json.Unmarshal(b, &row); err != nil {
		p.Reason = "ACL provider returned unparseable metadata"
		p.Confidence = evidence.ConfidenceLow
		return p
	}
	if strings.EqualFold(row.State, "OBSERVED") {
		p.State = evidence.StateObserved
		p.Exists = true
		p.Owner = row.Owner
		p.BroadlyWritable = row.Broad
		o := strings.ToLower(row.Owner)
		p.TrustedOwner = strings.Contains(o, "system") || strings.Contains(o, "administrators")
		return p
	}
	p.Reason = strings.TrimSpace(row.Reason)
	if p.Reason == "" {
		p.Reason = "ACL metadata unavailable"
	}
	p.Confidence = evidence.ConfidenceLow
	return p
}
