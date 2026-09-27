//go:build windows

package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsSSHACLMetadata struct {
	Owner       string `json:"owner"`
	OwnerMatch  string `json:"owner_match"`
	BroadRead   bool   `json:"broad_read"`
	BroadWrite  bool   `json:"broad_write"`
	WeakEntries int    `json:"weak_entries"`
}

func collectSSHKeyPosture(ctx context.Context, inv *Inventory) {
	p := SSHKeyPosture{Source: "Windows filesystem/ACL SSH metadata (no key contents read)"}
	ps, psErr := exec.LookPath("powershell.exe")
	if psErr != nil {
		ps, psErr = exec.LookPath("powershell")
	}
	problems := []string{}
	examined := 0
	for _, a := range inv.Accounts {
		if examined >= maxSSHKeyAccounts || len(p.Records) >= maxSSHKeyRecords {
			problems = append(problems, fmt.Sprintf("SSH metadata account/record limit reached (%d accounts, %d records)", maxSSHKeyAccounts, maxSSHKeyRecords))
			break
		}
		if err := ctx.Err(); err != nil {
			problems = append(problems, "SSH metadata collection deadline reached: "+err.Error())
			break
		}
		home := strings.TrimSpace(a.Home)
		if home == "" {
			systemDrive := strings.TrimSpace(os.Getenv("SystemDrive"))
			if systemDrive == "" {
				systemDrive = `C:`
			}
			home = filepath.Join(systemDrive+`\`, "Users", a.Name)
		}
		sshDir := filepath.Join(home, ".ssh")
		info, err := os.Lstat(sshDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			examined++
			p.Records = append(p.Records, windowsUnavailableSSHRecord(a, sshDir, "SSH_DIRECTORY", err))
			problems = append(problems, a.Principal+" .ssh metadata: "+err.Error())
			continue
		}
		examined++
		if rec, err := windowsSSHRecord(ctx, ps, psErr, a, home, "HOME_DIRECTORY", nil); err == nil {
			p.Records = append(p.Records, rec)
		} else {
			problems = append(problems, home+": "+err.Error())
		}
		dirRecord, err := windowsSSHRecord(ctx, ps, psErr, a, sshDir, "SSH_DIRECTORY", info)
		if err != nil {
			problems = append(problems, sshDir+": "+err.Error())
		}
		p.Records = append(p.Records, dirRecord)
		if !info.IsDir() {
			problems = append(problems, sshDir+" exists but is not a directory")
			continue
		}
		entries, err := os.ReadDir(sshDir)
		if err != nil {
			problems = append(problems, a.Principal+" .ssh listing: "+err.Error())
			continue
		}
		for _, entry := range entries {
			kind := ""
			if isAuthorizedKeysName(entry.Name()) {
				kind = "AUTHORIZED_KEYS"
			} else if isSSHPrivateKeyCandidateName(entry.Name()) {
				kind = "PRIVATE_KEY_CANDIDATE"
			}
			if kind == "" {
				continue
			}
			path := filepath.Join(sshDir, entry.Name())
			rec, err := windowsSSHRecord(ctx, ps, psErr, a, path, kind, nil)
			if err != nil {
				problems = append(problems, path+": "+err.Error())
			}
			p.Records = append(p.Records, rec)
			if len(p.Records) >= maxSSHKeyRecords {
				break
			}
		}
	}
	if examined == 0 {
		p.State = evidence.StateObserved
		if len(inv.Accounts) == 0 {
			p.State = evidence.StateUnavailable
			p.Reason = "no local accounts were available to scope SSH key posture"
		}
	} else if len(problems) > 0 {
		p.State = evidence.StateDegraded
		p.Reason = strings.Join(uniqueSorted(problems), "; ")
		inv.Degraded = append(inv.Degraded, "ssh-key-posture: "+p.Reason)
	} else {
		p.State = evidence.StateObserved
	}
	inv.SSHKeyPosture = p
}

func windowsSSHRecord(ctx context.Context, ps string, psErr error, a Account, path, kind string, info os.FileInfo) (SSHKeyPathRecord, error) {
	if info == nil {
		var err error
		info, err = os.Lstat(path)
		if err != nil {
			return windowsUnavailableSSHRecord(a, path, kind, err), err
		}
	}
	rec := SSHKeyPathRecord{
		ID: stableSSHKeyID(a.ID, a.Principal, strings.ToLower(path), kind), AccountID: a.ID, Principal: a.Principal, Privileged: a.Privileged,
		Path: path, Kind: kind, State: evidence.StateObserved, Directory: info.IsDir(), Symlink: info.Mode()&os.ModeSymlink != 0,
		Mode: info.Mode().String(), OwnerMatch: "UNKNOWN", Source: "Windows Get-Acl metadata; no SSH key contents read", Confidence: evidence.ConfidenceHigh,
	}
	if psErr != nil {
		rec.State = evidence.StateUnavailable
		rec.Confidence = evidence.ConfidenceLow
		rec.Reason = "PowerShell is unavailable for Windows ACL metadata"
		return rec, psErr
	}
	raw, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", windowsSSHAclScript(), path, a.SID).Output()
	if err != nil {
		rec.State = evidence.StateUnavailable
		rec.Confidence = evidence.ConfidenceLow
		if ctx.Err() != nil {
			rec.Reason = ctx.Err().Error()
		} else {
			rec.Reason = err.Error()
		}
		return rec, err
	}
	var meta windowsSSHACLMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		rec.State = evidence.StateDegraded
		rec.Confidence = evidence.ConfidenceLow
		rec.Reason = "invalid Windows ACL metadata: " + err.Error()
		return rec, err
	}
	rec.Owner = strings.TrimSpace(meta.Owner)
	rec.OwnerMatch = upperDefault(meta.OwnerMatch, "UNKNOWN")
	rec.BroadRead = meta.BroadRead
	rec.BroadWrite = meta.BroadWrite
	basis := []string{}
	switch kind {
	case "HOME_DIRECTORY", "SSH_DIRECTORY", "AUTHORIZED_KEYS":
		if meta.BroadWrite {
			basis = append(basis, "broad Windows ACL grants write/modify access")
		}
	case "PRIVATE_KEY_CANDIDATE":
		if meta.BroadRead {
			basis = append(basis, "broad Windows ACL grants read access to private-key candidate")
		}
		if meta.BroadWrite {
			basis = append(basis, "broad Windows ACL grants write/modify access to private-key candidate")
		}
	}
	if rec.OwnerMatch == "MISMATCH" {
		basis = append(basis, "path owner is neither the account nor a trusted Windows system administrator principal")
	}
	if rec.Symlink && kind != "HOME_DIRECTORY" {
		basis = append(basis, "security-sensitive SSH path is a symbolic link/reparse target")
	}
	rec.InsecureBasis = uniqueSorted(basis)
	rec.Insecure = len(rec.InsecureBasis) > 0
	return rec, nil
}

func windowsUnavailableSSHRecord(a Account, path, kind string, err error) SSHKeyPathRecord {
	reason := "SSH path metadata unavailable"
	if err != nil {
		reason = err.Error()
	}
	state := evidence.StateUnavailable
	if errors.Is(err, os.ErrPermission) {
		state = evidence.StateDenied
	}
	return SSHKeyPathRecord{ID: stableSSHKeyID(a.ID, a.Principal, strings.ToLower(path), kind), AccountID: a.ID, Principal: a.Principal, Privileged: a.Privileged, Path: path, Kind: kind, State: state, OwnerMatch: "UNKNOWN", Source: "Windows filesystem/ACL metadata; no SSH key contents read", Confidence: evidence.ConfidenceLow, Reason: reason}
}

func windowsSSHAclScript() string {
	return `$p=$args[0];$targetSid=$args[1];$ErrorActionPreference='Stop';$acl=Get-Acl -LiteralPath $p;$owner=[string]$acl.Owner;$ownerMatch='UNKNOWN';try{$sid=(New-Object System.Security.Principal.NTAccount($owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value;if($sid -eq $targetSid){$ownerMatch='MATCH'}elseif($sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-32-544'){$ownerMatch='TRUSTED_SYSTEM'}else{$ownerMatch='MISMATCH'}}catch{};$broadRead=$false;$broadWrite=$false;$weak=0;foreach($r in $acl.Access){if($r.AccessControlType -ne 'Allow'){continue};$sid='';try{$sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{};if($sid -ne 'S-1-1-0' -and $sid -ne 'S-1-5-11' -and $sid -ne 'S-1-5-32-545'){continue};$rights=[string]$r.FileSystemRights;if($rights -match 'Read|Modify|FullControl'){$broadRead=$true};if($rights -match 'Write|Modify|FullControl|CreateFiles|CreateDirectories|Delete|ChangePermissions|TakeOwnership'){$broadWrite=$true};$weak++};[pscustomobject]@{owner=$owner;owner_match=$ownerMatch;broad_read=$broadRead;broad_write=$broadWrite;weak_entries=$weak}|ConvertTo-Json -Compress`
}
