//go:build windows

package filesystem

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsNFSShareJSON struct {
	Name                 string                     `json:"Name"`
	Path                 string                     `json:"Path"`
	AnonymousAccess      string                     `json:"AnonymousAccess"`
	UnmappedUserAccess   string                     `json:"UnmappedUserAccess"`
	Authentication       []string                   `json:"Authentication"`
	PermissionsAvailable bool                       `json:"PermissionsAvailable"`
	Permissions          []windowsNFSPermissionJSON `json:"Permissions"`
}

type windowsNFSPermissionJSON struct {
	ClientName      string `json:"ClientName"`
	ClientType      string `json:"ClientType"`
	Permission      string `json:"Permission"`
	AllowRootAccess string `json:"AllowRootAccess"`
}

type windowsNFSJSON struct {
	Available bool                  `json:"Available"`
	Shares    []windowsNFSShareJSON `json:"Shares"`
}

func collectPlatformNFSExports(ctx context.Context) ([]NetworkShareRecord, SourceStatus, []string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		reason := "PowerShell unavailable for Windows NFS share inventory"
		return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateUnsupported, Source: "PowerShell NFS module", Reason: reason}, nil
	}
	const script = `$shareCmd=Get-Command Get-NfsShare -ErrorAction SilentlyContinue; if (-not $shareCmd) { [pscustomobject]@{Available=$false;Shares=@()} | ConvertTo-Json -Depth 7 -Compress; exit 0 }; $permCmd=Get-Command Get-NfsSharePermission -ErrorAction SilentlyContinue; $rows=@(); foreach($s in @(Get-NfsShare -ErrorAction Stop)) { $perms=@(); $permsOK=$false; if ($permCmd) { try { $perms=@(Get-NfsSharePermission -Name $s.Name -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ClientName=[string]$_.ClientName;ClientType=[string]$_.ClientType;Permission=[string]$_.Permission;AllowRootAccess=[string]$_.AllowRootAccess} }); $permsOK=$true } catch { $permsOK=$false } }; $rows += [pscustomobject]@{Name=[string]$s.Name;Path=[string]$s.Path;AnonymousAccess=[string]$s.AnonymousAccess;UnmappedUserAccess=[string]$s.UnmappedUserAccess;Authentication=@($s.Authentication | ForEach-Object {[string]$_});PermissionsAvailable=$permsOK;Permissions=@($perms)} }; [pscustomobject]@{Available=$true;Shares=@($rows)} | ConvertTo-Json -Depth 7 -Compress`
	raw, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		reason := "Windows NFS share inventory failed: " + err.Error()
		return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateUnavailable, Source: "Get-NfsShare/Get-NfsSharePermission", Reason: reason}, []string{reason}
	}
	var payload windowsNFSJSON
	if err := json.Unmarshal(raw, &payload); err != nil {
		reason := "Windows NFS share JSON decode failed: " + err.Error()
		return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateDegraded, Source: "Get-NfsShare/Get-NfsSharePermission", Reason: reason}, []string{reason}
	}
	if !payload.Available {
		return nil, SourceStatus{ID: "nfs-exports", State: evidence.StateNotApplicable, Source: "PowerShell NFS module", ItemCount: 0, Reason: "Get-NfsShare is not installed; Windows Server for NFS is not exposed by the local provider"}, nil
	}
	out := make([]NetworkShareRecord, 0, len(payload.Shares))
	degraded := []string{}
	for _, sh := range payload.Shares {
		rec := windowsNFSShareRecord(sh)
		if !sh.PermissionsAvailable {
			degraded = append(degraded, "NFS share permission metadata unavailable for "+fallback(sh.Name, sh.Path))
		}
		out = append(out, rec)
		if len(out) >= maxNetworkShares {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return networkShareSortKey(out[i]) < networkShareSortKey(out[j]) })
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return out, SourceStatus{ID: "nfs-exports", State: state, Source: "Get-NfsShare/Get-NfsSharePermission", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func windowsNFSShareRecord(sh windowsNFSShareJSON) NetworkShareRecord {
	anonymous := windowsEnabled(sh.AnonymousAccess)
	unmapped := windowsEnabled(sh.UnmappedUserAccess)
	broad := false
	broadWrite := false
	anyWrite := false
	rootBroad := false
	for _, p := range sh.Permissions {
		isBroad := broadNFSAudience(p.ClientName)
		write := strings.Contains(strings.ToUpper(p.Permission), "WRITE")
		if write {
			anyWrite = true
		}
		if isBroad {
			broad = true
			if write {
				broadWrite = true
			}
			if strings.Contains(strings.ToUpper(p.AllowRootAccess), "ALLOW") {
				rootBroad = true
			}
		}
	}
	accessMode := MountAccessUnknown
	if sh.PermissionsAvailable {
		if anyWrite {
			accessMode = MountAccessReadWrite
		} else if len(sh.Permissions) > 0 {
			accessMode = MountAccessReadOnly
		}
	}
	security := []string{}
	for _, a := range sh.Authentication {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			security = append(security, "auth="+a)
		}
	}
	if anonymous {
		security = append(security, "anonymous-access")
	}
	if unmapped {
		security = append(security, "unmapped-user-access")
	}
	dangerous := []string{}
	if anonymous {
		dangerous = append(dangerous, "anonymous-access")
	}
	if unmapped {
		dangerous = append(dangerous, "unmapped-user-access")
	}
	if rootBroad {
		dangerous = append(dangerous, "broad-root-access")
	}
	if windowsAuthSysOnly(sh.Authentication) {
		dangerous = append(dangerous, "auth-sys-without-kerberos")
	}
	reason := ""
	if !sh.PermissionsAvailable {
		reason = "Get-NfsSharePermission did not return share-level client permissions"
	}
	rec := NetworkShareRecord{
		Direction:        NetworkShareDirectionExported,
		Protocol:         NetworkShareProtocolNFS,
		Name:             strings.TrimSpace(sh.Name),
		LocalPath:        strings.TrimSpace(sh.Path),
		SecurityOptions:  uniqueSorted(security),
		AccessMode:       accessMode,
		ReadOnly:         accessMode == MountAccessReadOnly,
		Writable:         accessMode == MountAccessReadWrite,
		AccessKnown:      sh.PermissionsAvailable,
		AnonymousAllowed: anonymous || unmapped,
		BroadAccess:      broad,
		BroadWrite:       broadWrite,
		DangerousOptions: uniqueSorted(dangerous),
		State:            evidence.StateObserved,
		CollectionSource: "Get-NfsShare/Get-NfsSharePermission",
		Confidence:       evidence.ConfidenceHigh,
		Reason:           reason,
	}
	rec.ID = stableNetworkShareID(rec)
	return rec
}

func windowsEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "enabled", "true", "yes", "1", "allow", "allow access":
		return true
	default:
		return false
	}
}

func windowsAuthSysOnly(values []string) bool {
	hasSys := false
	hasKerberos := false
	for _, value := range values {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "sys" || v == "auth_sys" {
			hasSys = true
		}
		if strings.HasPrefix(v, "krb5") {
			hasKerberos = true
		}
	}
	return hasSys && !hasKerberos
}
