//go:build darwin

package overview

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(ctx context.Context, o *Overview) {
	if s, err := run(ctx, "sw_vers", "-productName"); err == nil {
		o.OS = s
	}
	if s, err := run(ctx, "sw_vers", "-productVersion"); err == nil {
		o.OSVersion = s
	}
	if s, err := run(ctx, "sw_vers", "-buildVersion"); err == nil {
		o.OSBuild = s
	}
	if s, err := run(ctx, "sysctl", "-n", "kern.osrelease"); err == nil {
		o.Kernel = s
	}
	if s, err := run(ctx, "sysctl", "-n", "kern.boottime"); err == nil {
		if idx := strings.Index(s, "sec = "); idx >= 0 {
			rest := s[idx+6:]
			end := strings.IndexByte(rest, ',')
			if end > 0 {
				if sec, err := strconv.ParseInt(strings.TrimSpace(rest[:end]), 10, 64); err == nil {
					t := time.Unix(sec, 0).UTC()
					o.BootTime = &t
					o.UptimeSeconds = int64(time.Since(t).Seconds())
				}
			}
		}
	}
	o.Privilege = darwinPrivilege(ctx, o.CurrentUser)
	if s, err := run(ctx, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
		o.CPUModel = s
	} else if s, err := run(ctx, "sysctl", "-n", "hw.model"); err == nil {
		o.CPUModel = s
	}
	if s, err := run(ctx, "sysctl", "-n", "hw.memsize"); err == nil {
		o.MemoryTotalBytes = parseUint(s)
	}
	if s, err := run(ctx, "sh", "-c", `ps -axo pid= | wc -l`); err == nil {
		o.ProcessCount = int(parseUint(s))
	}
	if s, err := run(ctx, "sh", "-c", `netstat -anv -p tcp 2>/dev/null | grep -c LISTEN || true`); err == nil {
		o.ListenerCount = int(parseUint(s))
	}
	o.SecurityControls = darwinControls(ctx)
}

func darwinPrivilege(ctx context.Context, principal string) Privilege {
	_ = ctx
	euid := os.Geteuid()
	egid := os.Getegid()
	elevated := euid == 0
	adminState, groupDetail := darwinAdministrativeGroupState(elevated)
	level := "standard-user"
	elevationState := "standard"
	if elevated {
		level = "root"
		elevationState = "root"
	} else if adminState == AdminGroupMember {
		level = "administrator-standard-session"
		elevationState = "admin-user-not-root"
	}
	detail := "effective uid=" + strconv.Itoa(euid) + "; effective gid=" + strconv.Itoa(egid)
	if groupDetail != "" {
		detail += "; " + groupDetail
	}
	return Privilege{
		Level: level, Elevated: elevated, Principal: principal,
		EffectiveUID: strconv.Itoa(euid), EffectiveGID: strconv.Itoa(egid),
		AdministrativeGroup: adminState, ElevationState: elevationState,
		CollectionTier:  map[bool]string{true: "elevated", false: "standard"}[elevated],
		DetectionSource: "os.Geteuid/os.Getegid + os/user group metadata", Detail: detail,
	}
}

func darwinAdministrativeGroupState(elevated bool) (string, string) {
	if elevated {
		return AdminGroupMember, "root-equivalent effective identity"
	}
	u, err := user.Current()
	if err != nil {
		return AdminGroupUnknown, "administrative group membership unavailable: " + err.Error()
	}
	ids, err := u.GroupIds()
	if err != nil {
		return AdminGroupUnknown, "administrative group membership unavailable: " + err.Error()
	}
	for _, gid := range ids {
		g, err := user.LookupGroupId(gid)
		if err == nil && strings.EqualFold(strings.TrimSpace(g.Name), "admin") {
			return AdminGroupMember, "member of macOS admin group"
		}
	}
	return AdminGroupNotMember, "macOS admin group membership not observed"
}

func darwinControls(ctx context.Context) []Control {
	out := []Control{}
	if s, err := run(ctx, "csrutil", "status"); err == nil {
		state := "unknown"
		lower := strings.ToLower(s)
		if strings.Contains(lower, "enabled") {
			state = "enabled"
		} else if strings.Contains(lower, "disabled") {
			state = "disabled"
		}
		out = append(out, Control{Name: "System Integrity Protection", State: state, Detail: s, Source: "csrutil"})
	} else {
		out = append(out, Control{Name: "System Integrity Protection", State: "unavailable", Detail: err.Error(), Source: "csrutil"})
	}
	if s, err := run(ctx, "spctl", "--status"); err == nil {
		state := "unknown"
		lower := strings.ToLower(s)
		if strings.Contains(lower, "enabled") {
			state = "enabled"
		} else if strings.Contains(lower, "disabled") {
			state = "disabled"
		}
		out = append(out, Control{Name: "Gatekeeper", State: state, Detail: s, Source: "spctl"})
	}
	if s, err := run(ctx, "fdesetup", "status"); err == nil {
		state := "unknown"
		lower := strings.ToLower(s)
		if strings.Contains(lower, "is on") {
			state = "enabled"
		} else if strings.Contains(lower, "is off") {
			state = "disabled"
		}
		out = append(out, Control{Name: "FileVault", State: state, Detail: s, Source: "fdesetup"})
	} else {
		out = append(out, Control{Name: "FileVault", State: "unavailable", Detail: err.Error(), Source: "fdesetup"})
	}
	if s, err := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		state := "unknown"
		lower := strings.ToLower(s)
		if strings.Contains(lower, "enabled") {
			state = "enabled"
		} else if strings.Contains(lower, "disabled") {
			state = "disabled"
		}
		out = append(out, Control{Name: "Application Firewall", State: state, Detail: s, Source: "socketfilterfw"})
	}
	return out
}
