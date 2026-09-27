//go:build linux

package overview

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(ctx context.Context, o *Overview) {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		kv := parseKV(string(b))
		if v := kv["PRETTY_NAME"]; v != "" {
			o.OS = v
		}
		o.OSVersion = kv["VERSION_ID"]
		o.OSBuild = kv["BUILD_ID"]
	} else {
		o.Degraded = append(o.Degraded, "os-release: "+err.Error())
	}

	if s, err := run(ctx, "uname", "-r"); err == nil {
		o.Kernel = s
	} else {
		o.Degraded = append(o.Degraded, "kernel: "+err.Error())
	}

	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			if sec, err := strconv.ParseFloat(fields[0], 64); err == nil {
				o.UptimeSeconds = int64(sec)
				bt := time.Now().UTC().Add(-time.Duration(sec * float64(time.Second)))
				o.BootTime = &bt
			}
		}
	} else {
		o.Degraded = append(o.Degraded, "uptime: "+err.Error())
	}

	o.Privilege = linuxPrivilege(ctx, o.CurrentUser)
	o.CPUModel = linuxCPUModel()
	o.MemoryTotalBytes = linuxMemory()
	o.ProcessCount = linuxProcessCount()
	if n, err := linuxTCPListeners(); err == nil {
		o.ListenerCount = n
	} else {
		o.Degraded = append(o.Degraded, "listeners: "+err.Error())
	}
	o.SecurityControls = linuxControls(ctx)
}

func linuxPrivilege(ctx context.Context, principal string) Privilege {
	_ = ctx
	euid := os.Geteuid()
	egid := os.Getegid()
	elevated := euid == 0
	level := "standard-user"
	elevationState := "standard"
	if elevated {
		level = "root"
		elevationState = "root"
	}
	adminState, groupDetail := linuxAdministrativeGroupState(elevated)
	detail := fmt.Sprintf("effective uid=%d; effective gid=%d", euid, egid)
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

func linuxAdministrativeGroupState(elevated bool) (string, string) {
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
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(g.Name)) {
		case "sudo", "wheel", "admin":
			return AdminGroupMember, "member of conventional administrative group " + g.Name
		}
	}
	return AdminGroupNotMember, "no conventional sudo/wheel/admin group membership observed"
}

func linuxCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") {
			if _, v, ok := strings.Cut(line, ":"); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func linuxMemory() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func linuxProcessCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

func linuxTCPListeners() (int, error) {
	total := 0
	found := false
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		found = true
		s := bufio.NewScanner(f)
		first := true
		for s.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(s.Text())
			if len(fields) > 3 && fields[3] == "0A" {
				total++
			}
		}
		err = s.Err()
		f.Close()
		if err != nil {
			return 0, err
		}
	}
	if !found {
		return 0, fmt.Errorf("proc net tables unavailable")
	}
	return total, nil
}

func linuxControls(ctx context.Context) []Control {
	controls := []Control{}
	controls = append(controls, detectSecureBootLinux())
	controls = append(controls, detectKernelLockdownLinux())
	controls = append(controls, detectLSMLinux())
	controls = append(controls, detectASLRLinux())
	controls = append(controls, detectFirewallLinux(ctx))
	return controls
}

func detectSecureBootLinux() Control {
	matches, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if len(matches) == 0 {
		if _, err := os.Stat("/sys/firmware/efi"); err != nil {
			return Control{Name: "Secure Boot", State: "unavailable", Detail: "EFI variables not observable", Source: "sysfs"}
		}
		return Control{Name: "Secure Boot", State: "unknown", Detail: "SecureBoot EFI variable not found", Source: "sysfs"}
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		return Control{Name: "Secure Boot", State: "denied", Detail: err.Error(), Source: "efivarfs"}
	}
	if len(b) >= 5 && b[4] == 1 {
		return Control{Name: "Secure Boot", State: "enabled", Source: "efivarfs"}
	}
	if len(b) >= 5 {
		return Control{Name: "Secure Boot", State: "disabled", Source: "efivarfs"}
	}
	return Control{Name: "Secure Boot", State: "unknown", Detail: "unexpected EFI variable length", Source: "efivarfs"}
}

func detectKernelLockdownLinux() Control {
	b, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return Control{Name: "Kernel lockdown", State: "unavailable", Detail: err.Error(), Source: "sysfs"}
	}
	v := strings.TrimSpace(string(b))
	if strings.Contains(v, "[none]") {
		return Control{Name: "Kernel lockdown", State: "disabled", Detail: v, Source: "sysfs"}
	}
	return Control{Name: "Kernel lockdown", State: "enabled", Detail: v, Source: "sysfs"}
}

func detectLSMLinux() Control {
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return Control{Name: "Mandatory access control", State: "enabled", Detail: "SELinux enforcing", Source: "selinuxfs"}
		}
		return Control{Name: "Mandatory access control", State: "partial", Detail: "SELinux present but not enforcing", Source: "selinuxfs"}
	}
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(b))), "Y") {
			return Control{Name: "Mandatory access control", State: "enabled", Detail: "AppArmor enabled", Source: "sysfs"}
		}
		return Control{Name: "Mandatory access control", State: "disabled", Detail: "AppArmor disabled", Source: "sysfs"}
	}
	return Control{Name: "Mandatory access control", State: "unavailable", Detail: "SELinux/AppArmor state not observable", Source: "sysfs"}
}

func detectASLRLinux() Control {
	b, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err != nil {
		return Control{Name: "ASLR", State: "unavailable", Detail: err.Error(), Source: "procfs"}
	}
	v := strings.TrimSpace(string(b))
	switch v {
	case "2":
		return Control{Name: "ASLR", State: "enabled", Detail: "full randomization", Source: "procfs"}
	case "1":
		return Control{Name: "ASLR", State: "partial", Detail: "conservative randomization", Source: "procfs"}
	case "0":
		return Control{Name: "ASLR", State: "disabled", Source: "procfs"}
	default:
		return Control{Name: "ASLR", State: "unknown", Detail: "value=" + v, Source: "procfs"}
	}
}

func detectFirewallLinux(ctx context.Context) Control {
	checks := [][]string{{"nft", "list", "ruleset"}, {"iptables", "-S"}, {"ufw", "status"}, {"firewall-cmd", "--state"}}
	for _, c := range checks {
		if _, err := run(ctx, c[0], c[1:]...); err == nil {
			return Control{Name: "Host firewall", State: "present", Detail: c[0] + " observable", Source: c[0]}
		}
	}
	return Control{Name: "Host firewall", State: "unavailable", Detail: "no supported firewall provider observable", Source: "local providers"}
}
