//go:build linux

package kernel

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(ctx context.Context, k *Inventory) {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		m := parseKV(string(b))
		if m["PRETTY_NAME"] != "" {
			k.OSName = m["PRETTY_NAME"]
		}
		k.OSVersion = m["VERSION_ID"]
		if k.OSVersion == "" {
			k.OSVersion = m["VERSION"]
		}
		k.OSBuild = m["BUILD_ID"]
		k.SupportChannel = m["VERSION_CODENAME"]
		if k.SupportChannel == "" {
			k.SupportChannel = m["VARIANT_ID"]
		}
		if k.SupportChannel == "" {
			k.SupportChannel = m["ID"]
		}
	} else {
		k.Degraded = append(k.Degraded, "os-release: "+err.Error())
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		k.KernelRelease = strings.TrimSpace(string(b))
	} else if s, e := run(ctx, "uname", "-r"); e == nil {
		k.KernelRelease = s
	} else {
		k.Degraded = append(k.Degraded, "kernel release: "+err.Error())
	}
	if b, err := os.ReadFile("/proc/version"); err == nil {
		k.KernelVersion = strings.TrimSpace(string(b))
	} else if s, e := run(ctx, "uname", "-v"); e == nil {
		k.KernelVersion = s
	} else {
		k.Degraded = append(k.Degraded, "kernel version: "+err.Error())
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			if sec, e := strconv.ParseFloat(f[0], 64); e == nil {
				k.UptimeSeconds = int64(sec)
				t := time.Now().Add(-time.Duration(sec * float64(time.Second))).UTC()
				k.BootTime = &t
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		k.BootID = strings.TrimSpace(string(b))
	}
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		k.BootMode = "UEFI"
	} else {
		k.BootMode = "legacy-or-unreported"
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		k.Update = UpdateStatus{State: "REBOOT_REQUIRED", Source: "/var/run/reboot-required", Detail: "local package-management state requests a reboot"}
	}
	k.HardeningCapabilities = []Capability{
		capState("ASLR controls", pathExists("/proc/sys/kernel/randomize_va_space"), "/proc/sys/kernel/randomize_va_space", "provider availability; state is assessed in "),
		capState("Kernel lockdown", pathExists("/sys/kernel/security/lockdown"), "/sys/kernel/security/lockdown", "provider availability; state is assessed in "),
		capState("Module signature enforcement", pathExists("/sys/module/module/parameters/sig_enforce") || pathExists("/proc/sys/kernel/module_sig_enforce"), "Linux module loader signature policy", "provider availability; state is assessed in "),
		capState("Kernel pointer restrictions", pathExists("/proc/sys/kernel/kptr_restrict"), "/proc/sys/kernel/kptr_restrict", "provider availability; state is assessed in "),
		capState("Kernel log restrictions", pathExists("/proc/sys/kernel/dmesg_restrict"), "/proc/sys/kernel/dmesg_restrict", "provider availability; state is assessed in "),
		capState("Ptrace restrictions", pathExists("/proc/sys/kernel/yama/ptrace_scope"), "/proc/sys/kernel/yama/ptrace_scope", "provider availability; state is assessed in "),
		capState("Linux security modules", pathExists("/sys/kernel/security/lsm"), "/sys/kernel/security/lsm", "active LSM stack plus SELinux/AppArmor posture are assessed in "),
		capState("Unprivileged BPF control", pathExists("/proc/sys/kernel/unprivileged_bpf_disabled"), "/proc/sys/kernel/unprivileged_bpf_disabled", "capability only; assessment begins in "),
		capState("User namespace control", pathExists("/proc/sys/user/max_user_namespaces"), "/proc/sys/user/max_user_namespaces", "capability only; assessment begins in "),
		capState("Performance-event restrictions", pathExists("/proc/sys/kernel/perf_event_paranoid"), "/proc/sys/kernel/perf_event_paranoid", "provider availability; state is assessed in "),
		capState("Loaded module/driver metadata", pathExists("/proc/modules"), "/proc/modules + modinfo/sysfs", "loaded-module inventory and trust provenance are assessed in "),
		capState("Secure Boot provider", pathExists("/sys/firmware/efi/efivars"), "/sys/firmware/efi/efivars", "provider availability; Secure Boot state is assessed in "),
	}
}
func pathExists(p string) bool { _, err := os.Stat(p); return err == nil }
