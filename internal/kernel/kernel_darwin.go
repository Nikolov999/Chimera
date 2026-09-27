//go:build darwin

package kernel

import (
	"context"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(ctx context.Context, k *Inventory) {
	if s, e := run(ctx, "sw_vers", "-productName"); e == nil {
		k.OSName = s
	} else {
		k.Degraded = append(k.Degraded, "product name: "+e.Error())
	}
	if s, e := run(ctx, "sw_vers", "-productVersion"); e == nil {
		k.OSVersion = s
	}
	if s, e := run(ctx, "sw_vers", "-buildVersion"); e == nil {
		k.OSBuild = s
	}
	k.SupportChannel = "standard-release"
	if s, e := run(ctx, "sysctl", "-n", "kern.osrelease"); e == nil {
		k.KernelRelease = s
	}
	if s, e := run(ctx, "sysctl", "-n", "kern.version"); e == nil {
		k.KernelVersion = s
	}
	if s, e := run(ctx, "sysctl", "-n", "kern.boottime"); e == nil {
		if idx := strings.Index(s, "sec = "); idx >= 0 {
			rest := s[idx+6:]
			if end := strings.IndexByte(rest, ','); end > 0 {
				if sec, er := strconv.ParseInt(strings.TrimSpace(rest[:end]), 10, 64); er == nil {
					t := time.Unix(sec, 0).UTC()
					k.BootTime = &t
					k.UptimeSeconds = int64(time.Since(t).Seconds())
				}
			}
		}
	}
	k.BootMode = "platform-managed"
	k.HardeningCapabilities = []Capability{
		capState("System Integrity Protection provider", commandAvailable("csrutil"), "csrutil", "System Integrity Protection state is assessed in "),
		capState("Gatekeeper provider", commandAvailable("spctl"), "spctl", "capability inventory only"),
		capState("AMFI boot-policy metadata", commandAvailable("sysctl"), "sysctl kern.bootargs", "provider availability; AMFI-relevant boot-policy indicators are assessed in "),
		capState("ASLR boot-policy metadata", commandAvailable("sysctl"), "sysctl kern.bootargs", "provider availability; ASLR-relevant boot-policy overrides are assessed in "),
		capState("Mach-O PIE metadata", commandAvailable("otool"), "otool", "provider availability; representative system-binary PIE posture is assessed in "),
		capState("Kernel debug boot-policy metadata", commandAvailable("sysctl"), "sysctl kern.bootargs", "provider availability; debug/KDP boot-argument exposure is assessed in "),
		capState("Developer-tool debugging authorization", commandAvailable("DevToolsSecurity"), "DevToolsSecurity", "provider availability; state is assessed in "),
		capState("Secure Boot provider", commandAvailable("system_profiler"), "system_profiler", "provider availability; Secure Boot state is assessed in "),
		capState("Kernel extension metadata", commandAvailable("kmutil") || commandAvailable("kextstat"), "kmutil/kextstat", "provider availability; loaded kernel-extension provenance is assessed in "),
		capState("Kernel runtime controls", commandAvailable("sysctl"), "sysctl", "capability only; later phases assess individual controls"),
	}
}
