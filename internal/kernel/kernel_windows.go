//go:build windows

package kernel

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

type winKernel struct {
	Caption        string
	Version        string
	Build          string
	DisplayVersion string
	LastBoot       string
	Firmware       int
	RebootPending  bool
}

func collectPlatform(ctx context.Context, k *Inventory) {
	ps := `$o=Get-CimInstance Win32_OperatingSystem; $cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue; $fw=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue).PEFirmwareType; $rp=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'); [pscustomobject]@{Caption=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;DisplayVersion=$cv.DisplayVersion;LastBoot=$o.LastBootUpTime.ToUniversalTime().ToString('o');Firmware=[int]$fw;RebootPending=[bool]$rp}|ConvertTo-Json -Compress`
	s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err == nil {
		var v winKernel
		if json.Unmarshal([]byte(s), &v) == nil {
			k.OSName = strings.TrimSpace(v.Caption)
			k.OSVersion = strings.TrimSpace(v.Version)
			k.OSBuild = strings.TrimSpace(v.Build)
			k.SupportChannel = strings.TrimSpace(v.DisplayVersion)
			k.KernelRelease = k.OSVersion
			k.KernelVersion = "Windows NT build " + k.OSBuild
			if t, e := time.Parse(time.RFC3339Nano, v.LastBoot); e == nil {
				u := t.UTC()
				k.BootTime = &u
				k.UptimeSeconds = int64(time.Since(u).Seconds())
			}
			if v.Firmware == 2 {
				k.BootMode = "UEFI"
			} else if v.Firmware == 1 {
				k.BootMode = "BIOS"
			} else {
				k.BootMode = "unreported"
			}
			if v.RebootPending {
				k.Update = UpdateStatus{State: "REBOOT_REQUIRED", Source: "Windows local reboot-pending registry markers", Detail: "a local servicing marker requests reboot"}
			}
		}
	} else {
		k.Degraded = append(k.Degraded, "Windows kernel metadata: "+err.Error())
	}
	k.HardeningCapabilities = []Capability{
		capState("Secure Boot provider", commandAvailable("powershell.exe"), "Confirm-SecureBootUEFI", "provider availability; Secure Boot state is assessed in "),
		capState("Code integrity controls", commandAvailable("powershell.exe"), "DeviceGuard/code-integrity local providers", "provider availability; state is assessed in "),
		capState("Test-signing policy", commandAvailable("bcdedit.exe") || commandAvailable("bcdedit"), "bcdedit", "provider availability; state is assessed in "),
		capState("Process mitigation controls", commandAvailable("powershell.exe"), "Get-ProcessMitigation", "provider availability; state is assessed in "),
		capState("Kernel/boot debugging policy", commandAvailable("bcdedit.exe") || commandAvailable("bcdedit"), "bcdedit", "provider availability; state is assessed in "),
		capState("Developer Mode policy", commandAvailable("powershell.exe"), "AppModelUnlock registry policy", "provider availability; state is assessed in "),
		capState("Driver signing metadata", commandAvailable("powershell.exe"), "Win32_PnPSignedDriver", "provider availability; loaded-driver signing provenance is assessed in "),
		capState("Virtualization based security metadata", commandAvailable("powershell.exe"), "Win32_DeviceGuard", "provider availability; HVCI state is assessed in and VBS isolation-equivalent posture is assessed in "),
	}
}
