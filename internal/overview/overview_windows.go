//go:build windows

package overview

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

type winPrivilege struct {
	Principal      string `json:"Principal"`
	SID            string `json:"SID"`
	Elevated       bool   `json:"Elevated"`
	AdminGroup     bool   `json:"AdminGroup"`
	IntegrityLevel string `json:"IntegrityLevel"`
	ElevationState string `json:"ElevationState"`
}

type winOS struct {
	Caption                string `json:"Caption"`
	Version                string `json:"Version"`
	BuildNumber            string `json:"BuildNumber"`
	LastBootUpTime         string `json:"LastBootUpTime"`
	TotalVisibleMemorySize uint64 `json:"TotalVisibleMemorySize"`
}

func collectPlatform(ctx context.Context, o *Overview) {
	ps := `$o=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{Caption=$o.Caption;Version=$o.Version;BuildNumber=$o.BuildNumber;LastBootUpTime=$o.LastBootUpTime.ToUniversalTime().ToString('o');TotalVisibleMemorySize=$o.TotalVisibleMemorySize} | ConvertTo-Json -Compress`
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps); err == nil {
		var v winOS
		if json.Unmarshal([]byte(s), &v) == nil {
			if v.Caption != "" {
				o.OS = v.Caption
			}
			o.OSVersion = v.Version
			o.OSBuild = v.BuildNumber
			o.MemoryTotalBytes = v.TotalVisibleMemorySize * 1024
			if t, err := time.Parse(time.RFC3339Nano, v.LastBootUpTime); err == nil {
				u := t.UTC()
				o.BootTime = &u
				o.UptimeSeconds = int64(time.Since(t).Seconds())
			}
		}
	} else {
		o.Degraded = append(o.Degraded, "os metadata: "+err.Error())
	}

	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `[Environment]::OSVersion.VersionString`); err == nil {
		o.Kernel = s
	}
	o.Privilege = windowsPrivilege(ctx, o.CurrentUser)
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)`); err == nil {
		o.CPUModel = strings.TrimSpace(s)
	}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `(Get-Process).Count`); err == nil {
		o.ProcessCount = int(parseUint(s))
	} else {
		o.Degraded = append(o.Degraded, "process count: "+err.Error())
	}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Measure-Object).Count`); err == nil {
		o.ListenerCount = int(parseUint(s))
	} else {
		o.Degraded = append(o.Degraded, "listeners: "+err.Error())
	}
	o.SecurityControls = windowsControls(ctx)
}

func windowsPrivilege(ctx context.Context, principal string) Privilege {
	script := `$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($id); $e=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); $adminSid='S-1-5-32-544'; $ag=@($id.Groups | ForEach-Object {$_.Value}) -contains $adminSid; $il='unknown'; $isid=@($id.Groups | Where-Object {$_.Value -like 'S-1-16-*'} | ForEach-Object {$_.Value} | Select-Object -Last 1); if($isid){$rid=[int]($isid.Split('-')[-1]); if($rid -ge 16384){$il='system'}elseif($rid -ge 12288){$il='high'}elseif($rid -ge 8448){$il='medium-plus'}elseif($rid -ge 8192){$il='medium'}elseif($rid -ge 4096){$il='low'}else{$il='untrusted'}}; if($e){$es='elevated-administrator'}elseif($ag){$es='uac-filtered-administrator'}else{$es='standard'}; [pscustomobject]@{Principal=$id.Name;SID=$id.User.Value;Elevated=[bool]$e;AdminGroup=[bool]$ag;IntegrityLevel=$il;ElevationState=$es} | ConvertTo-Json -Compress`
	s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return Privilege{Level: "unknown", Principal: principal, AdministrativeGroup: AdminGroupUnknown, CollectionTier: "unknown", DetectionSource: "WindowsIdentity/WindowsPrincipal", Detail: err.Error()}
	}
	var v winPrivilege
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return Privilege{Level: "unknown", Principal: principal, AdministrativeGroup: AdminGroupUnknown, CollectionTier: "unknown", DetectionSource: "WindowsIdentity/WindowsPrincipal", Detail: "decode privilege context: " + err.Error()}
	}
	level := "standard-user"
	if v.Elevated {
		level = "administrator-elevated"
	} else if v.AdminGroup {
		level = "administrator-filtered"
	}
	if strings.TrimSpace(v.Principal) == "" {
		v.Principal = principal
	}
	tier := "standard"
	if v.Elevated {
		tier = "elevated"
	}
	return Privilege{
		Level: level, Elevated: v.Elevated, Principal: strings.TrimSpace(v.Principal), PrincipalID: strings.TrimSpace(v.SID),
		AdministrativeGroup: adminGroupState(v.AdminGroup), IntegrityLevel: strings.TrimSpace(v.IntegrityLevel),
		ElevationState: strings.TrimSpace(v.ElevationState), CollectionTier: tier,
		DetectionSource: "WindowsIdentity/WindowsPrincipal token metadata",
		Detail:          "effective token privilege and integrity derived from the current Windows access token",
	}
}

func windowsControls(ctx context.Context) []Control {
	out := []Control{}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `try { if(Confirm-SecureBootUEFI){'enabled'}else{'disabled'} } catch {'unavailable'}`); err == nil {
		out = append(out, Control{Name: "Secure Boot", State: strings.TrimSpace(s), Source: "Confirm-SecureBootUEFI"})
	} else {
		out = append(out, Control{Name: "Secure Boot", State: "unavailable", Detail: err.Error(), Source: "PowerShell"})
	}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$v=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA; if($v -eq 1){'enabled'}elseif($v -eq 0){'disabled'}else{'unknown'}`); err == nil {
		out = append(out, Control{Name: "UAC", State: strings.TrimSpace(s), Source: "registry"})
	}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$p=Get-NetFirewallProfile -ErrorAction SilentlyContinue; if(!$p){'unavailable'}elseif(($p|? Enabled).Count -eq $p.Count){'enabled'}elseif(($p|? Enabled).Count -eq 0){'disabled'}else{'partial'}`); err == nil {
		out = append(out, Control{Name: "Windows Defender Firewall", State: strings.TrimSpace(s), Source: "Get-NetFirewallProfile"})
	} else {
		out = append(out, Control{Name: "Windows Defender Firewall", State: "unavailable", Detail: err.Error(), Source: "PowerShell"})
	}
	if s, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$d=Get-MpComputerStatus -ErrorAction SilentlyContinue; if(!$d){'unavailable'}elseif($d.RealTimeProtectionEnabled){'enabled'}else{'disabled'}`); err == nil {
		out = append(out, Control{Name: "Microsoft Defender real-time protection", State: strings.TrimSpace(s), Source: "Get-MpComputerStatus"})
	}
	return out
}
