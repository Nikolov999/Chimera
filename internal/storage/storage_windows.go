//go:build windows

package storage

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsVolume struct {
	MountPoint           string  `json:"MountPoint"`
	VolumeName           string  `json:"VolumeName"`
	FileSystem           string  `json:"FileSystem"`
	DriveType            int     `json:"DriveType"`
	SystemVolume         bool    `json:"SystemVolume"`
	VolumeStatus         string  `json:"VolumeStatus"`
	ProtectionStatus     string  `json:"ProtectionStatus"`
	LockStatus           string  `json:"LockStatus"`
	EncryptionPercentage float64 `json:"EncryptionPercentage"`
	EncryptionMethod     string  `json:"EncryptionMethod"`
	AutoUnlockEnabled    string  `json:"AutoUnlockEnabled"`
	BitLockerAvailable   bool    `json:"BitLockerAvailable"`
	Error                string  `json:"Error"`
}

func collectPlatform(ctx context.Context) ([]Volume, []SourceStatus, []string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		reason := "PowerShell unavailable for BitLocker posture collection"
		return nil, []SourceStatus{{ID: "windows-bitlocker", State: evidence.StateUnavailable, Source: "PowerShell/Get-CimInstance + Get-BitLockerVolume", Reason: reason}}, []string{reason}
	}
	script := `$bl=Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue; $sys=$env:SystemDrive; Get-CimInstance Win32_LogicalDisk | ForEach-Object { $d=$_; $o=[ordered]@{MountPoint=$d.DeviceID;VolumeName=$d.VolumeName;FileSystem=$d.FileSystem;DriveType=[int]$d.DriveType;SystemVolume=([string]$d.DeviceID -ieq [string]$sys);VolumeStatus='';ProtectionStatus='';LockStatus='';EncryptionPercentage=0;EncryptionMethod='';AutoUnlockEnabled='';BitLockerAvailable=($null -ne $bl);Error=''}; if($bl -and ($d.DriveType -eq 3 -or $d.DriveType -eq 2)){try{$b=Get-BitLockerVolume -MountPoint $d.DeviceID -ErrorAction Stop;if($null -ne $b){$o.VolumeStatus=[string]$b.VolumeStatus;$o.ProtectionStatus=[string]$b.ProtectionStatus;$o.LockStatus=[string]$b.LockStatus;$o.EncryptionPercentage=[double]$b.EncryptionPercentage;$o.EncryptionMethod=[string]$b.EncryptionMethod;$o.AutoUnlockEnabled=[string]$b.AutoUnlockEnabled}}catch{$o.Error='BitLocker metadata unavailable: '+$_.Exception.Message}}; [pscustomobject]$o } | ConvertTo-Json -Compress`
	raw, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		// Fix55 distinguishes cooperative parent cancellation from an actual
		// PowerShell/provider exit defect. The scan scheduler will independently
		// report a real collector deadline when the parent collector itself
		// expires; this source must not manufacture a second provider-exit root.
		if ctx != nil && ctx.Err() != nil {
			reason := "safe collection boundary: BitLocker posture did not complete before the storage collection window closed"
			return nil, []SourceStatus{{ID: "windows-bitlocker", State: evidence.StateUnavailable, Source: "PowerShell/Get-CimInstance + Get-BitLockerVolume", Reason: reason}}, []string{reason}
		}
		reason := "Windows BitLocker posture collection failed: " + err.Error()
		return nil, []SourceStatus{{ID: "windows-bitlocker", State: evidence.StateUnavailable, Source: "PowerShell/Get-CimInstance + Get-BitLockerVolume", Reason: reason}}, []string{reason}
	}
	rows := []windowsVolume{}
	if strings.TrimSpace(string(raw)) != "" {
		if err := json.Unmarshal(raw, &rows); err != nil {
			var one windowsVolume
			if err2 := json.Unmarshal(raw, &one); err2 != nil {
				reason := "Windows BitLocker JSON decode failed: " + err.Error()
				return nil, []SourceStatus{{ID: "windows-bitlocker", State: evidence.StateDegraded, Source: "PowerShell/Get-CimInstance + Get-BitLockerVolume", Reason: reason}}, []string{reason}
			}
			rows = []windowsVolume{one}
		}
	}
	out := make([]Volume, 0, len(rows))
	degraded := []string{}
	for _, r := range rows {
		if strings.TrimSpace(r.MountPoint) == "" {
			continue
		}
		v := Volume{
			MountPoint: r.MountPoint + `\`, Device: r.MountPoint, VolumeName: r.VolumeName, Filesystem: r.FileSystem,
			SystemVolume: r.SystemVolume, Fixed: r.DriveType == 3, Removable: r.DriveType == 2,
			EncryptionProduct: "BitLocker", EncryptionState: EncryptionUnknown, ProtectionState: ProtectionUnknown,
			LockState: LockUnknown, EncryptionMethod: r.EncryptionMethod, AutoUnlock: normalizeAutoUnlock(r.AutoUnlockEnabled),
			State: evidence.StateObserved, CollectionSource: "PowerShell/Get-CimInstance Win32_LogicalDisk + Get-BitLockerVolume", Confidence: evidence.ConfidenceHigh,
		}
		if r.DriveType != 3 && r.DriveType != 2 {
			v.EncryptionState, v.ProtectionState = EncryptionNotApplicable, ProtectionNotApplicable
			v.LockState = LockNotApplicable
			v.EncryptionProduct = ""
			v.Confidence = evidence.ConfidenceExact
		} else if !r.BitLockerAvailable {
			v.Reason = "Get-BitLockerVolume cmdlet unavailable; encryption state left UNKNOWN"
			v.Confidence = evidence.ConfidenceMedium
			degraded = append(degraded, v.MountPoint+": Get-BitLockerVolume unavailable")
		} else if strings.TrimSpace(r.Error) != "" {
			v.State = evidence.StateUnavailable
			v.Reason = r.Error
			v.Confidence = evidence.ConfidenceMedium
			degraded = append(degraded, v.MountPoint+": "+r.Error)
		} else {
			v.EncryptionState = mapWindowsVolumeStatus(r.VolumeStatus)
			v.ProtectionState = mapWindowsProtection(r.ProtectionStatus)
			v.LockState = mapWindowsLock(r.LockStatus)
			p := r.EncryptionPercentage
			v.EncryptionPercentage = &p
			if v.EncryptionState == EncryptionEncrypted && v.ProtectionState == ProtectionEnabled {
				v.Confidence = evidence.ConfidenceExact
			}
		}
		out = append(out, v)
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return out, []SourceStatus{{ID: "windows-bitlocker", State: state, Source: "PowerShell/Get-CimInstance Win32_LogicalDisk + optional Get-BitLockerVolume", ItemCount: len(out), Reason: reason}}, degraded
}

func mapWindowsVolumeStatus(v string) string {
	x := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.Contains(x, "fullyencrypted"):
		return EncryptionEncrypted
	case strings.Contains(x, "encryptioninprogress"), strings.Contains(x, "encryptionpaused"), strings.Contains(x, "decryptioninprogress"), strings.Contains(x, "decryptionpaused"):
		return EncryptionPartial
	case strings.Contains(x, "fullydecrypted"):
		return EncryptionUnencrypted
	default:
		return EncryptionUnknown
	}
}
func mapWindowsProtection(v string) string {
	x := strings.ToLower(strings.TrimSpace(v))
	switch {
	case x == "on" || strings.Contains(x, "protectionon"):
		return ProtectionEnabled
	case x == "off" || strings.Contains(x, "protectionoff"):
		return ProtectionDisabled
	default:
		return ProtectionUnknown
	}
}
func mapWindowsLock(v string) string {
	x := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.Contains(x, "unlocked"):
		return LockUnlocked
	case strings.Contains(x, "locked"):
		return LockLocked
	default:
		return LockUnknown
	}
}
func normalizeAutoUnlock(v string) string {
	x := strings.ToLower(strings.TrimSpace(v))
	switch x {
	case "true":
		return "ENABLED"
	case "false":
		return "DISABLED"
	default:
		return "UNKNOWN"
	}
}
