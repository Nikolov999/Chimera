//go:build windows

package filesystem

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsVolume struct {
	DeviceID           string `json:"DeviceID"`
	FileSystem         string `json:"FileSystem"`
	DriveType          int    `json:"DriveType"`
	VolumeName         string `json:"VolumeName"`
	EncryptionState    string `json:"EncryptionState"`
	EncryptionType     string `json:"EncryptionType"`
	EncryptionEvidence string `json:"EncryptionEvidence"`
}

func collectPlatformMounts(ctx context.Context) ([]MountBoundary, SourceStatus, []string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		reason := "PowerShell unavailable for Windows logical-volume inventory"
		return nil, SourceStatus{ID: "mount-boundaries", State: evidence.StateUnavailable, Source: "PowerShell/Get-CimInstance Win32_LogicalDisk", Reason: reason}, []string{reason}
	}
	script := `$bitlocker = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue; Get-CimInstance Win32_LogicalDisk | ForEach-Object { $d = $_; $es='UNKNOWN'; $et=''; $ee='BitLocker state unavailable'; if ($bitlocker -and $d.DriveType -eq 3) { try { $b = Get-BitLockerVolume -MountPoint $d.DeviceID -ErrorAction Stop; if ($null -ne $b) { $ee = ('Get-BitLockerVolume VolumeStatus=' + [string]$b.VolumeStatus + '; ProtectionStatus=' + [string]$b.ProtectionStatus); if ([string]$b.VolumeStatus -match 'FullyEncrypted|EncryptionInProgress|EncryptionPaused') { $es='ENCRYPTED'; $et='BitLocker' } elseif ([string]$b.VolumeStatus -match 'FullyDecrypted|DecryptionInProgress|DecryptionPaused') { $es='NOT_OBSERVED'; $et='BitLocker' } } } catch { $ee='BitLocker metadata unavailable for this volume' } }; [pscustomobject]@{ DeviceID=$d.DeviceID; FileSystem=$d.FileSystem; DriveType=[int]$d.DriveType; VolumeName=$d.VolumeName; EncryptionState=$es; EncryptionType=$et; EncryptionEvidence=$ee } } | ConvertTo-Json -Compress`
	raw, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		reason := "Windows logical-volume inventory failed: " + err.Error()
		return nil, SourceStatus{ID: "mount-boundaries", State: evidence.StateUnavailable, Source: "PowerShell/Get-CimInstance Win32_LogicalDisk", Reason: reason}, []string{reason}
	}
	vols := []windowsVolume{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &vols); err != nil {
			var one windowsVolume
			if err2 := json.Unmarshal(raw, &one); err2 != nil {
				reason := "Windows logical-volume JSON decode failed: " + err.Error()
				return nil, SourceStatus{ID: "mount-boundaries", State: evidence.StateDegraded, Source: "PowerShell/Get-CimInstance Win32_LogicalDisk", Reason: reason}, []string{reason}
			}
			vols = []windowsVolume{one}
		}
	}
	out := make([]MountBoundary, 0, len(vols))
	for _, v := range vols {
		if strings.TrimSpace(v.DeviceID) == "" {
			continue
		}
		class, network, removable, access := windowsDriveClassification(v.DriveType)
		enc := strings.ToUpper(strings.TrimSpace(v.EncryptionState))
		if enc == "" {
			enc = MountEncryptionUnknown
		}
		if class == MountClassOptical {
			enc = MountEncryptionNotApplicable
		}
		out = append(out, MountBoundary{
			Path: v.DeviceID + `\`, Device: v.DeviceID, BackingSource: v.DeviceID,
			Filesystem: v.FileSystem, VolumeLabel: v.VolumeName, Options: []string{"drive_type:" + strconv.Itoa(v.DriveType)},
			AccessMode: access, ReadOnly: access == MountAccessReadOnly, Writable: access == MountAccessReadWrite,
			Classification: class, Network: network, Removable: removable,
			EncryptionState: enc, EncryptionType: strings.TrimSpace(v.EncryptionType), EncryptionEvidence: strings.TrimSpace(v.EncryptionEvidence),
			State: evidence.StateObserved, CollectionSource: "PowerShell/Get-CimInstance Win32_LogicalDisk + optional Get-BitLockerVolume", Confidence: evidence.ConfidenceHigh,
		})
	}
	return out, SourceStatus{ID: "mount-boundaries", State: evidence.StateObserved, Source: "PowerShell/Get-CimInstance Win32_LogicalDisk + optional Get-BitLockerVolume", ItemCount: len(out)}, nil
}

func windowsDriveClassification(driveType int) (class string, network, removable bool, access string) {
	access = MountAccessUnknown
	switch driveType {
	case 2:
		return MountClassRemovable, false, true, access
	case 3:
		return MountClassLocal, false, false, access
	case 4:
		return MountClassNetwork, true, false, access
	case 5:
		return MountClassOptical, false, true, MountAccessReadOnly
	case 6:
		return MountClassVirtual, false, false, access
	default:
		return MountClassUnknown, false, false, access
	}
}
