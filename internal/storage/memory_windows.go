//go:build windows

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type windowsMemoryState struct {
	SystemDrive       string            `json:"SystemDrive"`
	HibernateEnabled  int               `json:"HibernateEnabled"`
	HiberFileType     int               `json:"HiberFileType"`
	HiberbootEnabled  int               `json:"HiberbootEnabled"`
	EncryptPagingFile int               `json:"EncryptPagingFile"`
	PowerKeyAvailable bool              `json:"PowerKeyAvailable"`
	FSKeyAvailable    bool              `json:"FSKeyAvailable"`
	PageFileQueryOK   bool              `json:"PageFileQueryOK"`
	PageFiles         []windowsPageFile `json:"PageFiles"`
}

type windowsPageFile struct {
	Name              string `json:"Name"`
	AllocatedBaseSize uint64 `json:"AllocatedBaseSize"`
	CurrentUsage      uint64 `json:"CurrentUsage"`
}

func collectMemoryProtection(ctx context.Context, volumes []Volume) ([]SwapArea, HibernationPosture, []SourceStatus, []string) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		reason := "PowerShell unavailable for Windows paging/hibernation posture collection"
		h := HibernationPosture{
			SupportState: SupportUnknown, ConfigurationState: HibernationUnknown,
			ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown,
			State: evidence.StateUnavailable, CollectionSource: "PowerShell registry/CIM metadata",
			Confidence: evidence.ConfidenceMedium, Reason: reason,
		}
		return nil, h, []SourceStatus{{ID: "windows-memory-state", State: evidence.StateUnavailable, Source: "PowerShell registry/CIM metadata", Reason: reason}}, []string{reason}
	}
	script := `$power=$null; $fs=$null; $pages=@(); $pq=$true; try {$power=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -ErrorAction Stop} catch {}; try {$fs=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction Stop} catch {}; try {$pages=@(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | ForEach-Object {[PSCustomObject]@{Name=$_.Name;AllocatedBaseSize=[uint64]$_.AllocatedBaseSize;CurrentUsage=[uint64]$_.CurrentUsage}})} catch {$pq=$false}; [PSCustomObject]@{SystemDrive=$env:SystemDrive;HibernateEnabled=$(if($null -ne $power -and $null -ne $power.HibernateEnabled){[int]$power.HibernateEnabled}else{-1});HiberFileType=$(if($null -ne $power -and $null -ne $power.HiberFileType){[int]$power.HiberFileType}else{-1});HiberbootEnabled=$(if($null -ne $power -and $null -ne $power.HiberbootEnabled){[int]$power.HiberbootEnabled}else{-1});EncryptPagingFile=$(if($null -ne $fs -and $null -ne $fs.NtfsEncryptPagingFile){[int]$fs.NtfsEncryptPagingFile}else{-1});PowerKeyAvailable=($null -ne $power);FSKeyAvailable=($null -ne $fs);PageFileQueryOK=$pq;PageFiles=$pages} | ConvertTo-Json -Depth 5 -Compress`
	raw, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		reason := "Windows paging/hibernation metadata collection failed: " + err.Error()
		h := HibernationPosture{SupportState: SupportUnknown, ConfigurationState: HibernationUnknown, ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown, State: evidence.StateUnavailable, CollectionSource: "PowerShell registry/CIM metadata", Confidence: evidence.ConfidenceMedium, Reason: reason}
		return nil, h, []SourceStatus{{ID: "windows-memory-state", State: evidence.StateUnavailable, Source: "PowerShell registry/CIM metadata", Reason: reason}}, []string{reason}
	}
	var state windowsMemoryState
	if err := json.Unmarshal(raw, &state); err != nil {
		reason := "Windows paging/hibernation JSON decode failed: " + err.Error()
		h := HibernationPosture{SupportState: SupportUnknown, ConfigurationState: HibernationUnknown, ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown, State: evidence.StateDegraded, CollectionSource: "PowerShell registry/CIM metadata", Confidence: evidence.ConfidenceMedium, Reason: reason}
		return nil, h, []SourceStatus{{ID: "windows-memory-state", State: evidence.StateDegraded, Source: "PowerShell registry/CIM metadata", Reason: reason}}, []string{reason}
	}
	areas := make([]SwapArea, 0, len(state.PageFiles))
	for _, p := range state.PageFiles {
		path := strings.TrimSpace(p.Name)
		if path == "" {
			continue
		}
		a := SwapArea{
			Path: path, Kind: "PAGEFILE", SizeBytes: p.AllocatedBaseSize * 1024 * 1024,
			UsedBytes: p.CurrentUsage * 1024 * 1024, Active: true, EncryptionState: EncryptionUnknown,
			State: evidence.StateObserved, CollectionSource: "Win32_PageFileUsage + NtfsEncryptPagingFile + BitLocker volume correlation",
			Confidence: evidence.ConfidenceMedium,
		}
		enrichWindowsPageFileProtection(&a, state.EncryptPagingFile, volumes)
		areas = append(areas, a)
	}
	h := windowsHibernation(state, volumes)
	degraded := []string{}
	if !state.PageFileQueryOK {
		degraded = append(degraded, "Windows page-file inventory unavailable through Win32_PageFileUsage")
	}
	if !state.PowerKeyAvailable {
		degraded = append(degraded, "Windows hibernation registry metadata unavailable")
	}
	if !state.FSKeyAvailable && len(areas) > 0 {
		degraded = append(degraded, "Windows paging-file encryption policy metadata unavailable")
	}
	for _, a := range areas {
		if a.EncryptionState == EncryptionUnknown {
			degraded = append(degraded, a.Path+": "+fallback(a.Reason, "paging-file at-rest protection unresolved"))
		}
	}
	if h.ExposureState == ExposureUnknown && h.ConfigurationState == HibernationEnabled {
		degraded = append(degraded, fallback(h.Reason, "Windows hibernation-image protection unresolved"))
	}
	providerState := evidence.StateObserved
	providerReason := ""
	if len(degraded) > 0 {
		providerState = evidence.StateDegraded
		providerReason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return areas, h, []SourceStatus{{ID: "windows-memory-state", State: providerState, Source: "PowerShell registry + Win32_PageFileUsage + BitLocker volume correlation", ItemCount: len(areas) + 1, Reason: providerReason}}, degraded
}

func enrichWindowsPageFileProtection(a *SwapArea, encryptPagingFile int, volumes []Volume) {
	if a == nil {
		return
	}
	if encryptPagingFile == 1 {
		a.EncryptionState = EncryptionEncrypted
		a.EncryptionProduct = "Windows paging-file encryption"
		a.EncryptionBasis = "NtfsEncryptPagingFile policy is enabled"
		a.Confidence = evidence.ConfidenceExact
		return
	}
	if v, ok := volumeForPath(volumes, a.Path); ok {
		if v.EncryptionState == EncryptionEncrypted && v.ProtectionState == ProtectionEnabled {
			a.EncryptionState = EncryptionEncrypted
			a.EncryptionProduct = fallback(v.EncryptionProduct, "BitLocker")
			a.EncryptionBasis = "paging file resides on an encrypted volume with protection enabled"
			a.Confidence = v.Confidence
			return
		}
		if v.EncryptionState == EncryptionUnencrypted && encryptPagingFile == 0 {
			a.EncryptionState = EncryptionUnencrypted
			a.EncryptionProduct = "Windows paging-file encryption / BitLocker"
			a.EncryptionBasis = "paging-file encryption policy is disabled and the containing volume is unencrypted"
			a.Confidence = evidence.ConfidenceHigh
			return
		}
		a.Reason = appendReason(a.Reason, fallback(v.Reason, "containing-volume encryption/protection state is unresolved"))
	}
	if encryptPagingFile < 0 {
		a.Reason = appendReason(a.Reason, "NtfsEncryptPagingFile policy state is unavailable")
	} else if encryptPagingFile == 0 {
		a.Reason = appendReason(a.Reason, "paging-file encryption policy is disabled but containing-volume protection is unresolved")
	}
}

func windowsHibernation(s windowsMemoryState, volumes []Volume) HibernationPosture {
	h := HibernationPosture{
		SupportState: SupportUnknown, ConfigurationState: HibernationUnknown,
		ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown,
		FastStartupState: normalizedBinaryState(s.HiberbootEnabled), DestroyFileVaultKeyOnStandby: "NOT_APPLICABLE",
		State: evidence.StateObserved, CollectionSource: "Windows power registry + BitLocker volume correlation", Confidence: evidence.ConfidenceMedium,
	}
	if s.HibernateEnabled >= 0 {
		h.SupportState = SupportYes
	}
	if s.HibernateEnabled == 0 && s.HiberbootEnabled == 0 {
		h.ConfigurationState = HibernationDisabled
		h.ExposureState = ExposureNotApplicable
		h.EncryptionState = EncryptionNotApplicable
		h.Confidence = evidence.ConfidenceHigh
		return h
	}
	if s.HibernateEnabled == 1 || s.HiberbootEnabled == 1 {
		h.ConfigurationState = HibernationEnabled
		if s.HibernateEnabled == 0 && s.HiberbootEnabled == 1 {
			h.Mode = "FAST_STARTUP_ONLY"
		} else {
			h.Mode = "HIBERNATION"
		}
		if s.HiberFileType >= 0 {
			h.Mode += "/HIBERFILE_TYPE_" + strconv.Itoa(s.HiberFileType)
		}
		drive := strings.TrimSpace(s.SystemDrive)
		if drive != "" {
			h.ImagePath = strings.TrimRight(drive, "\\/") + `\hiberfil.sys`
		}
		if v, ok := volumeForPath(volumes, h.ImagePath); ok {
			h.EncryptionState = v.EncryptionState
			h.ProtectionBasis = "hibernation file resides on " + fallback(v.EncryptionProduct, "the system volume")
			h.Confidence = v.Confidence
			if v.EncryptionState == EncryptionEncrypted && v.ProtectionState == ProtectionEnabled {
				h.ExposureState = ExposureProtected
				return h
			}
			if v.EncryptionState == EncryptionUnencrypted || v.ProtectionState == ProtectionDisabled {
				h.ExposureState = ExposureExposed
				return h
			}
			h.Reason = fallback(v.Reason, "system-volume encryption/protection state is unresolved")
			return h
		}
		h.Reason = "system volume could not be correlated for hibernation-file protection"
		return h
	}
	if !s.PowerKeyAvailable {
		h.State = evidence.StateUnavailable
		h.Reason = "Windows hibernation registry metadata unavailable"
	}
	return h
}

func normalizedBinaryState(v int) string {
	switch v {
	case 1:
		return "ENABLED"
	case 0:
		return "DISABLED"
	default:
		return "UNKNOWN"
	}
}

func windowsMemoryDebugString(s windowsMemoryState) string {
	return fmt.Sprintf("hibernate=%d fast=%d pagefile-encryption=%d", s.HibernateEnabled, s.HiberbootEnabled, s.EncryptPagingFile)
}
