//go:build darwin

package storage

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context) ([]Volume, []SourceStatus, []string) {
	mountPath, err := exec.LookPath("mount")
	if err != nil {
		reason := "mount utility unavailable for macOS storage inventory"
		return nil, []SourceStatus{{ID: "macos-storage", State: evidence.StateUnavailable, Source: "mount + diskutil + fdesetup", Reason: reason}}, []string{reason}
	}
	raw, err := exec.CommandContext(ctx, mountPath).Output()
	if err != nil {
		reason := "macOS mounted-volume inventory failed: " + err.Error()
		return nil, []SourceStatus{{ID: "macos-storage", State: evidence.StateUnavailable, Source: "mount + diskutil + fdesetup", Reason: reason}}, []string{reason}
	}
	out := []Volume{}
	degraded := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		v, ok := parseDarwinMount(line)
		if !ok || !strings.HasPrefix(v.Device, "/dev/") {
			continue
		}
		enrichDarwinDiskutil(ctx, &v)
		if v.SystemVolume {
			enrichDarwinFileVault(ctx, &v, &degraded)
		}
		out = append(out, v)
		if len(out) >= maxVolumes {
			break
		}
	}
	if ctx != nil && ctx.Err() != nil {
		degraded = append(degraded, "macOS storage collection interrupted: "+ctx.Err().Error())
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return out, []SourceStatus{{ID: "macos-storage", State: state, Source: "mount + diskutil info + fdesetup status", ItemCount: len(out), Reason: reason}}, degraded
}

func parseDarwinMount(line string) (Volume, bool) {
	line = strings.TrimSpace(line)
	on := strings.Index(line, " on ")
	if on <= 0 {
		return Volume{}, false
	}
	dev := strings.TrimSpace(line[:on])
	rest := line[on+4:]
	open, close := strings.LastIndex(rest, " ("), strings.LastIndex(rest, ")")
	if open <= 0 || close <= open {
		return Volume{}, false
	}
	mountPoint := strings.TrimSpace(rest[:open])
	options := strings.Split(rest[open+2:close], ",")
	fs := ""
	if len(options) > 0 {
		fs = strings.TrimSpace(options[0])
	}
	return Volume{
		MountPoint: mountPoint, Device: dev, Filesystem: fs, SystemVolume: mountPoint == "/", Fixed: true,
		EncryptionProduct: "FileVault/APFS", EncryptionState: EncryptionUnknown, ProtectionState: ProtectionUnknown,
		LockState: LockUnlocked, State: evidence.StateObserved, CollectionSource: "mount + diskutil info", Confidence: evidence.ConfidenceHigh,
	}, true
}

func enrichDarwinDiskutil(ctx context.Context, v *Volume) {
	diskutil, err := exec.LookPath("diskutil")
	if err != nil {
		v.Reason = "diskutil unavailable for volume encryption enrichment"
		v.Confidence = evidence.ConfidenceMedium
		return
	}
	raw, err := exec.CommandContext(ctx, diskutil, "info", v.Device).Output()
	if err != nil {
		v.Reason = "diskutil info unavailable for this volume"
		v.Confidence = evidence.ConfidenceMedium
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		switch key {
		case "volume name":
			if value != "" && !strings.Contains(strings.ToLower(value), "not applicable") {
				v.VolumeName = value
			}
		case "file system personality":
			if value != "" {
				v.Filesystem = value
			}
		case "device location":
			if strings.EqualFold(value, "External") {
				v.Removable = true
				v.Fixed = false
			}
		case "removable media":
			if strings.Contains(strings.ToLower(value), "removable") || strings.HasPrefix(strings.ToLower(value), "yes") {
				v.Removable = true
				v.Fixed = false
			}
		case "filevault", "encrypted":
			low := strings.ToLower(value)
			if strings.HasPrefix(low, "yes") {
				v.EncryptionState = EncryptionEncrypted
				v.ProtectionState = ProtectionEnabled
				v.EncryptionPercentage = percentDarwin(100)
				v.Confidence = evidence.ConfidenceExact
			}
			if strings.HasPrefix(low, "no") {
				v.EncryptionState = EncryptionUnencrypted
				v.ProtectionState = ProtectionDisabled
			}
		}
	}
}

func enrichDarwinFileVault(ctx context.Context, v *Volume, degraded *[]string) {
	fdesetup, err := exec.LookPath("fdesetup")
	if err != nil {
		v.Reason = appendReason(v.Reason, "fdesetup unavailable for FileVault system-volume status")
		*degraded = append(*degraded, "FileVault system-volume status unavailable: fdesetup not found")
		return
	}
	raw, err := exec.CommandContext(ctx, fdesetup, "status").CombinedOutput()
	if err != nil {
		v.Reason = appendReason(v.Reason, "fdesetup status unavailable")
		*degraded = append(*degraded, "FileVault system-volume status unavailable: "+err.Error())
		return
	}
	low := strings.ToLower(strings.TrimSpace(string(raw)))
	v.EncryptionProduct = "FileVault"
	switch {
	case strings.Contains(low, "encryption in progress"), strings.Contains(low, "decryption in progress"):
		v.EncryptionState, v.ProtectionState = EncryptionPartial, ProtectionEnabled
		v.Confidence = evidence.ConfidenceHigh
	case strings.Contains(low, "filevault is on"):
		v.EncryptionState, v.ProtectionState = EncryptionEncrypted, ProtectionEnabled
		v.EncryptionPercentage = percentDarwin(100)
		v.Confidence = evidence.ConfidenceExact
	case strings.Contains(low, "filevault is off"):
		v.EncryptionState, v.ProtectionState = EncryptionUnencrypted, ProtectionDisabled
		v.Confidence = evidence.ConfidenceExact
	default:
		v.Reason = appendReason(v.Reason, "unrecognized fdesetup status; state retained as observed/unknown")
	}
}

func percentDarwin(v float64) *float64 { return &v }
