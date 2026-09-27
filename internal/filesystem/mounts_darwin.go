//go:build darwin

package filesystem

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformMounts(ctx context.Context) ([]MountBoundary, SourceStatus, []string) {
	path, err := exec.LookPath("mount")
	if err != nil {
		reason := "mount utility unavailable: " + err.Error()
		return nil, SourceStatus{ID: "mount-boundaries", State: evidence.StateUnavailable, Source: "mount", Reason: reason}, []string{reason}
	}
	raw, err := exec.CommandContext(ctx, path).Output()
	if err != nil {
		reason := "mount/volume inventory failed: " + err.Error()
		return nil, SourceStatus{ID: "mount-boundaries", State: evidence.StateUnavailable, Source: path, Reason: reason}, []string{reason}
	}
	out := []MountBoundary{}
	for _, line := range strings.Split(string(raw), "\n") {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		if m, ok := parseDarwinMountLine(line); ok {
			enrichDarwinMount(ctx, &m)
			out = append(out, m)
		}
		if len(out) >= maxMounts {
			break
		}
	}
	degraded := []string{}
	state := evidence.StateObserved
	reason := ""
	if ctx != nil && ctx.Err() != nil {
		reason = "mount/volume inventory interrupted: " + ctx.Err().Error()
		degraded = append(degraded, reason)
		state = evidence.StateDegraded
	}
	return out, SourceStatus{ID: "mount-boundaries", State: state, Source: path + " + optional diskutil metadata", ItemCount: len(out), Reason: reason}, degraded
}

func parseDarwinMountLine(line string) (MountBoundary, bool) {
	line = strings.TrimSpace(line)
	on := strings.Index(line, " on ")
	if on <= 0 {
		return MountBoundary{}, false
	}
	device := strings.TrimSpace(line[:on])
	rest := line[on+4:]
	open := strings.LastIndex(rest, " (")
	close := strings.LastIndex(rest, ")")
	if open <= 0 || close <= open {
		return MountBoundary{}, false
	}
	path := strings.TrimSpace(rest[:open])
	opts := []string{}
	for _, v := range strings.Split(rest[open+2:close], ",") {
		opts = append(opts, strings.TrimSpace(v))
	}
	fs := ""
	if len(opts) > 0 {
		fs = opts[0]
	}
	access := MountAccessReadWrite
	if containsStringFold(opts, "read-only") || containsStringFold(opts, "ro") {
		access = MountAccessReadOnly
	}
	class := classifyMount(fs, device, false, false)
	if containsStringFold(opts, "local") && class == MountClassUnknown {
		class = MountClassLocal
	}
	enc := MountEncryptionUnknown
	encType := ""
	encEvidence := ""
	if containsStringFold(opts, "encrypted") {
		enc = MountEncryptionEncrypted
		encType = "mounted-volume encryption"
		encEvidence = "mount option reports encrypted volume"
	} else if class == MountClassVirtual || class == MountClassOptical {
		enc = MountEncryptionNotApplicable
	}
	return MountBoundary{
		Path: path, Device: device, BackingSource: device, Filesystem: fs, Options: opts,
		AccessMode: access, ReadOnly: access == MountAccessReadOnly, Writable: access == MountAccessReadWrite,
		Classification: class, Network: class == MountClassNetwork,
		EncryptionState: enc, EncryptionType: encType, EncryptionEvidence: encEvidence,
		State: evidence.StateObserved, CollectionSource: "mount", Confidence: evidence.ConfidenceHigh,
	}, true
}

func enrichDarwinMount(ctx context.Context, m *MountBoundary) {
	if m == nil || !strings.HasPrefix(m.Device, "/dev/") {
		return
	}
	diskutil, err := exec.LookPath("diskutil")
	if err != nil {
		return
	}
	raw, err := exec.CommandContext(ctx, diskutil, "info", m.Device).Output()
	if err != nil {
		return
	}
	m.CollectionSource = "mount + diskutil info"
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "volume name":
			if value != "" && value != "Not applicable (no file system)" {
				m.VolumeLabel = value
			}
		case "removable media":
			low := strings.ToLower(value)
			if strings.Contains(low, "removable") || strings.Contains(low, "yes") {
				m.Removable = true
				m.Classification = MountClassRemovable
			} else if strings.Contains(low, "fixed") || strings.Contains(low, "no") {
				if m.Classification == MountClassUnknown {
					m.Classification = MountClassLocal
				}
			}
		case "device location":
			if strings.EqualFold(value, "External") {
				m.Removable = true
				m.Classification = MountClassRemovable
			}
		case "filevault", "encrypted":
			if strings.HasPrefix(strings.ToLower(value), "yes") {
				m.EncryptionState = MountEncryptionEncrypted
				m.EncryptionType = "FileVault/APFS volume encryption"
				m.EncryptionEvidence = "diskutil reports encrypted volume"
			} else if strings.HasPrefix(strings.ToLower(value), "no") && m.EncryptionState == MountEncryptionUnknown {
				m.EncryptionState = MountEncryptionNotObserved
				m.EncryptionEvidence = "diskutil does not report volume encryption"
			}
		}
	}
}
