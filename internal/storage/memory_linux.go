//go:build linux

package storage

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMemoryProtection(ctx context.Context, volumes []Volume) ([]SwapArea, HibernationPosture, []SourceStatus, []string) {
	swap, swapSource, swapDegraded := collectLinuxSwap(ctx, volumes)
	hibernation, hSource, hDegraded := collectLinuxHibernation(ctx, swap, volumes)
	return swap, hibernation, []SourceStatus{swapSource, hSource}, uniqueSorted(append(swapDegraded, hDegraded...))
}

func collectLinuxSwap(ctx context.Context, volumes []Volume) ([]SwapArea, SourceStatus, []string) {
	const source = "/proc/swaps"
	raw, err := os.ReadFile(source)
	if err != nil {
		state := evidence.StateUnavailable
		if os.IsPermission(err) {
			state = evidence.StateDenied
		}
		reason := "Linux active-swap inventory unavailable: " + err.Error()
		return nil, SourceStatus{ID: "linux-swap", State: state, Source: source, Reason: reason}, []string{reason}
	}
	areas := parseLinuxSwaps(string(raw), volumes)
	if ctx != nil && ctx.Err() != nil {
		reason := "Linux swap collection interrupted: " + ctx.Err().Error()
		return areas, SourceStatus{ID: "linux-swap", State: evidence.StateDegraded, Source: source + " + /sys/dev/block", ItemCount: len(areas), Reason: reason}, []string{reason}
	}
	degraded := []string{}
	for _, a := range areas {
		if a.EncryptionState == EncryptionUnknown || a.State != evidence.StateObserved {
			degraded = append(degraded, a.Path+": "+fallback(a.Reason, "swap encryption posture unresolved"))
		}
	}
	state := evidence.StateObserved
	reason := ""
	if len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return areas, SourceStatus{ID: "linux-swap", State: state, Source: source + " + /sys/dev/block + mounted-volume encryption context", ItemCount: len(areas), Reason: reason}, degraded
}

func parseLinuxSwaps(raw string, volumes []Volume) []SwapArea {
	out := []SwapArea{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(strings.ToLower(line), "filename") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		sizeKiB, _ := strconv.ParseUint(fields[2], 10, 64)
		usedKiB, _ := strconv.ParseUint(fields[3], 10, 64)
		a := SwapArea{
			Path: fields[0], Kind: strings.ToUpper(fields[1]), SizeBytes: sizeKiB * 1024,
			UsedBytes: usedKiB * 1024, Active: true, EncryptionState: EncryptionUnknown,
			State: evidence.StateObserved, CollectionSource: "/proc/swaps + /sys/dev/block + storage volume correlation",
			Confidence: evidence.ConfidenceMedium,
		}
		enrichLinuxSwapProtection(&a, volumes)
		out = append(out, a)
		if len(out) >= maxSwapAreas {
			break
		}
	}
	return out
}

func enrichLinuxSwapProtection(a *SwapArea, volumes []Volume) {
	if a == nil {
		return
	}
	low := strings.ToLower(strings.TrimSpace(a.Path))
	if strings.Contains(low, "/zram") || strings.Contains(low, "zram") {
		a.EncryptionState = EncryptionNotApplicable
		a.EncryptionProduct = "zram"
		a.EncryptionBasis = "volatile compressed RAM swap has no persistent at-rest backing"
		a.Confidence = evidence.ConfidenceExact
		return
	}
	if strings.HasPrefix(a.Path, "/dev/") {
		majorMinor, err := linuxDeviceMajorMinor(a.Path)
		if err != nil {
			a.Reason = "swap block-device identity unavailable: " + err.Error()
			return
		}
		enc, product, method, observed := linuxEncryptionStack(majorMinor, map[string]bool{})
		if !observed {
			a.Reason = "swap block-device encryption stack could not be resolved"
			return
		}
		if enc {
			a.EncryptionState = EncryptionEncrypted
			a.EncryptionProduct = product
			a.EncryptionBasis = method + " backing active swap device"
			a.Confidence = evidence.ConfidenceExact
			return
		}
		a.EncryptionState = EncryptionUnencrypted
		a.EncryptionProduct = "dm-crypt/LUKS"
		a.EncryptionBasis = "directly observable block stack contains no device-mapper CRYPT layer"
		a.Confidence = evidence.ConfidenceHigh
		return
	}
	if v, ok := volumeForPath(volumes, a.Path); ok {
		a.EncryptionState = v.EncryptionState
		a.EncryptionProduct = v.EncryptionProduct
		a.EncryptionBasis = "swap file inherits at-rest protection of containing volume " + fallback(v.MountPoint, v.Device)
		a.Confidence = v.Confidence
		if v.EncryptionState == EncryptionUnknown || v.EncryptionState == EncryptionPartial {
			a.Reason = appendReason(a.Reason, fallback(v.Reason, "containing-volume encryption state is unresolved"))
		}
		return
	}
	a.Reason = "swap-file backing volume could not be correlated to the normalized storage inventory"
}

func linuxDeviceMajorMinor(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("stat metadata does not expose Linux device identity")
	}
	dev := uint64(st.Rdev)
	major := ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)
	minor := (dev & 0xff) | ((dev >> 12) & 0xffffff00)
	return fmt.Sprintf("%d:%d", major, minor), nil
}

func collectLinuxHibernation(ctx context.Context, swap []SwapArea, volumes []Volume) (HibernationPosture, SourceStatus, []string) {
	const provider = "/sys/power/state + /sys/power/disk + /sys/power/resume + /proc/cmdline"
	h := HibernationPosture{
		SupportState: SupportUnknown, ConfigurationState: HibernationUnknown,
		ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown,
		FastStartupState: "NOT_APPLICABLE", DestroyFileVaultKeyOnStandby: "NOT_APPLICABLE",
		State: evidence.StateObserved, CollectionSource: provider, Confidence: evidence.ConfidenceMedium,
	}
	degraded := []string{}
	stateRaw, err := os.ReadFile("/sys/power/state")
	if err != nil {
		h.State = evidence.StateUnavailable
		if os.IsPermission(err) {
			h.State = evidence.StateDenied
		}
		h.Reason = "Linux hibernation capability metadata unavailable: " + err.Error()
		degraded = append(degraded, h.Reason)
		return h, SourceStatus{ID: "linux-hibernation", State: h.State, Source: provider, Reason: h.Reason}, degraded
	}
	states := strings.Fields(strings.ToLower(string(stateRaw)))
	if containsString(states, "disk") {
		h.SupportState = SupportYes
	} else {
		h.SupportState = SupportNo
		h.ConfigurationState = HibernationDisabled
		h.ExposureState = ExposureNotApplicable
		h.EncryptionState = EncryptionNotApplicable
		h.Confidence = evidence.ConfidenceExact
	}
	if raw, err := os.ReadFile("/sys/power/disk"); err == nil {
		h.Mode = strings.TrimSpace(string(raw))
	}
	resume := ""
	if raw, err := os.ReadFile("/sys/power/resume"); err == nil {
		resume = strings.TrimSpace(string(raw))
		if resume != "" && resume != "0:0" {
			h.ResumeTarget = resume
		}
	}
	cmdResume := ""
	if raw, err := os.ReadFile("/proc/cmdline"); err == nil {
		for _, token := range strings.Fields(string(raw)) {
			if strings.HasPrefix(token, "resume=") {
				cmdResume = strings.TrimSpace(strings.TrimPrefix(token, "resume="))
				if h.ResumeTarget == "" {
					h.ResumeTarget = cmdResume
				}
				break
			}
		}
	}
	if h.SupportState == SupportYes {
		if h.ResumeTarget != "" {
			h.ConfigurationState = HibernationEnabled
		} else if hasPersistentSwap(swap) {
			h.ConfigurationState = HibernationUnknown
			h.ExposureState = ExposureUnknown
			h.EncryptionState = EncryptionUnknown
			h.Reason = appendReason(h.Reason, "kernel supports hibernation and persistent swap exists, but no static resume target is observable; dynamic userspace resume policy may apply")
			degraded = append(degraded, h.Reason)
		} else {
			h.ConfigurationState = HibernationAvailableNotConfigured
			h.ExposureState = ExposureNotApplicable
			h.EncryptionState = EncryptionNotApplicable
			h.Confidence = evidence.ConfidenceHigh
		}
	}
	if h.ConfigurationState == HibernationEnabled {
		if area, ok := matchLinuxResumeSwap(resume, cmdResume, swap, volumes); ok {
			h.ImagePath = area.Path
			h.EncryptionState = area.EncryptionState
			h.ProtectionBasis = fallback(area.EncryptionBasis, area.EncryptionProduct)
			h.Confidence = area.Confidence
			switch area.EncryptionState {
			case EncryptionEncrypted:
				h.ExposureState = ExposureProtected
			case EncryptionUnencrypted:
				h.ExposureState = ExposureExposed
			case EncryptionNotApplicable:
				h.ExposureState = ExposureUnknown
				h.Reason = appendReason(h.Reason, "configured resume target is not persistent storage")
			default:
				h.ExposureState = ExposureUnknown
				h.Reason = appendReason(h.Reason, "configured hibernation target encryption is unresolved")
			}
		} else {
			h.ExposureState = ExposureUnknown
			h.EncryptionState = EncryptionUnknown
			h.Reason = appendReason(h.Reason, "configured Linux resume target could not be correlated to active swap/storage evidence")
			degraded = append(degraded, h.Reason)
		}
	}
	if ctx != nil && ctx.Err() != nil {
		h.State = evidence.StateDegraded
		h.Reason = appendReason(h.Reason, "Linux hibernation collection interrupted: "+ctx.Err().Error())
		degraded = append(degraded, h.Reason)
	}
	state := h.State
	if state == evidence.StateObserved && len(degraded) > 0 {
		state = evidence.StateDegraded
	}
	reason := ""
	if len(degraded) > 0 {
		reason = strings.Join(uniqueSorted(degraded), "; ")
	}
	return h, SourceStatus{ID: "linux-hibernation", State: state, Source: provider, ItemCount: 1, Reason: reason}, degraded
}

func matchLinuxResumeSwap(resumeMajorMinor, cmdResume string, swap []SwapArea, volumes []Volume) (SwapArea, bool) {
	cmdResume = strings.TrimSpace(cmdResume)
	for _, a := range swap {
		if cmdResume != "" && strings.EqualFold(strings.TrimSpace(a.Path), cmdResume) {
			return a, true
		}
		if resumeMajorMinor == "" || resumeMajorMinor == "0:0" {
			continue
		}
		if strings.HasPrefix(a.Path, "/dev/") {
			if mm, err := linuxDeviceMajorMinor(a.Path); err == nil && mm == resumeMajorMinor {
				return a, true
			}
			continue
		}
		if v, ok := volumeForPath(volumes, a.Path); ok && strings.TrimSpace(v.MajorMinor) == resumeMajorMinor {
			return a, true
		}
	}
	return SwapArea{}, false
}

func hasPersistentSwap(swap []SwapArea) bool {
	for _, area := range swap {
		if area.Active && area.EncryptionState != EncryptionNotApplicable {
			return true
		}
	}
	return false
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
