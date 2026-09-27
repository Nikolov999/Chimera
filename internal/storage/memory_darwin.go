//go:build darwin

package storage

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectMemoryProtection(ctx context.Context, volumes []Volume) ([]SwapArea, HibernationPosture, []SourceStatus, []string) {
	swap, swapSource, swapDegraded := collectDarwinSwap(ctx, volumes)
	h, hSource, hDegraded := collectDarwinHibernation(ctx, volumes)
	return swap, h, []SourceStatus{swapSource, hSource}, uniqueSorted(append(swapDegraded, hDegraded...))
}

func collectDarwinSwap(ctx context.Context, volumes []Volume) ([]SwapArea, SourceStatus, []string) {
	sysctl, err := exec.LookPath("sysctl")
	if err != nil {
		reason := "sysctl unavailable for macOS swap posture"
		return nil, SourceStatus{ID: "macos-swap", State: evidence.StateUnavailable, Source: "sysctl vm.swapusage", Reason: reason}, []string{reason}
	}
	raw, err := exec.CommandContext(ctx, sysctl, "-n", "vm.swapusage").CombinedOutput()
	if err != nil {
		reason := "macOS swap posture unavailable: " + err.Error()
		return nil, SourceStatus{ID: "macos-swap", State: evidence.StateUnavailable, Source: "sysctl vm.swapusage", Reason: reason}, []string{reason}
	}
	total, used := parseDarwinSwapUsage(string(raw))
	if total == 0 {
		return nil, SourceStatus{ID: "macos-swap", State: evidence.StateObserved, Source: "sysctl vm.swapusage", ItemCount: 0}, nil
	}
	a := SwapArea{
		Path: "/private/var/vm/swapfile*", Kind: "SWAPFILES", SizeBytes: total, UsedBytes: used,
		Active: true, EncryptionState: EncryptionUnknown, State: evidence.StateObserved,
		CollectionSource: "sysctl vm.swapusage + containing-volume encryption context", Confidence: evidence.ConfidenceMedium,
	}
	low := strings.ToLower(string(raw))
	if strings.Contains(low, "encrypted") {
		a.EncryptionState = EncryptionEncrypted
		a.EncryptionProduct = "macOS encrypted swap"
		a.EncryptionBasis = "vm.swapusage explicitly reports encrypted swap"
		a.Confidence = evidence.ConfidenceExact
	} else if v, ok := volumeForPath(volumes, "/private/var/vm"); ok {
		if v.EncryptionState == EncryptionEncrypted && v.ProtectionState == ProtectionEnabled {
			a.EncryptionState = EncryptionEncrypted
			a.EncryptionProduct = fallback(v.EncryptionProduct, "FileVault/APFS")
			a.EncryptionBasis = "swap files reside on an encrypted volume with protection enabled"
			a.Confidence = v.Confidence
		} else {
			a.Reason = "vm.swapusage does not expose swap encryption and containing-volume protection is not confirmed"
		}
	} else {
		a.Reason = "swap-file backing volume could not be correlated"
	}
	degraded := []string{}
	state := evidence.StateObserved
	if a.EncryptionState == EncryptionUnknown {
		degraded = append(degraded, a.Reason)
		state = evidence.StateDegraded
	}
	return []SwapArea{a}, SourceStatus{ID: "macos-swap", State: state, Source: "sysctl vm.swapusage + storage volume correlation", ItemCount: 1, Reason: strings.Join(degraded, "; ")}, degraded
}

func parseDarwinSwapUsage(raw string) (total, used uint64) {
	fields := strings.Fields(strings.ReplaceAll(raw, "=", " = "))
	for i := 0; i+2 < len(fields); i++ {
		key := strings.ToLower(strings.TrimSpace(fields[i]))
		if fields[i+1] != "=" {
			continue
		}
		value := parseHumanBytes(fields[i+2])
		switch key {
		case "total":
			total = value
		case "used":
			used = value
		}
	}
	return total, used
}

func parseHumanBytes(v string) uint64 {
	v = strings.TrimSpace(strings.Trim(v, ","))
	if v == "" {
		return 0
	}
	unit := v[len(v)-1]
	num := v
	mult := float64(1)
	switch unit {
	case 'K', 'k':
		num, mult = v[:len(v)-1], 1024
	case 'M', 'm':
		num, mult = v[:len(v)-1], 1024*1024
	case 'G', 'g':
		num, mult = v[:len(v)-1], 1024*1024*1024
	case 'T', 't':
		num, mult = v[:len(v)-1], 1024*1024*1024*1024
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0
	}
	return uint64(f * mult)
}

func collectDarwinHibernation(ctx context.Context, volumes []Volume) (HibernationPosture, SourceStatus, []string) {
	pmset, err := exec.LookPath("pmset")
	if err != nil {
		reason := "pmset unavailable for macOS hibernation posture"
		h := HibernationPosture{SupportState: SupportUnknown, ConfigurationState: HibernationUnknown, ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown, FastStartupState: "NOT_APPLICABLE", DestroyFileVaultKeyOnStandby: "UNKNOWN", State: evidence.StateUnavailable, CollectionSource: "pmset -g custom + storage volume correlation", Confidence: evidence.ConfidenceMedium, Reason: reason}
		return h, SourceStatus{ID: "macos-hibernation", State: evidence.StateUnavailable, Source: h.CollectionSource, Reason: reason}, []string{reason}
	}
	raw, err := exec.CommandContext(ctx, pmset, "-g", "custom").CombinedOutput()
	if err != nil {
		raw, err = exec.CommandContext(ctx, pmset, "-g").CombinedOutput()
	}
	if err != nil {
		reason := "macOS hibernation posture unavailable: " + err.Error()
		h := HibernationPosture{SupportState: SupportUnknown, ConfigurationState: HibernationUnknown, ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown, FastStartupState: "NOT_APPLICABLE", DestroyFileVaultKeyOnStandby: "UNKNOWN", State: evidence.StateUnavailable, CollectionSource: "pmset metadata", Confidence: evidence.ConfidenceMedium, Reason: reason}
		return h, SourceStatus{ID: "macos-hibernation", State: evidence.StateUnavailable, Source: h.CollectionSource, Reason: reason}, []string{reason}
	}
	text := string(raw)
	modes := pmsetValues(text, "hibernatemode")
	files := pmsetValues(text, "hibernatefile")
	destroy := pmsetValues(text, "destroyfvkeyonstandby")
	h := HibernationPosture{
		SupportState: SupportUnknown, ConfigurationState: HibernationUnknown,
		ExposureState: ExposureUnknown, EncryptionState: EncryptionUnknown,
		FastStartupState: "NOT_APPLICABLE", DestroyFileVaultKeyOnStandby: aggregateBinaryState(destroy),
		State: evidence.StateObserved, CollectionSource: "pmset -g custom + storage volume correlation", Confidence: evidence.ConfidenceMedium,
	}
	if len(modes) > 0 {
		h.SupportState = SupportYes
		enabled := false
		for _, m := range modes {
			if n, err := strconv.Atoi(m); err == nil && n != 0 {
				enabled = true
			}
		}
		h.Mode = "HIBERNATEMODE=" + strings.Join(uniqueSorted(modes), ",")
		if enabled {
			h.ConfigurationState = HibernationEnabled
		} else {
			h.ConfigurationState = HibernationDisabled
			h.ExposureState = ExposureNotApplicable
			h.EncryptionState = EncryptionNotApplicable
			h.Confidence = evidence.ConfidenceHigh
		}
	}
	if len(files) > 0 {
		h.ImagePath = files[0]
	}
	degraded := []string{}
	if h.ConfigurationState == HibernationEnabled {
		path := h.ImagePath
		if path == "" {
			path = "/private/var/vm/sleepimage"
		}
		if v, ok := volumeForPath(volumes, path); ok {
			h.EncryptionState = v.EncryptionState
			h.ProtectionBasis = "hibernation image resides on " + fallback(v.EncryptionProduct, "the containing APFS volume")
			h.Confidence = v.Confidence
			if v.EncryptionState == EncryptionEncrypted && v.ProtectionState == ProtectionEnabled {
				h.ExposureState = ExposureProtected
			} else if v.EncryptionState == EncryptionUnencrypted || v.ProtectionState == ProtectionDisabled {
				h.ExposureState = ExposureExposed
			} else {
				h.Reason = fallback(v.Reason, "hibernation-image volume encryption/protection state is unresolved")
				degraded = append(degraded, h.Reason)
			}
		} else {
			h.Reason = "hibernation-image backing volume could not be correlated"
			degraded = append(degraded, h.Reason)
		}
	}
	if h.ConfigurationState == HibernationUnknown {
		h.Reason = appendReason(h.Reason, "pmset did not expose hibernatemode")
		degraded = append(degraded, h.Reason)
	}
	state := evidence.StateObserved
	if len(degraded) > 0 {
		state = evidence.StateDegraded
	}
	return h, SourceStatus{ID: "macos-hibernation", State: state, Source: h.CollectionSource, ItemCount: 1, Reason: strings.Join(uniqueSorted(degraded), "; ")}, degraded
}

func pmsetValues(raw, key string) []string {
	out := []string{}
	key = strings.ToLower(strings.TrimSpace(key))
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || strings.ToLower(fields[0]) != key {
			continue
		}
		out = append(out, strings.Join(fields[1:], " "))
	}
	return out
}

func aggregateBinaryState(values []string) string {
	if len(values) == 0 {
		return "UNKNOWN"
	}
	seenEnabled := false
	seenDisabled := false
	for _, v := range values {
		switch strings.TrimSpace(v) {
		case "1":
			seenEnabled = true
		case "0":
			seenDisabled = true
		}
	}
	if seenDisabled {
		return "DISABLED"
	}
	if seenEnabled {
		return "ENABLED"
	}
	return "UNKNOWN"
}

func darwinMemoryDebug(total, used uint64) string {
	return fmt.Sprintf("swap total=%d used=%d", total, used)
}
