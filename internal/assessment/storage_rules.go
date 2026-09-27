package assessment

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
	stginv "github.com/Nikolov999/chimera/internal/storage"
)

// StorageRules contains the swap/hibernation protection checks plus
// the whole-volume encryption findings over the inventory.
// They consume normalized local metadata only and never inspect filesystem,
// page, swap, or hibernation-image contents.
func StorageRules() []Rule {
	return []Rule{
		{
			ID: "CHM-STG-001", Title: "Active swap and paging storage is protected at rest", Category: "storage", Severity: SeverityHigh,
			AffectedObject: "storage.swap", ExpectedState: "all active persistent swap/pagefile backing storage is encrypted or otherwise protected at rest",
			Risk:        "Persistent swap or paging storage can retain fragments of credentials, cryptographic material, documents, and process memory after shutdown or offline disk access.",
			Remediation: "Protect persistent swap/pagefile backing storage with the platform's supported full-volume or paging/swap encryption controls. Preserve operational recovery requirements and verify the resulting state before reassessment.",
			Evaluate:    evaluateSwapProtection,
		},
		{
			ID: "CHM-STG-002", Title: "Enabled hibernation state is protected at rest", Category: "storage", Severity: SeverityHigh,
			AffectedObject: "storage.hibernation", ExpectedState: "hibernation is disabled/not configured or its persistent image is protected by verified at-rest encryption",
			Risk:        "A hibernation or persistent sleep image can contain a broad snapshot of kernel and process memory, including sensitive security state, and can become an offline disclosure source when its backing storage is not protected.",
			Remediation: "Use supported full-volume encryption for the hibernation image or disable hibernation/persistent sleep where policy requires it. Reassess after changing the operating-system power configuration or storage protection.",
			Evaluate:    evaluateHibernationProtection,
		},
		{
			ID: "CHM-STG-003", Title: "System volume is protected by active at-rest encryption", Category: "storage", Severity: SeverityHigh,
			AffectedObject: "storage.system_volume.encryption", ExpectedState: "every observable system volume is fully encrypted and its encryption protection is enabled",
			Risk:        "An unencrypted system volume, or an encrypted system volume whose protection is disabled or suspended, can expose operating-system data, local security state, application data, and credentials to offline access outside normal host authentication controls.",
			Remediation: "Enable the platform-supported full-volume encryption mechanism for every system volume and ensure protection is active. Complete any in-progress encryption and restore suspended/disabled protectors before treating the volume as protected.",
			Evaluate:    evaluateSystemVolumeEncryption,
		},
		{
			ID: "CHM-STG-004", Title: "Fixed local data volumes are protected by active at-rest encryption", Category: "storage", Severity: SeverityMedium,
			AffectedObject: "storage.fixed_data_volume.encryption", ExpectedState: "observable fixed non-system local data volumes are fully encrypted and their encryption protection is enabled",
			Risk:        "Unencrypted fixed data volumes can retain documents, application state, caches, databases, backups, or security artifacts that remain readable through offline disk access even when the operating-system volume itself is protected.",
			Remediation: "Enable the platform-supported full-volume encryption mechanism on fixed local data volumes that hold persistent host data, complete any in-progress encryption, and restore disabled or suspended protection before reassessment.",
			Evaluate:    evaluateFixedDataVolumeEncryption,
		},
	}
}

type storageSwapEvidence struct {
	Key  string
	Area stginv.SwapArea
}

func evaluateSwapProtection(idx Index) Evaluation {
	areas := []storageSwapEvidence{}
	for key, obs := range idx {
		if !strings.HasPrefix(key, "storage.swap.") {
			continue
		}
		a, ok := obs.Value.(stginv.SwapArea)
		if !ok {
			continue
		}
		areas = append(areas, storageSwapEvidence{Key: key, Area: a})
	}
	sort.Slice(areas, func(i, j int) bool { return areas[i].Area.Path < areas[j].Area.Path })

	unprotected := []storageSwapEvidence{}
	unresolved := []storageSwapEvidence{}
	persistent := 0
	for _, item := range areas {
		if !item.Area.Active || item.Area.EncryptionState == stginv.EncryptionNotApplicable {
			continue
		}
		persistent++
		if item.Area.State != evidence.StateObserved {
			unresolved = append(unresolved, item)
			continue
		}
		switch item.Area.EncryptionState {
		case stginv.EncryptionEncrypted:
			// Protected.
		case stginv.EncryptionUnencrypted:
			unprotected = append(unprotected, item)
		default:
			unresolved = append(unresolved, item)
		}
	}
	if len(unprotected) > 0 {
		desc, keys := swapEvidenceDescriptions(unprotected)
		return Evaluation{Status: StatusFail, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d active persistent swap/pagefile area(s) are not protected at rest: %s", len(unprotected), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unresolved) > 0 {
		desc, keys := swapEvidenceDescriptions(unresolved)
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceMedium, ObservedState: fmt.Sprintf("swap/pagefile protection is unresolved for %d active persistent area(s): %s", len(unresolved), strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(areas) > 0 {
		keys := make([]string, 0, len(areas))
		for _, item := range areas {
			keys = append(keys, item.Key)
		}
		sort.Strings(keys)
		return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceHigh, ObservedState: fmt.Sprintf("%d active persistent swap/pagefile area(s) are protected at rest; volatile-only swap is excluded", persistent), Applicability: Applicable, EvidenceKeys: keys}
	}

	if src, ok := storageSwapSource(idx); ok {
		switch src.State {
		case evidence.StateObserved:
			return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: "no active persistent swap/pagefile areas were reported by the platform provider", Applicability: Applicable, EvidenceKeys: []string{src.Key}}
		case evidence.StateUnsupported, evidence.StateNotApplicable:
			return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: NotApplicable, EvidenceKeys: []string{src.Key}}
		default:
			return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
		}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "swap/pagefile protection evidence is missing", Applicability: Undetermined}
}

func evaluateHibernationProtection(idx Index) Evaluation {
	obs, ok := idx["storage.hibernation"]
	if !ok {
		return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "hibernation protection evidence is missing", Applicability: Undetermined}
	}
	if obs.State == evidence.StateUnsupported || obs.State == evidence.StateNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: obs.Confidence, ObservedState: observedText(obs), Applicability: NotApplicable, EvidenceKeys: []string{obs.Key}}
	}
	h, ok := obs.Value.(stginv.HibernationPosture)
	if !ok || obs.State != evidence.StateObserved {
		return Evaluation{Status: StatusUnknown, Confidence: obs.Confidence, ObservedState: observedText(obs), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
	}
	if h.SupportState == stginv.SupportNo || h.ConfigurationState == stginv.HibernationNotApplicable {
		return Evaluation{Status: StatusPass, Confidence: h.Confidence, ObservedState: "persistent hibernation is not applicable on this host", Applicability: NotApplicable, EvidenceKeys: []string{obs.Key}}
	}
	switch h.ConfigurationState {
	case stginv.HibernationDisabled, stginv.HibernationAvailableNotConfigured:
		return Evaluation{Status: StatusPass, Confidence: h.Confidence, ObservedState: "persistent hibernation is disabled or not configured", Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
	case stginv.HibernationEnabled:
		switch h.ExposureState {
		case stginv.ExposureProtected:
			return Evaluation{Status: StatusPass, Confidence: h.Confidence, ObservedState: "enabled hibernation/persistent sleep state is backed by protected storage: " + fallbackAssessment(h.ProtectionBasis, h.EncryptionState), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
		case stginv.ExposureExposed:
			return Evaluation{Status: StatusFail, Confidence: h.Confidence, ObservedState: "enabled hibernation/persistent sleep state is backed by unprotected storage: " + fallbackAssessment(h.ProtectionBasis, h.EncryptionState), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
		default:
			return Evaluation{Status: StatusUnknown, Confidence: h.Confidence, ObservedState: "hibernation is enabled but persistent-image protection is unresolved: " + fallbackAssessment(h.Reason, h.EncryptionState), Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
		}
	default:
		return Evaluation{Status: StatusUnknown, Confidence: h.Confidence, ObservedState: "hibernation configuration state is unresolved: " + h.ConfigurationState, Applicability: Applicable, EvidenceKeys: []string{obs.Key}}
	}
}

func storageSwapSource(idx Index) (evidence.Observation, bool) {
	for _, key := range []string{"storage.source.linux-swap", "storage.source.macos-swap", "storage.source.windows-memory-state", "storage.source.platform-memory-state"} {
		if obs, ok := idx[key]; ok {
			return obs, true
		}
	}
	return evidence.Observation{}, false
}

func swapEvidenceDescriptions(items []storageSwapEvidence) ([]string, []string) {
	desc := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		detail := item.Area.Path + " [" + item.Area.EncryptionState + "]"
		if item.Area.Reason != "" {
			detail += " [" + item.Area.Reason + "]"
		}
		desc = append(desc, detail)
		keys = append(keys, item.Key)
	}
	sort.Strings(desc)
	sort.Strings(keys)
	return desc, keys
}

func fallbackAssessment(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

type storageVolumeEvidence struct {
	Key    string
	Volume stginv.Volume
}

func evaluateSystemVolumeEncryption(idx Index) Evaluation {
	return evaluateVolumeEncryptionClass(idx, func(v stginv.Volume) bool { return v.SystemVolume }, "system volume")
}

func evaluateFixedDataVolumeEncryption(idx Index) Evaluation {
	return evaluateVolumeEncryptionClass(idx, func(v stginv.Volume) bool { return v.Fixed && !v.SystemVolume && !v.Removable }, "fixed non-system data volume")
}

func evaluateVolumeEncryptionClass(idx Index, relevant func(stginv.Volume) bool, label string) Evaluation {
	items := storageVolumeItems(idx, relevant)
	fail := make([]storageVolumeEvidence, 0)
	warn := make([]storageVolumeEvidence, 0)
	unknown := make([]storageVolumeEvidence, 0)
	protected := make([]storageVolumeEvidence, 0)

	for _, item := range items {
		v := item.Volume
		if v.State != evidence.StateObserved {
			unknown = append(unknown, item)
			continue
		}
		switch v.EncryptionState {
		case stginv.EncryptionUnencrypted:
			fail = append(fail, item)
		case stginv.EncryptionPartial:
			warn = append(warn, item)
		case stginv.EncryptionEncrypted:
			switch v.ProtectionState {
			case stginv.ProtectionDisabled, stginv.ProtectionSuspended:
				fail = append(fail, item)
			case stginv.ProtectionEnabled:
				protected = append(protected, item)
			default:
				unknown = append(unknown, item)
			}
		case stginv.EncryptionNotApplicable:
			// A relevant persistent system/fixed data volume should expose a real
			// encryption applicability state. Keep inconsistent metadata unknown.
			unknown = append(unknown, item)
		default:
			unknown = append(unknown, item)
		}
	}

	if len(fail) > 0 {
		desc, keys := storageVolumeDescriptions(fail)
		return Evaluation{Status: StatusFail, Confidence: storageVolumeConfidence(fail), ObservedState: fmt.Sprintf("%d %s(s) have unencrypted or inactive encryption protection: %s", len(fail), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(warn) > 0 {
		desc, keys := storageVolumeDescriptions(warn)
		return Evaluation{Status: StatusWarn, Confidence: storageVolumeConfidence(warn), ObservedState: fmt.Sprintf("%d %s(s) have partial/in-progress encryption state: %s", len(warn), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(unknown) > 0 {
		desc, keys := storageVolumeDescriptions(unknown)
		return Evaluation{Status: StatusUnknown, Confidence: storageVolumeConfidence(unknown), ObservedState: fmt.Sprintf("encryption protection is unresolved for %d %s(s): %s", len(unknown), label, strings.Join(desc, "; ")), Applicability: Applicable, EvidenceKeys: keys}
	}
	if len(protected) > 0 {
		_, keys := storageVolumeDescriptions(protected)
		return Evaluation{Status: StatusPass, Confidence: storageVolumeConfidence(protected), ObservedState: fmt.Sprintf("%d %s(s) are fully encrypted with active protection", len(protected), label), Applicability: Applicable, EvidenceKeys: keys}
	}

	if src, ok := storageVolumeSource(idx); ok {
		switch src.State {
		case evidence.StateObserved:
			return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: "no " + label + " was reported by the platform storage provider", Applicability: NotApplicable, EvidenceKeys: []string{src.Key}}
		case evidence.StateUnsupported, evidence.StateNotApplicable:
			return Evaluation{Status: StatusPass, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: NotApplicable, EvidenceKeys: []string{src.Key}}
		default:
			return Evaluation{Status: StatusUnknown, Confidence: src.Confidence, ObservedState: observedText(src), Applicability: Applicable, EvidenceKeys: []string{src.Key}}
		}
	}
	return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: label + " encryption evidence is missing", Applicability: Undetermined}
}

func storageVolumeItems(idx Index, relevant func(stginv.Volume) bool) []storageVolumeEvidence {
	out := make([]storageVolumeEvidence, 0)
	for key, obs := range idx {
		if !strings.HasPrefix(key, "storage.volume.") {
			continue
		}
		v, ok := obs.Value.(stginv.Volume)
		if !ok || !relevant(v) {
			continue
		}
		out = append(out, storageVolumeEvidence{Key: key, Volume: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Volume.MountPoint != out[j].Volume.MountPoint {
			return out[i].Volume.MountPoint < out[j].Volume.MountPoint
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func storageVolumeDescriptions(items []storageVolumeEvidence) ([]string, []string) {
	const maxDescriptions = 12
	desc := make([]string, 0, len(items))
	keys := make([]string, 0, len(items))
	for i, item := range items {
		if i < maxDescriptions {
			v := item.Volume
			name := strings.TrimSpace(v.MountPoint)
			if name == "" {
				name = strings.TrimSpace(v.Device)
			}
			if name == "" {
				name = v.ID
			}
			detail := fmt.Sprintf("%s [%s/%s", name, v.EncryptionState, v.ProtectionState)
			if v.EncryptionProduct != "" {
				detail += "; " + v.EncryptionProduct
			}
			if v.Reason != "" {
				detail += "; " + v.Reason
			}
			detail += "]"
			desc = append(desc, detail)
		}
		keys = append(keys, item.Key)
	}
	if len(items) > maxDescriptions {
		desc = append(desc, fmt.Sprintf("+%d more", len(items)-maxDescriptions))
	}
	sort.Strings(keys)
	return desc, keys
}

func storageVolumeConfidence(items []storageVolumeEvidence) evidence.Confidence {
	if len(items) == 0 {
		return evidence.ConfidenceLow
	}
	rank := func(c evidence.Confidence) int {
		switch c {
		case evidence.ConfidenceExact:
			return 4
		case evidence.ConfidenceHigh:
			return 3
		case evidence.ConfidenceMedium:
			return 2
		case evidence.ConfidenceLow:
			return 1
		default:
			return 0
		}
	}
	best := items[0].Volume.Confidence
	for _, item := range items[1:] {
		if rank(item.Volume.Confidence) < rank(best) {
			best = item.Volume.Confidence
		}
	}
	if best == "" {
		return evidence.ConfidenceLow
	}
	return best
}

func storageVolumeSource(idx Index) (evidence.Observation, bool) {
	for _, key := range []string{"storage.source.windows-bitlocker", "storage.source.linux-mounts", "storage.source.macos-storage"} {
		if obs, ok := idx[key]; ok {
			return obs, true
		}
	}
	return evidence.Observation{}, false
}
