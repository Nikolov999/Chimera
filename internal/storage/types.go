package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.storage/v1"
	CollectorName    = "storage-encryption"
	CollectorVersion = "storage/phase084-v1"
	maxVolumes       = 1024
	maxSwapAreas     = 128

	EncryptionEncrypted     = "ENCRYPTED"
	EncryptionUnencrypted   = "UNENCRYPTED"
	EncryptionPartial       = "PARTIAL"
	EncryptionUnknown       = "UNKNOWN"
	EncryptionNotApplicable = "NOT_APPLICABLE"

	ProtectionEnabled       = "ENABLED"
	ProtectionDisabled      = "DISABLED"
	ProtectionSuspended     = "SUSPENDED"
	ProtectionUnknown       = "UNKNOWN"
	ProtectionNotApplicable = "NOT_APPLICABLE"

	LockUnlocked      = "UNLOCKED"
	LockLocked        = "LOCKED"
	LockUnknown       = "UNKNOWN"
	LockNotApplicable = "NOT_APPLICABLE"

	SupportYes     = "YES"
	SupportNo      = "NO"
	SupportUnknown = "UNKNOWN"

	HibernationEnabled                = "ENABLED"
	HibernationDisabled               = "DISABLED"
	HibernationAvailableNotConfigured = "AVAILABLE_NOT_CONFIGURED"
	HibernationUnknown                = "UNKNOWN"
	HibernationNotApplicable          = "NOT_APPLICABLE"

	ExposureProtected     = "PROTECTED"
	ExposureExposed       = "EXPOSED"
	ExposureUnknown       = "UNKNOWN"
	ExposureNotApplicable = "NOT_APPLICABLE"
)

type Volume struct {
	ID                   string              `json:"id"`
	MountPoint           string              `json:"mount_point,omitempty"`
	Device               string              `json:"device,omitempty"`
	VolumeName           string              `json:"volume_name,omitempty"`
	MajorMinor           string              `json:"major_minor,omitempty"`
	Filesystem           string              `json:"filesystem,omitempty"`
	SystemVolume         bool                `json:"system_volume"`
	Fixed                bool                `json:"fixed"`
	Removable            bool                `json:"removable"`
	EncryptionProduct    string              `json:"encryption_product,omitempty"`
	EncryptionState      string              `json:"encryption_state"`
	ProtectionState      string              `json:"protection_state"`
	LockState            string              `json:"lock_state"`
	EncryptionPercentage *float64            `json:"encryption_percentage,omitempty"`
	EncryptionMethod     string              `json:"encryption_method,omitempty"`
	AutoUnlock           string              `json:"auto_unlock,omitempty"`
	State                evidence.State      `json:"state"`
	CollectionSource     string              `json:"collection_source"`
	Confidence           evidence.Confidence `json:"confidence"`
	Reason               string              `json:"reason,omitempty"`
}

// SwapArea describes active paging/swap storage without reading any page data.
// EncryptionState reflects the defensible at-rest protection of the backing
// storage, including a protected containing volume when the platform exposes it.
type SwapArea struct {
	ID                string              `json:"id"`
	Path              string              `json:"path"`
	Kind              string              `json:"kind"`
	SizeBytes         uint64              `json:"size_bytes,omitempty"`
	UsedBytes         uint64              `json:"used_bytes,omitempty"`
	Active            bool                `json:"active"`
	EncryptionState   string              `json:"encryption_state"`
	EncryptionProduct string              `json:"encryption_product,omitempty"`
	EncryptionBasis   string              `json:"encryption_basis,omitempty"`
	State             evidence.State      `json:"state"`
	CollectionSource  string              `json:"collection_source"`
	Confidence        evidence.Confidence `json:"confidence"`
	Reason            string              `json:"reason,omitempty"`
}

// HibernationPosture describes whether persistent sleep/hibernation state is
// enabled and whether its backing storage is protected at rest. It never reads
// hibernation-image contents.
type HibernationPosture struct {
	SupportState                 string              `json:"support_state"`
	ConfigurationState           string              `json:"configuration_state"`
	Mode                         string              `json:"mode,omitempty"`
	ImagePath                    string              `json:"image_path,omitempty"`
	ResumeTarget                 string              `json:"resume_target,omitempty"`
	ExposureState                string              `json:"exposure_state"`
	EncryptionState              string              `json:"encryption_state"`
	ProtectionBasis              string              `json:"protection_basis,omitempty"`
	FastStartupState             string              `json:"fast_startup_state,omitempty"`
	DestroyFileVaultKeyOnStandby string              `json:"destroy_filevault_key_on_standby,omitempty"`
	State                        evidence.State      `json:"state"`
	CollectionSource             string              `json:"collection_source"`
	Confidence                   evidence.Confidence `json:"confidence"`
	Reason                       string              `json:"reason,omitempty"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Volumes                  int    `json:"volumes"`
	SystemVolumes            int    `json:"system_volumes"`
	EncryptedVolumes         int    `json:"encrypted_volumes"`
	UnencryptedVolumes       int    `json:"unencrypted_volumes"`
	PartialVolumes           int    `json:"partial_volumes"`
	UnknownVolumes           int    `json:"unknown_volumes"`
	ProtectionEnabled        int    `json:"protection_enabled"`
	ProtectionDisabled       int    `json:"protection_disabled"`
	ProtectionSuspended      int    `json:"protection_suspended"`
	RemovableVolumes         int    `json:"removable_volumes"`
	UnavailableMetadata      int    `json:"unavailable_metadata"`
	SwapAreas                int    `json:"swap_areas"`
	EncryptedSwapAreas       int    `json:"encrypted_swap_areas"`
	UnencryptedSwapAreas     int    `json:"unencrypted_swap_areas"`
	UnknownSwapAreas         int    `json:"unknown_swap_areas"`
	VolatileSwapAreas        int    `json:"volatile_swap_areas"`
	HibernationConfiguration string `json:"hibernation_configuration"`
	HibernationExposure      string `json:"hibernation_exposure"`
}

type Inventory struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Volumes          []Volume               `json:"volumes"`
	SwapAreas        []SwapArea             `json:"swap_areas"`
	Hibernation      HibernationPosture     `json:"hibernation"`
	Sources          []SourceStatus         `json:"sources"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	volumes, sources, degraded := collectPlatform(ctx)
	volumes = normalizeVolumes(volumes)
	swap, hibernation, memorySources, memoryDegraded := collectMemoryProtection(ctx, volumes)
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion,
		Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at,
		Volumes: volumes, SwapAreas: normalizeSwapAreas(swap), Hibernation: normalizeHibernation(hibernation),
		Sources: normalizeSources(append(sources, memorySources...)), Degraded: uniqueSorted(append(degraded, memoryDegraded...)),
	}
	inv.Summary = summarize(inv.Volumes, inv.SwapAreas, inv.Hibernation)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected storage collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("storage inventory identity is incomplete")
	}
	if len(inv.Volumes) > maxVolumes || len(inv.SwapAreas) > maxSwapAreas {
		return fmt.Errorf("storage inventory exceeds bounded record limits")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, v := range inv.Volumes {
		if v.ID == "" || v.State == "" || strings.TrimSpace(v.EncryptionState) == "" || strings.TrimSpace(v.ProtectionState) == "" || strings.TrimSpace(v.LockState) == "" || strings.TrimSpace(v.CollectionSource) == "" || v.Confidence == "" {
			return fmt.Errorf("storage volume record %d is incomplete", i)
		}
		if !validEncryptionState(v.EncryptionState) || !validProtectionState(v.ProtectionState) || !validLockState(v.LockState) {
			return fmt.Errorf("storage volume record %q has invalid normalized posture", v.ID)
		}
		if _, ok := seen[v.ID]; ok {
			return fmt.Errorf("duplicate storage volume id %q", v.ID)
		}
		seen[v.ID] = struct{}{}
		key := volumeSortKey(v)
		if last != "" && key < last {
			return fmt.Errorf("storage volumes are not deterministically ordered")
		}
		last = key
	}
	seen = map[string]struct{}{}
	last = ""
	for i, s := range inv.SwapAreas {
		if s.ID == "" || strings.TrimSpace(s.Path) == "" || strings.TrimSpace(s.Kind) == "" || strings.TrimSpace(s.EncryptionState) == "" || s.State == "" || strings.TrimSpace(s.CollectionSource) == "" || s.Confidence == "" {
			return fmt.Errorf("swap record %d is incomplete", i)
		}
		if !validEncryptionState(s.EncryptionState) {
			return fmt.Errorf("swap record %q has invalid encryption state", s.ID)
		}
		if _, ok := seen[s.ID]; ok {
			return fmt.Errorf("duplicate swap id %q", s.ID)
		}
		seen[s.ID] = struct{}{}
		key := swapSortKey(s)
		if last != "" && key < last {
			return fmt.Errorf("swap records are not deterministically ordered")
		}
		last = key
	}
	if err := validateHibernation(inv.Hibernation); err != nil {
		return err
	}
	if inv.Summary != summarize(inv.Volumes, inv.SwapAreas, inv.Hibernation) {
		return fmt.Errorf("storage summary does not match inventory")
	}
	if err := evidence.ValidateAll(inv.Evidence); err != nil {
		return fmt.Errorf("validate storage evidence: %w", err)
	}
	return nil
}

func normalizeVolumes(in []Volume) []Volume {
	out := make([]Volume, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v.MountPoint = strings.TrimSpace(v.MountPoint)
		v.Device = strings.TrimSpace(v.Device)
		v.VolumeName = strings.TrimSpace(v.VolumeName)
		v.MajorMinor = strings.TrimSpace(v.MajorMinor)
		v.Filesystem = strings.TrimSpace(v.Filesystem)
		v.EncryptionProduct = strings.TrimSpace(v.EncryptionProduct)
		v.EncryptionState = normalizeToken(v.EncryptionState, EncryptionUnknown)
		v.ProtectionState = normalizeToken(v.ProtectionState, ProtectionUnknown)
		v.LockState = normalizeToken(v.LockState, LockUnknown)
		v.EncryptionMethod = strings.TrimSpace(v.EncryptionMethod)
		v.AutoUnlock = strings.TrimSpace(v.AutoUnlock)
		v.CollectionSource = strings.TrimSpace(v.CollectionSource)
		v.Reason = strings.TrimSpace(v.Reason)
		if v.State == "" {
			v.State = evidence.StateObserved
		}
		if v.Confidence == "" {
			v.Confidence = evidence.ConfidenceMedium
		}
		if v.CollectionSource == "" {
			v.CollectionSource = "platform storage provider"
		}
		if v.ID == "" {
			v.ID = stableVolumeID(v.MountPoint, v.Device, v.VolumeName)
		}
		if _, ok := seen[v.ID]; ok {
			continue
		}
		seen[v.ID] = struct{}{}
		out = append(out, v)
		if len(out) >= maxVolumes {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return volumeSortKey(out[i]) < volumeSortKey(out[j]) })
	return out
}

func normalizeSwapAreas(in []SwapArea) []SwapArea {
	out := make([]SwapArea, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s.Path = strings.TrimSpace(s.Path)
		if s.Path == "" {
			continue
		}
		s.Kind = strings.ToUpper(strings.TrimSpace(s.Kind))
		if s.Kind == "" {
			s.Kind = "UNKNOWN"
		}
		s.EncryptionState = normalizeToken(s.EncryptionState, EncryptionUnknown)
		s.EncryptionProduct = strings.TrimSpace(s.EncryptionProduct)
		s.EncryptionBasis = strings.TrimSpace(s.EncryptionBasis)
		s.CollectionSource = strings.TrimSpace(s.CollectionSource)
		s.Reason = strings.TrimSpace(s.Reason)
		if s.State == "" {
			s.State = evidence.StateObserved
		}
		if s.Confidence == "" {
			s.Confidence = evidence.ConfidenceMedium
		}
		if s.CollectionSource == "" {
			s.CollectionSource = "platform swap provider"
		}
		if s.ID == "" {
			s.ID = stableSwapID(s.Path, s.Kind)
		}
		if _, ok := seen[s.ID]; ok {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
		if len(out) >= maxSwapAreas {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return swapSortKey(out[i]) < swapSortKey(out[j]) })
	return out
}

func normalizeHibernation(h HibernationPosture) HibernationPosture {
	h.SupportState = normalizeToken(h.SupportState, SupportUnknown)
	h.ConfigurationState = normalizeToken(h.ConfigurationState, HibernationUnknown)
	h.Mode = strings.TrimSpace(h.Mode)
	h.ImagePath = strings.TrimSpace(h.ImagePath)
	h.ResumeTarget = strings.TrimSpace(h.ResumeTarget)
	h.ExposureState = normalizeToken(h.ExposureState, ExposureUnknown)
	h.EncryptionState = normalizeToken(h.EncryptionState, EncryptionUnknown)
	h.ProtectionBasis = strings.TrimSpace(h.ProtectionBasis)
	h.FastStartupState = normalizeOptionalState(h.FastStartupState)
	h.DestroyFileVaultKeyOnStandby = normalizeOptionalState(h.DestroyFileVaultKeyOnStandby)
	h.CollectionSource = strings.TrimSpace(h.CollectionSource)
	h.Reason = strings.TrimSpace(h.Reason)
	if h.State == "" {
		h.State = evidence.StateObserved
	}
	if h.Confidence == "" {
		h.Confidence = evidence.ConfidenceMedium
	}
	if h.CollectionSource == "" {
		h.CollectionSource = "platform hibernation provider"
	}
	return h
}

func normalizeOptionalState(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func summarize(volumes []Volume, swap []SwapArea, h HibernationPosture) Summary {
	var s Summary
	s.Volumes = len(volumes)
	for _, v := range volumes {
		if v.SystemVolume {
			s.SystemVolumes++
		}
		if v.Removable {
			s.RemovableVolumes++
		}
		switch v.EncryptionState {
		case EncryptionEncrypted:
			s.EncryptedVolumes++
		case EncryptionUnencrypted:
			s.UnencryptedVolumes++
		case EncryptionPartial:
			s.PartialVolumes++
		case EncryptionUnknown:
			s.UnknownVolumes++
		}
		switch v.ProtectionState {
		case ProtectionEnabled:
			s.ProtectionEnabled++
		case ProtectionDisabled:
			s.ProtectionDisabled++
		case ProtectionSuspended:
			s.ProtectionSuspended++
		}
		if v.State != evidence.StateObserved {
			s.UnavailableMetadata++
		}
	}
	s.SwapAreas = len(swap)
	for _, a := range swap {
		switch a.EncryptionState {
		case EncryptionEncrypted:
			s.EncryptedSwapAreas++
		case EncryptionUnencrypted:
			s.UnencryptedSwapAreas++
		case EncryptionUnknown, EncryptionPartial:
			s.UnknownSwapAreas++
		case EncryptionNotApplicable:
			s.VolatileSwapAreas++
		}
		if a.State != evidence.StateObserved {
			s.UnavailableMetadata++
		}
	}
	s.HibernationConfiguration = h.ConfigurationState
	s.HibernationExposure = h.ExposureState
	if h.State != evidence.StateObserved {
		s.UnavailableMetadata++
	}
	return s
}

func buildEvidence(inv Inventory) []evidence.Observation {
	out := []evidence.Observation{
		evidence.NewObserved("storage.summary", inv.Summary, "storage encryption and memory-state inventory", inv.CollectedAt, evidence.ConfidenceHigh),
	}
	for _, src := range inv.Sources {
		key := "storage.source." + src.ID
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, src, src.Source, inv.CollectedAt, evidence.ConfidenceHigh))
		} else {
			out = append(out, evidence.NewState(key, src.State, src.Source, inv.CollectedAt, evidence.ConfidenceMedium, fallback(src.Reason, "storage provider unavailable")))
		}
	}
	for _, v := range inv.Volumes {
		key := "storage.volume." + v.ID
		if v.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, v, v.CollectionSource, inv.CollectedAt, v.Confidence))
		} else {
			out = append(out, evidence.NewState(key, v.State, v.CollectionSource, inv.CollectedAt, v.Confidence, fallback(v.Reason, "storage encryption metadata unavailable")))
		}
	}
	for _, s := range inv.SwapAreas {
		key := "storage.swap." + s.ID
		if s.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, s, s.CollectionSource, inv.CollectedAt, s.Confidence))
		} else {
			out = append(out, evidence.NewState(key, s.State, s.CollectionSource, inv.CollectedAt, s.Confidence, fallback(s.Reason, "swap protection metadata unavailable")))
		}
	}
	if inv.Hibernation.State == evidence.StateObserved {
		out = append(out, evidence.NewObserved("storage.hibernation", inv.Hibernation, inv.Hibernation.CollectionSource, inv.CollectedAt, inv.Hibernation.Confidence))
	} else {
		out = append(out, evidence.NewState("storage.hibernation", inv.Hibernation.State, inv.Hibernation.CollectionSource, inv.CollectedAt, inv.Hibernation.Confidence, fallback(inv.Hibernation.Reason, "hibernation protection metadata unavailable")))
	}
	return out
}

func stableVolumeID(mountPoint, device, name string) string {
	raw := strings.ToLower(strings.TrimSpace(mountPoint)) + "\x00" + strings.ToLower(strings.TrimSpace(device)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
	sum := sha256.Sum256([]byte(raw))
	return "stg-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

func stableSwapID(path, kind string) string {
	raw := strings.ToLower(strings.TrimSpace(path)) + "\x00" + strings.ToUpper(strings.TrimSpace(kind))
	sum := sha256.Sum256([]byte(raw))
	return "swp-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

func volumeSortKey(v Volume) string {
	return strings.ToLower(v.MountPoint) + "|" + strings.ToLower(v.Device) + "|" + v.ID
}

func swapSortKey(s SwapArea) string {
	return strings.ToLower(s.Path) + "|" + strings.ToUpper(s.Kind) + "|" + s.ID
}

func normalizeToken(v, fallbackValue string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return fallbackValue
	}
	return v
}

func validEncryptionState(v string) bool {
	switch v {
	case EncryptionEncrypted, EncryptionUnencrypted, EncryptionPartial, EncryptionUnknown, EncryptionNotApplicable:
		return true
	}
	return false
}
func validProtectionState(v string) bool {
	switch v {
	case ProtectionEnabled, ProtectionDisabled, ProtectionSuspended, ProtectionUnknown, ProtectionNotApplicable:
		return true
	}
	return false
}
func validLockState(v string) bool {
	switch v {
	case LockUnlocked, LockLocked, LockUnknown, LockNotApplicable:
		return true
	}
	return false
}
func validSupportState(v string) bool {
	return v == SupportYes || v == SupportNo || v == SupportUnknown
}
func validHibernationState(v string) bool {
	switch v {
	case HibernationEnabled, HibernationDisabled, HibernationAvailableNotConfigured, HibernationUnknown, HibernationNotApplicable:
		return true
	}
	return false
}
func validExposureState(v string) bool {
	switch v {
	case ExposureProtected, ExposureExposed, ExposureUnknown, ExposureNotApplicable:
		return true
	}
	return false
}
func validateHibernation(h HibernationPosture) error {
	if !validSupportState(h.SupportState) || !validHibernationState(h.ConfigurationState) || !validExposureState(h.ExposureState) || !validEncryptionState(h.EncryptionState) {
		return fmt.Errorf("hibernation posture has invalid normalized state")
	}
	if h.State == "" || h.CollectionSource == "" || h.Confidence == "" {
		return fmt.Errorf("hibernation posture is incomplete")
	}
	return nil
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func appendReason(existing, add string) string {
	existing = strings.TrimSpace(existing)
	add = strings.TrimSpace(add)
	if existing == "" {
		return add
	}
	if add == "" {
		return existing
	}
	return existing + "; " + add
}

func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func volumeForPath(volumes []Volume, path string) (Volume, bool) {
	path = filepathClean(path)
	best := -1
	var out Volume
	for _, v := range volumes {
		mount := filepathClean(v.MountPoint)
		if mount == "" {
			continue
		}
		if path == mount || strings.HasPrefix(path, mountWithSeparator(mount)) {
			if len(mount) > best {
				best = len(mount)
				out = v
			}
		}
	}
	return out, best >= 0
}

func filepathClean(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "\\", "/"))
	if len(v) > 1 {
		v = strings.TrimRight(v, "/")
	}
	return strings.ToLower(v)
}

func mountWithSeparator(v string) string {
	if v == "/" {
		return "/"
	}
	return strings.TrimRight(v, "/") + "/"
}
