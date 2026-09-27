package kernel

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.kernel/v9"
	CollectorName    = "kernel"
	CollectorVersion = "kernel/v9"
)

type Capability struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
}

type UpdateStatus struct {
	State  string `json:"state"`
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
}

// SecureBootAssessment is the normalized view of the platform's
// firmware boot-trust state. CollectionState follows chimera.evidence/v1 so a
// caller can distinguish a real disabled control from evidence that was denied,
// unsupported, unavailable, degraded, or not applicable.
type SecureBootAssessment struct {
	CollectionState evidence.State      `json:"collection_state"`
	State           string              `json:"state"`
	Enabled         *bool               `json:"enabled,omitempty"`
	Mode            string              `json:"mode,omitempty"`
	Provider        string              `json:"provider"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

type Inventory struct {
	Schema                string                          `json:"kernel_schema"`
	EvidenceSchema        string                          `json:"evidence_schema"`
	CollectedAt           time.Time                       `json:"collected_at"`
	Platform              string                          `json:"platform"`
	OSName                string                          `json:"os_name"`
	OSVersion             string                          `json:"os_version,omitempty"`
	OSBuild               string                          `json:"os_build,omitempty"`
	SupportChannel        string                          `json:"support_channel,omitempty"`
	KernelRelease         string                          `json:"kernel_release"`
	KernelVersion         string                          `json:"kernel_version,omitempty"`
	Architecture          string                          `json:"architecture"`
	BootTime              *time.Time                      `json:"boot_time,omitempty"`
	UptimeSeconds         int64                           `json:"uptime_seconds,omitempty"`
	BootID                string                          `json:"boot_id,omitempty"`
	BootMode              string                          `json:"boot_mode,omitempty"`
	Update                UpdateStatus                    `json:"update"`
	SecureBoot            SecureBootAssessment            `json:"secure_boot"`
	IntegrityControls     []ControlAssessment             `json:"integrity_controls"`
	MemoryMitigations     []MitigationAssessment          `json:"memory_mitigations"`
	DebugExposure         []DebugExposureAssessment       `json:"debug_exposure"`
	UnprivilegedFeatures  []UnprivilegedFeatureAssessment `json:"unprivileged_kernel_features"`
	LoadedModules         []ModuleAssessment              `json:"loaded_modules"`
	DriverIntelligence    DriverIntelligenceStatus        `json:"driver_intelligence"`
	VulnerableDrivers     []VulnerableDriverAssessment    `json:"vulnerable_drivers"`
	MandatoryAccess       []MandatoryAccessAssessment     `json:"mandatory_access_controls"`
	HardeningCapabilities []Capability                    `json:"hardening_capabilities"`
	Evidence              []evidence.Observation          `json:"evidence"`
	Degraded              []string                        `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	k := Inventory{
		Schema:         SchemaVersion,
		EvidenceSchema: evidence.SchemaVersion,
		CollectedAt:    time.Now().UTC(),
		Platform:       runtime.GOOS,
		OSName:         runtime.GOOS,
		Architecture:   runtime.GOARCH,
		Update:         UpdateStatus{State: "UNKNOWN", Source: "local platform metadata", Detail: "no reliable local pending-update state observed"},
	}
	collectPlatform(ctx, &k)
	k.SecureBoot = collectSecureBoot(ctx, k)
	k.IntegrityControls = collectIntegrityControls(ctx, k)
	k.MemoryMitigations = collectMemoryMitigations(ctx, k)
	k.DebugExposure = collectDebugExposure(ctx, k)
	k.UnprivilegedFeatures = collectUnprivilegedFeatures(ctx, k)
	k.LoadedModules = collectLoadedModules(ctx, k)
	k.DriverIntelligence, k.VulnerableDrivers = collectVulnerableDrivers(ctx, k)
	k.MandatoryAccess = collectMandatoryAccess(ctx, k)
	sort.Slice(k.IntegrityControls, func(i, j int) bool { return k.IntegrityControls[i].ID < k.IntegrityControls[j].ID })
	sort.Slice(k.MemoryMitigations, func(i, j int) bool { return k.MemoryMitigations[i].ID < k.MemoryMitigations[j].ID })
	sort.Slice(k.DebugExposure, func(i, j int) bool { return k.DebugExposure[i].ID < k.DebugExposure[j].ID })
	sort.Slice(k.UnprivilegedFeatures, func(i, j int) bool { return k.UnprivilegedFeatures[i].ID < k.UnprivilegedFeatures[j].ID })
	sort.Slice(k.LoadedModules, func(i, j int) bool { return k.LoadedModules[i].ID < k.LoadedModules[j].ID })
	sort.Slice(k.VulnerableDrivers, func(i, j int) bool { return k.VulnerableDrivers[i].ID < k.VulnerableDrivers[j].ID })
	sort.Slice(k.MandatoryAccess, func(i, j int) bool { return k.MandatoryAccess[i].ID < k.MandatoryAccess[j].ID })
	sort.Slice(k.HardeningCapabilities, func(i, j int) bool { return k.HardeningCapabilities[i].Name < k.HardeningCapabilities[j].Name })
	if err := ctx.Err(); err != nil {
		k.Degraded = append(k.Degraded, "collection timeout reached: "+err.Error())
	}
	k.Evidence = buildEvidence(k)
	return k
}

func buildEvidence(k Inventory) []evidence.Observation {
	at := k.CollectedAt
	out := make([]evidence.Observation, 0, 15+len(k.HardeningCapabilities)+len(k.IntegrityControls)*3+len(k.MemoryMitigations)*3+len(k.DebugExposure)*3+len(k.UnprivilegedFeatures)*3+len(k.LoadedModules)*7+6+len(k.VulnerableDrivers)*9+len(k.MandatoryAccess)*4)
	add := func(key string, value any, source string, conf evidence.Confidence) {
		if strings.TrimSpace(fmt.Sprint(value)) == "" {
			out = append(out, evidence.NewState(key, evidence.StateUnavailable, source, at, evidence.ConfidenceLow, "value was not observable"))
			return
		}
		out = append(out, evidence.NewObserved(key, value, source, at, conf))
	}
	add("kernel.os.name", k.OSName, "platform OS metadata", evidence.ConfidenceHigh)
	add("kernel.os.version", k.OSVersion, "platform OS metadata", evidence.ConfidenceHigh)
	add("kernel.os.build", k.OSBuild, "platform OS metadata", evidence.ConfidenceHigh)
	add("kernel.os.support_channel", k.SupportChannel, "platform release metadata", evidence.ConfidenceMedium)
	add("kernel.release", k.KernelRelease, "kernel runtime metadata", evidence.ConfidenceExact)
	add("kernel.version", k.KernelVersion, "kernel runtime metadata", evidence.ConfidenceHigh)
	add("kernel.architecture", k.Architecture, "Go runtime", evidence.ConfidenceExact)
	add("kernel.boot.mode", k.BootMode, "local boot metadata", evidence.ConfidenceMedium)
	if k.BootTime != nil {
		add("kernel.boot.time", k.BootTime.UTC().Format(time.RFC3339), "local boot metadata", evidence.ConfidenceHigh)
	} else {
		out = append(out, evidence.NewState("kernel.boot.time", evidence.StateUnavailable, "local boot metadata", at, evidence.ConfidenceLow, "boot time was not observable"))
	}
	if k.BootID != "" {
		add("kernel.boot.id", k.BootID, "local boot metadata", evidence.ConfidenceHigh)
	} else {
		out = append(out, evidence.NewState("kernel.boot.id", evidence.StateNotApplicable, "local boot metadata", at, evidence.ConfidenceMedium, "platform does not expose a stable local boot identifier through this collector"))
	}
	add("kernel.update.state", k.Update.State, k.Update.Source, evidence.ConfidenceMedium)
	if k.SecureBoot.CollectionState == evidence.StateObserved {
		add("kernel.secure_boot.state", k.SecureBoot.State, k.SecureBoot.Source, k.SecureBoot.Confidence)
		if k.SecureBoot.Enabled != nil {
			add("kernel.secure_boot.enabled", *k.SecureBoot.Enabled, k.SecureBoot.Source, k.SecureBoot.Confidence)
		}
		if strings.TrimSpace(k.SecureBoot.Mode) != "" {
			add("kernel.secure_boot.mode", k.SecureBoot.Mode, k.SecureBoot.Source, k.SecureBoot.Confidence)
		}
	} else {
		state := k.SecureBoot.CollectionState
		if state == "" {
			state = evidence.StateUnavailable
		}
		reason := strings.TrimSpace(k.SecureBoot.Reason)
		if reason == "" {
			reason = "Secure Boot state was not observable"
		}
		source := strings.TrimSpace(k.SecureBoot.Source)
		if source == "" {
			source = "platform Secure Boot provider"
		}
		conf := k.SecureBoot.Confidence
		if conf == "" {
			conf = evidence.ConfidenceLow
		}
		out = append(out, evidence.NewState("kernel.secure_boot.state", state, source, at, conf, reason))
	}
	for _, c := range k.IntegrityControls {
		base := "kernel.integrity." + slug(c.ID)
		if c.CollectionState == evidence.StateObserved {
			add(base+".state", c.State, c.Source, c.Confidence)
			if c.Enabled != nil {
				add(base+".enabled", *c.Enabled, c.Source, c.Confidence)
			}
			if strings.TrimSpace(c.Mode) != "" {
				add(base+".mode", c.Mode, c.Source, c.Confidence)
			}
		} else {
			state := c.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(c.Reason)
			if reason == "" {
				reason = "integrity-control state was not observable"
			}
			source := strings.TrimSpace(c.Source)
			if source == "" {
				source = "platform integrity provider"
			}
			conf := c.Confidence
			if conf == "" {
				conf = evidence.ConfidenceLow
			}
			out = append(out, evidence.NewState(base+".state", state, source, at, conf, reason))
		}
	}
	for _, m := range k.MemoryMitigations {
		base := "kernel.mitigation." + slug(m.ID)
		if m.CollectionState == evidence.StateObserved {
			add(base+".state", m.State, m.Source, m.Confidence)
			if m.Enabled != nil {
				add(base+".enabled", *m.Enabled, m.Source, m.Confidence)
			}
			if strings.TrimSpace(m.Mode) != "" {
				add(base+".mode", m.Mode, m.Source, m.Confidence)
			}
		} else {
			state := m.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(m.Reason)
			if reason == "" {
				reason = "memory-mitigation state was not observable"
			}
			source := strings.TrimSpace(m.Source)
			if source == "" {
				source = "platform mitigation provider"
			}
			conf := m.Confidence
			if conf == "" {
				conf = evidence.ConfidenceLow
			}
			out = append(out, evidence.NewState(base+".state", state, source, at, conf, reason))
		}
	}
	for _, d := range k.DebugExposure {
		base := "kernel.debug." + slug(d.ID)
		if d.CollectionState == evidence.StateObserved {
			add(base+".state", d.State, d.Source, d.Confidence)
			if d.Exposed != nil {
				add(base+".exposed", *d.Exposed, d.Source, d.Confidence)
			}
			if strings.TrimSpace(d.Mode) != "" {
				add(base+".mode", d.Mode, d.Source, d.Confidence)
			}
		} else {
			state := d.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(d.Reason)
			if reason == "" {
				reason = "kernel/debug exposure state was not observable"
			}
			source := strings.TrimSpace(d.Source)
			if source == "" {
				source = "platform debug-exposure provider"
			}
			conf := d.Confidence
			if conf == "" {
				conf = evidence.ConfidenceLow
			}
			out = append(out, evidence.NewState(base+".state", state, source, at, conf, reason))
		}
	}
	for _, u := range k.UnprivilegedFeatures {
		base := "kernel.unprivileged." + slug(u.ID)
		if u.CollectionState == evidence.StateObserved {
			add(base+".state", u.State, u.Source, u.Confidence)
			if u.Exposed != nil {
				add(base+".exposed", *u.Exposed, u.Source, u.Confidence)
			}
			if strings.TrimSpace(u.Mode) != "" {
				add(base+".mode", u.Mode, u.Source, u.Confidence)
			}
		} else {
			state := u.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(u.Reason)
			if reason == "" {
				reason = "unprivileged-kernel-feature state was not observable"
			}
			source := strings.TrimSpace(u.Source)
			if source == "" {
				source = "platform unprivileged-feature provider"
			}
			conf := u.Confidence
			if conf == "" {
				conf = evidence.ConfidenceLow
			}
			out = append(out, evidence.NewState(base+".state", state, source, at, conf, reason))
		}
	}
	for _, m := range k.LoadedModules {
		base := "kernel.module." + slug(m.ID)
		if m.CollectionState == evidence.StateObserved || m.CollectionState == evidence.StateDegraded {
			add(base+".load_state", m.LoadState, m.Source, m.Confidence)
			add(base+".signature_state", m.SignatureState, m.Source, m.Confidence)
			add(base+".trust_state", m.TrustState, m.Source, m.Confidence)
			add(base+".backing_state", m.BackingState, m.Source, m.Confidence)
			add(base+".flags", moduleFlagSummary(m), m.Source, m.Confidence)
			if strings.TrimSpace(m.Path) != "" {
				add(base+".path", m.Path, m.Source, m.Confidence)
			}
			if strings.TrimSpace(m.Signer) != "" {
				add(base+".signer", m.Signer, m.Source, m.Confidence)
			}
			if m.OutOfTree != nil {
				add(base+".out_of_tree", *m.OutOfTree, m.Source, m.Confidence)
			}
		} else {
			state := m.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(m.Reason)
			if reason == "" {
				reason = "loaded module/driver state was not observable"
			}
			out = append(out, evidence.NewState(base+".load_state", state, m.Source, at, m.Confidence, reason))
		}
	}
	add("kernel.vulnerable_driver.intelligence.version", k.DriverIntelligence.Version, k.DriverIntelligence.Source, evidence.ConfidenceExact)
	add("kernel.vulnerable_driver.intelligence.platform_entries", k.DriverIntelligence.PlatformEntries, k.DriverIntelligence.Source, evidence.ConfidenceExact)
	add("kernel.vulnerable_driver.intelligence.candidates", k.DriverIntelligence.CandidateCount, k.DriverIntelligence.Source, evidence.ConfidenceHigh)
	add("kernel.vulnerable_driver.intelligence.matches", k.DriverIntelligence.MatchCount, k.DriverIntelligence.Source, evidence.ConfidenceExact)
	add("kernel.vulnerable_driver.intelligence.unresolved", k.DriverIntelligence.UnresolvedCount, k.DriverIntelligence.Source, evidence.ConfidenceExact)
	if k.DriverIntelligence.InstalledCollectionState == evidence.StateObserved {
		add("kernel.vulnerable_driver.installed_collection.state", string(k.DriverIntelligence.InstalledCollectionState), k.DriverIntelligence.InstalledCollectionSource, evidence.ConfidenceHigh)
	} else {
		state := k.DriverIntelligence.InstalledCollectionState
		if state == "" {
			state = evidence.StateUnavailable
		}
		reason := strings.TrimSpace(k.DriverIntelligence.InstalledCollectionReason)
		if reason == "" {
			reason = "installed vulnerable-driver candidate collection state was unavailable"
		}
		source := strings.TrimSpace(k.DriverIntelligence.InstalledCollectionSource)
		if source == "" {
			source = k.DriverIntelligence.Source
		}
		out = append(out, evidence.NewState("kernel.vulnerable_driver.installed_collection.state", state, source, at, evidence.ConfidenceMedium, reason))
	}
	for _, v := range k.VulnerableDrivers {
		base := "kernel.vulnerable_driver." + slug(v.ID)
		if v.CollectionState == evidence.StateObserved || v.CollectionState == evidence.StateDegraded {
			add(base+".assessment", vulnerableDriverEvidenceValue(v), v.Source, v.Confidence)
			add(base+".installed_state", v.InstalledState, v.Source, v.Confidence)
			add(base+".load_state", v.LoadState, v.Source, v.Confidence)
			add(base+".exposure_state", v.ExposureState, v.Source, v.Confidence)
			add(base+".resolution_state", v.ResolutionState, v.Source, v.Confidence)
			add(base+".intelligence_id", v.IntelligenceID, k.DriverIntelligence.Source, evidence.ConfidenceExact)
			add(base+".vulnerabilities", strings.Join(v.Vulnerabilities, ","), k.DriverIntelligence.Source, v.Confidence)
			if strings.TrimSpace(v.DriverPath) != "" {
				add(base+".path", v.DriverPath, v.Source, v.Confidence)
			}
			if strings.TrimSpace(v.SHA256) != "" {
				add(base+".sha256", v.SHA256, v.Source, evidence.ConfidenceExact)
			}
		} else {
			state := v.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(v.Reason)
			if reason == "" {
				reason = "vulnerable-driver correlation state was not observable"
			}
			out = append(out, evidence.NewState(base+".assessment", state, v.Source, at, v.Confidence, reason))
		}
	}
	for _, m := range k.MandatoryAccess {
		base := "kernel.mandatory_access." + slug(m.ID)
		if m.CollectionState == evidence.StateObserved {
			add(base+".state", m.State, m.Source, m.Confidence)
			add(base+".framework", m.Framework, m.Source, m.Confidence)
			if m.Enabled != nil {
				add(base+".enabled", *m.Enabled, m.Source, m.Confidence)
			}
			if strings.TrimSpace(m.Mode) != "" {
				add(base+".mode", m.Mode, m.Source, m.Confidence)
			}
		} else {
			state := m.CollectionState
			if state == "" {
				state = evidence.StateUnavailable
			}
			reason := strings.TrimSpace(m.Reason)
			if reason == "" {
				reason = "mandatory-access-control state was not observable"
			}
			source := strings.TrimSpace(m.Source)
			if source == "" {
				source = "platform mandatory-access provider"
			}
			conf := m.Confidence
			if conf == "" {
				conf = evidence.ConfidenceLow
			}
			out = append(out, evidence.NewState(base+".state", state, source, at, conf, reason))
		}
	}
	for _, c := range k.HardeningCapabilities {
		key := "kernel.hardening.capability." + slug(c.Name)
		add(key, c.State, c.Source, evidence.ConfidenceHigh)
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastSep := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastSep = false
			continue
		}
		if !lastSep {
			b.WriteByte('_')
			lastSep = true
		}
	}
	return strings.Trim(b.String(), "_")
}
