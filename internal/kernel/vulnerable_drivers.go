package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	DriverIntelligenceSchema  = "chimera.driver-intelligence/v1"
	DriverIntelligenceVersion = "seed-2026.08-phase017"
)

// DriverIntelligenceStatus describes the local, pinned vulnerable-driver
// intelligence used by . It is deliberately separate from the general
// software/CVE intelligence store planned for .
type DriverIntelligenceStatus struct {
	Schema                    string         `json:"schema"`
	Version                   string         `json:"version"`
	Source                    string         `json:"source"`
	PlatformEntries           int            `json:"platform_entries"`
	CandidateCount            int            `json:"candidate_count"`
	MatchCount                int            `json:"match_count"`
	UnresolvedCount           int            `json:"unresolved_count"`
	NetworkAccess             bool           `json:"network_access"`
	InstalledCollectionState  evidence.State `json:"installed_collection_state"`
	InstalledCollectionSource string         `json:"installed_collection_source"`
	InstalledCollectionReason string         `json:"installed_collection_reason,omitempty"`
}

// VulnerableDriverAssessment is one defensive correlation result. Identity
// matches never become exploitability claims: a historical vulnerable-driver
// identity may still require a version/hash decision before it is confirmed.
type VulnerableDriverAssessment struct {
	ID               string              `json:"id"`
	DriverName       string              `json:"driver_name"`
	DriverPath       string              `json:"driver_path,omitempty"`
	DriverVersion    string              `json:"driver_version,omitempty"`
	Platform         string              `json:"platform"`
	CollectionState  evidence.State      `json:"collection_state"`
	InstalledState   string              `json:"installed_state"`
	LoadState        string              `json:"load_state"`
	ExposureState    string              `json:"exposure_state"`
	ExposureReason   string              `json:"exposure_reason,omitempty"`
	ResolutionState  string              `json:"resolution_state"`
	MatchBasis       string              `json:"match_basis"`
	IntelligenceID   string              `json:"intelligence_id"`
	IntelligenceVer  string              `json:"intelligence_version"`
	Vendor           string              `json:"vendor,omitempty"`
	Product          string              `json:"product,omitempty"`
	Vulnerabilities  []string            `json:"vulnerabilities"`
	Advisory         string              `json:"advisory,omitempty"`
	SHA256           string              `json:"sha256,omitempty"`
	FingerprintState string              `json:"fingerprint_state"`
	Source           string              `json:"source"`
	Confidence       evidence.Confidence `json:"confidence"`
	Reason           string              `json:"reason,omitempty"`
}

type driverIntelEntry struct {
	ID              string
	Platform        string
	FileNames       []string
	ServiceNames    []string
	Vendor          string
	Product         string
	Vulnerabilities []string
	Advisory        string
}

type driverCandidate struct {
	Name            string
	Path            string
	Version         string
	Installed       bool
	Loaded          bool
	CollectionState evidence.State
	Source          string
	ExposureState   string
	ExposureReason  string
	Confidence      evidence.Confidence
}

func vulnerableDriverCatalog() []driverIntelEntry {
	// This compact seed is intentionally identity-based and conservative. Exact
	// vulnerable-version/range and hash intelligence belongs to the +
	// intelligence engine; therefore reports these as identity matches
	// requiring version/hash confirmation rather than as proven exploitable code.
	return []driverIntelEntry{
		{
			ID: "CHM-DRV-0001", Platform: "windows",
			FileNames: []string{"dbutil_2_3.sys"}, ServiceNames: []string{"dbutil_2_3"},
			Vendor: "Dell", Product: "DBUtil driver",
			Vulnerabilities: []string{"CVE-2021-21551"}, Advisory: "Dell DSA-2021-088",
		},
		{
			ID: "CHM-DRV-0002", Platform: "windows",
			FileNames: []string{"gdrv.sys"}, ServiceNames: []string{"gdrv"},
			Vendor: "GIGABYTE", Product: "GDRV driver",
			Vulnerabilities: []string{"CVE-2018-19320"}, Advisory: "GIGABYTE vulnerable-driver identity",
		},
		{
			ID: "CHM-DRV-0003", Platform: "windows",
			FileNames: []string{"rtcore64.sys", "rtcore32.sys"}, ServiceNames: []string{"rtcore64", "rtcore32"},
			Vendor: "Micro-Star International", Product: "RTCore driver",
			Vulnerabilities: []string{"CVE-2019-16098"}, Advisory: "MSI RTCore vulnerable-driver identity",
		},
		{
			ID: "CHM-DRV-0004", Platform: "windows",
			FileNames: []string{"iqvw64e.sys"}, ServiceNames: []string{"iqvw64e"},
			Vendor: "Intel", Product: "Network Adapter Diagnostic driver",
			Vulnerabilities: []string{"CVE-2015-2291"}, Advisory: "Intel diagnostic-driver vulnerable identity",
		},
	}
}

func collectVulnerableDrivers(ctx context.Context, k Inventory) (DriverIntelligenceStatus, []VulnerableDriverAssessment) {
	catalog := vulnerableDriverCatalog()
	platformEntries := make([]driverIntelEntry, 0, len(catalog))
	for _, e := range catalog {
		if strings.EqualFold(e.Platform, k.Platform) {
			platformEntries = append(platformEntries, e)
		}
	}

	candidates := candidatesFromLoadedModules(k.LoadedModules)
	installed, installedState, installedReason, installedSource := collectInstalledVulnerableDriverCandidatesPlatform(ctx, platformEntries)
	candidates = mergeDriverCandidates(candidates, installed)

	matches := correlateVulnerableDrivers(candidates, platformEntries)
	unresolved := 0
	for i := range matches {
		if err := ctx.Err(); err != nil {
			break
		}
		fingerprintDriver(&matches[i])
		if strings.HasPrefix(matches[i].ResolutionState, "UNRESOLVED") || matches[i].ResolutionState == "IDENTITY_MATCH_REQUIRES_CONFIRMATION" {
			unresolved++
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].IntelligenceID == matches[j].IntelligenceID {
			if matches[i].DriverName == matches[j].DriverName {
				return strings.ToLower(matches[i].DriverPath) < strings.ToLower(matches[j].DriverPath)
			}
			return strings.ToLower(matches[i].DriverName) < strings.ToLower(matches[j].DriverName)
		}
		return matches[i].IntelligenceID < matches[j].IntelligenceID
	})

	status := DriverIntelligenceStatus{
		Schema:                    DriverIntelligenceSchema,
		Version:                   DriverIntelligenceVersion,
		Source:                    "embedded local vulnerable-driver seed intelligence",
		PlatformEntries:           len(platformEntries),
		CandidateCount:            len(candidates),
		MatchCount:                len(matches),
		UnresolvedCount:           unresolved,
		NetworkAccess:             false,
		InstalledCollectionState:  installedState,
		InstalledCollectionSource: installedSource,
		InstalledCollectionReason: installedReason,
	}
	return status, matches
}

func candidatesFromLoadedModules(mods []ModuleAssessment) []driverCandidate {
	out := make([]driverCandidate, 0, len(mods))
	for _, m := range mods {
		if m.CollectionState != evidence.StateObserved && m.CollectionState != evidence.StateDegraded {
			continue
		}
		if m.Name == "" || strings.Contains(strings.ToLower(m.Kind), "-set") {
			continue
		}
		loaded := m.LoadState != "" && m.LoadState != "UNKNOWN" && m.LoadState != "EMPTY" && m.LoadState != "NOT_LOADED" && m.LoadState != "STOPPED"
		out = append(out, driverCandidate{
			Name: m.Name, Path: m.Path, Version: m.Version, Installed: m.BackingState == "PRESENT" || m.BackingState == "BUILT_IN", Loaded: loaded,
			CollectionState: m.CollectionState, Source: m.Source, ExposureState: exposureFromLoad(loaded),
			ExposureReason: exposureReasonFromLoad(loaded), Confidence: m.Confidence,
		})
	}
	return out
}

func exposureFromLoad(loaded bool) string {
	if !loaded {
		return "NOT_ACTIVE"
	}
	return "UNKNOWN"
}

func exposureReasonFromLoad(loaded bool) string {
	if !loaded {
		return "driver is not observed loaded; active runtime exposure is not present"
	}
	return "driver is loaded, but user-reachable device/interface exposure is not proven without active device interaction"
}

func mergeDriverCandidates(in ...[]driverCandidate) []driverCandidate {
	byKey := map[string]driverCandidate{}
	for _, set := range in {
		for _, c := range set {
			key := candidateKey(c)
			if key == "|" || key == "" {
				continue
			}
			if old, ok := byKey[key]; ok {
				old.Installed = old.Installed || c.Installed
				old.Loaded = old.Loaded || c.Loaded
				if old.Path == "" {
					old.Path = c.Path
				}
				if old.Version == "" {
					old.Version = c.Version
				}
				if old.Source == "" {
					old.Source = c.Source
				} else if c.Source != "" && !strings.Contains(old.Source, c.Source) {
					old.Source += "; " + c.Source
				}
				if c.CollectionState == evidence.StateDegraded {
					old.CollectionState = evidence.StateDegraded
				}
				if old.Confidence == evidence.ConfidenceLow && c.Confidence != "" {
					old.Confidence = c.Confidence
				}
				if old.Loaded {
					old.ExposureState = exposureFromLoad(true)
					old.ExposureReason = exposureReasonFromLoad(true)
				}
				byKey[key] = old
				continue
			}
			if c.CollectionState == "" {
				c.CollectionState = evidence.StateObserved
			}
			if c.Confidence == "" {
				c.Confidence = evidence.ConfidenceMedium
			}
			if c.ExposureState == "" {
				c.ExposureState = exposureFromLoad(c.Loaded)
			}
			if c.ExposureReason == "" {
				c.ExposureReason = exposureReasonFromLoad(c.Loaded)
			}
			byKey[key] = c
		}
	}
	out := make([]driverCandidate, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return candidateKey(out[i]) < candidateKey(out[j]) })
	return out
}

func candidateKey(c driverCandidate) string {
	if name := strings.ToLower(strings.TrimSpace(c.Name)); name != "" {
		return "name:" + name
	}
	if base := strings.ToLower(strings.TrimSpace(driverBaseName(c.Path))); base != "" && base != "." {
		return "path:" + base
	}
	return ""
}

func correlateVulnerableDrivers(candidates []driverCandidate, catalog []driverIntelEntry) []VulnerableDriverAssessment {
	out := []VulnerableDriverAssessment{}
	for _, c := range candidates {
		for _, e := range catalog {
			basis, ok := driverIdentityMatches(c, e)
			if !ok {
				continue
			}
			installedState := "UNKNOWN"
			if c.Installed {
				installedState = "INSTALLED"
			}
			loadState := "NOT_LOADED"
			if c.Loaded {
				loadState = "LOADED"
			}
			resolution := "IDENTITY_MATCH_REQUIRES_CONFIRMATION"
			reason := "exact local driver identity matches vulnerable-driver intelligence; exact affected-version/hash confirmation is not available in the seed"
			conf := evidence.ConfidenceMedium
			if basis == "EXACT_FILE_NAME+EXACT_SERVICE_NAME" {
				conf = evidence.ConfidenceHigh
			}
			out = append(out, VulnerableDriverAssessment{
				ID:         "vulndriver." + slug(e.ID+"."+c.Name+"."+driverBaseName(c.Path)),
				DriverName: c.Name, DriverPath: c.Path, DriverVersion: c.Version, Platform: e.Platform,
				CollectionState: c.CollectionState, InstalledState: installedState, LoadState: loadState,
				ExposureState: c.ExposureState, ExposureReason: c.ExposureReason, ResolutionState: resolution,
				MatchBasis: basis, IntelligenceID: e.ID, IntelligenceVer: DriverIntelligenceVersion,
				Vendor: e.Vendor, Product: e.Product, Vulnerabilities: append([]string(nil), e.Vulnerabilities...), Advisory: e.Advisory,
				FingerprintState: "NOT_ATTEMPTED", Source: c.Source + "; " + DriverIntelligenceVersion,
				Confidence: conf, Reason: reason,
			})
		}
	}
	return out
}

func driverIdentityMatches(c driverCandidate, e driverIntelEntry) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(c.Name))
	base := strings.ToLower(strings.TrimSpace(driverBaseName(c.Path)))
	service := false
	file := false
	for _, s := range e.ServiceNames {
		if name == strings.ToLower(strings.TrimSpace(s)) {
			service = true
			break
		}
	}
	for _, f := range e.FileNames {
		if base == strings.ToLower(strings.TrimSpace(f)) || (base == "" && name == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f)), ".sys")) {
			file = true
			break
		}
	}
	switch {
	case service && file:
		return "EXACT_FILE_NAME+EXACT_SERVICE_NAME", true
	case file:
		return "EXACT_FILE_NAME", true
	case service:
		return "EXACT_SERVICE_NAME", true
	default:
		return "", false
	}
}

func driverBaseName(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	p = strings.ReplaceAll(p, `\`, "/")
	return filepath.Base(p)
}

func fingerprintDriver(a *VulnerableDriverAssessment) {
	p := strings.TrimSpace(a.DriverPath)
	if p == "" {
		a.FingerprintState = "UNAVAILABLE"
		return
	}
	st, err := os.Stat(p)
	if err != nil {
		if os.IsPermission(err) {
			a.FingerprintState = "DENIED"
		} else {
			a.FingerprintState = "UNAVAILABLE"
		}
		return
	}
	const maxDriverSize = int64(128 << 20)
	if st.Size() < 0 || st.Size() > maxDriverSize {
		a.FingerprintState = "SKIPPED_SIZE_BOUND"
		return
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsPermission(err) {
			a.FingerprintState = "DENIED"
		} else {
			a.FingerprintState = "UNAVAILABLE"
		}
		return
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		a.FingerprintState = "UNAVAILABLE"
		return
	}
	a.SHA256 = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	a.FingerprintState = "OBSERVED"
}

func vulnerableDriverEvidenceValue(v VulnerableDriverAssessment) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", v.IntelligenceID, v.InstalledState, v.LoadState, v.ExposureState, v.ResolutionState)
}
