package processes

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	maxLoadedModulesPerProcess = 4096
	maxLoadedModulesTotal      = 32768
)

// LoadedModule is metadata for one DLL/shared-library/dylib mapped by
// an observed process. It records path, provenance and directory-control
// metadata only; module bytes are never read or emitted.
type LoadedModule struct {
	Path                string              `json:"path"`
	Name                string              `json:"name"`
	BaseAddress         string              `json:"base_address,omitempty"`
	DeletedBacking      bool                `json:"deleted_backing"`
	TrustState          string              `json:"trust_state"`
	TrustBasis          string              `json:"trust_basis"`
	Provenance          string              `json:"provenance,omitempty"`
	Signature           string              `json:"signature,omitempty"`
	DirectoryState      string              `json:"directory_state"`
	DirectoryWritable   bool                `json:"directory_writable"`
	BroadDirectoryWrite bool                `json:"broad_directory_write"`
	TrustMismatch       bool                `json:"trust_mismatch"`
	Source              string              `json:"source"`
	Confidence          evidence.Confidence `json:"confidence"`
	Reason              string              `json:"reason,omitempty"`
}

// LoadedModuleContext is additive evidence. One context is emitted
// for every process already present in chimera.processes/v1 so provider denial
// or unsupported collection cannot be mistaken for a clean host.
type LoadedModuleContext struct {
	ProcessID               string              `json:"process_id"`
	PID                     int                 `json:"pid"`
	Platform                string              `json:"platform"`
	State                   string              `json:"state"`
	Modules                 []LoadedModule      `json:"modules,omitempty"`
	ModuleCount             int                 `json:"module_count"`
	DeletedMappings         int                 `json:"deleted_mappings"`
	ExplicitTrustFailures   int                 `json:"explicit_trust_failures"`
	UnsignedModules         int                 `json:"unsigned_modules"`
	UnmanagedModules        int                 `json:"unmanaged_modules"`
	WritableLocationModules int                 `json:"writable_location_modules"`
	TrustMismatches         int                 `json:"trust_mismatches"`
	Source                  string              `json:"source"`
	Confidence              evidence.Confidence `json:"confidence"`
	Reason                  string              `json:"reason,omitempty"`
}

type moduleProviderStats struct {
	ID      string
	State   evidence.State
	Source  string
	Count   int
	Denied  int
	Missing int
	Reason  string
}

func collectLoadedModules(ctx context.Context, items []Process, platform string) ([]LoadedModuleContext, SourceStatus) {
	raw, stats := collectLoadedModulesPlatform(ctx, items)
	byPID := make(map[int]LoadedModuleContext, len(raw))
	for _, c := range raw {
		c.Platform = fallback(strings.ToLower(strings.TrimSpace(c.Platform)), strings.ToLower(strings.TrimSpace(platform)))
		c.State = strings.ToUpper(fallback(strings.TrimSpace(c.State), "UNKNOWN"))
		c.Source = fallback(strings.TrimSpace(c.Source), "platform loaded-module metadata")
		if c.Confidence == "" {
			c.Confidence = evidence.ConfidenceLow
		}
		c.Modules = normalizeLoadedModules(c.Modules, c.Platform)
		c.ModuleCount = len(c.Modules)
		summarizeLoadedModules(&c)
		if old, ok := byPID[c.PID]; !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) {
			byPID[c.PID] = c
		}
	}

	out := make([]LoadedModuleContext, 0, len(items))
	for _, p := range items {
		c, ok := byPID[p.PID]
		if !ok {
			c = LoadedModuleContext{
				PID: p.PID, Platform: strings.ToLower(strings.TrimSpace(platform)), State: "UNKNOWN",
				Source: "platform loaded-module metadata", Confidence: evidence.ConfidenceLow,
				Reason: "loaded-module metadata unavailable for observed process",
			}
		}
		c.ProcessID = p.ID
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].ProcessID < out[j].ProcessID
	})

	state := stats.State
	if state == "" {
		state = evidence.StateUnavailable
	}
	reason := strings.TrimSpace(stats.Reason)
	if reason == "" && (stats.Denied > 0 || stats.Missing > 0) {
		reason = "some process loaded-module records were unavailable"
	}
	return out, SourceStatus{ID: stats.ID, State: state, Source: fallback(stats.Source, "platform loaded-module metadata"), ItemCount: stats.Count, Reason: reason}
}

func normalizeLoadedModules(in []LoadedModule, platform string) []LoadedModule {
	seen := map[string]LoadedModule{}
	for _, m := range in {
		m.Path = strings.TrimSpace(strings.TrimSuffix(m.Path, " (deleted)"))
		if m.Path == "" {
			continue
		}
		m.Name = fallback(strings.TrimSpace(m.Name), filepath.Base(m.Path))
		m.TrustState = strings.ToUpper(fallback(strings.TrimSpace(m.TrustState), "UNKNOWN"))
		m.TrustBasis = fallback(strings.TrimSpace(m.TrustBasis), "loaded-module provenance unresolved")
		m.DirectoryState = strings.ToUpper(fallback(strings.TrimSpace(m.DirectoryState), "UNKNOWN"))
		m.Source = fallback(strings.TrimSpace(m.Source), "platform loaded-module metadata")
		if m.Confidence == "" {
			m.Confidence = evidence.ConfidenceLow
		}
		m.Reason = strings.TrimSpace(m.Reason)
		key := filepath.Clean(m.Path)
		if platform == "windows" || platform == "darwin" {
			key = strings.ToLower(key)
		}
		old, ok := seen[key]
		if !ok || moduleConfidenceScore(m) > moduleConfidenceScore(old) {
			seen[key] = m
		}
	}
	out := make([]LoadedModule, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Path, out[j].Path
		if platform == "windows" || platform == "darwin" {
			a, b = strings.ToLower(a), strings.ToLower(b)
			return a < b
		}
		if platform == "linux" {
			// Inventory validation intentionally uses a case-folded ordering key
			// so serialized output is deterministic even when a host contains
			// case-distinct paths. Linux de-duplication above remains
			// case-sensitive; only the ordering key is folded.
			af, bf := strings.ToLower(a), strings.ToLower(b)
			if af != bf {
				return af < bf
			}
		}
		return a < b
	})
	if len(out) > maxLoadedModulesPerProcess {
		out = out[:maxLoadedModulesPerProcess]
	}
	return out
}

func moduleConfidenceScore(m LoadedModule) int {
	score := confidenceRank(m.Confidence) * 10
	if m.TrustState != "UNKNOWN" {
		score++
	}
	if m.DirectoryState != "UNKNOWN" {
		score++
	}
	return score
}

func summarizeLoadedModules(c *LoadedModuleContext) {
	c.DeletedMappings = 0
	c.ExplicitTrustFailures = 0
	c.UnsignedModules = 0
	c.UnmanagedModules = 0
	c.WritableLocationModules = 0
	c.TrustMismatches = 0
	for _, m := range c.Modules {
		if m.DeletedBacking {
			c.DeletedMappings++
		}
		switch strings.ToUpper(strings.TrimSpace(m.TrustState)) {
		case "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID", "INVALID_SIGNATURE", "UNTRUSTED", "REVOKED", "HASH_MISMATCH":
			c.ExplicitTrustFailures++
		case "UNSIGNED":
			c.UnsignedModules++
		case "UNMANAGED":
			c.UnmanagedModules++
		}
		if m.DirectoryWritable {
			c.WritableLocationModules++
		}
		if m.TrustMismatch {
			c.TrustMismatches++
		}
	}
}

func moduleTrustMismatch(processTrust, moduleTrust string, deleted bool) bool {
	if deleted {
		return true
	}
	p := normalizeTrustStateLocal(processTrust)
	m := normalizeTrustStateLocal(moduleTrust)
	strongProcess := p == "SIGNED_VALID" || p == "PACKAGE_MANAGED" || p == "APPLICATION_MANAGED"
	if !strongProcess {
		return false
	}
	switch m {
	case "SIGNED_VALID", "PACKAGE_MANAGED", "APPLICATION_MANAGED":
		return false
	case "UNKNOWN", "":
		return false
	default:
		return true
	}
}

func normalizeTrustStateLocal(v string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), "-", "_"))
}
