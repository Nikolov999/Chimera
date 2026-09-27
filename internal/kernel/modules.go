package kernel

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// ModuleAssessment is the normalized view of one loaded kernel
// module/driver. The record deliberately separates collection state, backing
// provenance, and signature/trust state so an absent provider is never turned
// into an "unsigned" conclusion.
type ModuleAssessment struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Kind            string              `json:"kind"`
	CollectionState evidence.State      `json:"collection_state"`
	LoadState       string              `json:"load_state"`
	Version         string              `json:"version,omitempty"`
	Path            string              `json:"path,omitempty"`
	Provider        string              `json:"provider"`
	Source          string              `json:"source"`
	SignatureState  string              `json:"signature_state"`
	Signer          string              `json:"signer,omitempty"`
	TrustState      string              `json:"trust_state"`
	Provenance      string              `json:"provenance,omitempty"`
	BackingState    string              `json:"backing_state"`
	OutOfTree       *bool               `json:"out_of_tree,omitempty"`
	Taint           string              `json:"taint,omitempty"`
	Flags           []string            `json:"flags,omitempty"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

func collectLoadedModules(ctx context.Context, k Inventory) []ModuleAssessment {
	out := collectLoadedModulesPlatform(ctx, k)
	for i := range out {
		normalizeModule(&out[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func normalizeModule(m *ModuleAssessment) {
	if m.ID == "" {
		m.ID = "module." + slug(m.Name)
	}
	if m.Kind == "" {
		m.Kind = "kernel-module-or-driver"
	}
	if m.CollectionState == "" {
		m.CollectionState = evidence.StateUnavailable
	}
	if m.LoadState == "" {
		m.LoadState = "UNKNOWN"
	}
	if m.Provider == "" {
		m.Provider = "platform loaded-module provider"
	}
	if m.Source == "" {
		m.Source = m.Provider
	}
	if m.SignatureState == "" {
		m.SignatureState = "UNKNOWN"
	}
	if m.TrustState == "" {
		m.TrustState = "UNKNOWN"
	}
	if m.BackingState == "" {
		m.BackingState = "UNKNOWN"
	}
	if m.Confidence == "" {
		m.Confidence = evidence.ConfidenceLow
	}
	m.Flags = uniqueSortedStrings(m.Flags)
}

func uniqueSortedStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToUpper(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func moduleFlagSummary(m ModuleAssessment) string {
	if len(m.Flags) == 0 {
		return "NONE"
	}
	return strings.Join(m.Flags, ",")
}
