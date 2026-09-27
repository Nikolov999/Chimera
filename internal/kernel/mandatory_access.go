package kernel

import (
	"context"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// MandatoryAccessAssessment is the normalized view of one
// mandatory-access-control, sandbox, or platform isolation control. It keeps
// provider availability separate from an observed enabled/enforcing state so
// Chimera never treats missing evidence as a disabled security boundary.
type MandatoryAccessAssessment struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Framework       string              `json:"framework"`
	CollectionState evidence.State      `json:"collection_state"`
	State           string              `json:"state"`
	Enabled         *bool               `json:"enabled,omitempty"`
	Mode            string              `json:"mode,omitempty"`
	Provider        string              `json:"provider"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

func collectMandatoryAccess(ctx context.Context, k Inventory) []MandatoryAccessAssessment {
	out := collectMandatoryAccessPlatform(ctx, k)
	for i := range out {
		normalizeMandatoryAccess(&out[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework == out[j].Framework {
			return out[i].ID < out[j].ID
		}
		return strings.ToLower(out[i].Framework) < strings.ToLower(out[j].Framework)
	})
	return out
}

func normalizeMandatoryAccess(m *MandatoryAccessAssessment) {
	if m.ID == "" {
		m.ID = "mandatory-access." + slug(m.Name)
	}
	if m.Framework == "" {
		m.Framework = "platform-mandatory-access"
	}
	if m.CollectionState == "" {
		m.CollectionState = evidence.StateUnavailable
	}
	if m.State == "" {
		m.State = string(m.CollectionState)
	}
	m.State = strings.ToUpper(strings.TrimSpace(m.State))
	if m.Provider == "" {
		m.Provider = "platform mandatory-access provider"
	}
	if m.Source == "" {
		m.Source = m.Provider
	}
	if m.Confidence == "" {
		m.Confidence = evidence.ConfidenceLow
	}
}

func observedMandatoryAccess(id, name, framework, state, mode, provider, source string, enabled *bool, confidence evidence.Confidence) MandatoryAccessAssessment {
	return MandatoryAccessAssessment{
		ID: id, Name: name, Framework: framework,
		CollectionState: evidence.StateObserved,
		State:           state, Enabled: enabled, Mode: mode,
		Provider: provider, Source: source, Confidence: confidence,
	}
}

func unavailableMandatoryAccess(id, name, framework string, collectionState evidence.State, provider, source, reason string, confidence evidence.Confidence) MandatoryAccessAssessment {
	return MandatoryAccessAssessment{
		ID: id, Name: name, Framework: framework,
		CollectionState: collectionState, State: string(collectionState),
		Provider: provider, Source: source, Confidence: confidence, Reason: reason,
	}
}

func parseLinuxLSMList(text string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, item := range strings.Split(strings.TrimSpace(text), ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func summarizeAppArmorProfiles(text string) (total, enforce, complain, other int) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		total++
		lower := strings.ToLower(line)
		switch {
		case strings.HasSuffix(lower, "(enforce)"):
			enforce++
		case strings.HasSuffix(lower, "(complain)"):
			complain++
		default:
			other++
		}
	}
	return
}

func parseCSRUtilStatus(text string) (state, mode string, enabled *bool, ok bool) {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return "", "", nil, false
	}
	switch {
	case strings.Contains(lower, "system integrity protection status: enabled"):
		return "ENABLED", "full-or-custom-enabled", boolPtr(true), true
	case strings.Contains(lower, "system integrity protection status: disabled"):
		return "DISABLED", "disabled", boolPtr(false), true
	case strings.Contains(lower, "system integrity protection status: unknown"):
		return "UNKNOWN", "unknown", nil, true
	}
	if strings.Contains(lower, "system integrity protection") {
		return "CUSTOM_OR_UNRECOGNIZED", strings.TrimSpace(text), nil, true
	}
	return "", "", nil, false
}
