package kernel

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// MitigationAssessment is the normalized representation of one
// OS-level ASLR or exploit-mitigation control. CollectionState is deliberately
// separate from State so collection failure is never reported as a disabled
// mitigation.
type MitigationAssessment struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	CollectionState evidence.State      `json:"collection_state"`
	State           string              `json:"state"`
	Enabled         *bool               `json:"enabled,omitempty"`
	Mode            string              `json:"mode,omitempty"`
	Provider        string              `json:"provider"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

func observedMitigation(id, name, state, mode, provider, source string, enabled *bool, confidence evidence.Confidence) MitigationAssessment {
	return MitigationAssessment{
		ID:              strings.TrimSpace(id),
		Name:            strings.TrimSpace(name),
		CollectionState: evidence.StateObserved,
		State:           strings.ToUpper(strings.TrimSpace(state)),
		Enabled:         enabled,
		Mode:            strings.TrimSpace(mode),
		Provider:        strings.TrimSpace(provider),
		Source:          strings.TrimSpace(source),
		Confidence:      confidence,
	}
}

func unavailableMitigation(id, name string, collectionState evidence.State, provider, source, reason string, confidence evidence.Confidence) MitigationAssessment {
	return MitigationAssessment{
		ID:              strings.TrimSpace(id),
		Name:            strings.TrimSpace(name),
		CollectionState: collectionState,
		State:           string(collectionState),
		Provider:        strings.TrimSpace(provider),
		Source:          strings.TrimSpace(source),
		Confidence:      confidence,
		Reason:          strings.TrimSpace(reason),
	}
}

func normalizeMitigationSetting(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.Trim(s, "[]{}()")
	switch s {
	case "ON", "TRUE", "ENABLED", "ENABLE":
		return "ON"
	case "OFF", "FALSE", "DISABLED", "DISABLE":
		return "OFF"
	case "NOTSET", "NOT_SET", "DEFAULT", "":
		return "DEFAULT"
	default:
		return s
	}
}

func aggregateMitigationSettings(settings map[string]string) (state string, enabled *bool, mode string) {
	if len(settings) == 0 {
		return "UNKNOWN", nil, ""
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	// tiny deterministic insertion sort avoids another package-level dependency
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	on, off, def := 0, 0, 0
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := normalizeMitigationSetting(settings[k])
		switch v {
		case "ON":
			on++
		case "OFF":
			off++
		case "DEFAULT":
			def++
		}
		parts = append(parts, k+"="+v)
	}
	mode = strings.Join(parts, "; ")
	switch {
	case off > 0 && on == 0 && def == 0:
		return "DISABLED", boolPtr(false), mode
	case on > 0 && off == 0 && def == 0:
		return "ENABLED", boolPtr(true), mode
	case off > 0:
		return "MIXED_WITH_EXPLICIT_DISABLE", nil, mode
	case on > 0:
		return "PARTIAL_OR_DEFAULT", nil, mode
	default:
		return "PLATFORM_DEFAULT", nil, mode
	}
}
