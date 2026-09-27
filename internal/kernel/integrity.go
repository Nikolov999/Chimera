package kernel

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// ControlAssessment is a normalized read-only view of one kernel/code-integrity
// security control. CollectionState explicitly separates a real observed
// enabled/disabled/mode result from evidence that was denied, unavailable,
// unsupported, degraded, or not applicable.
type ControlAssessment struct {
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

func observedControl(id, name, state, mode, provider, source string, enabled *bool, confidence evidence.Confidence) ControlAssessment {
	return ControlAssessment{
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

func unavailableControl(id, name string, collectionState evidence.State, provider, source, reason string, confidence evidence.Confidence) ControlAssessment {
	return ControlAssessment{
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

func boolPtr(v bool) *bool { return &v }

func parseBoolControl(text string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "1", "y", "yes", "true", "enabled", "on":
		return true, true
	case "0", "n", "no", "false", "disabled", "off":
		return false, true
	default:
		return false, false
	}
}
