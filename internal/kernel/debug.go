package kernel

import (
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// DebugExposureAssessment is the normalized representation of one
// kernel-pointer, kernel-debugging, or developer-debug access boundary.  The
// collection state is kept separate from the observed posture so unavailable
// evidence is never mistaken for an exposed host.
type DebugExposureAssessment struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	CollectionState evidence.State      `json:"collection_state"`
	State           string              `json:"state"`
	Exposed         *bool               `json:"exposed,omitempty"`
	Mode            string              `json:"mode,omitempty"`
	Provider        string              `json:"provider"`
	Source          string              `json:"source"`
	Confidence      evidence.Confidence `json:"confidence"`
	Reason          string              `json:"reason,omitempty"`
}

func observedDebugExposure(id, name, state, mode, provider, source string, exposed *bool, confidence evidence.Confidence) DebugExposureAssessment {
	return DebugExposureAssessment{
		ID:              strings.TrimSpace(id),
		Name:            strings.TrimSpace(name),
		CollectionState: evidence.StateObserved,
		State:           strings.ToUpper(strings.TrimSpace(state)),
		Exposed:         exposed,
		Mode:            strings.TrimSpace(mode),
		Provider:        strings.TrimSpace(provider),
		Source:          strings.TrimSpace(source),
		Confidence:      confidence,
	}
}

func unavailableDebugExposure(id, name string, collectionState evidence.State, provider, source, reason string, confidence evidence.Confidence) DebugExposureAssessment {
	return DebugExposureAssessment{
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

func parseBCDBooleanElement(text, element string) (bool, bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], element) {
			continue
		}
		if v, ok := parseBoolControl(fields[len(fields)-1]); ok {
			return v, true
		}
	}
	return false, false
}

func debugBootArguments(text string) []string {
	var out []string
	for _, raw := range strings.Fields(strings.TrimSpace(text)) {
		token := strings.ToLower(strings.TrimSpace(raw))
		if strings.HasPrefix(token, "debug=") || strings.HasPrefix(token, "kdp_") || token == "-kdp" || token == "keepsyms=1" {
			out = append(out, raw)
		}
	}
	return out
}
