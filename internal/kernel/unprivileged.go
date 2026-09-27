package kernel

import (
	"fmt"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// UnprivilegedFeatureAssessment is the normalized representation of
// one kernel feature whose availability to an unprivileged local principal can
// materially change host attack surface. CollectionState is intentionally
// distinct from State so an unreadable provider is never guessed as enabled or
// disabled.
type UnprivilegedFeatureAssessment struct {
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

func observedUnprivilegedFeature(id, name, state, mode, provider, source string, exposed *bool, confidence evidence.Confidence) UnprivilegedFeatureAssessment {
	return UnprivilegedFeatureAssessment{
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

func unavailableUnprivilegedFeature(id, name string, collectionState evidence.State, provider, source, reason string, confidence evidence.Confidence) UnprivilegedFeatureAssessment {
	return UnprivilegedFeatureAssessment{
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

func interpretUnprivilegedBPF(v int) (state, mode string, exposed *bool, ok bool) {
	switch v {
	case 0:
		return "ENABLED", "unprivileged_bpf_disabled=0 (unprivileged BPF use is not disabled by this sysctl)", boolPtr(true), true
	case 1:
		return "DISABLED", "unprivileged_bpf_disabled=1 (unprivileged BPF use is disabled by kernel policy)", boolPtr(false), true
	case 2:
		return "DISABLED", "unprivileged_bpf_disabled=2 (unprivileged BPF use is disabled by kernel policy; exact transition semantics are left to the running kernel)", boolPtr(false), true
	default:
		return "", fmt.Sprintf("unprivileged_bpf_disabled=%d", v), nil, false
	}
}

func interpretBinaryExposure(setting string, v int) (state, mode string, exposed *bool, ok bool) {
	switch v {
	case 0:
		return "DISABLED", fmt.Sprintf("%s=0", setting), boolPtr(false), true
	case 1:
		return "ENABLED", fmt.Sprintf("%s=1", setting), boolPtr(true), true
	default:
		return "", fmt.Sprintf("%s=%d", setting, v), nil, false
	}
}

func interpretPerfEventParanoid(v int) (state, mode string, exposed *bool) {
	switch {
	case v < 0:
		return "BROAD_UNPRIVILEGED_ACCESS", fmt.Sprintf("perf_event_paranoid=%d (least restrictive local perf-event policy)", v), boolPtr(true)
	case v == 0:
		return "PERMISSIVE", "perf_event_paranoid=0 (raw tracepoint access is restricted, while broader performance monitoring remains available)", boolPtr(true)
	case v == 1:
		return "RESTRICTED", "perf_event_paranoid=1 (CPU-wide performance-event access is additionally restricted)", nil
	case v >= 2:
		return "STRONGLY_RESTRICTED", fmt.Sprintf("perf_event_paranoid=%d (kernel profiling is restricted for unprivileged callers; higher vendor-specific values are preserved verbatim)", v), nil
	default:
		return "UNKNOWN", fmt.Sprintf("perf_event_paranoid=%d", v), nil
	}
}

func interpretNamespaceLimit(v int) (state, mode string, exposed *bool) {
	if v <= 0 {
		return "DISABLED", fmt.Sprintf("max_user_namespaces=%d", v), boolPtr(false)
	}
	return "AVAILABLE_WITH_LIMIT", fmt.Sprintf("max_user_namespaces=%d (namespace creation capacity exists; other policy may still restrict unprivileged callers)", v), nil
}
