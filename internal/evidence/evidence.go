package evidence

import (
	"fmt"
	"strings"
	"time"
)

// SchemaVersion identifies the normalized observation contract emitted by Chimera.
const SchemaVersion = "chimera.evidence/v1"

// State describes whether an evidence fact was actually observed and, if not,
// why it could not be represented as a normal observed value.
type State string

const (
	StateObserved      State = "OBSERVED"
	StateDegraded      State = "DEGRADED"
	StateDenied        State = "DENIED"
	StateUnavailable   State = "UNAVAILABLE"
	StateUnsupported   State = "UNSUPPORTED"
	StateNotApplicable State = "NOT_APPLICABLE"
)

// Confidence describes how strongly the collector can stand behind an
// observation. It is evidence confidence, not finding severity.
type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceExact  Confidence = "EXACT"
)

// Observation is Chimera's normalized collector output. Future collectors are
// expected to emit this contract before rule evaluation or correlation.
type Observation struct {
	Key         string     `json:"key"`
	State       State      `json:"state"`
	Value       any        `json:"value,omitempty"`
	Source      string     `json:"source"`
	CollectedAt time.Time  `json:"collected_at"`
	Confidence  Confidence `json:"confidence"`
	Reason      string     `json:"reason,omitempty"`
}

// NewObserved creates a successful evidence observation.
func NewObserved(key string, value any, source string, collectedAt time.Time, confidence Confidence) Observation {
	return Observation{
		Key:         strings.TrimSpace(key),
		State:       StateObserved,
		Value:       value,
		Source:      strings.TrimSpace(source),
		CollectedAt: collectedAt.UTC(),
		Confidence:  confidence,
	}
}

// NewState creates an explicit non-normal observation such as UNAVAILABLE,
// DENIED, UNSUPPORTED, NOT_APPLICABLE, or DEGRADED.
func NewState(key string, state State, source string, collectedAt time.Time, confidence Confidence, reason string) Observation {
	return Observation{
		Key:         strings.TrimSpace(key),
		State:       state,
		Source:      strings.TrimSpace(source),
		CollectedAt: collectedAt.UTC(),
		Confidence:  confidence,
		Reason:      strings.TrimSpace(reason),
	}
}

// Validate enforces the v1 evidence contract at collector boundaries and in
// tests. Rule/finding phases can therefore rely on stable evidence semantics.
func (o Observation) Validate() error {
	if strings.TrimSpace(o.Key) == "" {
		return fmt.Errorf("evidence key is required")
	}
	if strings.TrimSpace(o.Source) == "" {
		return fmt.Errorf("evidence %q source is required", o.Key)
	}
	if o.CollectedAt.IsZero() {
		return fmt.Errorf("evidence %q collection timestamp is required", o.Key)
	}
	if !validState(o.State) {
		return fmt.Errorf("evidence %q has invalid state %q", o.Key, o.State)
	}
	if !validConfidence(o.Confidence) {
		return fmt.Errorf("evidence %q has invalid confidence %q", o.Key, o.Confidence)
	}
	if o.State == StateObserved {
		if o.Value == nil {
			return fmt.Errorf("evidence %q OBSERVED state requires a value", o.Key)
		}
		return nil
	}
	if strings.TrimSpace(o.Reason) == "" {
		return fmt.Errorf("evidence %q state %s requires a reason", o.Key, o.State)
	}
	return nil
}

func validState(s State) bool {
	switch s {
	case StateObserved, StateDegraded, StateDenied, StateUnavailable, StateUnsupported, StateNotApplicable:
		return true
	default:
		return false
	}
}

func validConfidence(c Confidence) bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceExact:
		return true
	default:
		return false
	}
}

// ValidateAll validates a collector batch and rejects duplicate stable keys.
// A single collector snapshot must not emit two facts under the same key.
func ValidateAll(observations []Observation) error {
	seen := make(map[string]struct{}, len(observations))
	for i, o := range observations {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("observation %d: %w", i, err)
		}
		if _, ok := seen[o.Key]; ok {
			return fmt.Errorf("duplicate evidence key %q", o.Key)
		}
		seen[o.Key] = struct{}{}
	}
	return nil
}
