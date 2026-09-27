package reliability

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func FuzzLimitStringsNeverExceedsBound(f *testing.F) {
	f.Add("a,b,c", uint8(3))
	f.Add("duplicate,duplicate,z", uint8(2))
	f.Fuzz(func(t *testing.T, raw string, n uint8) {
		limit := int(n%32) + 1
		parts := []string{raw, raw, "fixed"}
		got := LimitStrings(parts, limit)
		if len(got) > limit {
			t.Fatalf("len=%d limit=%d", len(got), limit)
		}
	})
}

func FuzzEvidenceValidationNeverPanics(f *testing.F) {
	f.Add("key", "source", "OBSERVED", "EXACT")
	f.Add("", "source", "DENIED", "HIGH")
	f.Fuzz(func(t *testing.T, key, source, state, confidence string) {
		o := evidence.Observation{Key: key, Source: source, State: evidence.State(state), Confidence: evidence.Confidence(confidence)}
		_ = o.Validate()
	})
}
