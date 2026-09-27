package kernel

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestObservedControlContract(t *testing.T) {
	got := observedControl("test.control", "Test control", "ENFORCED", "runtime", "provider", "source", boolPtr(true), evidence.ConfidenceExact)
	if got.ID != "test.control" || got.CollectionState != evidence.StateObserved || got.State != "ENFORCED" || got.Enabled == nil || !*got.Enabled || got.Provider == "" || got.Source == "" {
		t.Fatalf("unexpected control: %#v", got)
	}
}

func TestParseBoolControl(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		ok   bool
	}{
		{"Y", true, true}, {"1", true, true}, {"enabled", true, true},
		{"N", false, true}, {"0", false, true}, {"off", false, true},
		{"unknown", false, false},
	} {
		got, ok := parseBoolControl(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseBoolControl(%q)=(%v,%v), want (%v,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
