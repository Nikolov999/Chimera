package kernel

import (
	"reflect"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeModuleDeterministicFlags(t *testing.T) {
	m := ModuleAssessment{
		Name:            "demo-driver",
		CollectionState: evidence.StateObserved,
		LoadState:       "LOADED",
		Provider:        "test-provider",
		Source:          "test-source",
		SignatureState:  "UNSIGNED",
		TrustState:      "UNSIGNED",
		BackingState:    "PRESENT",
		Confidence:      evidence.ConfidenceExact,
		Flags:           []string{"unsigned", "OUT_OF_TREE", "UNSIGNED"},
	}
	normalizeModule(&m)
	if m.ID != "module.demo_driver" {
		t.Fatalf("unexpected module id %q", m.ID)
	}
	want := []string{"OUT_OF_TREE", "UNSIGNED"}
	if !reflect.DeepEqual(m.Flags, want) {
		t.Fatalf("flags=%v want=%v", m.Flags, want)
	}
	if got := moduleFlagSummary(m); got != "OUT_OF_TREE,UNSIGNED" {
		t.Fatalf("summary=%q", got)
	}
}
