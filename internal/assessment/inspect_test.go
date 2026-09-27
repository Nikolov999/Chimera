package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestInspectFindingReproducesFromNormalizedEvidence(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	obs := []evidence.Observation{
		evidence.NewObserved("host.os.name", "linux", "test", now, evidence.ConfidenceExact),
	}
	rule := availabilityRule("CHM-TEST-001", "OS known", "inventory", SeverityInfo, "host.os.name", "identified", "risk", "fix")
	id := StableFindingID(rule.ID, rule.AffectedObject)
	first, err := InspectFinding([]Rule{rule}, obs, now, id)
	if err != nil {
		t.Fatal(err)
	}
	if first.Finding.ID != id || !first.Reproducible.MatchesID {
		t.Fatalf("unexpected inspection: %#v", first)
	}
	if first.Reproducible.EvidenceDigest == "" || len(first.Provenance) != 1 {
		t.Fatalf("missing provenance/reproducibility: %#v", first)
	}

	// Collection/assessment timestamps can change while the normalized fact is
	// identical. The digest intentionally represents decision inputs, not wall time.
	later := now.Add(5 * time.Minute)
	obsLater := []evidence.Observation{
		evidence.NewObserved("host.os.name", "linux", "test", later, evidence.ConfidenceExact),
	}
	second, err := InspectFinding([]Rule{rule}, obsLater, later, id)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reproducible.EvidenceDigest != second.Reproducible.EvidenceDigest {
		t.Fatalf("same normalized evidence produced different digests: %q != %q", first.Reproducible.EvidenceDigest, second.Reproducible.EvidenceDigest)
	}
	if first.Finding.Status != second.Finding.Status || first.Finding.ObservedState != second.Finding.ObservedState {
		t.Fatalf("same normalized evidence produced different decision")
	}
}

func TestInspectFindingRejectsUnknownID(t *testing.T) {
	now := time.Now().UTC()
	obs := []evidence.Observation{evidence.NewObserved("host.os.name", "linux", "test", now, evidence.ConfidenceExact)}
	rule := availabilityRule("CHM-TEST-002", "OS known", "inventory", SeverityInfo, "host.os.name", "identified", "risk", "fix")
	if _, err := InspectFinding([]Rule{rule}, obs, now, "CHM-F-DOESNOTEXIST"); err == nil {
		t.Fatal("expected unknown finding error")
	}
}
