package assessmentdiff

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestMatchedFindingClassifications(t *testing.T) {
	base := fixtureFinding("CHM-TST-001", "object", assessment.StatusFail)
	after := base
	after.Status = assessment.StatusPass
	change, err := compareFinding(base, true, after, true, map[string]bool{"CHM-TST-001": true}, map[string]bool{"CHM-TST-001": true})
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassResolved || !change.StatusChanged {
		t.Fatalf("expected resolved status change, got %+v", change)
	}

	after = base
	after.Status = assessment.StatusWarn
	change, err = compareFinding(base, true, after, true, map[string]bool{"CHM-TST-001": true}, map[string]bool{"CHM-TST-001": true})
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassImproved {
		t.Fatalf("expected improved, got %s", change.Classification)
	}

	before := base
	before.Status = assessment.StatusPass
	after = base
	after.Status = assessment.StatusFail
	change, err = compareFinding(before, true, after, true, map[string]bool{"CHM-TST-001": true}, map[string]bool{"CHM-TST-001": true})
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassRegressed {
		t.Fatalf("expected regressed, got %s", change.Classification)
	}
}

func TestScopeAwareAdditionAndRemoval(t *testing.T) {
	f := fixtureFinding("CHM-TST-002", "object", assessment.StatusFail)
	change, err := compareFinding(assessment.Finding{}, false, f, true, map[string]bool{}, map[string]bool{"CHM-TST-002": true})
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassAddedToScope {
		t.Fatalf("expected added to scope, got %s", change.Classification)
	}

	change, err = compareFinding(f, true, assessment.Finding{}, false, map[string]bool{"CHM-TST-002": true}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassRemovedFromScope {
		t.Fatalf("expected removed from scope, got %s", change.Classification)
	}
}

func TestEvidenceDigestIgnoresCollectionTimestampButDetectsContent(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	one := []assessment.EvidenceRef{{Key: "x", State: evidence.StateObserved, Value: "enabled", Source: "fixture", CollectedAt: at, Confidence: evidence.ConfidenceExact}}
	two := []assessment.EvidenceRef{{Key: "x", State: evidence.StateObserved, Value: "enabled", Source: "fixture", CollectedAt: at.Add(time.Hour), Confidence: evidence.ConfidenceExact}}
	a, err := evidenceDigest(one)
	if err != nil {
		t.Fatal(err)
	}
	b, err := evidenceDigest(two)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("collection timestamp alone must not change evidence digest")
	}
	two[0].Value = "disabled"
	b, err = evidenceDigest(two)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("evidence content change must alter digest")
	}
}

func TestSuppressionDigestIgnoresAppliedAt(t *testing.T) {
	f := fixtureFinding("CHM-TST-003", "object", assessment.StatusFail)
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	f.Suppression = assessment.SuppressionSuppressed
	f.Suppressions = []assessment.SuppressionRecord{{ID: "SEC-1", MatchScope: "RULE", Reason: "accepted", Owner: "security", CreatedAt: created, ExpiresAt: created.Add(30 * 24 * time.Hour), AppliedAt: created.Add(time.Hour)}}
	g := f
	g.Suppressions = append([]assessment.SuppressionRecord(nil), f.Suppressions...)
	g.Suppressions[0].AppliedAt = created.Add(2 * time.Hour)
	if suppressionDigest(f) != suppressionDigest(g) {
		t.Fatalf("per-assessment application timestamp must not create suppression-policy drift")
	}
}

func TestValidateContract(t *testing.T) {
	if err := ValidateContract(); err != nil {
		t.Fatal(err)
	}
}

func fixtureFinding(ruleID, object string, status assessment.Status) assessment.Finding {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	return assessment.Finding{
		ID: assessment.StableFindingID(ruleID, object), RuleID: ruleID, Title: "Fixture finding",
		Status: status, Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh,
		Category: "fixture", Platform: "linux", AffectedObject: object,
		ObservedState: "fixture observed", ExpectedState: "fixture expected",
		Evidence: []assessment.EvidenceRef{{Key: "fixture.key", State: evidence.StateObserved, Value: "value", Source: "fixture", CollectedAt: at, Confidence: evidence.ConfidenceHigh}},
		Risk:     "fixture risk", Remediation: "fixture remediation", CollectionSource: "fixture",
		FirstObserved: at, AssessmentTimestamp: at, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
}

func TestMissingFindingAfterNotEvaluatedRuleIsNotResolved(t *testing.T) {
	f := fixtureFinding("CHM-TST-004", "object", assessment.StatusFail)
	selected := map[string]bool{"CHM-TST-004": true}
	beforeEvaluated := map[string]bool{"CHM-TST-004": true}
	afterEvaluated := map[string]bool{}
	change, err := compareFinding(f, true, assessment.Finding{}, false, selected, selected, beforeEvaluated, afterEvaluated)
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassNotEvaluated {
		t.Fatalf("expected NOT_EVALUATED, got %s", change.Classification)
	}
}

func TestFindingAfterPreviouslyNotEvaluatedRuleIsNewlyEvaluated(t *testing.T) {
	f := fixtureFinding("CHM-TST-005", "object", assessment.StatusFail)
	selected := map[string]bool{"CHM-TST-005": true}
	beforeEvaluated := map[string]bool{}
	afterEvaluated := map[string]bool{"CHM-TST-005": true}
	change, err := compareFinding(assessment.Finding{}, false, f, true, selected, selected, beforeEvaluated, afterEvaluated)
	if err != nil {
		t.Fatal(err)
	}
	if change.Classification != ClassNewlyEvaluated {
		t.Fatalf("expected NEWLY_EVALUATED, got %s", change.Classification)
	}
}
