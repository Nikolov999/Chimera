package remediation

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/prioritization"
)

func remediationFinding(id, rule, category, object string, status assessment.Status, severity assessment.Severity) assessment.Finding {
	now := time.Unix(1700000000, 0).UTC()
	return assessment.Finding{
		ID: id, RuleID: rule, Title: id, Status: status, Severity: severity,
		Confidence: evidence.ConfidenceHigh, Category: category, Platform: "linux",
		AffectedObject: object, ObservedState: "weak", ExpectedState: "hardened",
		Evidence: []assessment.EvidenceRef{{Key: "service.item.demo", State: evidence.StateObserved, Value: true, Source: "test", CollectedAt: now, Confidence: evidence.ConfidenceHigh}},
		Risk:     "risk", Remediation: "Apply the approved hardening change and preserve rollback material.",
		CollectionSource: "test", FirstObserved: now, AssessmentTimestamp: now,
		Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
}

func TestBuildGroupsByPriorityCategoryAndObject(t *testing.T) {
	findings := []assessment.Finding{
		remediationFinding("F1", "CHM-COR-001", "service", "service.alpha", assessment.StatusFail, assessment.SeverityHigh),
		remediationFinding("F2", "CHM-TEST-002", "service", "service.beta", assessment.StatusWarn, assessment.SeverityMedium),
	}
	priority := prioritization.Compute(findings, nil)
	got, err := Build(findings, priority)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Actions != 2 || got.Summary.Categories != 1 || got.Summary.AffectedComponents != 2 {
		t.Fatalf("unexpected summary: %#v", got.Summary)
	}
	if len(got.Groups) == 0 || got.Actions[0].PriorityRank >= got.Actions[1].PriorityRank {
		t.Fatalf("actions are not deterministically prioritized: %#v", got.Actions)
	}
	for _, a := range got.Actions {
		if a.Guidance == "" || a.Verification == "" || a.RawSeverity == "" {
			t.Fatalf("incomplete remediation action: %#v", a)
		}
	}
}

func TestBuildExcludesSuppressedAndUnknownFromFixActions(t *testing.T) {
	suppressed := remediationFinding("F1", "CHM-COR-001", "service", "service.alpha", assessment.StatusFail, assessment.SeverityHigh)
	suppressed.Suppression = assessment.SuppressionSuppressed
	suppressed.Suppressions = []assessment.SuppressionRecord{{ID: "SUP-1"}}
	unknown := remediationFinding("F2", "CHM-TEST-002", "kernel", "kernel.alpha", assessment.StatusUnknown, assessment.SeverityMedium)
	findings := []assessment.Finding{suppressed, unknown}
	priority := prioritization.Compute(findings, nil)
	got, err := Build(findings, priority)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.Actions != 0 || got.Summary.Suppressed != 1 || got.Summary.NeedsEvidence != 1 || len(got.Groups) != 0 {
		t.Fatalf("unexpected non-actionable handling: %#v", got)
	}
}

func TestValidateEngineContract(t *testing.T) {
	if err := ValidateEngineContract(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPreservesIncompleteEvaluationCoverage(t *testing.T) {
	priority := prioritization.Compute(nil, nil)
	got, err := Build(nil, priority, EvaluationCoverage{SelectedRules: 10, EvaluatedRules: 4, NotEvaluatedRules: 6, Percent: 40, Complete: false})
	if err != nil {
		t.Fatal(err)
	}
	if got.Evaluation.Complete || got.Evaluation.NotEvaluatedRules != 6 || got.Summary.Actions != 0 {
		t.Fatalf("incomplete remediation coverage was not preserved: %#v", got)
	}
}
