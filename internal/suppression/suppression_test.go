package suppression

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func rule(id, object string) assessment.Rule {
	return assessment.Rule{ID: id, Title: id, Category: "test", Severity: assessment.SeverityHigh, AffectedObject: object, ExpectedState: "secure", Risk: "risk", Remediation: "fix", Evaluate: func(assessment.Index) assessment.Evaluation {
		return assessment.Evaluation{Status: assessment.StatusFail, Confidence: evidence.ConfidenceExact, ObservedState: "weak", Applicability: assessment.Applicable}
	}}
}

func TestApplySuppressesWithoutDeletingEvidence(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	rules := []assessment.Rule{rule("CHM-TST-001", "service:ssh")}
	findings, err := assessment.EvaluateRules(rules, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	defs := []Definition{{ID: "ticket-42", RuleID: "CHM-TST-001", Reason: "accepted during migration", Owner: "security", CreatedAt: at.Add(-time.Hour), ExpiresAt: at.Add(24 * time.Hour), Metadata: map[string]string{"ticket": "SEC-42"}}}
	got, report, err := Apply(findings, defs, rules, at)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Suppression != assessment.SuppressionSuppressed || len(got[0].Suppressions) != 1 {
		t.Fatalf("not suppressed: %#v", got[0])
	}
	if got[0].Status != assessment.StatusFail || got[0].ObservedState != "weak" {
		t.Fatalf("suppression mutated raw finding: %#v", got[0])
	}
	if report.Summary.Applied != 1 || report.Summary.FindingsSuppressed != 1 || report.Entries[0].State != StateApplied {
		t.Fatalf("bad report: %#v", report)
	}
}

func TestExpiredSuppressionIsAuditedButNotApplied(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	rules := []assessment.Rule{rule("CHM-TST-001", "service:ssh")}
	findings, _ := assessment.EvaluateRules(rules, nil, at)
	defs := []Definition{{RuleID: "CHM-TST-001", Reason: "old exception", Owner: "security", CreatedAt: at.Add(-48 * time.Hour), ExpiresAt: at.Add(-time.Hour)}}
	got, report, err := Apply(findings, defs, rules, at)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Suppression != assessment.SuppressionActive || report.Summary.Expired != 1 || report.Entries[0].State != StateExpired {
		t.Fatalf("unexpected expired behavior: %#v %#v", got[0], report)
	}
}

func TestRuleAndObjectMatchingIsExact(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	rules := []assessment.Rule{rule("CHM-TST-001", "service:ssh"), rule("CHM-TST-002", "service:web")}
	findings, _ := assessment.EvaluateRules(rules, nil, at)
	defs := []Definition{{RuleID: "CHM-TST-001", AffectedObject: "service:ssh", Reason: "accepted", Owner: "security", CreatedAt: at.Add(-time.Hour), ExpiresAt: at.Add(time.Hour)}}
	got, report, err := Apply(findings, defs, rules, at)
	if err != nil {
		t.Fatal(err)
	}
	suppressed := 0
	for _, f := range got {
		if f.Suppression == assessment.SuppressionSuppressed {
			suppressed++
		}
	}
	if suppressed != 1 || report.Summary.FindingsSuppressed != 1 {
		t.Fatalf("unexpected match: %#v %#v", got, report)
	}
}

func TestValidationRejectsUnsafeOrAmbiguousDefinitions(t *testing.T) {
	at := time.Now().UTC()
	rules := []assessment.Rule{rule("CHM-TST-001", "service:ssh")}
	cases := []Definition{
		{Reason: "x", Owner: "o", CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{RuleID: "CHM-NOPE", Reason: "x", Owner: "o", CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{RuleID: "CHM-TST-001", Owner: "o", CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{RuleID: "CHM-TST-001", Reason: "x", CreatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{RuleID: "CHM-TST-001", Reason: "x", Owner: "o", CreatedAt: at, ExpiresAt: at},
	}
	for i, c := range cases {
		if _, err := NormalizeAndValidate([]Definition{c}, rules); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
}
