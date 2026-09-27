package baseline

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/snapshot"
)

func TestValidateEngineContractCoversEveryBuiltInProfile(t *testing.T) {
	if err := ValidateEngineContract(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProducesProfileDrivenCategoryStates(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 0, 0, 0, time.UTC)
	findings := []assessment.Finding{
		fixtureFinding(at, "CHM-A-001", "kernel", assessment.StatusPass, assessment.Applicable),
		fixtureFinding(at, "CHM-A-002", "kernel", assessment.StatusUnknown, assessment.Applicable),
		fixtureFinding(at, "CHM-B-001", "network", assessment.StatusFail, assessment.Applicable),
		fixtureFinding(at, "CHM-C-001", "identity", assessment.StatusPass, assessment.NotApplicable),
	}
	decisions := make([]selection.Decision, 0, len(findings))
	profileDecisions := make([]profile.RuleDecision, 0, len(findings))
	for _, f := range findings {
		decisions = append(decisions, selection.Decision{RuleID: f.RuleID, Category: f.Category, Severity: f.Severity, Outcome: selection.OutcomeSelected, Reason: "selected"})
		profileDecisions = append(profileDecisions, profile.RuleDecision{RuleID: f.RuleID, Category: f.Category, Applicable: f.Applicability != assessment.NotApplicable, BaseSeverity: f.Severity, EffectiveSeverity: f.Severity, Reason: "fixture"})
	}
	in := scan.Result{
		State: scan.StateComplete, AssessedAt: at,
		Profile:   scan.ProfileResult{Descriptor: profile.Descriptor{Schema: profile.SchemaVersion, Name: "server", DefaultApplicable: true}, RuleDecisions: profileDecisions},
		Selection: selection.Report{Schema: selection.SchemaVersion, Summary: selection.Summary{Total: 4, Selected: 4}, Decisions: decisions},
		Findings:  findings,
		Snapshot:  snapshot.Snapshot{AssessmentID: "asm-test", HostFingerprint: snapshot.HostFingerprint{Value: "host-test"}},
	}

	got, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != SchemaVersion || got.EngineVersion != EngineVersion || got.AssessmentID != "asm-test" || got.HostFingerprint != "host-test" {
		t.Fatalf("unexpected baseline provenance: %#v", got)
	}
	if got.State != StateFail || got.Coverage.State != "FULL" || got.Summary.Total != 4 || got.Summary.Fail != 1 || got.Summary.Unknown != 1 || got.Summary.Pass != 1 || got.Summary.NotApplicable != 1 {
		t.Fatalf("unexpected baseline summary: state=%s coverage=%#v summary=%#v", got.State, got.Coverage, got.Summary)
	}
	if len(got.Categories) != 3 || got.Categories[0].Name != "identity" || got.Categories[0].State != StateNotApplicable || got.Categories[1].Name != "kernel" || got.Categories[1].State != StateUnknown || got.Categories[2].Name != "network" || got.Categories[2].State != StateFail {
		t.Fatalf("unexpected deterministic category states: %#v", got.Categories)
	}
}

func TestBuildMarksSelectionLimitedCoveragePartial(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 15, 0, 0, time.UTC)
	f := fixtureFinding(at, "CHM-A-001", "kernel", assessment.StatusPass, assessment.Applicable)
	in := scan.Result{
		State: scan.StateComplete, AssessedAt: at,
		Profile: scan.ProfileResult{Descriptor: profile.Descriptor{Schema: profile.SchemaVersion, Name: "default", DefaultApplicable: true}},
		Selection: selection.Report{
			Schema:  selection.SchemaVersion,
			Summary: selection.Summary{Total: 2, Selected: 1, Skipped: 1},
			Decisions: []selection.Decision{
				{RuleID: f.RuleID, Category: f.Category, Severity: f.Severity, Outcome: selection.OutcomeSelected, Reason: "selected"},
				{RuleID: "CHM-A-002", Category: "kernel", Severity: assessment.SeverityLow, Outcome: selection.OutcomeSkipped, Reason: "threshold"},
			},
		},
		Findings: []assessment.Finding{f},
	}
	got, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Coverage.State != "PARTIAL" || got.Coverage.Selected != 1 || got.Coverage.Skipped != 1 || got.State != StatePass {
		t.Fatalf("unexpected partial coverage: %#v", got)
	}
}

func TestBuildRepresentsSelectedRuleWithoutFindingAsNotEvaluated(t *testing.T) {
	at := time.Date(2026, 8, 20, 7, 30, 0, 0, time.UTC)
	in := scan.Result{
		State: scan.StateComplete, AssessedAt: at,
		Profile: scan.ProfileResult{Descriptor: profile.Descriptor{Schema: profile.SchemaVersion, Name: "default", DefaultApplicable: true}},
		Selection: selection.Report{
			Schema:    selection.SchemaVersion,
			Summary:   selection.Summary{Total: 1, Selected: 1},
			Decisions: []selection.Decision{{RuleID: "CHM-A-001", Category: "kernel", Severity: assessment.SeverityLow, Outcome: selection.OutcomeSelected, Reason: "selected"}},
		},
	}
	got, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Coverage.State != "PARTIAL" || got.Coverage.Evaluated != 0 || got.Coverage.NotEvaluated != 1 || got.Summary.NotEvaluated != 1 || got.State != StateNotEvaluated {
		t.Fatalf("unexpected NOT_EVALUATED baseline: coverage=%#v summary=%#v state=%s", got.Coverage, got.Summary, got.State)
	}
	if len(got.Categories) != 1 || len(got.Categories[0].Rules) != 1 || got.Categories[0].Rules[0].State != StateNotEvaluated {
		t.Fatalf("missing synthesized NOT_EVALUATED rule result: %#v", got.Categories)
	}
}

func fixtureFinding(at time.Time, ruleID, category string, status assessment.Status, applicability assessment.Applicability) assessment.Finding {
	return assessment.Finding{
		ID: assessment.StableFindingID(ruleID, ruleID+"-object"), RuleID: ruleID, Title: ruleID + " title",
		Status: status, Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh,
		Category: category, Platform: "linux", AffectedObject: ruleID + "-object",
		ObservedState: "fixture observed", ExpectedState: "fixture expected", Risk: "fixture risk", Remediation: "fixture remediation",
		CollectionSource: "fixture", FirstObserved: at, AssessmentTimestamp: at, Applicability: applicability, Suppression: assessment.SuppressionActive,
	}
}
