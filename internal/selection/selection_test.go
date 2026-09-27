package selection

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func testRule(id, category string, severity assessment.Severity) assessment.Rule {
	return assessment.Rule{
		ID: id, Title: id, Category: category, Severity: severity,
		AffectedObject: id, ExpectedState: "ok", Risk: "risk", Remediation: "remediation",
		Evaluate: func(assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "ok", Applicability: assessment.Applicable}
		},
	}
}

func catalog() []assessment.Rule {
	return []assessment.Rule{
		testRule("CHM-A-001", "alpha", assessment.SeverityInfo),
		testRule("CHM-A-002", "alpha", assessment.SeverityHigh),
		testRule("CHM-B-001", "beta", assessment.SeverityMedium),
	}
}

func TestApplyDefaultSelectsEveryRule(t *testing.T) {
	got, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo})
	if err != nil {
		t.Fatal(err)
	}
	if got.Report.Schema != SchemaVersion || got.Report.Summary.Selected != 3 || got.Report.Summary.Skipped != 0 || got.Report.Summary.Suppressed != 0 || len(got.Rules) != 3 {
		t.Fatalf("unexpected selection: %#v", got.Report)
	}
}

func TestCategoryAndSeveritySelection(t *testing.T) {
	got, err := Apply(catalog(), Request{Severity: assessment.SeverityMedium, Category: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "CHM-A-002" {
		t.Fatalf("unexpected selected rules: %#v", got.Rules)
	}
	if got.Report.Summary.Selected != 1 || got.Report.Summary.Skipped != 2 {
		t.Fatalf("unexpected summary: %#v", got.Report.Summary)
	}
}

func TestIncludeExactRuleOrCategory(t *testing.T) {
	got, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo, Include: []string{"rule:CHM-A-001", "category:beta"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 2 || got.Rules[0].ID != "CHM-A-001" || got.Rules[1].ID != "CHM-B-001" {
		t.Fatalf("unexpected selected rules: %#v", got.Rules)
	}
}

func TestExcludeOverridesIncludeAndIsSuppressed(t *testing.T) {
	got, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo, Include: []string{"alpha"}, Exclude: []string{"CHM-A-002"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "CHM-A-001" {
		t.Fatalf("unexpected selected rules: %#v", got.Rules)
	}
	d, ok := DecisionFor(got.Report, "CHM-A-002")
	if !ok || d.Outcome != OutcomeSuppressed {
		t.Fatalf("expected suppression decision, got %#v", d)
	}
}

func TestUnknownSelectorsFailClosed(t *testing.T) {
	if _, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo, Include: []string{"does-not-exist"}}); err == nil {
		t.Fatal("expected unknown include selector error")
	}
	if _, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo, Category: "does-not-exist"}); err == nil {
		t.Fatal("expected unknown category error")
	}
}

func TestCommaSeparatedSelectorsAreNormalized(t *testing.T) {
	got, err := Apply(catalog(), Request{Severity: assessment.SeverityInfo, Include: []string{"alpha, CHM-B-001", "ALPHA"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Report.Summary.Selected != 3 || len(got.Report.Request.Include) != 2 {
		t.Fatalf("unexpected normalization: %#v", got.Report)
	}
}
