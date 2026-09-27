package app

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/snapshot"
)

func testWorkflowFinding(id, ruleID, category string) assessment.Finding {
	return assessment.Finding{
		ID: id, RuleID: ruleID, Title: "test finding", Status: assessment.StatusFail,
		Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh,
		Category: category, Platform: "test", AffectedObject: "test.object",
		ObservedState: "weak", ExpectedState: "hardened", Risk: "risk", Remediation: "fix",
		CollectionSource: "test", Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
}

func TestWorkflowViewScopesAreDeterministic(t *testing.T) {
	result := scan.Result{
		State:      scan.StateComplete,
		Profile:    scan.ProfileResult{Descriptor: profile.Descriptor{Name: "default"}},
		Selection:  selection.Report{Schema: selection.SchemaVersion},
		Snapshot:   snapshot.Snapshot{AssessmentID: "assessment-test"},
		Categories: []scan.CategoryResult{{Name: "correlation"}, {Name: "network"}, {Name: "kernel"}},
		Findings: []assessment.Finding{
			testWorkflowFinding("CHM-F-COR", "CHM-COR-001", "correlation"),
			testWorkflowFinding("CHM-F-NET", "CHM-NET-001", "network"),
			testWorkflowFinding("CHM-F-KER", "CHM-KER-001", "kernel"),
		},
	}

	relationships, err := buildWorkflowView(result, "relationships")
	if err != nil {
		t.Fatal(err)
	}
	if relationships.Schema != workflowViewSchema || relationships.AssessmentID != "assessment-test" {
		t.Fatalf("unexpected relationship contract: %#v", relationships)
	}
	if len(relationships.Categories) != 1 || relationships.Categories[0].Name != "correlation" {
		t.Fatalf("unexpected relationship categories: %#v", relationships.Categories)
	}
	if len(relationships.Findings) != 1 || relationships.Findings[0].Category != "correlation" {
		t.Fatalf("unexpected relationship findings: %#v", relationships.Findings)
	}

	hardening, err := buildWorkflowView(result, "hardening")
	if err != nil {
		t.Fatal(err)
	}
	if len(hardening.Findings) != 3 {
		t.Fatalf("hardening should include all three synthetic hardening domains, got %d", len(hardening.Findings))
	}
}

func TestV1RoadmapWorkflowCommandsAreRegistered(t *testing.T) {
	registry := commandRegistry()
	for _, name := range []string{"exposure", "hardening", "misconfigurations", "relationships", "surface", "summary", "rules"} {
		command, ok := registry[name]
		if !ok {
			t.Fatalf("roadmap workflow %q is not registered", name)
		}
		if command.Run == nil || command.Help.Purpose == "" || command.Help.Output == "" {
			t.Fatalf("roadmap workflow %q is scaffolding-only: %#v", name, command)
		}
	}
	if err := validateV1CommandRegistry(registry); err != nil {
		t.Fatal(err)
	}
}
