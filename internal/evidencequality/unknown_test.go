package evidencequality

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix33UnknownCauseClassificationPreservesUnknown(t *testing.T) {
	findings := []assessment.Finding{
		{RuleID: "CHM-A", Status: assessment.StatusUnknown, ObservedState: "required evidence dependencies missing: x"},
		{RuleID: "CHM-B", Status: assessment.StatusUnknown, Evidence: []assessment.EvidenceRef{{State: evidence.StateDenied, Reason: "access denied"}}},
		{RuleID: "CHM-C", Status: assessment.StatusUnknown, Evidence: []assessment.EvidenceRef{{State: evidence.StateUnavailable, Reason: "windows-loaded-modules: exit code 1"}}},
		{RuleID: "CHM-D", Status: assessment.StatusPass},
	}
	causes, summary := ClassifyUnknownFindings(findings)
	if summary.Total != 3 || summary.MissingRequiredEvidence != 1 || summary.PermissionRestriction != 1 || summary.ProductDefect != 1 {
		t.Fatalf("summary=%#v", summary)
	}
	if len(causes) != 3 {
		t.Fatalf("causes=%#v", causes)
	}
}

func TestFix33DegradedUnknownIsNotConvertedToPass(t *testing.T) {
	findings := []assessment.Finding{{
		RuleID: "CHM-X", Status: assessment.StatusUnknown,
		ObservedState: "permission posture unresolved for one record",
		Evidence:      []assessment.EvidenceRef{{State: evidence.StateDegraded, Reason: "provider record incomplete"}},
	}}
	_, summary := ClassifyUnknownFindings(findings)
	if findings[0].Status != assessment.StatusUnknown {
		t.Fatalf("status mutated to %s", findings[0].Status)
	}
	if summary.DegradedEvidence != 1 {
		t.Fatalf("summary=%#v", summary)
	}
}
