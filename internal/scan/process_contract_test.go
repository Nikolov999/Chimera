package scan

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidencequality"
)

func TestFix42ScanSummaryCarriesUnknownAudit(t *testing.T) {
	findings := []assessment.Finding{{
		RuleID: "CHM-ID-005", Category: "identity", Status: assessment.StatusUnknown,
		ObservedState: "password state is not safely observable for 2 of 2 enabled login-capable account(s)",
	}}
	got := summarize([]CategoryResult{{Name: "identity", State: StateDegraded, RuleCount: 1, EvaluatedRules: 1}}, findings, EvidenceCounts{})
	if got.Findings.Unknown != 1 {
		t.Fatalf("findings=%#v", got.Findings)
	}
	if err := got.UnknownAudit.Validate(1); err != nil {
		t.Fatal(err)
	}
	if got.UnknownAudit.Summary.SafeCollectionBoundary != 1 || got.UnknownAudit.Entries[0].Classification != evidencequality.UnknownSafeCollectionBoundary {
		t.Fatalf("audit=%#v", got.UnknownAudit)
	}
}
