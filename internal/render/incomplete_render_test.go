package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidencequality"

	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/report"
	"github.com/Nikolov999/chimera/internal/scan"
)

func TestFix20ScanHumanCannotPresentIncompleteAssessmentAsClean(t *testing.T) {
	var out bytes.Buffer
	ScanHuman(&out, scan.Result{
		State: scan.StatePartial,
		Summary: scan.Summary{Evaluation: scan.EvaluationCoverage{
			SelectedRules: 219, EvaluatedRules: 0, NotEvaluatedRules: 219, Percent: 0, Complete: false,
		}},
	}, false)
	text := out.String()
	for _, want := range []string{"Assessment         INCOMPLETE", "ASSESSMENT INCOMPLETE", "NOT_EVALUATED      219", "Rule evaluation    0/219"} {
		if !strings.Contains(text, want) {
			t.Fatalf("incomplete scan output missing %q:\n%s", want, text)
		}
	}
}

func TestFix20RemediationHumanRejectsZeroFindingCleanConclusionWhenNothingEvaluated(t *testing.T) {
	var out bytes.Buffer
	RemediationHuman(&out, remediation.Result{
		Evaluation: remediation.EvaluationCoverage{SelectedRules: 219, EvaluatedRules: 0, NotEvaluatedRules: 219, Percent: 0, Complete: false},
	}, false)
	text := out.String()
	if !strings.Contains(text, "Assessment incomplete. No remediation conclusion can be made") {
		t.Fatalf("missing incomplete-remediation guard:\n%s", text)
	}
	if strings.Contains(text, "No active FAIL/WARN findings require remediation under the current profile") {
		t.Fatalf("incomplete remediation was rendered as a clean conclusion:\n%s", text)
	}
}

func TestFix20ReportHumanMakesPartialCoverageExplicitBeforeFindings(t *testing.T) {
	var out bytes.Buffer
	ReportHuman(&out, report.Result{
		Assessment: report.Assessment{
			State:      scan.StatePartial,
			Evaluation: scan.EvaluationCoverage{SelectedRules: 219, EvaluatedRules: 25, NotEvaluatedRules: 194, Percent: 25.0 / 219.0 * 100.0, Complete: false},
		},
	}, false)
	text := out.String()
	incomplete := strings.Index(text, "ASSESSMENT INCOMPLETE")
	findings := strings.Index(text, "\nFINDINGS\n")
	if incomplete < 0 || findings < 0 || incomplete > findings {
		t.Fatalf("partial coverage warning must precede findings:\n%s", text)
	}
	if !strings.Contains(text, "Findings below represent only 25 of 219 selected rules evaluated") {
		t.Fatalf("report does not quantify partial evaluation:\n%s", text)
	}
}

func TestFix33ReportHumanShowsCanonicalLimitationAndUnknownSummaries(t *testing.T) {
	var out bytes.Buffer
	ReportHuman(&out, report.Result{
		EvidenceQuality: report.EvidenceQuality{
			LimitationSummary: evidencequality.Summary{TotalOccurrences: 192, UniqueLimitations: 1, AffectedRecords: 192},
			UnknownSummary:    evidencequality.UnknownSummary{Total: 3, MissingRequiredEvidence: 1, PermissionRestriction: 1, ExpectedEnvironment: 1},
		},
		Findings:    report.Findings{Summary: scan.FindingCounts{Unknown: 3}},
		Limitations: []string{"persistence privilege correlation: local-account privilege inventory is unavailable (affected records=192, occurrences=192)"},
	}, false)
	text := out.String()
	for _, want := range []string{"Limitations         1 unique / 192 raw", "Affected records    192", "UNKNOWN CAUSES", "Missing / degraded  1 / 0", "Permission          1", "affected records=192"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Fix33 report output missing %q:\n%s", want, text)
		}
	}
}
