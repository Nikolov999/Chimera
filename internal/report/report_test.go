package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/snapshot"
)

func TestBuildPreservesEnterpriseReportProvenance(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	f := assessment.Finding{
		ID: "CHM-F-REPORTTEST01", RuleID: "CHM-TEST-001", Title: "Test finding",
		Status: assessment.StatusFail, Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh,
		Category: "service", Platform: "linux", AffectedObject: "service.test",
		ObservedState: "weak", ExpectedState: "hardened",
		Evidence: []assessment.EvidenceRef{{Key: "service.item.test", State: evidence.StateObserved, Value: true, Source: "test", CollectedAt: at, Confidence: evidence.ConfidenceHigh}},
		Risk:     "test risk", Remediation: "apply approved hardening", CollectionSource: "test",
		FirstObserved: at, AssessmentTimestamp: at, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
	priority := prioritization.Compute([]assessment.Finding{f}, nil)
	rem, err := remediation.Build([]assessment.Finding{f}, priority)
	if err != nil {
		t.Fatal(err)
	}
	s := scan.Result{
		State:      scan.StateDegraded,
		Timing:     scan.Timing{StartedAt: at.Add(-time.Second), CompletedAt: at, DurationMS: 1000},
		Overview:   overview.Overview{Hostname: "host-a", CurrentUser: "tester", OS: "linux", Architecture: "amd64", Privilege: overview.Privilege{CollectionTier: "standard"}},
		Profile:    scan.ProfileResult{Descriptor: profile.Descriptor{Name: "default"}},
		Collection: scan.CollectionResult{State: scan.StateDegraded, Evidence: scan.EvidenceCounts{Total: 2, Observed: 1, Denied: 1}, DegradationReasons: []string{"permission denied for provider"}},
		Summary:    scan.Summary{Categories: scan.CategoryCounts{Total: 1, Degraded: 1}, Findings: scan.FindingCounts{Total: 1, Fail: 1}},
		Findings:   []assessment.Finding{f}, Prioritization: &priority, Remediation: &rem,
		Snapshot: snapshot.Snapshot{
			AssessmentID: "assessment-1", HostFingerprint: snapshot.HostFingerprint{Algorithm: "sha256", Value: "abcdef", Inputs: []string{"host"}},
			Rules:        snapshot.RuleSetProvenance{Schema: "rules/v1", Version: "rules-1", Digest: snapshot.Digest{Algorithm: "sha256", Value: "rulesdigest"}, RuleCount: 1, SelectedCount: 1},
			Intelligence: snapshot.IntelligenceProvenance{State: "PINNED", Version: "intel-1", Source: "local", ReadOnly: true},
		},
	}
	got, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != SchemaVersion || got.EngineVersion != EngineVersion || got.Assessment.ID != "assessment-1" || got.Host.Fingerprint != "abcdef" {
		t.Fatalf("unexpected report identity: %#v", got)
	}
	if got.Findings.Summary.Total != 1 || len(got.Findings.Items) != 1 || got.Remediation.Summary.Actions != 1 {
		t.Fatalf("report lost findings/remediation: %#v", got)
	}
	if len(got.Limitations) != 1 || got.Limitations[0] != "permission denied for provider" {
		t.Fatalf("unexpected limitations: %#v", got.Limitations)
	}
	if got.EvidenceQuality.LimitationSummary.Permission != 1 || got.EvidenceQuality.LimitationSummary.ReleaseBlockers != 0 {
		t.Fatalf("unexpected limitation classification: %#v", got.EvidenceQuality.LimitationSummary)
	}
}

func TestValidateEngineContract(t *testing.T) {
	if err := ValidateEngineContract(); err != nil {
		t.Fatal(err)
	}
}

func TestFix33BuildAggregatesLimitationsAndClassifiesUnknownCauses(t *testing.T) {
	at := time.Unix(1700000100, 0).UTC()
	f := assessment.Finding{
		ID: "CHM-F-REPORTUNKNOWN01", RuleID: "CHM-TEST-UNKNOWN", Title: "Unknown test",
		Status: assessment.StatusUnknown, Severity: assessment.SeverityMedium, Confidence: evidence.ConfidenceLow,
		Category: "persistence", Platform: "windows", AffectedObject: "persistence.test",
		ObservedState: "required evidence dependencies missing: account privilege correlation", ExpectedState: "privilege evidence available",
		Risk: "unknown evidence prevents a conclusion", Remediation: "collect the missing local evidence", CollectionSource: "test",
		FirstObserved: at, AssessmentTimestamp: at, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
	priority := prioritization.Compute([]assessment.Finding{f}, nil)
	rem, err := remediation.Build([]assessment.Finding{f}, priority)
	if err != nil {
		t.Fatal(err)
	}
	reasons := []string{
		"persistence.privilege.per-0552fcae934d0a60b4a3: local-account privilege inventory is unavailable",
		"persistence.privilege.per-05fb7b6b8866b4fa93ca: local-account privilege inventory is unavailable",
		"persistence: persistence.privilege.per-0552fcae934d0a60b4a3: local-account privilege inventory is unavailable",
	}
	s := scan.Result{
		State:      scan.StateDegraded,
		Timing:     scan.Timing{StartedAt: at.Add(-time.Second), CompletedAt: at, DurationMS: 1000},
		Overview:   overview.Overview{Hostname: "host-w", CurrentUser: "tester", OS: "windows", Architecture: "amd64", Privilege: overview.Privilege{CollectionTier: "elevated"}},
		Profile:    scan.ProfileResult{Descriptor: profile.Descriptor{Name: "default"}},
		Collection: scan.CollectionResult{State: scan.StateDegraded, Evidence: scan.EvidenceCounts{Total: 3, Observed: 2, Unavailable: 1}, DegradationReasons: reasons},
		Summary:    scan.Summary{Categories: scan.CategoryCounts{Total: 1, Degraded: 1}, Findings: scan.FindingCounts{Total: 1, Unknown: 1}, Evaluation: scan.EvaluationCoverage{SelectedRules: 1, EvaluatedRules: 1, Percent: 100, Complete: true}},
		Findings:   []assessment.Finding{f}, Prioritization: &priority, Remediation: &rem,
		Snapshot: snapshot.Snapshot{
			AssessmentID: "assessment-fix33", HostFingerprint: snapshot.HostFingerprint{Algorithm: "sha256", Value: "abcdef33", Inputs: []string{"host"}},
			Rules:        snapshot.RuleSetProvenance{Schema: "rules/v1", Version: "rules-1", Digest: snapshot.Digest{Algorithm: "sha256", Value: "rulesdigest"}, RuleCount: 1, SelectedCount: 1},
			Intelligence: snapshot.IntelligenceProvenance{State: "PINNED", Version: "intel-1", Source: "local", ReadOnly: true},
		},
	}
	got, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.EvidenceQuality.LimitationSummary.TotalOccurrences != 3 || got.EvidenceQuality.LimitationSummary.UniqueLimitations != 1 {
		t.Fatalf("limitation summary=%#v", got.EvidenceQuality.LimitationSummary)
	}
	if len(got.EvidenceQuality.Limitations) != 1 || got.EvidenceQuality.Limitations[0].AffectedRecords != 2 {
		t.Fatalf("canonical limitations=%#v", got.EvidenceQuality.Limitations)
	}
	if len(got.EvidenceQuality.RawLimitations) != 3 {
		t.Fatalf("raw limitations=%#v", got.EvidenceQuality.RawLimitations)
	}
	if len(got.Limitations) != 1 || !strings.Contains(got.Limitations[0], "affected records=2") {
		t.Fatalf("human limitations=%#v", got.Limitations)
	}
	if got.EvidenceQuality.UnknownSummary.Total != 1 || got.EvidenceQuality.UnknownSummary.MissingRequiredEvidence != 1 {
		t.Fatalf("unknown summary=%#v", got.EvidenceQuality.UnknownSummary)
	}
	if err := got.EvidenceQuality.UnknownAudit.Validate(1); err != nil {
		t.Fatal(err)
	}
	if got.EvidenceQuality.UnknownAudit.Summary.RequiredEvidenceMissing != 1 || len(got.EvidenceQuality.UnknownAudit.Entries) != 1 {
		t.Fatalf("Fix42 UNKNOWN audit=%#v", got.EvidenceQuality.UnknownAudit)
	}
	if f.Status != assessment.StatusUnknown {
		t.Fatalf("Fix33 mutated finding status to %s", f.Status)
	}
}

func TestFix40ReportExposesUniqueReleaseBlockerRoots(t *testing.T) {
	at := time.Unix(1700000200, 0).UTC()
	priority := prioritization.Compute(nil, nil)
	rem, err := remediation.Build(nil, priority)
	if err != nil {
		t.Fatal(err)
	}
	reasons := []string{
		"windows-service-object-security: windows-service-security-enrichment: context deadline exceeded",
		"services: windows-service-registry-security: windows-service-security-enrichment: context deadline exceeded",
		"persistence.source.services: windows-service-account-security: windows-service-security-enrichment: context deadline exceeded",
	}
	s := scan.Result{
		State:      scan.StateDegraded,
		Timing:     scan.Timing{StartedAt: at.Add(-time.Second), CompletedAt: at, DurationMS: 1000},
		Overview:   overview.Overview{Hostname: "host-w", CurrentUser: "tester", OS: "windows", Architecture: "amd64", Privilege: overview.Privilege{CollectionTier: "elevated"}},
		Profile:    scan.ProfileResult{Descriptor: profile.Descriptor{Name: "default"}},
		Collection: scan.CollectionResult{State: scan.StateDegraded, Evidence: scan.EvidenceCounts{Total: 1, Observed: 1}, DegradationReasons: reasons},
		Summary:    scan.Summary{Evaluation: scan.EvaluationCoverage{SelectedRules: 0, EvaluatedRules: 0, Complete: true}},
		Findings:   nil, Prioritization: &priority, Remediation: &rem,
		Snapshot: snapshot.Snapshot{
			AssessmentID: "assessment-fix40", HostFingerprint: snapshot.HostFingerprint{Algorithm: "sha256", Value: "abcdef40", Inputs: []string{"host"}},
			Rules:        snapshot.RuleSetProvenance{Schema: "rules/v1", Version: "rules-1", Digest: snapshot.Digest{Algorithm: "sha256", Value: "rulesdigest"}, RuleCount: 0, SelectedCount: 0},
			Intelligence: snapshot.IntelligenceProvenance{State: "PINNED", Version: "intel-1", Source: "local", ReadOnly: true},
		},
	}
	got, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	q := got.EvidenceQuality
	if q.LimitationSummary.TotalOccurrences != 3 || q.LimitationSummary.UniqueLimitations != 1 || q.LimitationSummary.UniqueReleaseBlockers != 1 || q.LimitationSummary.ReleaseBlockers != 1 {
		t.Fatalf("summary=%#v", q.LimitationSummary)
	}
	if len(q.Limitations) != 1 {
		t.Fatalf("limitations=%#v", q.Limitations)
	}
	root := q.Limitations[0]
	if root.RootCauseID == "" || root.Provider != "windows-service-security" || root.Stage != "enrichment" || root.Platform != "windows" {
		t.Fatalf("root=%#v", root)
	}
	if len(root.Aliases) != 3 || len(root.AffectedCategories) < 2 {
		t.Fatalf("alias/category metadata=%#v", root)
	}
}

func TestFix48ReleaseReadinessMirrorsCanonicalEvidenceAccounting(t *testing.T) {
	at := time.Unix(1700000300, 0).UTC()
	f := assessment.Finding{
		ID: "CHM-F-FIX48UNKNOWN01", RuleID: "CHM-NET-048", Title: "Provider-backed state unresolved",
		Status: assessment.StatusUnknown, Severity: assessment.SeverityMedium, Confidence: evidence.ConfidenceLow,
		Category: "network", Platform: "windows", AffectedObject: "network.firewall",
		ObservedState: "required firewall evidence is unavailable", ExpectedState: "firewall evidence available",
		Evidence: []assessment.EvidenceRef{{
			Key: "firewall.source.windows", State: evidence.StateUnavailable, Source: "test", CollectedAt: at, Confidence: evidence.ConfidenceLow,
			Reason: "firewall: provider=network stage=collector class=DEADLINE message=context deadline exceeded",
		}},
		Risk: "provider defect prevents a conclusion", Remediation: "repair the provider and reassess", CollectionSource: "test",
		FirstObserved: at, AssessmentTimestamp: at, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive,
	}
	priority := prioritization.Compute([]assessment.Finding{f}, nil)
	rem, err := remediation.Build([]assessment.Finding{f}, priority)
	if err != nil {
		t.Fatal(err)
	}
	reasons := []string{
		"network: provider=network stage=collector class=DEADLINE message=context deadline exceeded",
		"firewall: provider=firewall stage=collection class=DEADLINE upstream provider=network stage=collector class=DEADLINE message=context deadline exceeded",
	}
	s := scan.Result{
		State:      scan.StateDegraded,
		Timing:     scan.Timing{StartedAt: at.Add(-time.Second), CompletedAt: at, DurationMS: 1000},
		Overview:   overview.Overview{Hostname: "host-fix48", CurrentUser: "tester", OS: "windows", Architecture: "amd64", Privilege: overview.Privilege{CollectionTier: "elevated"}},
		Profile:    scan.ProfileResult{Descriptor: profile.Descriptor{Name: "default"}},
		Collection: scan.CollectionResult{State: scan.StateDegraded, Evidence: scan.EvidenceCounts{Total: 2, Unavailable: 2}, DegradationReasons: reasons},
		Summary:    scan.Summary{Categories: scan.CategoryCounts{Total: 1, Degraded: 1}, Findings: scan.FindingCounts{Total: 1, Unknown: 1}, Evaluation: scan.EvaluationCoverage{SelectedRules: 1, EvaluatedRules: 1, Percent: 100, Complete: true}},
		Findings:   []assessment.Finding{f}, Prioritization: &priority, Remediation: &rem,
		Snapshot: snapshot.Snapshot{
			AssessmentID: "assessment-fix48", HostFingerprint: snapshot.HostFingerprint{Algorithm: "sha256", Value: "abcdef48", Inputs: []string{"host"}},
			Rules:        snapshot.RuleSetProvenance{Schema: "rules/v1", Version: "rules-1", Digest: snapshot.Digest{Algorithm: "sha256", Value: "rulesdigest"}, RuleCount: 1, SelectedCount: 1},
			Intelligence: snapshot.IntelligenceProvenance{State: "PINNED", Version: "intel-1", Source: "local", ReadOnly: true},
		},
	}
	got, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	ready := got.EvidenceQuality.ReleaseReadiness
	if ready.RawLimitationOccurrences != 2 || ready.UniqueLimitations != 1 || ready.UniqueReleaseBlockers != 1 {
		t.Fatalf("release readiness limitation accounting=%#v", ready)
	}
	if ready.DeadlineBudgetLimitations != 2 || ready.ProductDefectUnknown != 1 {
		t.Fatalf("release readiness defect accounting=%#v", ready)
	}
	if len(ready.ReleaseBlockerRootCauseIDs) != 1 || ready.ReleaseBlockerRootCauseIDs[0] != "DEADLINE_BUDGET:network:collector:deadline-budget" {
		t.Fatalf("release readiness roots=%#v", ready.ReleaseBlockerRootCauseIDs)
	}
}
