package snapshot

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cli"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/version"
)

func TestBuildIsDeterministicForSameInputs(t *testing.T) {
	in := fixtureInput(t)
	a, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID != b.AssessmentID || a.HostFingerprint.Value != b.HostFingerprint.Value || a.Config.Digest.Value != b.Config.Digest.Value || a.Profile.Digest.Value != b.Profile.Digest.Value || a.Rules.Digest.Value != b.Rules.Digest.Value {
		t.Fatalf("same snapshot inputs were not deterministic:\nA=%#v\nB=%#v", a, b)
	}
}

func TestBuildChangesAssessmentIDWhenAssessmentSemanticsChange(t *testing.T) {
	base := fixtureInput(t)
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}

	changed := base
	changed.Options.Severity = "HIGH"
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.Config.Digest.Value == b.Config.Digest.Value {
		t.Fatal("config digest did not change with severity threshold")
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment id did not change with assessment semantics")
	}
}

func TestBuildIgnoresPresentationOnlyOptionsInConfigDigest(t *testing.T) {
	base := fixtureInput(t)
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Options.JSON = true
	changed.Options.Plain = true
	changed.Options.NoColor = true
	changed.Options.Verbose = true
	changed.Options.Output = "result.json"
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.Config.Digest.Value != b.Config.Digest.Value {
		t.Fatal("presentation/output options must not alter assessment-semantic config digest")
	}
}

func TestRuleDigestIsOrderingIndependent(t *testing.T) {
	base := fixtureInput(t)
	extra := base.Rules[0]
	extra.ID = "CHM-TEST-999"
	extra.Title = "second rule"
	extra.AffectedObject = "host.test.second"
	base.Rules = []assessment.Rule{extra, base.Rules[0]}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Rules[0], base.Rules[1] = base.Rules[1], base.Rules[0]
	b, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	if a.Rules.Digest.Value != b.Rules.Digest.Value {
		t.Fatal("rule-set digest changed with rule ordering")
	}
}

func fixtureInput(t *testing.T) Input {
	t.Helper()
	at := time.Date(2026, 8, 18, 17, 0, 0, 123456789, time.UTC)
	p, err := profile.Resolve("default")
	if err != nil {
		t.Fatal(err)
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-001", Title: "test rule", Category: "test", Severity: assessment.SeverityLow,
		AffectedObject: "host.test", ExpectedState: "present", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "present", Applicability: assessment.Applicable}
		},
	}
	return Input{
		StartedAt:   at,
		CollectedAt: at.Add(time.Millisecond),
		AssessedAt:  at.Add(2 * time.Millisecond),
		CompletedAt: at.Add(3 * time.Millisecond),
		Overview: overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at.Add(time.Millisecond),
			Hostname:       "HOST-A", OS: "linux", Architecture: "amd64", CPUModel: "Test CPU", MemoryTotalBytes: 16 << 30,
		},
		Options:       cli.Options{Timeout: 30 * time.Second, Profile: "default", Severity: "INFO", MaxWorkers: 4},
		ConfigSources: []string{"/etc/chimera/config.json", "/home/test/.config/chimera/config.json"},
		Profile:       p,
		Rules:         []assessment.Rule{rule},
		Selection:     selection.Report{Decisions: []selection.Decision{{RuleID: rule.ID, Outcome: selection.OutcomeSelected}}},
		Tool:          version.Info{Product: "IRONCLAD Chimera", Version: "0.0.0-phase009", Commit: "test", BuildDate: "test"},
	}
}

func TestIntelligenceIdentityChangesAssessmentID(t *testing.T) {
	base := fixtureInput(t)
	base.Intelligence = &IntelligenceProvenance{
		State: "PINNED_LOCAL", Schema: "chimera.intelligence/v1", Version: "intel-a", Source: "/tmp/intel-a/manifest.json",
		DigestAlgorithm: "sha256", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RetrievedAt: base.StartedAt.Add(-time.Hour), SourceCount: 1, ProductCount: 2, VulnerabilityCount: 3,
		Mode: "LOCAL_PINNED", Freshness: "CURRENT", AgeSeconds: 3600, MaxAgeSeconds: int64((30 * 24 * time.Hour) / time.Second), ReadOnly: true, NetworkAccess: false,
	}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	copyIntel := *base.Intelligence
	copyIntel.Version = "intel-b"
	copyIntel.Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	changed.Intelligence = &copyIntel
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment ID did not change when pinned intelligence identity changed")
	}
}

func TestProductNormalizationIdentityChangesAssessmentID(t *testing.T) {
	base := fixtureInput(t)
	base.ProductNormalization = &ProductNormalizationProvenance{
		State: "COMPLETE", Schema: "chimera.product-normalization/v1", EngineVersion: "productnorm/v1",
		IntelligenceVersion: "intel-a", IntelligenceDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CandidateCount: 10, MatchedCount: 3,
	}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	copyNorm := *base.ProductNormalization
	copyNorm.EngineVersion = "productnorm/v2"
	changed.ProductNormalization = &copyNorm
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment ID did not change when product-normalization engine identity changed")
	}
}

func TestVulnerabilityCorrelationIdentityChangesAssessmentID(t *testing.T) {
	base := fixtureInput(t)
	base.VulnerabilityCorrelation = &VulnerabilityCorrelationProvenance{
		State: "COMPLETE", Schema: "chimera.vulnerability-correlation/v1", EngineVersion: "vulncorrelator/v1",
		IntelligenceVersion: "intel-a", IntelligenceDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvaluationCount: 4, AffectedCount: 1, UnresolvedCount: 1,
	}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	copyCorrelation := *base.VulnerabilityCorrelation
	copyCorrelation.EngineVersion = "vulncorrelator/v2"
	changed.VulnerabilityCorrelation = &copyCorrelation
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment ID did not change when vulnerability-correlation engine identity changed")
	}
}

func TestVulnerabilityReachabilityIdentityChangesAssessmentID(t *testing.T) {
	base := fixtureInput(t)
	base.VulnerabilityReachability = &VulnerabilityReachabilityProvenance{
		State: "COMPLETE", Schema: "chimera.vulnerability-reachability/v1", CollectorVersion: "vulnreach/v1",
		EvaluationCount: 2, AffectedEvaluationCount: 2, InstalledOnlyCount: 1, RunningCount: 1,
	}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	copyReach := *base.VulnerabilityReachability
	copyReach.ListeningCount = 1
	changed.VulnerabilityReachability = &copyReach
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment ID did not change when vulnerability-reachability context changed")
	}
}

func TestLifecycleIdentityChangesAssessmentID(t *testing.T) {
	base := fixtureInput(t)
	base.Lifecycle = &LifecycleProvenance{
		State: "COMPLETE", Schema: "chimera.lifecycle/v1", EngineVersion: "lifecycle/v1",
		IntelligenceVersion: "intel-a", IntelligenceDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CandidateCount: 10, WithIntelligenceCount: 3, SupportedCount: 1, EndOfLifeCount: 1, UnsupportedCount: 1,
	}
	a, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	copyLifecycle := *base.Lifecycle
	copyLifecycle.EndOfLifeCount = 2
	copyLifecycle.SupportedCount = 0
	changed.Lifecycle = &copyLifecycle
	b, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.AssessmentID == b.AssessmentID {
		t.Fatal("assessment ID did not change when lifecycle assessment provenance changed")
	}
}
