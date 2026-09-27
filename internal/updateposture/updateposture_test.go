package updateposture

import (
	"github.com/Nikolov999/chimera/internal/evidence"
	"testing"
	"time"
)

func TestNormalizeDeterministicSummary(t *testing.T) {
	r := Result{Schema: SchemaVersion, CollectorVersion: CollectorVersion, State: StateComplete, Platform: "linux", Architecture: "amd64", CollectedAt: time.Now().UTC(), Providers: []Provider{{ID: "apt", State: evidence.StateObserved, Source: "apt", Freshness: FreshnessFresh}}, Updates: []Update{{Product: "openssl", PackageID: "openssl", InstalledVersion: "1", CandidateVersion: "2", Classification: ClassificationSecurity, Source: "apt", Confidence: evidence.ConfidenceHigh, Reason: "security"}, {Product: "openssl", PackageID: "openssl", InstalledVersion: "1", CandidateVersion: "2", Classification: ClassificationSecurity, Source: "apt", Confidence: evidence.ConfidenceHigh, Reason: "security"}}}
	normalize(&r)
	if r.Summary.Pending != 1 || r.Summary.Security != 1 || len(r.Updates) != 1 {
		t.Fatalf("unexpected summary %#v updates=%d", r.Summary, len(r.Updates))
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFreshness(t *testing.T) {
	now := time.Now().UTC()
	if freshness(now.Add(-24*time.Hour), now) != FreshnessFresh {
		t.Fatal("expected fresh")
	}
	if freshness(now.Add(-30*24*time.Hour), now) != FreshnessStale {
		t.Fatal("expected stale")
	}
	if freshness(time.Time{}, now) != FreshnessUnknown {
		t.Fatal("expected unknown")
	}
}

func TestFix50PartialObservedProviderDegradesWithoutDiscardingEvidence(t *testing.T) {
	code := 0
	r := Result{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, CollectorVersion: CollectorVersion,
		State: StateComplete, Platform: "windows", Architecture: "amd64", CollectedAt: time.Now().UTC(),
		Providers: []Provider{{
			ID: "windows-update", State: evidence.StateObserved, Source: "staged local metadata",
			Freshness: FreshnessFresh, Partial: true,
			Stages: []ProviderStage{
				{ID: "DETECTION_INSTALL_METADATA", State: evidence.StateObserved, Command: "registry", ExitCode: &code},
				{ID: "CBS_PENDING_PACKAGES", State: evidence.StateUnavailable, Command: "Get-WindowsPackage", ExitCode: &code, Reason: "cmdlet unavailable"},
			},
		}},
		Updates: []Update{}, Evidence: []evidence.Observation{}, Limitations: []string{"secondary package stage unavailable"},
	}
	normalize(&r)
	r.Evidence = buildEvidence(r)
	if r.State != StateDegraded {
		t.Fatalf("partial observed provider must degrade aggregate posture without becoming unavailable: %s", r.State)
	}
	if len(r.Providers) != 1 || r.Providers[0].State != evidence.StateObserved || !r.Providers[0].Partial {
		t.Fatalf("successful staged provider evidence was not preserved: %#v", r.Providers)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}
