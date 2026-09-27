package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestStableFindingID(t *testing.T) {
	a := StableFindingID("CHM-CORE-001", "overview.collection_health")
	b := StableFindingID("CHM-CORE-001", "overview.collection_health")
	c := StableFindingID("CHM-CORE-002", "overview.collection_health")
	if a != b {
		t.Fatalf("finding id not deterministic: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("different rule identity produced same finding id: %q", a)
	}
}

func TestEvaluateRulesPassUnknownAndStableContract(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	obs := []evidence.Observation{
		evidence.NewObserved("overview.collection_health", "complete", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("host.os.name", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewState("host.kernel", evidence.StateDenied, "test", now, evidence.ConfidenceHigh, "permission denied"),
		evidence.NewObserved("host.privilege", "standard", "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("host.network.tcp_listener_count", 0, "test", now, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(CoreRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 5 {
		t.Fatalf("got %d findings, want 5", len(findings))
	}
	seenUnknown := false
	seenPass := false
	for _, f := range findings {
		if f.Status == StatusUnknown {
			seenUnknown = true
		}
		if f.Status == StatusPass {
			seenPass = true
		}
		if f.ID == "" || f.RuleID == "" || f.ExpectedState == "" || f.Remediation == "" {
			t.Fatalf("incomplete finding: %#v", f)
		}
	}
	if !seenUnknown || !seenPass {
		t.Fatalf("expected PASS and UNKNOWN results: %#v", findings)
	}
}

func TestFindingStatusValidationIncludesWarnAndFail(t *testing.T) {
	for _, s := range []Status{StatusPass, StatusWarn, StatusFail, StatusUnknown} {
		if !validStatus(s) {
			t.Fatalf("status %q rejected", s)
		}
	}
}
