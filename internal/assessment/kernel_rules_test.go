package assessment

import (
	"runtime"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestImplementedRulesIncludeKernelPack(t *testing.T) {
	rules := ImplementedRules()
	if len(rules) <= len(CoreRules()) {
		t.Fatalf("implemented catalog did not add kernel rules: %d", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %s: %v", r.ID, err)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
	}
	for _, id := range []string{"CHM-KRN-001", "CHM-KRN-020", "CHM-KRN-021"} {
		if !seen[id] {
			t.Fatalf("missing cross-platform kernel rule %s", id)
		}
	}
}

func TestSecureBootRuleFailAndNotApplicable(t *testing.T) {
	r := mustRule(t, KernelRules(), "CHM-KRN-001")
	now := time.Now().UTC()
	findings, err := EvaluateRules([]Rule{r}, []evidence.Observation{
		evidence.NewObserved("kernel.secure_boot.enabled", false, "test", now, evidence.ConfidenceExact),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || findings[0].Applicability != Applicable {
		t.Fatalf("unexpected disabled Secure Boot result: %#v", findings[0])
	}

	findings, err = EvaluateRules([]Rule{r}, []evidence.Observation{
		evidence.NewState("kernel.secure_boot.state", evidence.StateNotApplicable, "test", now, evidence.ConfidenceHigh, "legacy firmware"),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Applicability != NotApplicable || findings[0].Status != StatusPass {
		t.Fatalf("not-applicable Secure Boot was not preserved: %#v", findings[0])
	}
}

func TestLoadedModuleTrustAggregateDetectsUntrustedComponent(t *testing.T) {
	r := mustRule(t, KernelRules(), "CHM-KRN-020")
	now := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("kernel.module.test_driver.flags", "UNSIGNED", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("kernel.module.test_driver.trust_state", "UNSIGNED", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("kernel.module.test_driver.backing_state", "PRESENT", "test", now, evidence.ConfidenceExact),
	}
	findings, err := EvaluateRules([]Rule{r}, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusFail || len(findings[0].Evidence) != 3 {
		t.Fatalf("untrusted module not detected with full provenance: %#v", findings[0])
	}
}

func TestVulnerableDriverRulePreservesSeedApplicability(t *testing.T) {
	r := mustRule(t, KernelRules(), "CHM-KRN-021")
	now := time.Now().UTC()
	findings, err := EvaluateRules([]Rule{r}, []evidence.Observation{
		evidence.NewObserved("kernel.vulnerable_driver.intelligence.platform_entries", 0, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("kernel.vulnerable_driver.intelligence.matches", 0, "test", now, evidence.ConfidenceExact),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Applicability != NotApplicable {
		t.Fatalf("zero platform entries should be not applicable: %#v", findings[0])
	}

	findings, err = EvaluateRules([]Rule{r}, []evidence.Observation{
		evidence.NewObserved("kernel.vulnerable_driver.intelligence.platform_entries", 4, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("kernel.vulnerable_driver.intelligence.matches", 1, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("kernel.vulnerable_driver.sample.assessment", "IDENTITY_MATCH_REQUIRES_CONFIRMATION", "test", now, evidence.ConfidenceHigh),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != StatusWarn || findings[0].Applicability != Applicable {
		t.Fatalf("identity match should remain warning pending exact confirmation: %#v", findings[0])
	}
}

func TestPlatformKernelRulesAreConcrete(t *testing.T) {
	wantPrefix := map[string]string{"linux": "CHM-KRN-LNX-", "windows": "CHM-KRN-WIN-", "darwin": "CHM-KRN-MAC-"}[runtime.GOOS]
	if wantPrefix == "" {
		t.Skip("unsupported test platform")
	}
	count := 0
	for _, r := range KernelRules() {
		if len(r.ID) >= len(wantPrefix) && r.ID[:len(wantPrefix)] == wantPrefix {
			count++
		}
	}
	if count == 0 {
		t.Fatalf("no platform kernel rules for %s", runtime.GOOS)
	}
}

func mustRule(t *testing.T, rules []Rule, id string) Rule {
	t.Helper()
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}
