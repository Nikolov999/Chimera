package profile

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func testRule(id, category string, severity assessment.Severity) assessment.Rule {
	return assessment.Rule{
		ID: id, Title: id, Category: category, Severity: severity,
		AffectedObject: "host.test", ExpectedState: "observed", Risk: "risk", Remediation: "fix",
		Evaluate: func(idx assessment.Index) assessment.Evaluation {
			o := idx["host.test"]
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: o.Confidence, ObservedState: "ok", Applicability: assessment.Applicable, EvidenceKeys: []string{"host.test"}}
		},
	}
}

func TestCatalogContainsRequiredProfiles(t *testing.T) {
	want := map[string]bool{"default": true, "workstation": true, "server": true, "developer": true, "high-security": true, "minimal": true}
	for _, p := range Catalog() {
		delete(want, p.Name)
		if p.Schema != SchemaVersion {
			t.Fatalf("profile %q has schema %q", p.Name, p.Schema)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing required profiles: %#v", want)
	}
}

func TestMinimalChangesApplicabilityWithoutChangingEvidence(t *testing.T) {
	p, err := Resolve("minimal")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(p, []assessment.Rule{
		testRule("CHM-TEST-001", "inventory", assessment.SeverityInfo),
		testRule("CHM-TEST-002", "network", assessment.SeverityLow),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	obs := []evidence.Observation{evidence.NewObserved("host.test", "value", "test", now, evidence.ConfidenceExact)}
	before := obs[0]
	findings, err := assessment.EvaluateRules(applied.Rules, obs, now)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]assessment.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}
	if byRule["CHM-TEST-001"].Applicability != assessment.Applicable {
		t.Fatalf("inventory rule unexpectedly not applicable: %#v", byRule["CHM-TEST-001"])
	}
	if byRule["CHM-TEST-002"].Applicability != assessment.NotApplicable {
		t.Fatalf("network rule should be not applicable under minimal: %#v", byRule["CHM-TEST-002"])
	}
	if obs[0] != before {
		t.Fatalf("profile application mutated raw evidence: before=%#v after=%#v", before, obs[0])
	}
}

func TestHighSecurityAppliesSeverityFloors(t *testing.T) {
	p, err := Resolve("high-security")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(p, []assessment.Rule{
		testRule("CHM-TEST-003", "identity", assessment.SeverityLow),
		testRule("CHM-TEST-004", "network", assessment.SeverityHigh),
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Rules[0].Severity != assessment.SeverityMedium {
		t.Fatalf("identity floor not applied: %s", applied.Rules[0].Severity)
	}
	if applied.Rules[1].Severity != assessment.SeverityHigh {
		t.Fatalf("severity floor incorrectly lowered rule: %s", applied.Rules[1].Severity)
	}
}

func TestResolveRejectsUnknownProfile(t *testing.T) {
	if _, err := Resolve("does-not-exist"); err == nil {
		t.Fatal("expected unknown profile to fail")
	}
}

func TestApplyUsesProfileAwareEvaluatorWhenPresent(t *testing.T) {
	base := testRule("CHM-TEST-005", "service", assessment.SeverityMedium)
	base.EvaluateProfile = func(name string, idx assessment.Index) assessment.Evaluation {
		return assessment.Evaluation{Status: assessment.StatusWarn, Confidence: evidence.ConfidenceHigh, ObservedState: "profile=" + name, Applicability: assessment.Applicable, EvidenceKeys: []string{"host.test"}}
	}
	p, err := Resolve("server")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(p, []assessment.Rule{base})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	idx := assessment.NewIndex([]evidence.Observation{evidence.NewObserved("host.test", true, "test", at, evidence.ConfidenceExact)})
	got := applied.Rules[0].Evaluate(idx)
	if got.Status != assessment.StatusWarn || got.ObservedState != "profile=server" {
		t.Fatalf("profile-aware evaluator was not applied: %#v", got)
	}
}

func TestPhase110CustomProfileInheritanceRuleTogglesAndSeverityOverride(t *testing.T) {
	rules := []assessment.Rule{
		testRule("CHM-TEST-101", "network", assessment.SeverityLow),
		testRule("CHM-TEST-102", "identity", assessment.SeverityMedium),
	}
	registry, err := NewRegistry([]Definition{{
		Name: "prod-web", Extends: "server", Description: "Production web host",
		DisabledCategories: []string{"network"}, EnabledRules: []string{"CHM-TEST-101"}, DisabledRules: []string{"CHM-TEST-102"},
		SeverityOverrides: map[string]assessment.Severity{"CHM-TEST-101": assessment.SeverityCritical},
		Environment:       map[string]string{"environment": "production", "role": "web"},
	}}, rules)
	if err != nil {
		t.Fatal(err)
	}
	p, err := registry.Resolve("prod-web")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Custom || p.Extends != "server" || p.BehaviorProfile != "server" || p.Environment["role"] != "web" {
		t.Fatalf("unexpected custom descriptor: %#v", p)
	}
	applied, err := Apply(p, rules)
	if err != nil {
		t.Fatal(err)
	}
	d1, ok := DecisionFor(applied, "CHM-TEST-101")
	if !ok || !d1.Applicable || d1.EffectiveSeverity != assessment.SeverityCritical {
		t.Fatalf("rule-level enable/override not applied: %#v", d1)
	}
	d2, ok := DecisionFor(applied, "CHM-TEST-102")
	if !ok || d2.Applicable {
		t.Fatalf("rule-level disable not applied: %#v", d2)
	}
}

func TestPhase110CustomProfileCanInheritAnotherCustomProfile(t *testing.T) {
	rules := []assessment.Rule{testRule("CHM-TEST-201", "network", assessment.SeverityLow)}
	registry, err := NewRegistry([]Definition{
		{Name: "corp-base", Extends: "high-security", Description: "Corporate base", DisabledRules: []string{"CHM-TEST-201"}},
		{Name: "corp-web", Extends: "corp-base", Description: "Corporate web", EnabledRules: []string{"CHM-TEST-201"}},
	}, rules)
	if err != nil {
		t.Fatal(err)
	}
	p, err := registry.Resolve("corp-web")
	if err != nil {
		t.Fatal(err)
	}
	if p.BehaviorProfile != "high-security" || !containsFold(p.EnabledRules, "CHM-TEST-201") || containsFold(p.DisabledRules, "CHM-TEST-201") {
		t.Fatalf("custom inheritance merge is incorrect: %#v", p)
	}
}

func TestPhase110CustomProfileInheritanceCycleFailsClosed(t *testing.T) {
	rules := []assessment.Rule{testRule("CHM-TEST-301", "network", assessment.SeverityLow)}
	_, err := NewRegistry([]Definition{{Name: "a", Extends: "b"}, {Name: "b", Extends: "a"}}, rules)
	if err == nil {
		t.Fatal("expected inheritance cycle to fail")
	}
}
