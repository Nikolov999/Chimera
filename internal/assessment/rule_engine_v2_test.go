package assessment

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestPhase105DeclarativeCatalogCompilesAndIsSerializable(t *testing.T) {
	defs := RuleEngineV2Definitions()
	if len(defs) != 7 {
		t.Fatalf("declarative definition count=%d want 7", len(defs))
	}
	if err := ValidateRuleEngineV2Catalog(defs); err != nil {
		t.Fatal(err)
	}
	rules, err := CompileDeclarativeRules(defs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(defs) {
		t.Fatalf("compiled rules=%d definitions=%d", len(rules), len(defs))
	}
	for _, r := range rules {
		if r.Definition == nil || r.Definition.EngineVersion != RuleEngineVersion {
			t.Fatalf("rule %s missing v2 definition provenance", r.ID)
		}
		raw, err := json.Marshal(r.Definition)
		if err != nil || strings.Contains(string(raw), "func(") {
			t.Fatalf("rule %s definition is not executable-free JSON: %v %s", r.ID, err, raw)
		}
	}
}

func TestPhase105DeclarativePredicateOperators(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("bool", true, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("string", "Current", "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("number", 12, "test", now, evidence.ConfidenceMedium),
		evidence.NewState("denied", evidence.StateDenied, "test", now, evidence.ConfidenceHigh, "permission denied"),
	})
	cases := []struct {
		p    Predicate
		want bool
	}{
		{Predicate{Key: "bool", Operator: PredicateExists}, true},
		{Predicate{Key: "denied", Operator: PredicateStateIs, State: evidence.StateDenied}, true},
		{Predicate{Key: "string", Operator: PredicateValueEquals, Value: "current", CaseInsensitive: true}, true},
		{Predicate{Key: "string", Operator: PredicateValueNotEqual, Value: "stale", CaseInsensitive: true}, true},
		{Predicate{Key: "string", Operator: PredicateStringIn, Values: []string{"stale", "current"}, CaseInsensitive: true}, true},
		{Predicate{Key: "bool", Operator: PredicateBoolIs, Value: true}, true},
		{Predicate{Key: "number", Operator: PredicateNumberGTE, Value: 10}, true},
		{Predicate{Key: "number", Operator: PredicateNumberLTE, Value: 20}, true},
	}
	for _, tc := range cases {
		if err := tc.p.Validate(); err != nil {
			t.Fatalf("predicate %s invalid: %v", tc.p.Operator, err)
		}
		got, found := evaluatePredicate(tc.p, idx)
		if !found || got != tc.want {
			t.Fatalf("predicate %s got match=%t found=%t", tc.p.Operator, got, found)
		}
	}
}

func TestPhase105ApplicabilityAndEvidenceConfidence(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	def := DeclarativeRuleDefinition{
		Schema: DeclarativeRuleSchema, EngineVersion: RuleEngineVersion,
		ID: "CHM-TEST-105", Title: "Declarative applicability", Category: "test", Severity: SeverityMedium,
		AffectedObject: "feature.enabled", ExpectedState: "true", Risk: "test risk", Remediation: "test remediation",
		Applicability: &Predicate{Key: "host.os.name", Operator: PredicateValueEquals, Value: "linux", CaseInsensitive: true},
		EvidenceKeys:  []string{"feature.enabled"},
		Cases:         []DeclarativeCase{{Name: "enabled", When: Predicate{Key: "feature.enabled", Operator: PredicateBoolIs, Value: true}, Then: inheritedOutcome(StatusPass, Applicable, "feature.enabled")}},
		Default:       inheritedOutcome(StatusFail, Applicable, "feature.enabled"),
	}
	if err := def.Validate(); err != nil {
		t.Fatal(err)
	}

	notApplicable := NewIndex([]evidence.Observation{
		evidence.NewObserved("host.os.name", "windows", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("feature.enabled", false, "test", now, evidence.ConfidenceHigh),
	})
	got := EvaluateDeclarativeRule(def, notApplicable)
	if got.Status != StatusPass || got.Applicability != NotApplicable || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected non-applicable evaluation: %#v", got)
	}

	applicable := NewIndex([]evidence.Observation{
		evidence.NewObserved("host.os.name", "linux", "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("feature.enabled", false, "test", now, evidence.ConfidenceMedium),
	})
	got = EvaluateDeclarativeRule(def, applicable)
	if got.Status != StatusFail || got.Applicability != Applicable || got.Confidence != evidence.ConfidenceMedium || got.ObservedState != "false" {
		t.Fatalf("unexpected applicable evaluation: %#v", got)
	}

	missing := NewIndex([]evidence.Observation{evidence.NewObserved("feature.enabled", true, "test", now, evidence.ConfidenceExact)})
	got = EvaluateDeclarativeRule(def, missing)
	if got.Status != StatusUnknown || got.Applicability != Undetermined || got.Confidence != evidence.ConfidenceLow {
		t.Fatalf("unexpected missing applicability evaluation: %#v", got)
	}

	denied := NewIndex([]evidence.Observation{
		evidence.NewState("host.os.name", evidence.StateDenied, "test", now, evidence.ConfidenceHigh, "permission denied"),
		evidence.NewObserved("feature.enabled", true, "test", now, evidence.ConfidenceExact),
	})
	got = EvaluateDeclarativeRule(def, denied)
	if got.Status != StatusUnknown || got.Applicability != Undetermined || got.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("unexpected denied applicability evaluation: %#v", got)
	}
}

func TestPhase105CoreRulesActuallyUseV2Engine(t *testing.T) {
	for _, r := range append(CoreRules(), IntelligenceRules()...) {
		if r.Definition == nil {
			t.Fatalf("rule %s is not compiled from declarative definition", r.ID)
		}
		if r.Definition.Schema != DeclarativeRuleSchema || r.Definition.EngineVersion != RuleEngineVersion {
			t.Fatalf("rule %s has bad definition provenance: %#v", r.ID, r.Definition)
		}
	}
}

func TestPhase106CompositeConditionsResolveDeterministically(t *testing.T) {
	now := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("a", true, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("b", "ready", "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("c", false, "test", now, evidence.ConfidenceMedium),
	})

	all := AllConditions(
		PredicateCondition(Predicate{Key: "a", Operator: PredicateBoolIs, Value: true}),
		PredicateCondition(Predicate{Key: "b", Operator: PredicateValueEquals, Value: "READY", CaseInsensitive: true}),
	)
	if err := all.Validate(); err != nil {
		t.Fatal(err)
	}
	got := evaluateCondition(all, idx)
	if !got.Resolved || !got.Match || len(got.Keys) != 2 {
		t.Fatalf("ALL result=%#v", got)
	}

	any := AnyConditions(
		PredicateCondition(Predicate{Key: "missing", Operator: PredicateBoolIs, Value: true}),
		PredicateCondition(Predicate{Key: "c", Operator: PredicateBoolIs, Value: false}),
	)
	got = evaluateCondition(any, idx)
	if !got.Resolved || !got.Match {
		t.Fatalf("ANY should be decisively true despite another unresolved child: %#v", got)
	}

	unresolved := AllConditions(
		PredicateCondition(Predicate{Key: "a", Operator: PredicateBoolIs, Value: true}),
		PredicateCondition(Predicate{Key: "missing", Operator: PredicateExists}),
	)
	got = evaluateCondition(unresolved, idx)
	if got.Resolved || got.Match {
		t.Fatalf("ALL with no false child and one missing child should be unresolved: %#v", got)
	}

	not := NotCondition(PredicateCondition(Predicate{Key: "c", Operator: PredicateBoolIs, Value: true}))
	got = evaluateCondition(not, idx)
	if !got.Resolved || !got.Match {
		t.Fatalf("NOT result=%#v", got)
	}
}

func TestPhase106RequiredDependenciesFailClosedOnMissingEvidence(t *testing.T) {
	now := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	def := DeclarativeRuleDefinition{
		Schema: DeclarativeRuleSchema, EngineVersion: RuleEngineVersion,
		ID: "CHM-TEST-106", Title: "Composite dependency rule", Category: "test", Severity: SeverityHigh,
		AffectedObject: "test.composite", ExpectedState: "both facts true", Risk: "test risk", Remediation: "test remediation",
		Dependencies: []EvidenceDependency{{Key: "left"}, {Key: "right"}},
		EvidenceKeys: []string{"left", "right"},
		Cases: []DeclarativeCase{{
			Name: "both", Condition: conditionPtr(AllConditions(
				PredicateCondition(Predicate{Key: "left", Operator: PredicateBoolIs, Value: true}),
				PredicateCondition(Predicate{Key: "right", Operator: PredicateBoolIs, Value: true}),
			)), Then: fixedOutcome(StatusPass, Applicable, evidence.ConfidenceExact, "both facts true"),
		}},
		Default: inheritedOutcomeWithLiteral(StatusFail, Applicable, "dependency facts do not jointly satisfy policy", "left"),
	}
	if err := def.Validate(); err != nil {
		t.Fatal(err)
	}

	missing := NewIndex([]evidence.Observation{evidence.NewObserved("left", true, "test", now, evidence.ConfidenceExact)})
	got := EvaluateDeclarativeRule(def, missing)
	if got.Status != StatusUnknown || got.Applicability != Undetermined || got.Confidence != evidence.ConfidenceLow || !strings.Contains(got.ObservedState, "right") {
		t.Fatalf("missing dependency result=%#v", got)
	}

	complete := NewIndex([]evidence.Observation{
		evidence.NewObserved("left", true, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("right", true, "test", now, evidence.ConfidenceHigh),
	})
	got = EvaluateDeclarativeRule(def, complete)
	if got.Status != StatusPass || got.Applicability != Applicable || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("complete dependency result=%#v", got)
	}
}

func TestPhase106IntelligenceFreshnessUsesRealCompositeRule(t *testing.T) {
	var def *DeclarativeRuleDefinition
	for _, candidate := range RuleEngineV2Definitions() {
		if candidate.ID == "CHM-INTEL-002" {
			copy := candidate
			def = &copy
			break
		}
	}
	if def == nil {
		t.Fatal("CHM-INTEL-002 definition missing")
	}
	if len(def.Dependencies) != 2 {
		t.Fatalf("dependencies=%d want 2", len(def.Dependencies))
	}
	composites := 0
	for _, c := range def.Cases {
		if c.Condition != nil && (c.Condition.Operator == ConditionAll || c.Condition.Operator == ConditionAny) {
			composites++
		}
	}
	if composites < 2 {
		t.Fatalf("composite cases=%d want at least 2", composites)
	}

	now := time.Date(2026, 8, 20, 6, 0, 0, 0, time.UTC)
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("intelligence.snapshot.available", true, "test", now, evidence.ConfidenceExact),
		evidence.NewObserved("intelligence.snapshot.freshness", "STALE", "test", now, evidence.ConfidenceHigh),
	})
	got := EvaluateDeclarativeRule(*def, idx)
	if got.Status != StatusWarn || got.Applicability != Applicable || got.ObservedState != "STALE" || got.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("stale composite result=%#v", got)
	}

	delete(idx, "intelligence.snapshot.available")
	got = EvaluateDeclarativeRule(*def, idx)
	if got.Status != StatusUnknown || got.Applicability != Undetermined || !strings.Contains(got.ObservedState, "required evidence dependencies missing") {
		t.Fatalf("missing dependency result=%#v", got)
	}
}

func TestPhase106CompositeDefinitionCanonicalSerialization(t *testing.T) {
	for _, def := range RuleEngineV2Definitions() {
		if def.ID != "CHM-INTEL-002" {
			continue
		}
		raw, err := def.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, want := range []string{"\"dependencies\"", "\"condition\"", "\"ALL\"", "\"ANY\""} {
			if !strings.Contains(text, want) {
				t.Fatalf("canonical definition missing %s: %s", want, text)
			}
		}
		return
	}
	t.Fatal("CHM-INTEL-002 definition missing")
}
