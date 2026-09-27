package assessment

import (
	"fmt"
	"sort"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// RuleEngineV2Definitions returns the real rules migrated to the declarative
// Rule Engine v2. The catalog starts with Chimera's core collection-health
// and pinned-intelligence rules so every ordinary assessment exercises v2.
// makes CHM-INTEL-002 a real multi-evidence composite rule.
func RuleEngineV2Definitions() []DeclarativeRuleDefinition {
	defs := append([]DeclarativeRuleDefinition(nil), coreRuleDefinitions()...)
	defs = append(defs, intelligenceRuleDefinitions()...)
	sort.Slice(defs, func(i, j int) bool { return defs[i].ID < defs[j].ID })
	return defs
}

func ValidateRuleEngineV2Catalog(defs []DeclarativeRuleDefinition) error {
	if len(defs) == 0 {
		return fmt.Errorf("declarative rule catalog is empty")
	}
	seen := make(map[string]struct{}, len(defs))
	for i, def := range defs {
		if err := def.Validate(); err != nil {
			return fmt.Errorf("definition %d: %w", i, err)
		}
		if _, ok := seen[def.ID]; ok {
			return fmt.Errorf("duplicate declarative rule id %q", def.ID)
		}
		seen[def.ID] = struct{}{}
		if _, err := def.MarshalCanonical(); err != nil {
			return fmt.Errorf("definition %q canonical serialization: %w", def.ID, err)
		}
		if _, err := CompileDeclarativeRule(def); err != nil {
			return fmt.Errorf("definition %q compilation: %w", def.ID, err)
		}
	}
	return nil
}

func mustCompileDefinitions(defs []DeclarativeRuleDefinition) []Rule {
	rules, err := CompileDeclarativeRules(defs)
	if err != nil {
		panic("invalid built-in declarative rule catalog: " + err.Error())
	}
	return rules
}

func coreRuleDefinitions() []DeclarativeRuleDefinition {
	return []DeclarativeRuleDefinition{
		availabilityDefinition("CHM-CORE-001", "Overview evidence collection is complete", "collection", SeverityInfo, "overview.collection_health", "complete", "Incomplete collection can hide host posture and reduce assessment confidence.", "Resolve the reported local permission or provider errors, then rerun Chimera."),
		availabilityDefinition("CHM-CORE-002", "Operating system identity is observable", "inventory", SeverityInfo, "host.os.name", "identified", "An unidentified operating system prevents reliable platform-specific assessment.", "Restore access to local operating-system metadata and rerun Chimera."),
		availabilityDefinition("CHM-CORE-003", "Kernel identity is observable", "inventory", SeverityInfo, "host.kernel", "identified", "Missing kernel identity prevents reliable kernel hardening and vulnerability correlation.", "Restore access to local kernel metadata and rerun Chimera."),
		availabilityDefinition("CHM-CORE-004", "Effective privilege context is observable", "identity", SeverityLow, "host.privilege", "identified", "Unknown privilege context can make permission-related assessment results ambiguous.", "Run Chimera in a context where the operating system can report the current principal and effective privilege level."),
		availabilityDefinition("CHM-CORE-005", "TCP listener inventory is observable", "network", SeverityLow, "host.network.tcp_listener_count", "observed", "Unavailable listener metadata can hide locally exposed services from later assessment stages.", "Restore access to the operating system's local TCP listener metadata and rerun Chimera."),
	}
}

func availabilityDefinition(id, title, category string, severity Severity, key, expected, risk, remediation string) DeclarativeRuleDefinition {
	return DeclarativeRuleDefinition{
		Schema: DeclarativeRuleSchema, EngineVersion: RuleEngineVersion,
		ID: id, Title: title, Category: category, Severity: severity,
		AffectedObject: key, ExpectedState: expected, Risk: risk, Remediation: remediation,
		EvidenceKeys: []string{key},
		Cases: []DeclarativeCase{
			{Name: "not-applicable", When: Predicate{Key: key, Operator: PredicateStateIs, State: evidence.StateNotApplicable}, Then: inheritedOutcome(StatusPass, NotApplicable, key)},
			{Name: "observed", When: Predicate{Key: key, Operator: PredicateStateIs, State: evidence.StateObserved}, Then: inheritedOutcome(StatusPass, Applicable, key)},
			{Name: "present-but-degraded", When: Predicate{Key: key, Operator: PredicateExists}, Then: inheritedOutcome(StatusUnknown, Applicable, key)},
		},
		Default: fixedOutcome(StatusUnknown, Undetermined, evidence.ConfidenceLow, "evidence key missing"),
	}
}

func intelligenceRuleDefinitions() []DeclarativeRuleDefinition {
	availableKey := "intelligence.snapshot.available"
	freshnessKey := "intelligence.snapshot.freshness"
	return []DeclarativeRuleDefinition{
		{
			Schema: DeclarativeRuleSchema, EngineVersion: RuleEngineVersion,
			ID: "CHM-INTEL-001", Title: "Pinned vulnerability intelligence is available", Category: "intelligence", Severity: SeverityMedium,
			AffectedObject: availableKey, ExpectedState: "valid pinned local intelligence snapshot available",
			Risk:         "Missing vulnerability intelligence prevents reliable product-to-vulnerability and lifecycle correlation.",
			Remediation:  "Provide a valid pinned Chimera intelligence manifest or use the embedded snapshot; validate it with chimera doctor before reassessment.",
			EvidenceKeys: []string{availableKey},
			Cases: []DeclarativeCase{
				{Name: "not-applicable", When: Predicate{Key: availableKey, Operator: PredicateStateIs, State: evidence.StateNotApplicable}, Then: inheritedOutcome(StatusPass, NotApplicable, availableKey)},
				{Name: "available", When: Predicate{Key: availableKey, Operator: PredicateBoolIs, Value: true}, Then: fixedOutcomeFrom(StatusPass, Applicable, evidence.ConfidenceExact, "pinned intelligence snapshot available", availableKey)},
				{Name: "observed-unavailable", When: Predicate{Key: availableKey, Operator: PredicateStateIs, State: evidence.StateObserved}, Then: inheritedOutcomeWithLiteral(StatusUnknown, Applicable, "pinned intelligence snapshot not available", availableKey)},
				{Name: "present-degraded", When: Predicate{Key: availableKey, Operator: PredicateExists}, Then: inheritedOutcome(StatusUnknown, Applicable, availableKey)},
			},
			Default: fixedOutcome(StatusUnknown, Undetermined, evidence.ConfidenceLow, "evidence key missing"),
		},
		{
			Schema: DeclarativeRuleSchema, EngineVersion: RuleEngineVersion,
			ID: "CHM-INTEL-002", Title: "Pinned vulnerability intelligence is current", Category: "intelligence", Severity: SeverityLow,
			AffectedObject: freshnessKey, ExpectedState: "CURRENT",
			Risk:         "Stale vulnerability intelligence can miss newly disclosed vulnerabilities or fixed-version/lifecycle changes and reduce assessment confidence.",
			Remediation:  "Refresh intelligence through the explicit signed refresh workflow when available, then rerun the assessment with the new pinned snapshot.",
			Dependencies: []EvidenceDependency{{Key: availableKey}, {Key: freshnessKey}},
			EvidenceKeys: []string{availableKey, freshnessKey},
			Cases: []DeclarativeCase{
				{Name: "not-applicable", When: Predicate{Key: freshnessKey, Operator: PredicateStateIs, State: evidence.StateNotApplicable}, Then: inheritedOutcome(StatusPass, NotApplicable, freshnessKey)},
				{Name: "snapshot-unavailable", Condition: conditionPtr(PredicateCondition(Predicate{Key: availableKey, Operator: PredicateBoolIs, Value: false})), Then: inheritedOutcomeWithLiteral(StatusUnknown, Applicable, "pinned intelligence snapshot unavailable; freshness cannot be established", availableKey)},
				{Name: "current", Condition: conditionPtr(AllConditions(
					PredicateCondition(Predicate{Key: availableKey, Operator: PredicateBoolIs, Value: true}),
					PredicateCondition(Predicate{Key: freshnessKey, Operator: PredicateValueEquals, Value: "CURRENT", CaseInsensitive: true}),
				)), Then: inheritedOutcomeWithLiteral(StatusPass, Applicable, "CURRENT", freshnessKey)},
				{Name: "stale", Condition: conditionPtr(AllConditions(
					PredicateCondition(Predicate{Key: availableKey, Operator: PredicateBoolIs, Value: true}),
					PredicateCondition(Predicate{Key: freshnessKey, Operator: PredicateValueEquals, Value: "STALE", CaseInsensitive: true}),
				)), Then: inheritedOutcomeWithLiteral(StatusWarn, Applicable, "STALE", freshnessKey)},
				{Name: "degraded-dependency", Condition: conditionPtr(AnyConditions(
					PredicateCondition(Predicate{Key: availableKey, Operator: PredicateStateIs, State: evidence.StateDenied}),
					PredicateCondition(Predicate{Key: availableKey, Operator: PredicateStateIs, State: evidence.StateUnavailable}),
					PredicateCondition(Predicate{Key: freshnessKey, Operator: PredicateStateIs, State: evidence.StateDenied}),
					PredicateCondition(Predicate{Key: freshnessKey, Operator: PredicateStateIs, State: evidence.StateUnavailable}),
				)), Then: inheritedOutcomeWithLiteral(StatusUnknown, Applicable, "intelligence freshness dependency degraded", freshnessKey)},
				{Name: "present-unknown", When: Predicate{Key: freshnessKey, Operator: PredicateExists}, Then: inheritedOutcome(StatusUnknown, Applicable, freshnessKey)},
			},
			Default: fixedOutcome(StatusUnknown, Undetermined, evidence.ConfidenceLow, "required intelligence evidence did not satisfy a known state"),
		},
	}
}

func inheritedOutcome(status Status, applicability Applicability, key string) DeclarativeOutcome {
	return DeclarativeOutcome{Status: status, Applicability: applicability, ConfidencePolicy: ConfidenceInherit, ObservedFromKey: key}
}

func inheritedOutcomeWithLiteral(status Status, applicability Applicability, observed, key string) DeclarativeOutcome {
	return DeclarativeOutcome{Status: status, Applicability: applicability, ConfidencePolicy: ConfidenceInherit, ObservedState: observed, ObservedFromKey: key}
}

func fixedOutcome(status Status, applicability Applicability, confidence evidence.Confidence, observed string) DeclarativeOutcome {
	return DeclarativeOutcome{Status: status, Applicability: applicability, ConfidencePolicy: ConfidenceFixed, Confidence: confidence, ObservedState: observed}
}

func fixedOutcomeFrom(status Status, applicability Applicability, confidence evidence.Confidence, observed, key string) DeclarativeOutcome {
	return DeclarativeOutcome{Status: status, Applicability: applicability, ConfidencePolicy: ConfidenceFixed, Confidence: confidence, ObservedState: observed, ObservedFromKey: key}
}

func conditionPtr(c Condition) *Condition { return &c }
