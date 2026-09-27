package assessment

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const RuleSetVersion = "chimera.rules/v1"

type Evaluation struct {
	Status        Status
	Confidence    evidence.Confidence
	ObservedState string
	Applicability Applicability
	EvidenceKeys  []string
}

type Rule struct {
	ID              string
	Title           string
	Category        string
	Severity        Severity
	AffectedObject  string
	ExpectedState   string
	Risk            string
	Remediation     string
	References      []Reference
	Definition      *DeclarativeRuleDefinition
	Evaluate        func(Index) Evaluation
	EvaluateProfile func(string, Index) Evaluation
}

func (r Rule) ValidateMetadata() error {
	if strings.TrimSpace(r.ID) == "" || !strings.HasPrefix(r.ID, "CHM-") {
		return fmt.Errorf("stable rule id beginning CHM- is required")
	}
	if strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Category) == "" || strings.TrimSpace(r.AffectedObject) == "" {
		return fmt.Errorf("rule %q title, category, and affected object are required", r.ID)
	}
	if !validSeverity(r.Severity) {
		return fmt.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
	}
	if strings.TrimSpace(r.ExpectedState) == "" || strings.TrimSpace(r.Risk) == "" || strings.TrimSpace(r.Remediation) == "" {
		return fmt.Errorf("rule %q expected state, risk, and remediation are required", r.ID)
	}
	return nil
}

func (r Rule) Validate() error {
	if err := r.ValidateMetadata(); err != nil {
		return err
	}
	if r.Evaluate == nil {
		return fmt.Errorf("rule %q evaluator is required", r.ID)
	}
	if r.Definition != nil {
		if err := r.Definition.Validate(); err != nil {
			return fmt.Errorf("rule %q declarative definition: %w", r.ID, err)
		}
		d := r.Definition
		if d.ID != r.ID || d.Title != r.Title || d.Category != r.Category || d.Severity != r.Severity || d.AffectedObject != r.AffectedObject || d.ExpectedState != r.ExpectedState || d.Risk != r.Risk || d.Remediation != r.Remediation {
			return fmt.Errorf("rule %q compiled metadata diverges from declarative definition", r.ID)
		}
	}
	return nil
}

type Index map[string]evidence.Observation

func NewIndex(observations []evidence.Observation) Index {
	idx := make(Index, len(observations))
	for _, o := range observations {
		idx[o.Key] = o
	}
	return idx
}

func CoreRules() []Rule {
	return mustCompileDefinitions(coreRuleDefinitions())
}

// ImplementedRules is the complete rule catalog available for the runtime platform.
func ImplementedRules() []Rule {
	return ImplementedRulesForPlatform(runtime.GOOS)
}

// ImplementedRulesForPlatform returns the deterministic v1 catalog projection for
// a supported operating system. Only platform-selected rule families vary; the
// stable rule namespace and shared rule packs remain unchanged.
func ImplementedRulesForPlatform(platform string) []Rule {
	rules := append([]Rule(nil), CoreRules()...)
	rules = append(rules, KernelRulesForPlatform(platform)...)
	rules = append(rules, IntelligenceRules()...)
	rules = append(rules, ProcessRules()...)
	rules = append(rules, ServiceSchedulerRulePack()...)
	rules = append(rules, NetworkExposureRulePack()...)
	rules = append(rules, IdentityAuthenticationRulePack()...)
	rules = append(rules, FilesystemStorageRulePack()...)
	rules = append(rules, ContainerSecurityRules()...)
	rules = append(rules, PersistenceSecretRulePack()...)
	rules = append(rules, CrossDomainCorrelationRules()...)
	return rules
}

// IntelligenceRules are the pinned-intelligence rules migrated to Rule Engine v2.
func IntelligenceRules() []Rule {
	return mustCompileDefinitions(intelligenceRuleDefinitions())
}

func availabilityRule(id, title, category string, severity Severity, key, expected, risk, remediation string) Rule {
	return Rule{
		ID: id, Title: title, Category: category, Severity: severity, AffectedObject: key,
		ExpectedState: expected, Risk: risk, Remediation: remediation,
		Evaluate: func(idx Index) Evaluation {
			o, ok := idx[key]
			if !ok {
				return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "evidence key missing", Applicability: Undetermined, EvidenceKeys: []string{key}}
			}
			if o.State == evidence.StateNotApplicable {
				return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: string(o.State), Applicability: NotApplicable, EvidenceKeys: []string{key}}
			}
			if o.State != evidence.StateObserved {
				return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
			}
			return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: observedText(o), Applicability: Applicable, EvidenceKeys: []string{key}}
		},
	}
}

func EvaluateRules(rules []Rule, observations []evidence.Observation, assessedAt time.Time) ([]Finding, error) {
	if err := evidence.ValidateAll(observations); err != nil {
		return nil, fmt.Errorf("evaluate rules: invalid evidence: %w", err)
	}
	idx := NewIndex(observations)
	findings := make([]Finding, 0, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		ev := r.Evaluate(idx)
		if !validStatus(ev.Status) || !validApplicability(ev.Applicability) || !validConfidence(ev.Confidence) {
			return nil, fmt.Errorf("rule %q returned invalid evaluation", r.ID)
		}
		refs := make([]EvidenceRef, 0, len(ev.EvidenceKeys))
		first := assessedAt.UTC()
		sources := make([]string, 0, len(ev.EvidenceKeys))
		for _, key := range ev.EvidenceKeys {
			o, ok := idx[key]
			if !ok {
				continue
			}
			refs = append(refs, EvidenceRef{Key: o.Key, State: o.State, Value: o.Value, Source: o.Source, CollectedAt: o.CollectedAt, Confidence: o.Confidence, Reason: o.Reason})
			if o.CollectedAt.Before(first) {
				first = o.CollectedAt
			}
			sources = appendUnique(sources, o.Source)
		}
		if first.IsZero() {
			first = assessedAt.UTC()
		}
		collectionSource := strings.Join(sources, ", ")
		if collectionSource == "" {
			collectionSource = "normalized evidence index"
		}
		f := Finding{
			ID: StableFindingID(r.ID, r.AffectedObject), RuleID: r.ID, Title: r.Title,
			Status: ev.Status, Severity: r.Severity, Confidence: ev.Confidence, Category: r.Category,
			Platform: runtime.GOOS, AffectedObject: r.AffectedObject, ObservedState: ev.ObservedState,
			ExpectedState: r.ExpectedState, Evidence: refs, Risk: r.Risk, Remediation: r.Remediation,
			References: append([]Reference(nil), r.References...), CollectionSource: collectionSource,
			FirstObserved: first.UTC(), AssessmentTimestamp: assessedAt.UTC(), Applicability: ev.Applicability,
			Suppression: SuppressionActive,
		}
		if err := f.Validate(); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	SortFindings(findings)
	if err := ValidateAll(findings); err != nil {
		return nil, err
	}
	return findings, nil
}

func observedText(o evidence.Observation) string {
	if o.State != evidence.StateObserved {
		if strings.TrimSpace(o.Reason) != "" {
			return string(o.State) + ": " + o.Reason
		}
		return string(o.State)
	}
	return fmt.Sprint(o.Value)
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
