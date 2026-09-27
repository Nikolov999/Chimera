package assessment

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

// RuleEngineVersion identifies the declarative normalized-evidence evaluation
// engine introduced in and extended in with explicit
// evidence dependencies and bounded composite conditions. Existing callback-
// backed rules remain supported while rule families migrate; rules compiled
// from a Definition are evaluated through this engine.
const RuleEngineVersion = "chimera.rule-engine/v2-phase106"

const DeclarativeRuleSchema = "chimera.rule-definition/v2"

type PredicateOperator string

const (
	PredicateExists        PredicateOperator = "EXISTS"
	PredicateStateIs       PredicateOperator = "STATE_IS"
	PredicateValueEquals   PredicateOperator = "VALUE_EQUALS"
	PredicateValueNotEqual PredicateOperator = "VALUE_NOT_EQUALS"
	PredicateStringIn      PredicateOperator = "STRING_IN"
	PredicateBoolIs        PredicateOperator = "BOOL_IS"
	PredicateNumberGTE     PredicateOperator = "NUMBER_GTE"
	PredicateNumberLTE     PredicateOperator = "NUMBER_LTE"
)

// Predicate evaluates one normalized evidence fact. composes these
// leaves through bounded ALL/ANY/NOT condition trees without moving correlation
// logic into collectors.
type Predicate struct {
	Key             string            `json:"key"`
	Operator        PredicateOperator `json:"operator"`
	State           evidence.State    `json:"state,omitempty"`
	Value           any               `json:"value,omitempty"`
	Values          []string          `json:"values,omitempty"`
	CaseInsensitive bool              `json:"case_insensitive,omitempty"`
}

func (p Predicate) Validate() error {
	if strings.TrimSpace(p.Key) == "" {
		return fmt.Errorf("predicate evidence key is required")
	}
	switch p.Operator {
	case PredicateExists:
		return nil
	case PredicateStateIs:
		if !validEvidenceState(p.State) {
			return fmt.Errorf("predicate %q has invalid evidence state %q", p.Key, p.State)
		}
		return nil
	case PredicateValueEquals, PredicateValueNotEqual:
		if p.Value == nil {
			return fmt.Errorf("predicate %q operator %s requires value", p.Key, p.Operator)
		}
		return nil
	case PredicateStringIn:
		if len(p.Values) == 0 {
			return fmt.Errorf("predicate %q STRING_IN requires values", p.Key)
		}
		for _, v := range p.Values {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("predicate %q STRING_IN contains an empty value", p.Key)
			}
		}
		return nil
	case PredicateBoolIs:
		if _, ok := p.Value.(bool); !ok {
			return fmt.Errorf("predicate %q BOOL_IS requires a boolean value", p.Key)
		}
		return nil
	case PredicateNumberGTE, PredicateNumberLTE:
		if _, ok := numericValue(p.Value); !ok {
			return fmt.Errorf("predicate %q %s requires a numeric value", p.Key, p.Operator)
		}
		return nil
	default:
		return fmt.Errorf("predicate %q has unsupported operator %q", p.Key, p.Operator)
	}
}

type ConditionOperator string

const (
	ConditionPredicate ConditionOperator = "PREDICATE"
	ConditionAll       ConditionOperator = "ALL"
	ConditionAny       ConditionOperator = "ANY"
	ConditionNot       ConditionOperator = "NOT"
)

const (
	maxConditionDepth = 12
	maxConditionNodes = 64
)

// Condition is a bounded, serializable dependency graph over normalized
// evidence predicates. ALL requires every child, ANY requires at least one,
// and NOT negates exactly one child. Predicate leaves remain the only objects
// allowed to read evidence values.
type Condition struct {
	Operator  ConditionOperator `json:"operator"`
	Predicate *Predicate        `json:"predicate,omitempty"`
	Children  []Condition       `json:"children,omitempty"`
}

func PredicateCondition(p Predicate) Condition {
	copy := p
	return Condition{Operator: ConditionPredicate, Predicate: &copy}
}

func AllConditions(children ...Condition) Condition {
	return Condition{Operator: ConditionAll, Children: append([]Condition(nil), children...)}
}

func AnyConditions(children ...Condition) Condition {
	return Condition{Operator: ConditionAny, Children: append([]Condition(nil), children...)}
}

func NotCondition(child Condition) Condition {
	return Condition{Operator: ConditionNot, Children: []Condition{child}}
}

func (c Condition) Validate() error {
	nodes := 0
	return c.validateAt(0, &nodes)
}

func (c Condition) validateAt(depth int, nodes *int) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("condition exceeds maximum depth %d", maxConditionDepth)
	}
	*nodes++
	if *nodes > maxConditionNodes {
		return fmt.Errorf("condition exceeds maximum node count %d", maxConditionNodes)
	}
	switch c.Operator {
	case ConditionPredicate:
		if c.Predicate == nil {
			return fmt.Errorf("PREDICATE condition requires predicate")
		}
		if len(c.Children) != 0 {
			return fmt.Errorf("PREDICATE condition must not contain children")
		}
		return c.Predicate.Validate()
	case ConditionAll, ConditionAny:
		if c.Predicate != nil {
			return fmt.Errorf("%s condition must not contain predicate", c.Operator)
		}
		if len(c.Children) < 2 {
			return fmt.Errorf("%s condition requires at least two children", c.Operator)
		}
	case ConditionNot:
		if c.Predicate != nil {
			return fmt.Errorf("NOT condition must not contain predicate")
		}
		if len(c.Children) != 1 {
			return fmt.Errorf("NOT condition requires exactly one child")
		}
	default:
		return fmt.Errorf("unsupported condition operator %q", c.Operator)
	}
	for i := range c.Children {
		if err := c.Children[i].validateAt(depth+1, nodes); err != nil {
			return fmt.Errorf("%s child %d: %w", c.Operator, i, err)
		}
	}
	return nil
}

func (c Condition) EvidenceKeys() []string {
	keys := []string{}
	var walk func(Condition)
	walk = func(node Condition) {
		if node.Predicate != nil {
			keys = uniqueKeys(keys, node.Predicate.Key)
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(c)
	return keys
}

// EvidenceDependency declares a normalized evidence fact that must be present
// before a rule can be evaluated. Presence is distinct from OBSERVED state:
// explicit DENIED/UNAVAILABLE/UNSUPPORTED observations remain valid evidence
// and may be handled by the rule's cases.
type EvidenceDependency struct {
	Key string `json:"key"`
}

func (d EvidenceDependency) Validate() error {
	if strings.TrimSpace(d.Key) == "" {
		return fmt.Errorf("dependency evidence key is required")
	}
	return nil
}

type ConfidencePolicy string

const (
	ConfidenceInherit ConfidencePolicy = "INHERIT_EVIDENCE"
	ConfidenceFixed   ConfidencePolicy = "FIXED"
)

// DeclarativeOutcome describes the finding state produced when a case matches
// (or when the definition falls through to its Default outcome). Confidence can
// be fixed by policy or conservatively inherited from referenced evidence.
type DeclarativeOutcome struct {
	Status           Status              `json:"status"`
	Applicability    Applicability       `json:"applicability"`
	ConfidencePolicy ConfidencePolicy    `json:"confidence_policy"`
	Confidence       evidence.Confidence `json:"confidence,omitempty"`
	ObservedState    string              `json:"observed_state,omitempty"`
	ObservedFromKey  string              `json:"observed_from_key,omitempty"`
}

func (o DeclarativeOutcome) Validate() error {
	if !validStatus(o.Status) {
		return fmt.Errorf("invalid outcome status %q", o.Status)
	}
	if !validApplicability(o.Applicability) {
		return fmt.Errorf("invalid outcome applicability %q", o.Applicability)
	}
	switch o.ConfidencePolicy {
	case ConfidenceInherit:
		if o.Confidence != "" {
			return fmt.Errorf("inherited-confidence outcome must not set fixed confidence")
		}
	case ConfidenceFixed:
		if !validConfidence(o.Confidence) {
			return fmt.Errorf("fixed-confidence outcome has invalid confidence %q", o.Confidence)
		}
	default:
		return fmt.Errorf("invalid confidence policy %q", o.ConfidencePolicy)
	}
	if strings.TrimSpace(o.ObservedState) == "" && strings.TrimSpace(o.ObservedFromKey) == "" {
		return fmt.Errorf("outcome requires observed_state or observed_from_key")
	}
	return nil
}

type DeclarativeCase struct {
	Name      string             `json:"name,omitempty"`
	When      Predicate          `json:"when,omitempty"`
	Condition *Condition         `json:"condition,omitempty"`
	Then      DeclarativeOutcome `json:"then"`
}

// DeclarativeRuleDefinition is a serializable Rule Engine v2 contract. Phase
// 106 adds required evidence dependencies plus optional composite applicability
// and case conditions while preserving single-predicate definitions.
// The definition contains no executable function values.
type DeclarativeRuleDefinition struct {
	Schema                 string               `json:"schema"`
	EngineVersion          string               `json:"engine_version"`
	ID                     string               `json:"id"`
	Title                  string               `json:"title"`
	Category               string               `json:"category"`
	Severity               Severity             `json:"severity"`
	AffectedObject         string               `json:"affected_object"`
	ExpectedState          string               `json:"expected_state"`
	Risk                   string               `json:"risk"`
	Remediation            string               `json:"remediation"`
	References             []Reference          `json:"references,omitempty"`
	Applicability          *Predicate           `json:"applicability,omitempty"`
	ApplicabilityCondition *Condition           `json:"applicability_condition,omitempty"`
	Dependencies           []EvidenceDependency `json:"dependencies,omitempty"`
	Cases                  []DeclarativeCase    `json:"cases"`
	Default                DeclarativeOutcome   `json:"default"`
	EvidenceKeys           []string             `json:"evidence_keys,omitempty"`
}

func (d DeclarativeRuleDefinition) Validate() error {
	if d.Schema != DeclarativeRuleSchema {
		return fmt.Errorf("rule %q definition schema=%q want %q", d.ID, d.Schema, DeclarativeRuleSchema)
	}
	if d.EngineVersion != RuleEngineVersion {
		return fmt.Errorf("rule %q engine=%q want %q", d.ID, d.EngineVersion, RuleEngineVersion)
	}
	base := Rule{
		ID: d.ID, Title: d.Title, Category: d.Category, Severity: d.Severity,
		AffectedObject: d.AffectedObject, ExpectedState: d.ExpectedState,
		Risk: d.Risk, Remediation: d.Remediation, References: d.References,
		Evaluate: func(Index) Evaluation {
			return Evaluation{Status: StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "validation", Applicability: Applicable}
		},
	}
	if err := base.ValidateMetadata(); err != nil {
		return err
	}
	if d.Applicability != nil && d.ApplicabilityCondition != nil {
		return fmt.Errorf("rule %q must use applicability or applicability_condition, not both", d.ID)
	}
	if d.Applicability != nil {
		if err := d.Applicability.Validate(); err != nil {
			return fmt.Errorf("rule %q applicability: %w", d.ID, err)
		}
	}
	if d.ApplicabilityCondition != nil {
		if err := d.ApplicabilityCondition.Validate(); err != nil {
			return fmt.Errorf("rule %q applicability condition: %w", d.ID, err)
		}
	}
	depSeen := map[string]struct{}{}
	for i, dep := range d.Dependencies {
		if err := dep.Validate(); err != nil {
			return fmt.Errorf("rule %q dependency %d: %w", d.ID, i, err)
		}
		key := strings.TrimSpace(dep.Key)
		if _, ok := depSeen[key]; ok {
			return fmt.Errorf("rule %q has duplicate dependency %q", d.ID, key)
		}
		depSeen[key] = struct{}{}
	}
	if len(d.Cases) == 0 {
		return fmt.Errorf("rule %q requires at least one declarative case", d.ID)
	}
	for i, c := range d.Cases {
		hasWhen := strings.TrimSpace(c.When.Key) != "" || c.When.Operator != ""
		if hasWhen && c.Condition != nil {
			return fmt.Errorf("rule %q case %d must use when or condition, not both", d.ID, i)
		}
		if !hasWhen && c.Condition == nil {
			return fmt.Errorf("rule %q case %d requires when or condition", d.ID, i)
		}
		if c.Condition != nil {
			if err := c.Condition.Validate(); err != nil {
				return fmt.Errorf("rule %q case %d condition: %w", d.ID, i, err)
			}
		} else if err := c.When.Validate(); err != nil {
			return fmt.Errorf("rule %q case %d predicate: %w", d.ID, i, err)
		}
		if err := c.Then.Validate(); err != nil {
			return fmt.Errorf("rule %q case %d outcome: %w", d.ID, i, err)
		}
	}
	if err := d.Default.Validate(); err != nil {
		return fmt.Errorf("rule %q default outcome: %w", d.ID, err)
	}
	seen := map[string]struct{}{}
	for _, key := range d.EvidenceKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("rule %q has empty evidence key", d.ID)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("rule %q has duplicate evidence key %q", d.ID, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// MarshalCanonical returns the executable-free declarative contract used by
// snapshot hashing/tests and future rule ingestion. Encoding through JSON also
// proves that no callback/function is required to represent a v2 definition.
func (d DeclarativeRuleDefinition) MarshalCanonical() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// CompileDeclarativeRule validates and compiles a serializable v2 definition
// into Chimera's existing Rule surface. This preserves compatibility with
// selection/profiles while moving evaluation semantics into Rule Engine v2.
func CompileDeclarativeRule(def DeclarativeRuleDefinition) (Rule, error) {
	if err := def.Validate(); err != nil {
		return Rule{}, err
	}
	copyDef := def
	copyDef.References = append([]Reference(nil), def.References...)
	copyDef.Cases = cloneDeclarativeCases(def.Cases)
	copyDef.Dependencies = append([]EvidenceDependency(nil), def.Dependencies...)
	copyDef.Applicability = clonePredicatePtr(def.Applicability)
	copyDef.ApplicabilityCondition = cloneConditionPtr(def.ApplicabilityCondition)
	copyDef.EvidenceKeys = append([]string(nil), def.EvidenceKeys...)
	return Rule{
		ID: def.ID, Title: def.Title, Category: def.Category, Severity: def.Severity,
		AffectedObject: def.AffectedObject, ExpectedState: def.ExpectedState,
		Risk: def.Risk, Remediation: def.Remediation, References: append([]Reference(nil), def.References...),
		Definition: &copyDef,
		Evaluate:   func(idx Index) Evaluation { return EvaluateDeclarativeRule(copyDef, idx) },
	}, nil
}

func CompileDeclarativeRules(defs []DeclarativeRuleDefinition) ([]Rule, error) {
	rules := make([]Rule, 0, len(defs))
	seen := make(map[string]struct{}, len(defs))
	for i, def := range defs {
		if _, ok := seen[def.ID]; ok {
			return nil, fmt.Errorf("declarative rule %d duplicates id %q", i, def.ID)
		}
		r, err := CompileDeclarativeRule(def)
		if err != nil {
			return nil, fmt.Errorf("compile declarative rule %d: %w", i, err)
		}
		seen[def.ID] = struct{}{}
		rules = append(rules, r)
	}
	return rules, nil
}

func EvaluateDeclarativeRule(def DeclarativeRuleDefinition, idx Index) Evaluation {
	dependencyKeys := make([]string, 0, len(def.Dependencies))
	missingDependencies := make([]string, 0)
	for _, dep := range def.Dependencies {
		key := strings.TrimSpace(dep.Key)
		dependencyKeys = uniqueKeys(dependencyKeys, key)
		if _, ok := idx[key]; !ok {
			missingDependencies = append(missingDependencies, key)
		}
	}
	if len(missingDependencies) > 0 {
		return Evaluation{
			Status: StatusUnknown, Confidence: evidence.ConfidenceLow,
			ObservedState: "required evidence dependencies missing: " + strings.Join(missingDependencies, ", "),
			Applicability: Undetermined, EvidenceKeys: uniqueKeys(def.EvidenceKeys, dependencyKeys...),
		}
	}

	if def.ApplicabilityCondition != nil {
		res := evaluateCondition(*def.ApplicabilityCondition, idx)
		keys := uniqueKeys(def.EvidenceKeys, append(dependencyKeys, res.Keys...)...)
		if !res.Resolved {
			return Evaluation{Status: StatusUnknown, Confidence: inheritedConfidence(keys, idx), ObservedState: "applicability condition unresolved", Applicability: Undetermined, EvidenceKeys: keys}
		}
		if !res.Match {
			return Evaluation{Status: StatusPass, Confidence: inheritedConfidence(keys, idx), ObservedState: "applicability condition not satisfied", Applicability: NotApplicable, EvidenceKeys: keys}
		}
	} else if def.Applicability != nil {
		matched, found := evaluatePredicate(*def.Applicability, idx)
		keys := uniqueKeys(def.EvidenceKeys, append(dependencyKeys, def.Applicability.Key)...)
		if !found {
			return Evaluation{Status: StatusUnknown, Confidence: evidence.ConfidenceLow, ObservedState: "applicability evidence key missing: " + def.Applicability.Key, Applicability: Undetermined, EvidenceKeys: keys}
		}
		o := idx[def.Applicability.Key]
		if !predicateResolved(*def.Applicability, o) {
			return Evaluation{Status: StatusUnknown, Confidence: o.Confidence, ObservedState: "applicability unresolved: " + observedText(o), Applicability: Undetermined, EvidenceKeys: keys}
		}
		if !matched {
			return Evaluation{Status: StatusPass, Confidence: o.Confidence, ObservedState: "applicability predicate not satisfied: " + observedText(o), Applicability: NotApplicable, EvidenceKeys: keys}
		}
	}

	for _, c := range def.Cases {
		caseKeys := []string{}
		matched := false
		if c.Condition != nil {
			res := evaluateCondition(*c.Condition, idx)
			matched = res.Resolved && res.Match
			caseKeys = res.Keys
		} else {
			matched, _ = evaluatePredicate(c.When, idx)
			caseKeys = []string{c.When.Key}
		}
		if matched {
			return outcomeEvaluation(c.Then, def, idx, uniqueKeys(dependencyKeys, caseKeys...))
		}
	}
	return outcomeEvaluation(def.Default, def, idx, dependencyKeys)
}

func outcomeEvaluation(out DeclarativeOutcome, def DeclarativeRuleDefinition, idx Index, caseKeys []string) Evaluation {
	keys := append([]string(nil), def.EvidenceKeys...)
	if def.Applicability != nil {
		keys = uniqueKeys(keys, def.Applicability.Key)
	}
	keys = uniqueKeys(keys, caseKeys...)
	keys = uniqueKeys(keys, out.ObservedFromKey)
	confidence := inheritedConfidence(keys, idx)
	if out.ConfidencePolicy == ConfidenceFixed {
		confidence = out.Confidence
	}
	observed := strings.TrimSpace(out.ObservedState)
	if observed == "" {
		key := strings.TrimSpace(out.ObservedFromKey)
		if key == "" && len(keys) > 0 {
			key = keys[0]
		}
		if o, ok := idx[key]; ok {
			observed = observedText(o)
		} else if key != "" {
			observed = "evidence key missing: " + key
		} else {
			observed = "declarative outcome"
		}
	}
	return Evaluation{Status: out.Status, Confidence: confidence, ObservedState: observed, Applicability: out.Applicability, EvidenceKeys: keys}
}

type conditionResult struct {
	Match    bool
	Resolved bool
	Keys     []string
}

func evaluateCondition(c Condition, idx Index) conditionResult {
	switch c.Operator {
	case ConditionPredicate:
		if c.Predicate == nil {
			return conditionResult{}
		}
		match, found := evaluatePredicate(*c.Predicate, idx)
		if !found {
			return conditionResult{Match: false, Resolved: false, Keys: []string{c.Predicate.Key}}
		}
		o := idx[c.Predicate.Key]
		return conditionResult{Match: match, Resolved: predicateResolved(*c.Predicate, o), Keys: []string{c.Predicate.Key}}
	case ConditionAll:
		keys := []string{}
		unresolved := false
		for _, child := range c.Children {
			res := evaluateCondition(child, idx)
			keys = uniqueKeys(keys, res.Keys...)
			if res.Resolved && !res.Match {
				return conditionResult{Match: false, Resolved: true, Keys: keys}
			}
			if !res.Resolved {
				unresolved = true
			}
		}
		if unresolved {
			return conditionResult{Match: false, Resolved: false, Keys: keys}
		}
		return conditionResult{Match: true, Resolved: true, Keys: keys}
	case ConditionAny:
		keys := []string{}
		unresolved := false
		for _, child := range c.Children {
			res := evaluateCondition(child, idx)
			keys = uniqueKeys(keys, res.Keys...)
			if res.Resolved && res.Match {
				return conditionResult{Match: true, Resolved: true, Keys: keys}
			}
			if !res.Resolved {
				unresolved = true
			}
		}
		if unresolved {
			return conditionResult{Match: false, Resolved: false, Keys: keys}
		}
		return conditionResult{Match: false, Resolved: true, Keys: keys}
	case ConditionNot:
		if len(c.Children) != 1 {
			return conditionResult{}
		}
		res := evaluateCondition(c.Children[0], idx)
		if !res.Resolved {
			return res
		}
		res.Match = !res.Match
		return res
	default:
		return conditionResult{}
	}
}

func clonePredicatePtr(in *Predicate) *Predicate {
	if in == nil {
		return nil
	}
	out := *in
	out.Values = append([]string(nil), in.Values...)
	return &out
}

func cloneConditionPtr(in *Condition) *Condition {
	if in == nil {
		return nil
	}
	out := cloneCondition(*in)
	return &out
}

func cloneCondition(in Condition) Condition {
	out := in
	if in.Predicate != nil {
		p := *in.Predicate
		p.Values = append([]string(nil), in.Predicate.Values...)
		out.Predicate = &p
	}
	out.Children = make([]Condition, len(in.Children))
	for i := range in.Children {
		out.Children[i] = cloneCondition(in.Children[i])
	}
	return out
}

func cloneDeclarativeCases(in []DeclarativeCase) []DeclarativeCase {
	out := make([]DeclarativeCase, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].When.Values = append([]string(nil), in[i].When.Values...)
		out[i].Condition = cloneConditionPtr(in[i].Condition)
	}
	return out
}

func predicateResolved(p Predicate, o evidence.Observation) bool {
	switch p.Operator {
	case PredicateExists, PredicateStateIs:
		return true
	default:
		return o.State == evidence.StateObserved
	}
}

func evaluatePredicate(p Predicate, idx Index) (match bool, found bool) {
	o, ok := idx[strings.TrimSpace(p.Key)]
	if !ok {
		return false, false
	}
	if p.Operator == PredicateExists {
		return true, true
	}
	if p.Operator == PredicateStateIs {
		return o.State == p.State, true
	}
	if o.State != evidence.StateObserved {
		return false, true
	}
	switch p.Operator {
	case PredicateValueEquals:
		return scalarEqual(o.Value, p.Value, p.CaseInsensitive), true
	case PredicateValueNotEqual:
		return !scalarEqual(o.Value, p.Value, p.CaseInsensitive), true
	case PredicateStringIn:
		actual := strings.TrimSpace(fmt.Sprint(o.Value))
		for _, want := range p.Values {
			if stringEqual(actual, strings.TrimSpace(want), p.CaseInsensitive) {
				return true, true
			}
		}
		return false, true
	case PredicateBoolIs:
		want := p.Value.(bool)
		actual, ok := booleanValue(o.Value)
		return ok && actual == want, true
	case PredicateNumberGTE, PredicateNumberLTE:
		actual, okA := numericValue(o.Value)
		want, okW := numericValue(p.Value)
		if !okA || !okW || math.IsNaN(actual) || math.IsNaN(want) {
			return false, true
		}
		if p.Operator == PredicateNumberGTE {
			return actual >= want, true
		}
		return actual <= want, true
	default:
		return false, true
	}
}

func scalarEqual(a, b any, caseInsensitive bool) bool {
	if af, ok := numericValue(a); ok {
		if bf, ok := numericValue(b); ok {
			return af == bf
		}
	}
	if ab, ok := booleanValue(a); ok {
		if bb, ok := booleanValue(b); ok {
			return ab == bb
		}
	}
	return stringEqual(strings.TrimSpace(fmt.Sprint(a)), strings.TrimSpace(fmt.Sprint(b)), caseInsensitive)
}

func stringEqual(a, b string, insensitive bool) bool {
	if insensitive {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func booleanValue(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		return b, err == nil
	default:
		return false, false
	}
}

func numericValue(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func inheritedConfidence(keys []string, idx Index) evidence.Confidence {
	if len(keys) == 0 {
		return evidence.ConfidenceLow
	}
	best := evidence.ConfidenceExact
	seen := false
	for _, key := range keys {
		o, ok := idx[key]
		if !ok {
			return evidence.ConfidenceLow
		}
		seen = true
		if confidenceRank(o.Confidence) < confidenceRank(best) {
			best = o.Confidence
		}
	}
	if !seen {
		return evidence.ConfidenceLow
	}
	return best
}

func confidenceRank(c evidence.Confidence) int {
	switch c {
	case evidence.ConfidenceLow:
		return 1
	case evidence.ConfidenceMedium:
		return 2
	case evidence.ConfidenceHigh:
		return 3
	case evidence.ConfidenceExact:
		return 4
	default:
		return 0
	}
}

func uniqueKeys(base []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, key := range append(append([]string(nil), base...), extra...) {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func validEvidenceState(s evidence.State) bool {
	switch s {
	case evidence.StateObserved, evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateNotApplicable:
		return true
	default:
		return false
	}
}
