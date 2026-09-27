package profile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion           = "chimera.profile/v2"
	EnterprisePolicyVersion = "chimera.enterprise-policy/v1-phase110"
)

const (
	ServiceModeRequired  = "required"
	ServiceModeAllowlist = "allowlist"
	PortModeRequired     = "required"
	PortModeAllowlist    = "allowlist"
)

type ExpectedService struct {
	Name     string `json:"name"`
	Manager  string `json:"manager,omitempty"`
	State    string `json:"state,omitempty"`
	Required bool   `json:"required"`
}

type ExpectedPort struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Binding  string `json:"binding,omitempty"`
	Required bool   `json:"required"`
}

type AllowedException struct {
	Kind   string `json:"kind"`
	Match  string `json:"match"`
	Reason string `json:"reason"`
}

// Definition is the user-authored custom-profile contract. Definitions
// are resolved into immutable Descriptor values before any host evidence is
// collected. Extends may name a built-in profile or another custom profile.
type Definition struct {
	Name               string                         `json:"name"`
	Extends            string                         `json:"extends"`
	Description        string                         `json:"description,omitempty"`
	DefaultApplicable  *bool                          `json:"default_applicable,omitempty"`
	EnabledCategories  []string                       `json:"enabled_categories,omitempty"`
	DisabledCategories []string                       `json:"disabled_categories,omitempty"`
	EnabledRules       []string                       `json:"enabled_rules,omitempty"`
	DisabledRules      []string                       `json:"disabled_rules,omitempty"`
	SeverityFloors     map[string]assessment.Severity `json:"severity_floors,omitempty"`
	SeverityOverrides  map[string]assessment.Severity `json:"severity_overrides,omitempty"`
	Environment        map[string]string              `json:"environment,omitempty"`
	ServicePolicyMode  string                         `json:"service_policy_mode,omitempty"`
	PortPolicyMode     string                         `json:"port_policy_mode,omitempty"`
	ExpectedServices   []ExpectedService              `json:"expected_services,omitempty"`
	ExpectedPorts      []ExpectedPort                 `json:"expected_ports,omitempty"`
	AllowedExceptions  []AllowedException             `json:"allowed_exceptions,omitempty"`
}

type Descriptor struct {
	Schema             string                         `json:"profile_schema"`
	Name               string                         `json:"name"`
	Description        string                         `json:"description"`
	Custom             bool                           `json:"custom"`
	Extends            string                         `json:"extends,omitempty"`
	BehaviorProfile    string                         `json:"behavior_profile"`
	DefaultApplicable  bool                           `json:"default_applicable"`
	EnabledCategories  []string                       `json:"enabled_categories,omitempty"`
	DisabledCategories []string                       `json:"disabled_categories,omitempty"`
	EnabledRules       []string                       `json:"enabled_rules,omitempty"`
	DisabledRules      []string                       `json:"disabled_rules,omitempty"`
	SeverityFloors     map[string]assessment.Severity `json:"severity_floors,omitempty"`
	SeverityOverrides  map[string]assessment.Severity `json:"severity_overrides,omitempty"`
	Environment        map[string]string              `json:"environment,omitempty"`
	ServicePolicyMode  string                         `json:"service_policy_mode,omitempty"`
	PortPolicyMode     string                         `json:"port_policy_mode,omitempty"`
	ExpectedServices   []ExpectedService              `json:"expected_services,omitempty"`
	ExpectedPorts      []ExpectedPort                 `json:"expected_ports,omitempty"`
	AllowedExceptions  []AllowedException             `json:"allowed_exceptions,omitempty"`
	PolicyVersion      string                         `json:"policy_version,omitempty"`
}

type RuleDecision struct {
	RuleID            string              `json:"rule_id"`
	Category          string              `json:"category"`
	Applicable        bool                `json:"applicable"`
	BaseSeverity      assessment.Severity `json:"base_severity"`
	EffectiveSeverity assessment.Severity `json:"effective_severity"`
	Reason            string              `json:"reason"`
}

type Applied struct {
	Profile   Descriptor        `json:"profile"`
	Decisions []RuleDecision    `json:"rule_decisions"`
	Rules     []assessment.Rule `json:"-"`
}

type Registry struct {
	descriptors map[string]Descriptor
	ordered     []Descriptor
}

func Catalog() []Descriptor {
	return []Descriptor{
		{
			Schema: SchemaVersion, Name: "default", BehaviorProfile: "default",
			Description:       "Balanced general-purpose assessment. All implemented rules are applicable unless the rule itself determines otherwise.",
			DefaultApplicable: true,
		},
		{
			Schema: SchemaVersion, Name: "workstation", BehaviorProfile: "workstation",
			Description:       "Interactive endpoint profile. Preserves broad coverage and raises network-observability weaknesses to MEDIUM.",
			DefaultApplicable: true,
			SeverityFloors:    map[string]assessment.Severity{"network": assessment.SeverityMedium},
		},
		{
			Schema: SchemaVersion, Name: "server", BehaviorProfile: "server",
			Description:       "Service-host profile. Preserves broad coverage and raises identity and network-observability weaknesses to MEDIUM.",
			DefaultApplicable: true,
			SeverityFloors:    map[string]assessment.Severity{"identity": assessment.SeverityMedium, "network": assessment.SeverityMedium},
		},
		{
			Schema: SchemaVersion, Name: "developer", BehaviorProfile: "developer",
			Description:       "Developer endpoint profile. Broad evidence collection remains enabled while current core severities remain at their base values.",
			DefaultApplicable: true,
		},
		{
			Schema: SchemaVersion, Name: "high-security", BehaviorProfile: "high-security",
			Description:       "Strict profile for hardened systems. Broad coverage remains enabled and core collection, inventory, identity, and network weaknesses receive higher severity floors.",
			DefaultApplicable: true,
			SeverityFloors: map[string]assessment.Severity{
				"collection": assessment.SeverityLow,
				"inventory":  assessment.SeverityLow,
				"identity":   assessment.SeverityMedium,
				"network":    assessment.SeverityMedium,
				"kernel":     assessment.SeverityHigh,
			},
		},
		{
			Schema: SchemaVersion, Name: "minimal", BehaviorProfile: "minimal",
			Description:       "Reduced assessment profile. Only core collection and inventory rules are applicable; other rules remain visible as NOT_APPLICABLE without changing raw evidence.",
			DefaultApplicable: false,
			EnabledCategories: []string{"collection", "inventory"},
		},
	}
}

func Names() []string {
	catalog := Catalog()
	names := make([]string, 0, len(catalog))
	for _, p := range catalog {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

func Resolve(name string) (Descriptor, error) {
	name = normalizeName(name)
	if name == "" {
		name = "default"
	}
	for _, p := range Catalog() {
		if p.Name == name {
			return cloneDescriptor(p), nil
		}
	}
	return Descriptor{}, fmt.Errorf("unknown assessment profile %q (supported: %s)", name, strings.Join(Names(), ", "))
}

// NewRegistry resolves and validates all custom profile definitions against the
// current executable rule catalog. The result is deterministic and immutable.
func NewRegistry(definitions []Definition, rules []assessment.Rule) (Registry, error) {
	if err := validateRuleCatalog(rules); err != nil {
		return Registry{}, err
	}
	descriptors := make(map[string]Descriptor)
	ordered := make([]Descriptor, 0, len(Catalog())+len(definitions))
	for _, builtin := range Catalog() {
		c := cloneDescriptor(builtin)
		descriptors[c.Name] = c
		ordered = append(ordered, c)
	}

	defs := make(map[string]Definition, len(definitions))
	for i, raw := range definitions {
		d := cloneDefinition(raw)
		d.Name = normalizeName(d.Name)
		d.Extends = normalizeName(d.Extends)
		if d.Name == "" {
			return Registry{}, fmt.Errorf("custom profile %d: name is required", i)
		}
		if !validName(d.Name) {
			return Registry{}, fmt.Errorf("custom profile %q: name may contain only lowercase letters, numbers, dot, underscore, and hyphen", d.Name)
		}
		if _, builtin := descriptors[d.Name]; builtin {
			return Registry{}, fmt.Errorf("custom profile %q cannot replace a built-in profile", d.Name)
		}
		if _, exists := defs[d.Name]; exists {
			return Registry{}, fmt.Errorf("duplicate custom profile %q", d.Name)
		}
		if d.Extends == "" {
			return Registry{}, fmt.Errorf("custom profile %q: extends is required", d.Name)
		}
		defs[d.Name] = d
	}

	resolved := make(map[string]Descriptor, len(defs))
	visiting := make(map[string]bool, len(defs))
	var resolveCustom func(string) (Descriptor, error)
	resolveCustom = func(name string) (Descriptor, error) {
		if d, ok := resolved[name]; ok {
			return cloneDescriptor(d), nil
		}
		raw, ok := defs[name]
		if !ok {
			if d, ok := descriptors[name]; ok {
				return cloneDescriptor(d), nil
			}
			return Descriptor{}, fmt.Errorf("unknown parent profile %q", name)
		}
		if visiting[name] {
			return Descriptor{}, fmt.Errorf("custom profile inheritance cycle includes %q", name)
		}
		visiting[name] = true
		parent, err := resolveCustom(raw.Extends)
		if err != nil {
			return Descriptor{}, fmt.Errorf("custom profile %q: %w", name, err)
		}
		child, err := mergeDefinition(parent, raw, rules)
		if err != nil {
			return Descriptor{}, fmt.Errorf("custom profile %q: %w", name, err)
		}
		visiting[name] = false
		resolved[name] = child
		return cloneDescriptor(child), nil
	}

	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d, err := resolveCustom(name)
		if err != nil {
			return Registry{}, err
		}
		descriptors[name] = cloneDescriptor(d)
		ordered = append(ordered, cloneDescriptor(d))
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	return Registry{descriptors: descriptors, ordered: ordered}, nil
}

func BuiltinRegistry(rules []assessment.Rule) (Registry, error) { return NewRegistry(nil, rules) }

func (r Registry) Resolve(name string) (Descriptor, error) {
	name = normalizeName(name)
	if name == "" {
		name = "default"
	}
	d, ok := r.descriptors[name]
	if !ok {
		names := make([]string, 0, len(r.descriptors))
		for key := range r.descriptors {
			names = append(names, key)
		}
		sort.Strings(names)
		return Descriptor{}, fmt.Errorf("unknown assessment profile %q (supported: %s)", name, strings.Join(names, ", "))
	}
	return cloneDescriptor(d), nil
}

func (r Registry) Catalog() []Descriptor {
	out := make([]Descriptor, len(r.ordered))
	for i := range r.ordered {
		out[i] = cloneDescriptor(r.ordered[i])
	}
	return out
}

func Apply(p Descriptor, rules []assessment.Rule) (Applied, error) {
	resolved := cloneDescriptor(p)
	if resolved.Name == "" {
		var err error
		resolved, err = Resolve("default")
		if err != nil {
			return Applied{}, err
		}
	}
	if err := validateDescriptor(resolved, rules); err != nil {
		return Applied{}, fmt.Errorf("profile %q: %w", resolved.Name, err)
	}

	allRules := append([]assessment.Rule(nil), rules...)
	allRules = append(allRules, enterprisePolicyRules(resolved)...)
	out := Applied{Profile: resolved, Rules: make([]assessment.Rule, 0, len(allRules)), Decisions: make([]RuleDecision, 0, len(allRules))}
	for _, base := range allRules {
		if err := base.Validate(); err != nil {
			return Applied{}, fmt.Errorf("profile %q: invalid rule: %w", resolved.Name, err)
		}
		applicable, reason := applicability(resolved, base)
		effective := effectiveSeverity(resolved, base)
		r := base
		r.Severity = effective
		if base.Definition != nil {
			definition := *base.Definition
			definition.Severity = effective
			r.Definition = &definition
		}
		if applicable && base.EvaluateProfile != nil {
			behavior := resolved.BehaviorProfile
			if behavior == "" {
				behavior = resolved.Name
			}
			profileEvaluator := base.EvaluateProfile
			r.Evaluate = func(idx assessment.Index) assessment.Evaluation {
				return profileEvaluator(behavior, idx)
			}
		}
		if !applicable {
			r.Evaluate = func(assessment.Index) assessment.Evaluation {
				return assessment.Evaluation{
					Status:        assessment.StatusPass,
					Confidence:    evidence.ConfidenceExact,
					ObservedState: "profile " + resolved.Name + ": rule not applicable",
					Applicability: assessment.NotApplicable,
				}
			}
		}
		out.Rules = append(out.Rules, r)
		out.Decisions = append(out.Decisions, RuleDecision{
			RuleID: base.ID, Category: base.Category, Applicable: applicable,
			BaseSeverity: base.Severity, EffectiveSeverity: effective, Reason: reason,
		})
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].ID < out.Rules[j].ID })
	sort.Slice(out.Decisions, func(i, j int) bool { return out.Decisions[i].RuleID < out.Decisions[j].RuleID })
	return out, nil
}

func DecisionFor(applied Applied, ruleID string) (RuleDecision, bool) {
	for _, d := range applied.Decisions {
		if strings.EqualFold(d.RuleID, strings.TrimSpace(ruleID)) {
			return d, true
		}
	}
	return RuleDecision{}, false
}

func applicability(p Descriptor, rule assessment.Rule) (bool, string) {
	ruleID := strings.ToUpper(strings.TrimSpace(rule.ID))
	category := strings.ToLower(strings.TrimSpace(rule.Category))
	if containsFold(p.DisabledRules, ruleID) {
		return false, "rule disabled by profile " + p.Name
	}
	if containsFold(p.EnabledRules, ruleID) {
		return true, "rule explicitly enabled by profile " + p.Name
	}
	if containsFold(p.DisabledCategories, category) {
		return false, "category disabled by profile " + p.Name
	}
	if containsFold(p.EnabledCategories, category) {
		return true, "category explicitly enabled by profile " + p.Name
	}
	if p.DefaultApplicable {
		return true, "profile default applicability"
	}
	return false, "category not enabled by profile " + p.Name
}

func effectiveSeverity(p Descriptor, base assessment.Rule) assessment.Severity {
	if override, ok := lookupSeverity(p.SeverityOverrides, base.ID); ok {
		return override
	}
	floor, _ := lookupSeverity(p.SeverityFloors, strings.ToLower(strings.TrimSpace(base.Category)))
	return severityFloor(base.Severity, floor)
}

func severityFloor(base, floor assessment.Severity) assessment.Severity {
	if severityRank(floor) > severityRank(base) {
		return floor
	}
	return base
}

func severityRank(s assessment.Severity) int {
	switch s {
	case assessment.SeverityInfo:
		return 1
	case assessment.SeverityLow:
		return 2
	case assessment.SeverityMedium:
		return 3
	case assessment.SeverityHigh:
		return 4
	case assessment.SeverityCritical:
		return 5
	default:
		return 0
	}
}

func lookupSeverity(values map[string]assessment.Severity, key string) (assessment.Severity, bool) {
	for k, v := range values {
		if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(key)) {
			return v, true
		}
	}
	return "", false
}

func containsFold(items []string, value string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

func validateRuleCatalog(rules []assessment.Rule) error {
	seen := map[string]struct{}{}
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("profile rule catalog: %w", err)
		}
		id := strings.ToUpper(strings.TrimSpace(rule.ID))
		if _, ok := seen[id]; ok {
			return fmt.Errorf("profile rule catalog contains duplicate rule %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateDescriptor(d Descriptor, rules []assessment.Rule) error {
	if d.Schema != SchemaVersion {
		return fmt.Errorf("profile schema must be %s", SchemaVersion)
	}
	if normalizeName(d.Name) == "" || !validName(normalizeName(d.Name)) {
		return fmt.Errorf("valid profile name is required")
	}
	if strings.TrimSpace(d.Description) == "" {
		return fmt.Errorf("profile description is required")
	}
	if strings.TrimSpace(d.BehaviorProfile) == "" {
		return fmt.Errorf("behavior profile is required")
	}
	knownRules := map[string]struct{}{"CHM-ENT-001": {}, "CHM-ENT-002": {}}
	knownCategories := map[string]struct{}{"enterprise-policy": {}}
	catalogRules := append([]assessment.Rule(nil), rules...)
	catalogRules = append(catalogRules, assessment.ImplementedRules()...)
	for _, r := range catalogRules {
		knownRules[strings.ToUpper(strings.TrimSpace(r.ID))] = struct{}{}
		knownCategories[strings.ToLower(strings.TrimSpace(r.Category))] = struct{}{}
	}
	if d.Custom {
		for _, item := range append(append([]string{}, d.EnabledRules...), d.DisabledRules...) {
			id := strings.ToUpper(strings.TrimSpace(item))
			if _, ok := knownRules[id]; !ok {
				return fmt.Errorf("unknown rule %q in profile rule policy", item)
			}
		}
		for _, item := range append(append([]string{}, d.EnabledCategories...), d.DisabledCategories...) {
			cat := strings.ToLower(strings.TrimSpace(item))
			if _, ok := knownCategories[cat]; !ok {
				return fmt.Errorf("unknown category %q in profile category policy", item)
			}
		}
	}
	for cat, sev := range d.SeverityFloors {
		if d.Custom {
			if _, ok := knownCategories[strings.ToLower(strings.TrimSpace(cat))]; !ok {
				return fmt.Errorf("severity floor references unknown category %q", cat)
			}
		}
		if severityRank(sev) == 0 {
			return fmt.Errorf("severity floor for %q has invalid severity %q", cat, sev)
		}
	}
	for id, sev := range d.SeverityOverrides {
		if d.Custom {
			if _, ok := knownRules[strings.ToUpper(strings.TrimSpace(id))]; !ok {
				return fmt.Errorf("severity override references unknown rule %q", id)
			}
		}
		if severityRank(sev) == 0 {
			return fmt.Errorf("severity override for %q has invalid severity %q", id, sev)
		}
	}
	if err := validateEnvironmentPolicy(d); err != nil {
		return err
	}
	return nil
}

func mergeDefinition(parent Descriptor, raw Definition, rules []assessment.Rule) (Descriptor, error) {
	out := cloneDescriptor(parent)
	out.Schema = SchemaVersion
	out.Name = normalizeName(raw.Name)
	out.Custom = true
	out.Extends = normalizeName(raw.Extends)
	out.PolicyVersion = EnterprisePolicyVersion
	if strings.TrimSpace(raw.Description) != "" {
		out.Description = strings.TrimSpace(raw.Description)
	} else {
		out.Description = fmt.Sprintf("Custom enterprise profile extending %s.", out.Extends)
	}
	if raw.DefaultApplicable != nil {
		out.DefaultApplicable = *raw.DefaultApplicable
	}
	out.EnabledCategories, out.DisabledCategories = mergeToggleLists(out.EnabledCategories, out.DisabledCategories, raw.EnabledCategories, raw.DisabledCategories, false)
	out.EnabledRules, out.DisabledRules = mergeToggleLists(out.EnabledRules, out.DisabledRules, raw.EnabledRules, raw.DisabledRules, true)
	out.SeverityFloors = mergeSeverityMap(out.SeverityFloors, raw.SeverityFloors, false)
	out.SeverityOverrides = mergeSeverityMap(out.SeverityOverrides, raw.SeverityOverrides, true)
	out.Environment = mergeStringMap(out.Environment, raw.Environment)
	if strings.TrimSpace(raw.ServicePolicyMode) != "" {
		out.ServicePolicyMode = strings.ToLower(strings.TrimSpace(raw.ServicePolicyMode))
	}
	if strings.TrimSpace(raw.PortPolicyMode) != "" {
		out.PortPolicyMode = strings.ToLower(strings.TrimSpace(raw.PortPolicyMode))
	}
	out.ExpectedServices = mergeExpectedServices(out.ExpectedServices, raw.ExpectedServices)
	out.ExpectedPorts = mergeExpectedPorts(out.ExpectedPorts, raw.ExpectedPorts)
	out.AllowedExceptions = mergeExceptions(out.AllowedExceptions, raw.AllowedExceptions)
	normalizeDescriptor(&out)
	if err := validateDescriptor(out, rules); err != nil {
		return Descriptor{}, err
	}
	return out, nil
}

func normalizeDescriptor(d *Descriptor) {
	d.Name = normalizeName(d.Name)
	d.Extends = normalizeName(d.Extends)
	d.BehaviorProfile = normalizeName(d.BehaviorProfile)
	d.EnabledCategories = normalizeStrings(d.EnabledCategories, false)
	d.DisabledCategories = normalizeStrings(d.DisabledCategories, false)
	d.EnabledRules = normalizeStrings(d.EnabledRules, true)
	d.DisabledRules = normalizeStrings(d.DisabledRules, true)
	if d.Custom && d.PolicyVersion == "" {
		d.PolicyVersion = EnterprisePolicyVersion
	}
}

func mergeToggleLists(parentEnabled, parentDisabled, childEnabled, childDisabled []string, upper bool) ([]string, []string) {
	enabled := toSet(parentEnabled, upper)
	disabled := toSet(parentDisabled, upper)
	for _, raw := range childEnabled {
		value := normalizeToken(raw, upper)
		if value == "" {
			continue
		}
		enabled[value] = struct{}{}
		delete(disabled, value)
	}
	for _, raw := range childDisabled {
		value := normalizeToken(raw, upper)
		if value == "" {
			continue
		}
		disabled[value] = struct{}{}
		delete(enabled, value)
	}
	return setList(enabled), setList(disabled)
}

func mergeSeverityMap(parent, child map[string]assessment.Severity, upper bool) map[string]assessment.Severity {
	out := map[string]assessment.Severity{}
	for k, v := range parent {
		out[normalizeToken(k, upper)] = assessment.Severity(strings.ToUpper(strings.TrimSpace(string(v))))
	}
	for k, v := range child {
		out[normalizeToken(k, upper)] = assessment.Severity(strings.ToUpper(strings.TrimSpace(string(v))))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeStringMap(parent, child map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range parent {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	for k, v := range child {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeExpectedServices(parent, child []ExpectedService) []ExpectedService {
	byKey := map[string]ExpectedService{}
	for _, item := range append(append([]ExpectedService{}, parent...), child...) {
		item.Name = strings.TrimSpace(item.Name)
		item.Manager = strings.TrimSpace(item.Manager)
		item.State = strings.ToUpper(strings.TrimSpace(item.State))
		if item.State == "" {
			item.State = "ANY"
		}
		byKey[serviceExpectationKey(item)] = item
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ExpectedService, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func mergeExpectedPorts(parent, child []ExpectedPort) []ExpectedPort {
	byKey := map[string]ExpectedPort{}
	for _, item := range append(append([]ExpectedPort{}, parent...), child...) {
		item.Protocol = strings.ToUpper(strings.TrimSpace(item.Protocol))
		item.Binding = strings.ToUpper(strings.TrimSpace(item.Binding))
		if item.Binding == "" {
			item.Binding = "ANY"
		}
		byKey[portExpectationKey(item)] = item
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ExpectedPort, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func mergeExceptions(parent, child []AllowedException) []AllowedException {
	byKey := map[string]AllowedException{}
	for _, item := range append(append([]AllowedException{}, parent...), child...) {
		item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
		item.Match = strings.TrimSpace(item.Match)
		item.Reason = strings.TrimSpace(item.Reason)
		byKey[item.Kind+"\x00"+strings.ToLower(item.Match)] = item
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]AllowedException, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func validateEnvironmentPolicy(d Descriptor) error {
	switch d.ServicePolicyMode {
	case "", ServiceModeRequired, ServiceModeAllowlist:
	default:
		return fmt.Errorf("invalid service_policy_mode %q (use required or allowlist)", d.ServicePolicyMode)
	}
	switch d.PortPolicyMode {
	case "", PortModeRequired, PortModeAllowlist:
	default:
		return fmt.Errorf("invalid port_policy_mode %q (use required or allowlist)", d.PortPolicyMode)
	}
	for k, v := range d.Environment {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("environment labels require non-empty key and value")
		}
	}
	seenServices := map[string]struct{}{}
	for _, item := range d.ExpectedServices {
		if strings.TrimSpace(item.Name) == "" {
			return fmt.Errorf("expected service requires a name")
		}
		state := strings.ToUpper(strings.TrimSpace(item.State))
		if state == "" {
			state = "ANY"
		}
		switch state {
		case "ANY", "RUNNING", "STOPPED", "ENABLED", "DISABLED":
		default:
			return fmt.Errorf("expected service %q has invalid state %q", item.Name, item.State)
		}
		key := serviceExpectationKey(item)
		if _, ok := seenServices[key]; ok {
			return fmt.Errorf("duplicate expected service %q", item.Name)
		}
		seenServices[key] = struct{}{}
	}
	seenPorts := map[string]struct{}{}
	for _, item := range d.ExpectedPorts {
		if item.Protocol != "TCP" && item.Protocol != "UDP" {
			return fmt.Errorf("expected port %d has invalid protocol %q", item.Port, item.Protocol)
		}
		if item.Port == 0 {
			return fmt.Errorf("expected port requires a non-zero port")
		}
		binding := strings.ToUpper(strings.TrimSpace(item.Binding))
		if binding == "" {
			binding = "ANY"
		}
		switch binding {
		case "ANY", "LOOPBACK", "EXTERNAL", "ALL_INTERFACES", "NON_LOOPBACK":
		default:
			return fmt.Errorf("expected %s/%d has invalid binding %q", item.Protocol, item.Port, item.Binding)
		}
		key := portExpectationKey(item)
		if _, ok := seenPorts[key]; ok {
			return fmt.Errorf("duplicate expected port %s/%d", item.Protocol, item.Port)
		}
		seenPorts[key] = struct{}{}
	}
	for _, ex := range d.AllowedExceptions {
		if ex.Kind != "service" && ex.Kind != "port" {
			return fmt.Errorf("allowed exception kind %q is invalid (use service or port)", ex.Kind)
		}
		if strings.TrimSpace(ex.Match) == "" || strings.TrimSpace(ex.Reason) == "" {
			return fmt.Errorf("allowed %s exception requires match and reason", ex.Kind)
		}
	}
	return nil
}

func serviceExpectationKey(item ExpectedService) string {
	return strings.ToLower(strings.TrimSpace(item.Name)) + "\x00" + strings.ToLower(strings.TrimSpace(item.Manager))
}

func portExpectationKey(item ExpectedPort) string {
	binding := strings.ToUpper(strings.TrimSpace(item.Binding))
	if binding == "" {
		binding = "ANY"
	}
	return strings.ToUpper(strings.TrimSpace(item.Protocol)) + "\x00" + fmt.Sprint(item.Port) + "\x00" + binding
}

func normalizeName(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func validName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
func normalizeToken(value string, upper bool) string {
	value = strings.TrimSpace(value)
	if upper {
		return strings.ToUpper(value)
	}
	return strings.ToLower(value)
}
func normalizeStrings(values []string, upper bool) []string { return setList(toSet(values, upper)) }
func toSet(values []string, upper bool) map[string]struct{} {
	out := map[string]struct{}{}
	for _, raw := range values {
		value := normalizeToken(raw, upper)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
func setList(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func cloneDefinition(in Definition) Definition {
	out := in
	out.EnabledCategories = append([]string(nil), in.EnabledCategories...)
	out.DisabledCategories = append([]string(nil), in.DisabledCategories...)
	out.EnabledRules = append([]string(nil), in.EnabledRules...)
	out.DisabledRules = append([]string(nil), in.DisabledRules...)
	out.ExpectedServices = append([]ExpectedService(nil), in.ExpectedServices...)
	out.ExpectedPorts = append([]ExpectedPort(nil), in.ExpectedPorts...)
	out.AllowedExceptions = append([]AllowedException(nil), in.AllowedExceptions...)
	out.SeverityFloors = mergeSeverityMap(nil, in.SeverityFloors, false)
	out.SeverityOverrides = mergeSeverityMap(nil, in.SeverityOverrides, true)
	out.Environment = mergeStringMap(nil, in.Environment)
	return out
}

func cloneDescriptor(in Descriptor) Descriptor {
	out := in
	out.EnabledCategories = append([]string(nil), in.EnabledCategories...)
	out.DisabledCategories = append([]string(nil), in.DisabledCategories...)
	out.EnabledRules = append([]string(nil), in.EnabledRules...)
	out.DisabledRules = append([]string(nil), in.DisabledRules...)
	out.ExpectedServices = append([]ExpectedService(nil), in.ExpectedServices...)
	out.ExpectedPorts = append([]ExpectedPort(nil), in.ExpectedPorts...)
	out.AllowedExceptions = append([]AllowedException(nil), in.AllowedExceptions...)
	out.SeverityFloors = mergeSeverityMap(nil, in.SeverityFloors, false)
	out.SeverityOverrides = mergeSeverityMap(nil, in.SeverityOverrides, true)
	out.Environment = mergeStringMap(nil, in.Environment)
	return out
}

// ValidateEnterprisePolicyContract performs a build-health validation of the
// inheritance and generated enterprise-policy rule contract without
// collecting host evidence.
func ValidateEnterprisePolicyContract(rules []assessment.Rule) error {
	registry, err := NewRegistry([]Definition{{
		Name: "contract-check", Extends: "server", Description: "enterprise-profile contract check",
		Environment:       map[string]string{"environment": "contract-test"},
		ServicePolicyMode: ServiceModeRequired,
		PortPolicyMode:    PortModeRequired,
		ExpectedServices:  []ExpectedService{{Name: "contract-service", State: "RUNNING", Required: true}},
		ExpectedPorts:     []ExpectedPort{{Protocol: "TCP", Port: 443, Binding: "EXTERNAL", Required: true}},
	}}, rules)
	if err != nil {
		return err
	}
	d, err := registry.Resolve("contract-check")
	if err != nil {
		return err
	}
	if !d.Custom || d.Extends != "server" || d.BehaviorProfile != "server" || d.PolicyVersion != EnterprisePolicyVersion {
		return fmt.Errorf("resolved enterprise profile has invalid inheritance provenance")
	}
	applied, err := Apply(d, rules)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range applied.Rules {
		if r.ID == "CHM-ENT-001" || r.ID == "CHM-ENT-002" {
			if err := r.Validate(); err != nil {
				return fmt.Errorf("enterprise policy rule %s: %w", r.ID, err)
			}
			seen[r.ID] = true
		}
	}
	if !seen["CHM-ENT-001"] || !seen["CHM-ENT-002"] {
		return fmt.Errorf("enterprise policy rules are incomplete: service=%t port=%t", seen["CHM-ENT-001"], seen["CHM-ENT-002"])
	}
	return nil
}
