package selection

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
)

const SchemaVersion = "chimera.selection/v1"

type Outcome string

const (
	OutcomeSelected   Outcome = "SELECTED"
	OutcomeSkipped    Outcome = "SKIPPED"
	OutcomeSuppressed Outcome = "SUPPRESSED"
)

type Request struct {
	Severity assessment.Severity `json:"severity_threshold"`
	Category string              `json:"category,omitempty"`
	Include  []string            `json:"include,omitempty"`
	Exclude  []string            `json:"exclude,omitempty"`
}

type Decision struct {
	RuleID   string              `json:"rule_id"`
	Category string              `json:"category"`
	Severity assessment.Severity `json:"effective_severity"`
	Outcome  Outcome             `json:"outcome"`
	Reason   string              `json:"reason"`
}

type Summary struct {
	Total      int `json:"total"`
	Selected   int `json:"selected"`
	Skipped    int `json:"skipped"`
	Suppressed int `json:"suppressed"`
}

type Report struct {
	Schema    string     `json:"selection_schema"`
	Request   Request    `json:"request"`
	Summary   Summary    `json:"summary"`
	Decisions []Decision `json:"decisions"`
}

type Applied struct {
	Rules  []assessment.Rule `json:"-"`
	Report Report            `json:"report"`
}

type selectorKind int

const (
	selectorRule selectorKind = iota + 1
	selectorCategory
)

type selector struct {
	raw   string
	kind  selectorKind
	value string
}

func Apply(rules []assessment.Rule, request Request) (Applied, error) {
	normalized, err := normalizeRequest(request)
	if err != nil {
		return Applied{}, err
	}
	if err := validateRules(rules); err != nil {
		return Applied{}, err
	}

	include, err := resolveSelectors(normalized.Include, rules)
	if err != nil {
		return Applied{}, fmt.Errorf("include selector: %w", err)
	}
	exclude, err := resolveSelectors(normalized.Exclude, rules)
	if err != nil {
		return Applied{}, fmt.Errorf("exclude selector: %w", err)
	}
	if normalized.Category != "" && !knownCategory(normalized.Category, rules) {
		return Applied{}, fmt.Errorf("unknown category %q (available: %s)", normalized.Category, strings.Join(categories(rules), ", "))
	}

	thresholdRank := severityRank(normalized.Severity)
	selectedRules := make([]assessment.Rule, 0, len(rules))
	decisions := make([]Decision, 0, len(rules))
	for _, r := range rules {
		outcome := OutcomeSelected
		reason := "selected: rule satisfies active selection policy"

		if matched, label := matchesAny(exclude, r); matched {
			outcome = OutcomeSuppressed
			reason = "suppressed: matched --exclude " + label
		} else if normalized.Category != "" && !strings.EqualFold(strings.TrimSpace(r.Category), normalized.Category) {
			outcome = OutcomeSkipped
			reason = "skipped: category does not match --category " + normalized.Category
		} else if len(include) > 0 {
			if matched, _ := matchesAny(include, r); !matched {
				outcome = OutcomeSkipped
				reason = "skipped: rule does not match any --include selector"
			}
		}

		if outcome == OutcomeSelected && severityRank(r.Severity) < thresholdRank {
			outcome = OutcomeSkipped
			reason = fmt.Sprintf("skipped: effective severity %s is below threshold %s", r.Severity, normalized.Severity)
		}
		if outcome == OutcomeSelected {
			if normalized.Category != "" {
				reason = "selected: matched --category " + normalized.Category
			}
			if matched, label := matchesAny(include, r); matched {
				reason = "selected: matched --include " + label
			}
			if normalized.Severity != assessment.SeverityInfo {
				reason += fmt.Sprintf("; severity %s meets threshold %s", r.Severity, normalized.Severity)
			}
			selectedRules = append(selectedRules, r)
		}

		decisions = append(decisions, Decision{RuleID: r.ID, Category: r.Category, Severity: r.Severity, Outcome: outcome, Reason: reason})
	}

	sort.Slice(selectedRules, func(i, j int) bool { return selectedRules[i].ID < selectedRules[j].ID })
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].RuleID < decisions[j].RuleID })
	summary := Summary{Total: len(decisions)}
	for _, d := range decisions {
		switch d.Outcome {
		case OutcomeSelected:
			summary.Selected++
		case OutcomeSkipped:
			summary.Skipped++
		case OutcomeSuppressed:
			summary.Suppressed++
		}
	}
	return Applied{
		Rules:  selectedRules,
		Report: Report{Schema: SchemaVersion, Request: normalized, Summary: summary, Decisions: decisions},
	}, nil
}

func DecisionFor(report Report, ruleID string) (Decision, bool) {
	ruleID = strings.TrimSpace(ruleID)
	for _, d := range report.Decisions {
		if strings.EqualFold(d.RuleID, ruleID) {
			return d, true
		}
	}
	return Decision{}, false
}

func normalizeRequest(in Request) (Request, error) {
	if in.Category != "" && strings.TrimSpace(in.Category) == "" {
		return Request{}, fmt.Errorf("category selector cannot be empty")
	}
	if err := rejectBlankSelectors("include", in.Include); err != nil {
		return Request{}, err
	}
	if err := rejectBlankSelectors("exclude", in.Exclude); err != nil {
		return Request{}, err
	}
	out := Request{
		Severity: assessment.Severity(strings.ToUpper(strings.TrimSpace(string(in.Severity)))),
		Category: strings.ToLower(strings.TrimSpace(in.Category)),
		Include:  normalizeList(in.Include),
		Exclude:  normalizeList(in.Exclude),
	}
	if out.Severity == "" {
		out.Severity = assessment.SeverityInfo
	}
	if severityRank(out.Severity) == 0 {
		return Request{}, fmt.Errorf("invalid severity threshold %q", in.Severity)
	}
	return out, nil
}

func rejectBlankSelectors(name string, values []string) error {
	for _, raw := range values {
		if strings.Trim(strings.TrimSpace(raw), ",") == "" {
			return fmt.Errorf("%s selector cannot be empty", name)
		}
	}
	return nil
}

func normalizeList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			key := strings.ToLower(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func validateRules(rules []assessment.Rule) error {
	seen := map[string]struct{}{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("selection rule catalog: %w", err)
		}
		key := strings.ToLower(strings.TrimSpace(r.ID))
		if _, ok := seen[key]; ok {
			return fmt.Errorf("selection rule catalog contains duplicate rule id %q", r.ID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func resolveSelectors(raw []string, rules []assessment.Rule) ([]selector, error) {
	out := make([]selector, 0, len(raw))
	for _, value := range raw {
		s, err := resolveSelector(value, rules)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func resolveSelector(raw string, rules []assessment.Rule) (selector, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return selector{}, fmt.Errorf("empty selector")
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "rule:") {
		value := strings.TrimSpace(raw[len("rule:"):])
		if value == "" || !knownRule(value, rules) {
			return selector{}, fmt.Errorf("unknown rule selector %q", raw)
		}
		return selector{raw: raw, kind: selectorRule, value: value}, nil
	}
	if strings.HasPrefix(lower, "category:") {
		value := strings.ToLower(strings.TrimSpace(raw[len("category:"):]))
		if value == "" || !knownCategory(value, rules) {
			return selector{}, fmt.Errorf("unknown category selector %q", raw)
		}
		return selector{raw: raw, kind: selectorCategory, value: value}, nil
	}
	if knownRule(raw, rules) {
		return selector{raw: raw, kind: selectorRule, value: raw}, nil
	}
	if knownCategory(lower, rules) {
		return selector{raw: raw, kind: selectorCategory, value: lower}, nil
	}
	return selector{}, fmt.Errorf("unknown selector %q; use an exact rule ID, exact category, rule:<id>, or category:<name>", raw)
}

func knownRule(id string, rules []assessment.Rule) bool {
	for _, r := range rules {
		if strings.EqualFold(strings.TrimSpace(r.ID), strings.TrimSpace(id)) {
			return true
		}
	}
	return false
}

func knownCategory(category string, rules []assessment.Rule) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	for _, r := range rules {
		if strings.EqualFold(strings.TrimSpace(r.Category), category) {
			return true
		}
	}
	return false
}

func categories(rules []assessment.Rule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, r := range rules {
		c := strings.ToLower(strings.TrimSpace(r.Category))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func matchesAny(selectors []selector, r assessment.Rule) (bool, string) {
	for _, s := range selectors {
		switch s.kind {
		case selectorRule:
			if strings.EqualFold(strings.TrimSpace(r.ID), strings.TrimSpace(s.value)) {
				return true, s.raw
			}
		case selectorCategory:
			if strings.EqualFold(strings.TrimSpace(r.Category), strings.TrimSpace(s.value)) {
				return true, s.raw
			}
		}
	}
	return false, ""
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
