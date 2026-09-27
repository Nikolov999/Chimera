package baseline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cisalign"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/suppression"
)

const (
	SchemaVersion = "chimera.baseline/v2"
	EngineVersion = "chimera.baseline-engine/v2-phase109"
)

type State string

const (
	StatePass          State = "PASS"
	StateWarn          State = "WARN"
	StateFail          State = "FAIL"
	StateUnknown       State = "UNKNOWN"
	StateNotApplicable State = "NOT_APPLICABLE"
	StateNotEvaluated  State = "NOT_EVALUATED"
)

type Counts struct {
	Total         int `json:"total"`
	Applicable    int `json:"applicable"`
	Pass          int `json:"pass"`
	Warn          int `json:"warn"`
	Fail          int `json:"fail"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"not_applicable"`
	NotEvaluated  int `json:"not_evaluated"`
	Suppressed    int `json:"suppressed"`
}

type RuleResult struct {
	RuleID         string                         `json:"rule_id"`
	FindingID      string                         `json:"finding_id"`
	Title          string                         `json:"title"`
	Category       string                         `json:"category"`
	State          State                          `json:"state"`
	Status         assessment.Status              `json:"status"`
	Applicability  assessment.Applicability       `json:"applicability"`
	Severity       assessment.Severity            `json:"severity"`
	Confidence     evidence.Confidence            `json:"confidence"`
	AffectedObject string                         `json:"affected_object"`
	ObservedState  string                         `json:"observed_state"`
	ExpectedState  string                         `json:"expected_state"`
	Suppression    assessment.SuppressionState    `json:"suppression_state"`
	Suppressions   []assessment.SuppressionRecord `json:"suppressions,omitempty"`
	Reason         string                         `json:"reason,omitempty"`
}

type CategoryResult struct {
	Name   string       `json:"name"`
	State  State        `json:"state"`
	Counts Counts       `json:"counts"`
	Rules  []RuleResult `json:"rules"`
}

type Coverage struct {
	State             string  `json:"state"`
	Total             int     `json:"total_rules"`
	Selected          int     `json:"selected_rules"`
	Skipped           int     `json:"skipped_rules"`
	Suppressed        int     `json:"suppressed_rules"`
	Evaluated         int     `json:"evaluated_rules"`
	NotEvaluated      int     `json:"not_evaluated_rules"`
	EvaluationPercent float64 `json:"evaluation_percent"`
	Reason            string  `json:"reason"`
}

type Result struct {
	Schema          string                 `json:"baseline_schema"`
	EngineVersion   string                 `json:"engine_version"`
	RuleSetVersion  string                 `json:"rule_set_version"`
	AssessmentID    string                 `json:"assessment_id,omitempty"`
	HostFingerprint string                 `json:"host_fingerprint,omitempty"`
	AssessedAt      time.Time              `json:"assessed_at"`
	ScanState       scan.State             `json:"scan_state"`
	State           State                  `json:"state"`
	Profile         profile.Descriptor     `json:"profile"`
	RuleDecisions   []profile.RuleDecision `json:"profile_rule_decisions"`
	Selection       selection.Report       `json:"selection"`
	Coverage        Coverage               `json:"coverage"`
	Summary         Counts                 `json:"summary"`
	Categories      []CategoryResult       `json:"categories"`
	CISInspired     cisalign.Result        `json:"cis_inspired_mapping"`
	Suppressions    suppression.Report     `json:"suppressions"`
}

// ValidateEngineContract verifies that every built-in assessment profile can
// deterministically project the complete implemented rule catalog into baseline
// evaluation with no hidden rule loss.
func ValidateEngineContract() error {
	rules := assessment.ImplementedRules()
	if len(rules) == 0 {
		return fmt.Errorf("baseline engine requires at least one implemented rule")
	}
	for _, descriptor := range profile.Catalog() {
		applied, err := profile.Apply(descriptor, rules)
		if err != nil {
			return fmt.Errorf("apply profile %s: %w", descriptor.Name, err)
		}
		selected, err := selection.Apply(applied.Rules, selection.Request{Severity: assessment.SeverityInfo})
		if err != nil {
			return fmt.Errorf("select complete baseline for profile %s: %w", descriptor.Name, err)
		}
		if selected.Report.Summary.Total != len(rules) || selected.Report.Summary.Selected != len(rules) || selected.Report.Summary.Skipped != 0 || selected.Report.Summary.Suppressed != 0 {
			return fmt.Errorf("profile %s baseline coverage is incomplete: total=%d selected=%d skipped=%d suppressed=%d want=%d", descriptor.Name, selected.Report.Summary.Total, selected.Report.Summary.Selected, selected.Report.Summary.Skipped, selected.Report.Summary.Suppressed, len(rules))
		}
	}
	return nil
}

// Build converts one completed Chimera assessment into a deterministic,
// profile-aware baseline view. It does not recollect evidence or mutate the
// assessment: every baseline state is derived from the exact findings produced
// by the scan's selected rules.
func Build(in scan.Result) (Result, error) {
	if in.AssessedAt.IsZero() {
		return Result{}, fmt.Errorf("baseline requires a non-zero assessment timestamp")
	}
	if strings.TrimSpace(in.Profile.Descriptor.Name) == "" {
		return Result{}, fmt.Errorf("baseline requires an applied profile")
	}
	if in.Selection.Schema != selection.SchemaVersion {
		return Result{}, fmt.Errorf("baseline requires selection schema %s, got %q", selection.SchemaVersion, in.Selection.Schema)
	}
	if err := assessment.ValidateAll(in.Findings); err != nil {
		return Result{}, fmt.Errorf("validate baseline findings: %w", err)
	}

	selected := make(map[string]selection.Decision, in.Selection.Summary.Selected)
	for _, d := range in.Selection.Decisions {
		if d.Outcome == selection.OutcomeSelected {
			selected[strings.ToUpper(strings.TrimSpace(d.RuleID))] = d
		}
	}
	if len(selected) != in.Selection.Summary.Selected {
		return Result{}, fmt.Errorf("selection selected-count mismatch: summary=%d decisions=%d", in.Selection.Summary.Selected, len(selected))
	}
	byCategory := map[string][]RuleResult{}
	seen := make(map[string]struct{}, len(in.Findings))
	for _, f := range in.Findings {
		key := strings.ToUpper(strings.TrimSpace(f.RuleID))
		if _, ok := selected[key]; !ok {
			return Result{}, fmt.Errorf("finding %s from unselected rule %s", f.ID, f.RuleID)
		}
		if _, ok := seen[key]; ok {
			return Result{}, fmt.Errorf("multiple baseline findings produced for rule %s", f.RuleID)
		}
		seen[key] = struct{}{}
		category := strings.ToLower(strings.TrimSpace(f.Category))
		byCategory[category] = append(byCategory[category], RuleResult{
			RuleID: f.RuleID, FindingID: f.ID, Title: f.Title, Category: category,
			State: stateForFinding(f), Status: f.Status, Applicability: f.Applicability,
			Severity: f.Severity, Confidence: f.Confidence, AffectedObject: f.AffectedObject,
			ObservedState: f.ObservedState, ExpectedState: f.ExpectedState, Suppression: f.Suppression,
			Suppressions: append([]assessment.SuppressionRecord(nil), f.Suppressions...),
		})
	}
	implemented := make(map[string]assessment.Rule)
	for _, rule := range assessment.ImplementedRules() {
		implemented[strings.ToUpper(strings.TrimSpace(rule.ID))] = rule
	}
	categoryReasons := make(map[string]string)
	for _, category := range in.Categories {
		if category.NotEvaluatedRules > 0 && strings.TrimSpace(category.Reason) != "" {
			categoryReasons[strings.ToLower(strings.TrimSpace(category.Name))] = strings.TrimSpace(category.Reason)
		}
	}
	for ruleID, decision := range selected {
		if _, ok := seen[ruleID]; ok {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(decision.Category))
		rr := RuleResult{
			RuleID: ruleID, Title: ruleID, Category: category, State: StateNotEvaluated,
			Severity: decision.Severity, Suppression: assessment.SuppressionActive,
			Reason: "selected rule was not evaluated in the source assessment",
		}
		if rule, ok := implemented[ruleID]; ok {
			rr.RuleID = rule.ID
			rr.Title = rule.Title
			rr.Category = strings.ToLower(strings.TrimSpace(rule.Category))
			rr.Severity = rule.Severity
			rr.AffectedObject = rule.AffectedObject
			rr.ExpectedState = rule.ExpectedState
		}
		if reason := categoryReasons[rr.Category]; reason != "" {
			rr.Reason = reason
		}
		byCategory[rr.Category] = append(byCategory[rr.Category], rr)
	}

	categoryNames := make([]string, 0, len(byCategory))
	for category := range byCategory {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)
	categories := make([]CategoryResult, 0, len(categoryNames))
	total := Counts{}
	for _, category := range categoryNames {
		rules := byCategory[category]
		sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
		counts := countRules(rules)
		categories = append(categories, CategoryResult{Name: category, State: stateForCounts(counts), Counts: counts, Rules: rules})
		total = addCounts(total, counts)
	}

	cisInspired, err := cisalign.Evaluate(in.Findings, assessment.ImplementedRules())
	if err != nil {
		return Result{}, fmt.Errorf("build CIS-inspired control mapping: %w", err)
	}

	coverage := Coverage{
		Total: in.Selection.Summary.Total, Selected: in.Selection.Summary.Selected,
		Skipped: in.Selection.Summary.Skipped, Suppressed: in.Selection.Summary.Suppressed,
		Evaluated: total.Total - total.NotEvaluated, NotEvaluated: total.NotEvaluated,
	}
	if coverage.Selected == 0 {
		coverage.EvaluationPercent = 100
	} else {
		coverage.EvaluationPercent = (float64(coverage.Evaluated) / float64(coverage.Selected)) * 100
	}
	selectionFull := coverage.Selected == coverage.Total && coverage.Skipped == 0 && coverage.Suppressed == 0
	executionFull := coverage.NotEvaluated == 0 && coverage.Evaluated == coverage.Selected
	switch {
	case selectionFull && executionFull:
		coverage.State = "FULL"
		coverage.Reason = "all profile-adjusted selected rules were evaluated"
	case !executionFull && !selectionFull:
		coverage.State = "PARTIAL"
		coverage.Reason = "selection limited rule scope and some selected rules were not evaluated"
	case !executionFull:
		coverage.State = "PARTIAL"
		coverage.Reason = "some selected rules were not evaluated"
	default:
		coverage.State = "PARTIAL"
		coverage.Reason = "active severity/category/include/exclude selection limited baseline coverage"
	}

	out := Result{
		Schema: SchemaVersion, EngineVersion: EngineVersion, RuleSetVersion: assessment.RuleSetVersion,
		AssessmentID: in.Snapshot.AssessmentID, HostFingerprint: in.Snapshot.HostFingerprint.Value,
		AssessedAt: in.AssessedAt, ScanState: in.State, State: stateForCounts(total),
		Profile: in.Profile.Descriptor, RuleDecisions: append([]profile.RuleDecision(nil), in.Profile.RuleDecisions...),
		Selection: in.Selection, Coverage: coverage, Summary: total, Categories: categories, CISInspired: cisInspired, Suppressions: in.Suppressions,
	}
	return out, nil
}

func stateForFinding(f assessment.Finding) State {
	if f.Applicability == assessment.NotApplicable {
		return StateNotApplicable
	}
	switch f.Status {
	case assessment.StatusPass:
		return StatePass
	case assessment.StatusWarn:
		return StateWarn
	case assessment.StatusFail:
		return StateFail
	case assessment.StatusUnknown:
		return StateUnknown
	default:
		return StateUnknown
	}
}

func countRules(rules []RuleResult) Counts {
	c := Counts{Total: len(rules)}
	for _, r := range rules {
		if r.Suppression == assessment.SuppressionSuppressed {
			c.Suppressed++
		}
		switch r.State {
		case StateNotEvaluated:
			c.NotEvaluated++
		case StateNotApplicable:
			c.NotApplicable++
		case StatePass:
			c.Applicable++
			c.Pass++
		case StateWarn:
			c.Applicable++
			c.Warn++
		case StateFail:
			c.Applicable++
			c.Fail++
		case StateUnknown:
			c.Applicable++
			c.Unknown++
		}
	}
	return c
}

func addCounts(a, b Counts) Counts {
	return Counts{
		Total: a.Total + b.Total, Applicable: a.Applicable + b.Applicable,
		Pass: a.Pass + b.Pass, Warn: a.Warn + b.Warn, Fail: a.Fail + b.Fail,
		Unknown: a.Unknown + b.Unknown, NotApplicable: a.NotApplicable + b.NotApplicable, NotEvaluated: a.NotEvaluated + b.NotEvaluated, Suppressed: a.Suppressed + b.Suppressed,
	}
}

func stateForCounts(c Counts) State {
	if c.Fail > 0 {
		return StateFail
	}
	if c.Warn > 0 {
		return StateWarn
	}
	if c.Unknown > 0 {
		return StateUnknown
	}
	if c.NotEvaluated > 0 {
		return StateNotEvaluated
	}
	if c.Pass > 0 {
		return StatePass
	}
	if c.NotApplicable > 0 {
		return StateNotApplicable
	}
	return StateNotEvaluated
}
