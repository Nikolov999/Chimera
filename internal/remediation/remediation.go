package remediation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/prioritization"
)

const (
	SchemaVersion = "chimera.remediation/v1"
	EngineVersion = "remediation/phase114-v1"
)

type Action struct {
	FindingID      string              `json:"finding_id"`
	RuleID         string              `json:"rule_id"`
	Title          string              `json:"title"`
	Status         assessment.Status   `json:"status"`
	RawSeverity    assessment.Severity `json:"raw_severity"`
	Confidence     evidence.Confidence `json:"confidence"`
	PriorityScore  int                 `json:"priority_score"`
	PriorityBand   prioritization.Band `json:"priority_band"`
	PriorityRank   int                 `json:"priority_rank"`
	Category       string              `json:"category"`
	AffectedObject string              `json:"affected_object"`
	Risk           string              `json:"risk"`
	Guidance       string              `json:"guidance"`
	Verification   string              `json:"verification"`
	EvidenceKeys   []string            `json:"evidence_keys,omitempty"`
}

type ComponentGroup struct {
	AffectedObject string   `json:"affected_object"`
	Actions        []Action `json:"actions"`
}

type CategoryGroup struct {
	Category   string           `json:"category"`
	Components []ComponentGroup `json:"components"`
}

type PriorityGroup struct {
	Band       prioritization.Band `json:"band"`
	Categories []CategoryGroup     `json:"categories"`
}

type Summary struct {
	Findings           int `json:"findings"`
	Actions            int `json:"actions"`
	NeedsEvidence      int `json:"needs_evidence"`
	Suppressed         int `json:"suppressed"`
	CriticalActions    int `json:"critical_actions"`
	HighActions        int `json:"high_actions"`
	MediumActions      int `json:"medium_actions"`
	LowActions         int `json:"low_actions"`
	Categories         int `json:"categories"`
	AffectedComponents int `json:"affected_components"`
}

type EvaluationCoverage struct {
	SelectedRules     int     `json:"selected_rules"`
	EvaluatedRules    int     `json:"evaluated_rules"`
	NotEvaluatedRules int     `json:"not_evaluated_rules"`
	Percent           float64 `json:"evaluation_percent"`
	Complete          bool    `json:"complete"`
}

type Result struct {
	Schema        string             `json:"schema"`
	EngineVersion string             `json:"engine_version"`
	Safety        string             `json:"safety"`
	Evaluation    EvaluationCoverage `json:"evaluation"`
	Summary       Summary            `json:"summary"`
	Groups        []PriorityGroup    `json:"groups"`
	Actions       []Action           `json:"actions"`
}

// Build creates a deterministic, read-only remediation view from already
// evaluated findings and the priority result. It never executes the
// guidance, changes host state, or converts UNKNOWN evidence into a fix.
func Build(findings []assessment.Finding, priority prioritization.Result, coverage ...EvaluationCoverage) (Result, error) {
	if err := priority.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate prioritization: %w", err)
	}
	eval := EvaluationCoverage{Percent: 100, Complete: true}
	if len(coverage) > 0 {
		eval = coverage[0]
	}
	out := Result{
		Schema:        SchemaVersion,
		EngineVersion: EngineVersion,
		Safety:        "guidance only; Chimera does not apply changes, execute remediation commands, restart services, install updates, or mutate host state",
		Evaluation:    eval,
		Groups:        []PriorityGroup{},
		Actions:       []Action{},
	}
	out.Summary.Findings = len(findings)

	priorityByFinding := make(map[string]prioritization.FindingPriority, len(priority.Findings))
	for _, p := range priority.Findings {
		priorityByFinding[p.FindingID] = p
	}

	for _, f := range findings {
		if f.Suppression == assessment.SuppressionSuppressed {
			out.Summary.Suppressed++
			continue
		}
		if f.Status == assessment.StatusUnknown {
			out.Summary.NeedsEvidence++
			continue
		}
		if f.Status != assessment.StatusFail && f.Status != assessment.StatusWarn {
			continue
		}
		p, ok := priorityByFinding[f.ID]
		if !ok {
			return Result{}, fmt.Errorf("finding %q has no priority record", f.ID)
		}
		if !p.Actionable || p.Rank < 1 || p.Score < 1 {
			return Result{}, fmt.Errorf("active finding %q has invalid actionable priority", f.ID)
		}
		guidance := strings.TrimSpace(f.Remediation)
		if guidance == "" {
			return Result{}, fmt.Errorf("finding %q has empty remediation guidance", f.ID)
		}
		a := Action{
			FindingID:      f.ID,
			RuleID:         f.RuleID,
			Title:          f.Title,
			Status:         f.Status,
			RawSeverity:    f.Severity,
			Confidence:     f.Confidence,
			PriorityScore:  p.Score,
			PriorityBand:   p.Band,
			PriorityRank:   p.Rank,
			Category:       stableLabel(f.Category, "uncategorized"),
			AffectedObject: stableLabel(f.AffectedObject, "unspecified"),
			Risk:           strings.TrimSpace(f.Risk),
			Guidance:       guidance,
			Verification:   fmt.Sprintf("After an approved change, rerun Chimera and confirm rule %s no longer returns %s/WARN for this object; preserve evidence before and after the change.", f.RuleID, assessment.StatusFail),
			EvidenceKeys:   evidenceKeys(f.Evidence),
		}
		out.Actions = append(out.Actions, a)
		switch a.PriorityBand {
		case prioritization.BandCritical:
			out.Summary.CriticalActions++
		case prioritization.BandHigh:
			out.Summary.HighActions++
		case prioritization.BandMedium:
			out.Summary.MediumActions++
		case prioritization.BandLow:
			out.Summary.LowActions++
		}
	}

	sortActions(out.Actions)
	out.Groups = groupActions(out.Actions)
	out.Summary.Actions = len(out.Actions)
	categories := map[string]struct{}{}
	components := map[string]struct{}{}
	for _, a := range out.Actions {
		categories[a.Category] = struct{}{}
		components[a.Category+"\x00"+a.AffectedObject] = struct{}{}
	}
	out.Summary.Categories = len(categories)
	out.Summary.AffectedComponents = len(components)
	if err := out.Validate(); err != nil {
		return Result{}, err
	}
	return out, nil
}

func stableLabel(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func evidenceKeys(refs []assessment.EvidenceRef) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		key := strings.TrimSpace(ref.Key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortActions(actions []Action) {
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].PriorityRank != actions[j].PriorityRank {
			return actions[i].PriorityRank < actions[j].PriorityRank
		}
		if actions[i].Category != actions[j].Category {
			return actions[i].Category < actions[j].Category
		}
		if actions[i].AffectedObject != actions[j].AffectedObject {
			return actions[i].AffectedObject < actions[j].AffectedObject
		}
		if actions[i].RuleID != actions[j].RuleID {
			return actions[i].RuleID < actions[j].RuleID
		}
		return actions[i].FindingID < actions[j].FindingID
	})
}

func groupActions(actions []Action) []PriorityGroup {
	groups := []PriorityGroup{}
	bandIndex := map[prioritization.Band]int{}
	categoryIndex := map[string]int{}
	componentIndex := map[string]int{}
	for _, a := range actions {
		bi, ok := bandIndex[a.PriorityBand]
		if !ok {
			bi = len(groups)
			groups = append(groups, PriorityGroup{Band: a.PriorityBand, Categories: []CategoryGroup{}})
			bandIndex[a.PriorityBand] = bi
		}
		catKey := string(a.PriorityBand) + "\x00" + a.Category
		ci, ok := categoryIndex[catKey]
		if !ok {
			ci = len(groups[bi].Categories)
			groups[bi].Categories = append(groups[bi].Categories, CategoryGroup{Category: a.Category, Components: []ComponentGroup{}})
			categoryIndex[catKey] = ci
		}
		componentKey := catKey + "\x00" + a.AffectedObject
		coi, ok := componentIndex[componentKey]
		if !ok {
			coi = len(groups[bi].Categories[ci].Components)
			groups[bi].Categories[ci].Components = append(groups[bi].Categories[ci].Components, ComponentGroup{AffectedObject: a.AffectedObject, Actions: []Action{}})
			componentIndex[componentKey] = coi
		}
		groups[bi].Categories[ci].Components[coi].Actions = append(groups[bi].Categories[ci].Components[coi].Actions, a)
	}
	return groups
}

func (r Result) Validate() error {
	if r.Schema != SchemaVersion || r.EngineVersion != EngineVersion {
		return fmt.Errorf("unexpected remediation contract %q / %q", r.Schema, r.EngineVersion)
	}
	if r.Groups == nil || r.Actions == nil {
		return fmt.Errorf("remediation collections must be non-nil")
	}
	if r.Evaluation.SelectedRules < 0 || r.Evaluation.EvaluatedRules < 0 || r.Evaluation.NotEvaluatedRules < 0 || r.Evaluation.Percent < 0 || r.Evaluation.Percent > 100 {
		return fmt.Errorf("remediation evaluation coverage is invalid")
	}
	if r.Evaluation.SelectedRules > 0 && r.Evaluation.EvaluatedRules+r.Evaluation.NotEvaluatedRules != r.Evaluation.SelectedRules {
		return fmt.Errorf("remediation evaluation coverage does not account for selected rules")
	}
	if r.Evaluation.Complete && r.Evaluation.NotEvaluatedRules != 0 {
		return fmt.Errorf("remediation evaluation cannot be complete with NOT_EVALUATED rules")
	}
	if r.Summary.Actions != len(r.Actions) {
		return fmt.Errorf("remediation action count is inconsistent")
	}
	seen := map[string]struct{}{}
	lastRank := 0
	for i, a := range r.Actions {
		if a.FindingID == "" || a.RuleID == "" || a.Title == "" || a.Category == "" || a.AffectedObject == "" || a.Guidance == "" || a.Verification == "" {
			return fmt.Errorf("incomplete remediation action at index %d", i)
		}
		if a.Status != assessment.StatusFail && a.Status != assessment.StatusWarn {
			return fmt.Errorf("remediation action %q is not FAIL/WARN", a.FindingID)
		}
		if a.PriorityRank < 1 || a.PriorityScore < 1 || a.PriorityBand == prioritization.BandNone {
			return fmt.Errorf("remediation action %q has invalid priority", a.FindingID)
		}
		if a.PriorityRank <= lastRank {
			return fmt.Errorf("remediation actions are not in strict actionable priority order")
		}
		lastRank = a.PriorityRank
		if _, ok := seen[a.FindingID]; ok {
			return fmt.Errorf("duplicate remediation finding %q", a.FindingID)
		}
		seen[a.FindingID] = struct{}{}
	}
	grouped := 0
	for _, pg := range r.Groups {
		if pg.Band == prioritization.BandNone || len(pg.Categories) == 0 {
			return fmt.Errorf("invalid empty remediation priority group")
		}
		for _, cg := range pg.Categories {
			if cg.Category == "" || len(cg.Components) == 0 {
				return fmt.Errorf("invalid remediation category group")
			}
			for _, og := range cg.Components {
				if og.AffectedObject == "" || len(og.Actions) == 0 {
					return fmt.Errorf("invalid remediation component group")
				}
				grouped += len(og.Actions)
			}
		}
	}
	if grouped != len(r.Actions) {
		return fmt.Errorf("remediation grouped action count %d does not match flat count %d", grouped, len(r.Actions))
	}
	return nil
}

// ValidateEngineContract checks grouping, prioritization linkage, suppression,
// UNKNOWN handling, and guidance preservation without collecting host evidence.
func ValidateEngineContract() error {
	now := assessmentTimestamp()
	findings := []assessment.Finding{
		{ID: "F-HIGH", RuleID: "CHM-COR-001", Title: "high", Status: assessment.StatusFail, Severity: assessment.SeverityHigh, Confidence: evidence.ConfidenceHigh, Category: "service", Platform: "test", AffectedObject: "service.demo", ObservedState: "weak", ExpectedState: "hardened", Risk: "risk", Remediation: "Harden the service boundary.", CollectionSource: "test", FirstObserved: now, AssessmentTimestamp: now, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive},
		{ID: "F-UNKNOWN", RuleID: "CHM-TEST-002", Title: "unknown", Status: assessment.StatusUnknown, Severity: assessment.SeverityMedium, Confidence: evidence.ConfidenceLow, Category: "kernel", Platform: "test", AffectedObject: "kernel.demo", ObservedState: "unknown", ExpectedState: "hardened", Risk: "risk", Remediation: "Collect evidence first.", CollectionSource: "test", FirstObserved: now, AssessmentTimestamp: now, Applicability: assessment.Applicable, Suppression: assessment.SuppressionActive},
	}
	priority := prioritization.Compute(findings, nil)
	out, err := Build(findings, priority)
	if err != nil {
		return err
	}
	if out.Summary.Actions != 1 || out.Summary.NeedsEvidence != 1 || len(out.Groups) != 1 || out.Actions[0].FindingID != "F-HIGH" {
		return fmt.Errorf("unexpected remediation contract result: %#v", out.Summary)
	}
	return out.Validate()
}

func assessmentTimestamp() time.Time { return time.Unix(1700000000, 0).UTC() }
