package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/cli"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/render"
	"github.com/Nikolov999/chimera/internal/scan"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/version"
)

const (
	workflowViewSchema = "chimera.workflow-view/v1"
	summaryViewSchema  = "chimera.summary-view/v1"
	ruleCatalogSchema  = "chimera.rule-catalog/v1"
)

type workflowAssessmentView struct {
	Schema       string                `json:"schema"`
	View         string                `json:"view"`
	Description  string                `json:"description"`
	AssessmentID string                `json:"assessment_id"`
	State        scan.State            `json:"state"`
	Profile      profile.Descriptor    `json:"profile"`
	Selection    selection.Report      `json:"selection"`
	Categories   []scan.CategoryResult `json:"categories"`
	Findings     []assessment.Finding  `json:"findings"`
	Priorities   prioritization.Result `json:"prioritization"`
	Suppressions suppression.Report    `json:"suppressions"`
}

type summaryView struct {
	Schema       string                           `json:"schema"`
	AssessmentID string                           `json:"assessment_id"`
	State        scan.State                       `json:"state"`
	Profile      profile.Descriptor               `json:"profile"`
	Summary      scan.Summary                     `json:"summary"`
	Collection   scan.CollectionResult            `json:"collection"`
	TopPriority  []prioritization.FindingPriority `json:"top_priority_findings"`
	TopFindings  []assessment.Finding             `json:"top_findings"`
	Suppressions suppression.Report               `json:"suppressions"`
	Limitations  []string                         `json:"limitations,omitempty"`
}

type ruleCatalogEntry struct {
	RuleID            string                 `json:"rule_id"`
	Title             string                 `json:"title"`
	Category          string                 `json:"category"`
	BaseSeverity      assessment.Severity    `json:"base_severity"`
	EffectiveSeverity assessment.Severity    `json:"effective_severity"`
	Applicable        bool                   `json:"applicable"`
	Selected          bool                   `json:"selected"`
	SelectionOutcome  selection.Outcome      `json:"selection_outcome"`
	AffectedObject    string                 `json:"affected_object"`
	ExpectedState     string                 `json:"expected_state"`
	Risk              string                 `json:"risk"`
	Remediation       string                 `json:"remediation"`
	References        []assessment.Reference `json:"references,omitempty"`
}

type ruleCatalogView struct {
	Schema         string             `json:"schema"`
	RuleSetVersion string             `json:"rule_set_version"`
	Profile        profile.Descriptor `json:"profile"`
	Selection      selection.Report   `json:"selection"`
	Total          int                `json:"total"`
	Selected       int                `json:"selected"`
	Applicable     int                `json:"applicable"`
	Entries        []ruleCatalogEntry `json:"rules"`
}

var workflowScopes = map[string]struct {
	Description string
	Categories  []string
}{
	"exposure": {
		Description: "Externally or broadly reachable host exposure, local firewall coverage, service surfaces, container/developer endpoints, and cross-domain exposure correlations.",
		Categories:  []string{"network", "firewall", "service", "containers", "correlation"},
	},
	"hardening": {
		Description: "Security-control and trust-boundary hardening posture across kernel, runtime, services, identity, network, filesystems, storage, containers, persistence, and secret storage.",
		Categories:  []string{"kernel", "process", "service", "identity", "network", "firewall", "filesystem", "storage", "containers", "persistence", "secrets", "correlation"},
	},
	"misconfigurations": {
		Description: "Configuration weaknesses in services, schedulers, firewall, authentication, filesystems, storage, containers, persistence, and secret-storage boundaries.",
		Categories:  []string{"service", "scheduled", "firewall", "identity", "filesystem", "storage", "containers", "persistence", "secrets", "correlation"},
	},
	"relationships": {
		Description: "Cross-domain relationships proven by composite evidence joins rather than loose textual matching.",
		Categories:  []string{"correlation"},
	},
	"surface": {
		Description: "Consolidated local attack-surface assessment covering listeners, service exposure, firewall coverage, container/developer interfaces, and correlated exposure paths.",
		Categories:  []string{"network", "firewall", "service", "containers", "correlation"},
	},
}

func runExposure(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	return runWorkflowView(ctx, w, opts, rt, "exposure")
}

func runHardening(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	return runWorkflowView(ctx, w, opts, rt, "hardening")
}

func runMisconfigurations(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	return runWorkflowView(ctx, w, opts, rt, "misconfigurations")
}

func runRelationships(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	return runWorkflowView(ctx, w, opts, rt, "relationships")
}

func runSurface(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	return runWorkflowView(ctx, w, opts, rt, "surface")
}

func runWorkflowView(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime, name string) error {
	result, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return fmt.Errorf("run %s assessment: %w", name, err)
	}
	view, err := buildWorkflowView(result, name)
	if err != nil {
		return err
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: name, Version: version.Current(), Data: view})
	}
	renderWorkflowViewHuman(w, view, opts.Verbose)
	return nil
}

func buildWorkflowView(result scan.Result, name string) (workflowAssessmentView, error) {
	scope, ok := workflowScopes[name]
	if !ok {
		return workflowAssessmentView{}, fmt.Errorf("unknown workflow view %q", name)
	}
	allowed := make(map[string]struct{}, len(scope.Categories))
	for _, category := range scope.Categories {
		allowed[category] = struct{}{}
	}
	categories := make([]scan.CategoryResult, 0, len(result.Categories))
	for _, category := range result.Categories {
		if _, ok := allowed[category.Name]; ok {
			categories = append(categories, category)
		}
	}
	findings := make([]assessment.Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if _, ok := allowed[finding.Category]; ok {
			findings = append(findings, finding)
		}
	}
	assessment.SortFindings(findings)
	priorities := prioritization.Compute(findings, nil)
	if err := priorities.Validate(); err != nil {
		return workflowAssessmentView{}, fmt.Errorf("validate %s priorities: %w", name, err)
	}
	return workflowAssessmentView{
		Schema: workflowViewSchema, View: name, Description: scope.Description,
		AssessmentID: result.Snapshot.AssessmentID, State: result.State,
		Profile: result.Profile.Descriptor, Selection: result.Selection,
		Categories: categories, Findings: findings, Priorities: priorities,
		Suppressions: result.Suppressions,
	}, nil
}

func runSummary(ctx context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	result, err := executeFullAssessment(ctx, opts, rt)
	if err != nil {
		return fmt.Errorf("run summary assessment: %w", err)
	}
	data := buildSummaryView(result, 10)
	if opts.JSON {
		return render.JSON(w, envelope{Command: "summary", Version: version.Current(), Data: data})
	}
	renderSummaryViewHuman(w, data, opts.Verbose)
	return nil
}

func buildSummaryView(result scan.Result, limit int) summaryView {
	if limit < 1 {
		limit = 10
	}
	priorities := []prioritization.FindingPriority{}
	if result.Prioritization != nil {
		for _, p := range result.Prioritization.Findings {
			if !p.Actionable || p.Score <= 0 {
				continue
			}
			priorities = append(priorities, p)
			if len(priorities) == limit {
				break
			}
		}
	}
	byID := make(map[string]assessment.Finding, len(result.Findings))
	for _, f := range result.Findings {
		byID[f.ID] = f
	}
	topFindings := make([]assessment.Finding, 0, len(priorities))
	for _, p := range priorities {
		if f, ok := byID[p.FindingID]; ok {
			topFindings = append(topFindings, f)
		}
	}
	limitations := append([]string(nil), result.Collection.DegradationReasons...)
	if len(limitations) > 20 {
		limitations = limitations[:20]
	}
	return summaryView{
		Schema: summaryViewSchema, AssessmentID: result.Snapshot.AssessmentID,
		State: result.State, Profile: result.Profile.Descriptor,
		Summary: result.Summary, Collection: result.Collection,
		TopPriority: priorities, TopFindings: topFindings,
		Suppressions: result.Suppressions, Limitations: limitations,
	}
}

func runRules(_ context.Context, w io.Writer, opts cli.Options, rt Runtime) error {
	data, err := buildRuleCatalogView(opts, rt)
	if err != nil {
		return err
	}
	if opts.JSON {
		return render.JSON(w, envelope{Command: "rules", Version: version.Current(), Data: data})
	}
	renderRuleCatalogHuman(w, data, opts.Verbose)
	return nil
}

func buildRuleCatalogView(opts cli.Options, rt Runtime) (ruleCatalogView, error) {
	applied, err := appliedProfile(rt)
	if err != nil {
		return ruleCatalogView{}, fmt.Errorf("apply assessment profile: %w", err)
	}
	selected, err := appliedSelection(applied, opts)
	if err != nil {
		return ruleCatalogView{}, fmt.Errorf("apply rule selection: %w", err)
	}
	profileDecisions := make(map[string]profile.RuleDecision, len(applied.Decisions))
	for _, d := range applied.Decisions {
		profileDecisions[d.RuleID] = d
	}
	selectionDecisions := make(map[string]selection.Decision, len(selected.Report.Decisions))
	for _, d := range selected.Report.Decisions {
		selectionDecisions[d.RuleID] = d
	}
	rules := assessment.ImplementedRules()
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	data := ruleCatalogView{
		Schema: ruleCatalogSchema, RuleSetVersion: assessment.RuleSetVersion,
		Profile: applied.Profile, Selection: selected.Report, Total: len(rules),
		Entries: make([]ruleCatalogEntry, 0, len(rules)),
	}
	for _, rule := range rules {
		pd := profileDecisions[rule.ID]
		sd := selectionDecisions[rule.ID]
		entry := ruleCatalogEntry{
			RuleID: rule.ID, Title: rule.Title, Category: rule.Category,
			BaseSeverity: rule.Severity, EffectiveSeverity: pd.EffectiveSeverity,
			Applicable: pd.Applicable, Selected: sd.Outcome == selection.OutcomeSelected,
			SelectionOutcome: sd.Outcome, AffectedObject: rule.AffectedObject,
			ExpectedState: rule.ExpectedState, Risk: rule.Risk, Remediation: rule.Remediation,
			References: append([]assessment.Reference(nil), rule.References...),
		}
		if entry.Applicable {
			data.Applicable++
		}
		if entry.Selected {
			data.Selected++
		}
		data.Entries = append(data.Entries, entry)
	}
	return data, nil
}

func renderWorkflowViewHuman(w io.Writer, view workflowAssessmentView, verbose bool) {
	fmt.Fprintf(w, "%s\n", strings.ToUpper(view.View))
	fmt.Fprintf(w, "  Assessment ID      %s\n", display(view.AssessmentID))
	fmt.Fprintf(w, "  State              %s\n", view.State)
	fmt.Fprintf(w, "  Profile            %s\n", display(view.Profile.Name))
	fmt.Fprintf(w, "  Categories         %d\n", len(view.Categories))
	fmt.Fprintf(w, "  Findings           %d\n", len(view.Findings))
	fmt.Fprintf(w, "  Purpose            %s\n", view.Description)
	render.PrioritizationHuman(w, view.Priorities, verbose)
	if len(view.Findings) > 0 {
		fmt.Fprintln(w)
		render.FindingsHuman(w, view.Findings, verbose)
	}
}

func renderSummaryViewHuman(w io.Writer, view summaryView, verbose bool) {
	fmt.Fprintln(w, "SUMMARY")
	fmt.Fprintf(w, "  Assessment ID      %s\n", display(view.AssessmentID))
	fmt.Fprintf(w, "  State              %s\n", view.State)
	fmt.Fprintf(w, "  Profile            %s\n", display(view.Profile.Name))
	fmt.Fprintf(w, "  Findings           %d (FAIL %d / WARN %d / UNKNOWN %d / PASS %d)\n",
		view.Summary.Findings.Total, view.Summary.Findings.Fail, view.Summary.Findings.Warn,
		view.Summary.Findings.Unknown, view.Summary.Findings.Pass)
	fmt.Fprintf(w, "  Evidence           %d total / %d degraded / %d denied / %d unavailable\n",
		view.Summary.Evidence.Total, view.Summary.Evidence.Degraded,
		view.Summary.Evidence.Denied, view.Summary.Evidence.Unavailable)
	fmt.Fprintf(w, "  Suppressed         %d\n", view.Summary.Findings.Suppressed)
	if len(view.TopPriority) > 0 {
		fmt.Fprintln(w, "\nTOP PRIORITIES")
		for _, p := range view.TopPriority {
			fmt.Fprintf(w, "  #%d %-12s score=%3d band=%-8s severity=%-8s rule=%s\n",
				p.Rank, p.FindingID, p.Score, p.Band, p.Severity, p.RuleID)
		}
	}
	if verbose && len(view.Limitations) > 0 {
		fmt.Fprintln(w, "\nLIMITATIONS")
		for _, limitation := range view.Limitations {
			fmt.Fprintln(w, "  - "+limitation)
		}
	}
}

func renderRuleCatalogHuman(w io.Writer, view ruleCatalogView, verbose bool) {
	fmt.Fprintln(w, "RULES")
	fmt.Fprintf(w, "  Rule set           %s\n", view.RuleSetVersion)
	fmt.Fprintf(w, "  Profile            %s\n", view.Profile.Name)
	fmt.Fprintf(w, "  Total              %d\n", view.Total)
	fmt.Fprintf(w, "  Applicable         %d\n", view.Applicable)
	fmt.Fprintf(w, "  Selected           %d\n", view.Selected)
	for _, rule := range view.Entries {
		state := string(rule.SelectionOutcome)
		if state == "" {
			state = "UNKNOWN"
		}
		fmt.Fprintf(w, "  %-15s %-12s %-8s %-12s %s\n", rule.RuleID, rule.Category, rule.EffectiveSeverity, state, rule.Title)
		if verbose {
			fmt.Fprintf(w, "      affected: %s\n", rule.AffectedObject)
			fmt.Fprintf(w, "      expected: %s\n", rule.ExpectedState)
			fmt.Fprintf(w, "      risk: %s\n", rule.Risk)
			fmt.Fprintf(w, "      remediation: %s\n", rule.Remediation)
		}
	}
}
