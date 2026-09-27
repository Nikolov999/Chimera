package scan

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/assessment"
	containerinv "github.com/Nikolov999/chimera/internal/containers"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/evidencequality"
	"github.com/Nikolov999/chimera/internal/filesystem"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/kernel"
	"github.com/Nikolov999/chimera/internal/lifecycle"
	netinv "github.com/Nikolov999/chimera/internal/network"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/persistence"
	"github.com/Nikolov999/chimera/internal/prioritization"
	"github.com/Nikolov999/chimera/internal/processes"
	"github.com/Nikolov999/chimera/internal/productnorm"
	"github.com/Nikolov999/chimera/internal/profile"
	"github.com/Nikolov999/chimera/internal/reliability"
	"github.com/Nikolov999/chimera/internal/remediation"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
	"github.com/Nikolov999/chimera/internal/scheduled"
	secretinv "github.com/Nikolov999/chimera/internal/secrets"
	"github.com/Nikolov999/chimera/internal/selection"
	"github.com/Nikolov999/chimera/internal/services"
	"github.com/Nikolov999/chimera/internal/snapshot"
	"github.com/Nikolov999/chimera/internal/software"
	"github.com/Nikolov999/chimera/internal/storage"
	"github.com/Nikolov999/chimera/internal/suppression"
	"github.com/Nikolov999/chimera/internal/updateposture"
	"github.com/Nikolov999/chimera/internal/vulnerability"
)

// SchemaVersion identifies the full-scan orchestration contract.
const SchemaVersion = "chimera.scan/v1"

type State string

const (
	StateComplete      State = "COMPLETE"
	StateDegraded      State = "DEGRADED"
	StatePartial       State = "PARTIAL"
	StateNotApplicable State = "NOT_APPLICABLE"
	StateSkipped       State = "SKIPPED"
)

type Timing struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	DurationMS  float64   `json:"duration_ms"`
}

type EvidenceCounts struct {
	Total         int `json:"total"`
	Observed      int `json:"observed"`
	Degraded      int `json:"degraded"`
	Denied        int `json:"denied"`
	Unavailable   int `json:"unavailable"`
	Unsupported   int `json:"unsupported"`
	NotApplicable int `json:"not_applicable"`
}

type FindingCounts struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Warn          int `json:"warn"`
	Fail          int `json:"fail"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"not_applicable"`
	Suppressed    int `json:"suppressed"`
}

type ProviderBudgetTelemetry struct {
	Class             string  `json:"class"`
	RequestedMS       float64 `json:"requested_ms"`
	AppliedMS         float64 `json:"applied_ms"`
	ParentRemainingMS float64 `json:"parent_remaining_ms,omitempty"`
	CleanupReserveMS  float64 `json:"cleanup_reserve_ms,omitempty"`
	CappedByParent    bool    `json:"capped_by_parent,omitempty"`
}

// ProviderSchedulingTelemetry exposes Fix44 host-contention decisions without
// changing evidence semantics. Queue wait measures time after dependencies become
// ready but before the collector is admitted to its Windows execution lane.
type ProviderSchedulingTelemetry struct {
	Lane                     string     `json:"lane"`
	LaneLimit                int        `json:"lane_limit"`
	ManagementLimit          int        `json:"management_limit,omitempty"`
	ReadyAt                  *time.Time `json:"ready_at,omitempty"`
	DependencyWaitMS         float64    `json:"dependency_wait_ms,omitempty"`
	QueueWaitMS              float64    `json:"queue_wait_ms"`
	ExecutionStartedAt       *time.Time `json:"execution_started_at,omitempty"`
	ExecutionDurationMS      float64    `json:"execution_duration_ms"`
	DeadlineAt               *time.Time `json:"deadline_at,omitempty"`
	ParentRemainingAtStartMS float64    `json:"parent_remaining_at_start_ms,omitempty"`
	AdmissionMinimumMS       float64    `json:"admission_minimum_ms,omitempty"`
	SkippedBeforeExecution   bool       `json:"skipped_before_execution,omitempty"`
}

type ProviderResult struct {
	Name               string                       `json:"name"`
	State              State                        `json:"state"`
	Timing             Timing                       `json:"timing"`
	Evidence           EvidenceCounts               `json:"evidence"`
	Budget             *ProviderBudgetTelemetry     `json:"budget,omitempty"`
	Scheduling         *ProviderSchedulingTelemetry `json:"scheduling,omitempty"`
	DegradationReasons []string                     `json:"degradation_reasons,omitempty"`
	PanicContained     bool                         `json:"panic_contained"`
	InvalidEvidence    int                          `json:"invalid_evidence"`
	DuplicateEvidence  int                          `json:"duplicate_evidence"`
	Truncated          bool                         `json:"truncated"`
}

type CollectionResult struct {
	State              State            `json:"state"`
	Timing             Timing           `json:"timing"`
	Evidence           EvidenceCounts   `json:"evidence"`
	Providers          []ProviderResult `json:"providers,omitempty"`
	DegradationReasons []string         `json:"degradation_reasons,omitempty"`
}

type CategoryResult struct {
	Name               string        `json:"name"`
	State              State         `json:"state"`
	Timing             Timing        `json:"timing"`
	RuleCount          int           `json:"rule_count"`
	RuleIDs            []string      `json:"rule_ids,omitempty"`
	EvaluatedRules     int           `json:"evaluated_rules"`
	NotEvaluatedRules  int           `json:"not_evaluated_rules"`
	Findings           FindingCounts `json:"findings"`
	FindingIDs         []string      `json:"finding_ids,omitempty"`
	DegradedEvidence   int           `json:"degraded_evidence"`
	DegradationReasons []string      `json:"degradation_reasons,omitempty"`
	Reason             string        `json:"reason,omitempty"`
}

type CategoryCounts struct {
	Total         int `json:"total"`
	Complete      int `json:"complete"`
	Degraded      int `json:"degraded"`
	Skipped       int `json:"skipped"`
	NotApplicable int `json:"not_applicable"`
}

type EvaluationCoverage struct {
	SelectedRules     int      `json:"selected_rules"`
	EvaluatedRules    int      `json:"evaluated_rules"`
	NotEvaluatedRules int      `json:"not_evaluated_rules"`
	Percent           float64  `json:"evaluation_percent"`
	Complete          bool     `json:"complete"`
	Reasons           []string `json:"reasons,omitempty"`
}

type Summary struct {
	Categories   CategoryCounts               `json:"categories"`
	Findings     FindingCounts                `json:"findings"`
	Evidence     EvidenceCounts               `json:"evidence"`
	Evaluation   EvaluationCoverage           `json:"evaluation"`
	UnknownAudit evidencequality.UnknownAudit `json:"unknown_audit"`
}

type ProfileResult struct {
	Descriptor    profile.Descriptor     `json:"descriptor"`
	RuleDecisions []profile.RuleDecision `json:"rule_decisions"`
}

type Result struct {
	Schema                    string                            `json:"scan_schema"`
	EvidenceSchema            string                            `json:"evidence_schema"`
	FindingSchema             string                            `json:"finding_schema"`
	Profile                   ProfileResult                     `json:"profile"`
	Selection                 selection.Report                  `json:"selection"`
	State                     State                             `json:"state"`
	TimedOut                  bool                              `json:"timed_out"`
	Timing                    Timing                            `json:"timing"`
	MaxWorkers                int                               `json:"max_workers"`
	WorkersUsed               int                               `json:"workers_used"`
	Overview                  overview.Overview                 `json:"overview"`
	Kernel                    *kernel.Inventory                 `json:"kernel,omitempty"`
	Software                  *software.Inventory               `json:"software,omitempty"`
	Processes                 *processes.Inventory              `json:"processes,omitempty"`
	Services                  *services.Inventory               `json:"services,omitempty"`
	Scheduled                 *scheduled.Inventory              `json:"scheduled,omitempty"`
	Network                   *netinv.Inventory                 `json:"network,omitempty"`
	Firewall                  *firewall.Inventory               `json:"firewall,omitempty"`
	RemoteManagement          *remotemgmt.Report                `json:"remote_management,omitempty"`
	Accounts                  *accounts.Inventory               `json:"accounts,omitempty"`
	Filesystem                *filesystem.Inventory             `json:"filesystem,omitempty"`
	Storage                   *storage.Inventory                `json:"storage,omitempty"`
	Containers                *containerinv.Inventory           `json:"containers,omitempty"`
	Persistence               *persistence.Inventory            `json:"persistence,omitempty"`
	Secrets                   *secretinv.Inventory              `json:"secrets,omitempty"`
	ProductNormalization      *productnorm.Result               `json:"product_normalization,omitempty"`
	VulnerabilityCorrelation  *vulnerability.Result             `json:"vulnerability_correlation,omitempty"`
	VulnerabilityReachability *vulnerability.ReachabilityResult `json:"vulnerability_reachability,omitempty"`
	Lifecycle                 *lifecycle.Result                 `json:"lifecycle,omitempty"`
	UpdatePosture             *updateposture.Result             `json:"update_posture,omitempty"`
	Prioritization            *prioritization.Result            `json:"prioritization,omitempty"`
	Remediation               *remediation.Result               `json:"remediation,omitempty"`
	Collection                CollectionResult                  `json:"collection"`
	Categories                []CategoryResult                  `json:"categories"`
	Summary                   Summary                           `json:"summary"`
	Findings                  []assessment.Finding              `json:"findings"`
	Suppressions              suppression.Report                `json:"suppressions"`
	Snapshot                  snapshot.Snapshot                 `json:"snapshot"`
	AssessedAt                time.Time                         `json:"-"`
}

type Collector func(context.Context) overview.Overview

// EvidenceCollector adds an immutable normalized evidence batch to a scan.
// The returned degradation strings are merged into collection health without
// changing the evidence contract.
type EvidenceCollector func(context.Context) ([]evidence.Observation, []string)

// NamedEvidenceCollector is the provider boundary. A collector may
// optionally validate its typed inventory after collection; corrupt providers
// are quarantined without crashing the remaining assessment.
type NamedEvidenceCollector struct {
	Name         string
	Dependencies []string
	// Priority orders ready providers without changing dependency semantics.
	// Lower positive values start first; zero keeps the legacy/default class.
	Priority int
	// BudgetClass is a live-provider workload hint. Fix38 applies the explicit
	// FAST/MEDIUM/HEAVY classes on Windows while preserving the legacy portable
	// collector ceiling on Linux/macOS.
	BudgetClass reliability.ProviderBudgetClass
	// Lane is the Fix44 Windows host-resource scheduling class. It is ignored on
	// non-Windows platforms and does not alter evidence semantics.
	Lane     reliability.ProviderExecutionLane
	Collect  EvidenceCollector
	Validate func() error
}

type categoryJob struct {
	name  string
	rules []assessment.Rule
}

type categoryOutcome struct {
	result   CategoryResult
	findings []assessment.Finding
	err      error
}

// Run preserves the API for tests and integrations that do not need
// provider names. production scans use RunNamed so provider health is
// explicit in JSON and doctor/report surfaces.
func Run(ctx context.Context, maxWorkers int, collector Collector, rules []assessment.Rule, extraCollectors ...EvidenceCollector) (Result, error) {
	named := make([]NamedEvidenceCollector, 0, len(extraCollectors))
	for i, c := range extraCollectors {
		named = append(named, NamedEvidenceCollector{Name: fmt.Sprintf("extra-%02d", i+1), Collect: c})
	}
	return RunNamed(ctx, maxWorkers, collector, rules, named...)
}

// RunNamed performs a bounded full assessment with provider panic
// containment, cooperative collector deadlines, corrupt-evidence quarantine,
// deterministic evidence ordering, and global memory limits. Ordinary scans
// still perform no outbound network activity.
func RunNamed(ctx context.Context, maxWorkers int, collector Collector, rules []assessment.Rule, extraCollectors ...NamedEvidenceCollector) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("scan context is required")
	}
	if maxWorkers < 1 {
		return Result{}, fmt.Errorf("max workers must be at least 1")
	}
	if maxWorkers > reliability.MaxWorkers {
		return Result{}, fmt.Errorf("max workers %d exceeds safety limit %d", maxWorkers, reliability.MaxWorkers)
	}
	if collector == nil {
		return Result{}, fmt.Errorf("scan collector is required")
	}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return Result{}, fmt.Errorf("validate scan rule: %w", err)
		}
	}

	started := time.Now().UTC()
	collectionStarted := time.Now().UTC()
	seen := make(map[string]struct{})
	providers := make([]ProviderResult, 0, 1+len(extraCollectors))

	// Post-117 Fix 13 gives collection a soft deadline that expires before the
	// command's hard deadline. Expensive Windows providers therefore cannot
	// consume the time reserved for rule evaluation and final assessment work.
	collectionCtx, cancelCollection, _ := reliability.CollectionContext(ctx)
	defer cancelCollection()

	o, overviewProvider := collectOverviewSafe(collectionCtx, collector, seen)
	providers = append(providers, overviewProvider)
	allEvidence := append([]evidence.Observation(nil), o.Evidence...)
	allDegraded := append([]string(nil), o.Degraded...)
	allDegraded = append(allDegraded, overviewProvider.DegradationReasons...)

	rawOutcomes, err := runNamedEvidenceCollectors(collectionCtx, maxWorkers, extraCollectors)
	if err != nil {
		return Result{}, err
	}
	for _, raw := range rawOutcomes {
		remaining := reliability.MaxEvidenceObservations - len(allEvidence)
		if remaining < 0 {
			remaining = 0
		}
		obs, degraded, provider := finalizeCollectorOutcome(raw, seen, remaining)
		providers = append(providers, provider)
		allEvidence = append(allEvidence, obs...)
		allDegraded = append(allDegraded, degraded...)
		allDegraded = append(allDegraded, provider.DegradationReasons...)
	}
	allDegraded = reliability.LimitStrings(allDegraded, reliability.MaxDegradationReasons)
	sort.SliceStable(allEvidence, func(i, j int) bool {
		if allEvidence[i].Key != allEvidence[j].Key {
			return allEvidence[i].Key < allEvidence[j].Key
		}
		return allEvidence[i].Source < allEvidence[j].Source
	})
	collectionCompleted := time.Now().UTC()
	if err := evidence.ValidateAll(allEvidence); err != nil {
		return Result{}, fmt.Errorf("validate accepted evidence after quarantine: %w", err)
	}

	collection := summarizeCollection(allEvidence, allDegraded, providers, collectionStarted, collectionCompleted)
	assessedAt := time.Now().UTC()
	jobs := groupRules(rules)
	workers := reliability.BoundWorkers(maxWorkers, len(jobs))

	outcomes := make([]categoryOutcome, 0, len(jobs))
	if len(jobs) > 0 {
		jobCh := make(chan categoryJob, len(jobs))
		resultCh := make(chan categoryOutcome, len(jobs))
		for _, job := range jobs {
			jobCh <- job
		}
		close(jobCh)

		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				for job := range jobCh {
					resultCh <- evaluateCategorySafe(ctx, job, allEvidence, assessedAt)
				}
			}()
		}
		wg.Wait()
		close(resultCh)
		for outcome := range resultCh {
			outcomes = append(outcomes, outcome)
		}
	}

	for _, outcome := range outcomes {
		if outcome.err != nil {
			return Result{}, outcome.err
		}
	}
	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i].result.Name < outcomes[j].result.Name })

	categories := make([]CategoryResult, 0, len(outcomes))
	findings := make([]assessment.Finding, 0, len(rules))
	for _, outcome := range outcomes {
		categories = append(categories, outcome.result)
		if len(findings)+len(outcome.findings) > reliability.MaxEvidenceObservations {
			return Result{}, fmt.Errorf("finding count exceeds safety limit %d", reliability.MaxEvidenceObservations)
		}
		findings = append(findings, outcome.findings...)
	}
	assessment.SortFindings(findings)
	if err := assessment.ValidateAll(findings); err != nil {
		return Result{}, fmt.Errorf("validate scan findings: %w", err)
	}

	completed := time.Now().UTC()
	summary := summarize(categories, findings, collection.Evidence)
	state := overallState(collection, summary.Categories, summary.Findings, ctx.Err() != nil)
	return Result{
		Schema:         SchemaVersion,
		EvidenceSchema: evidence.SchemaVersion,
		FindingSchema:  assessment.SchemaVersion,
		State:          state,
		TimedOut:       ctx.Err() != nil,
		Timing:         timing(started, completed),
		MaxWorkers:     maxWorkers,
		WorkersUsed:    workers,
		Overview:       o,
		Collection:     collection,
		Categories:     categories,
		Summary:        summary,
		Findings:       findings,
		AssessedAt:     assessedAt,
	}, nil
}

func providerBudgetTelemetry(d reliability.BudgetDecision) *ProviderBudgetTelemetry {
	ms := func(v time.Duration) float64 { return float64(v) / float64(time.Millisecond) }
	return &ProviderBudgetTelemetry{
		Class:             string(d.Class),
		RequestedMS:       ms(d.Requested),
		AppliedMS:         ms(d.Applied),
		ParentRemainingMS: ms(d.ParentRemaining),
		CleanupReserveMS:  ms(d.Reserve),
		CappedByParent:    d.CappedByParent,
	}
}

func collectOverviewSafe(ctx context.Context, collector Collector, seen map[string]struct{}) (o overview.Overview, provider ProviderResult) {
	started := time.Now().UTC()
	provider = ProviderResult{Name: "overview", State: StateComplete}
	child, cancel, budget := reliability.CollectorContextFor(ctx, runtime.GOOS, reliability.ProviderBudgetFast)
	defer cancel()
	if runtime.GOOS == "windows" {
		provider.Budget = providerBudgetTelemetry(budget)
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				provider.PanicContained = true
				provider.State = StatePartial
				provider.DegradationReasons = append(provider.DegradationReasons, reliability.PanicReason("overview", recovered))
			}
		}()
		o = collector(child)
	}()
	if err := child.Err(); err != nil {
		if ctx.Err() != nil {
			provider.State = StatePartial
			provider.DegradationReasons = append(provider.DegradationReasons, "overview collection stopped at the reserved collection budget: "+err.Error())
		} else {
			if provider.State == StateComplete {
				provider.State = StateDegraded
			}
			provider.DegradationReasons = append(provider.DegradationReasons, "overview collector deadline reached: "+err.Error())
		}
	}
	if o.CollectedAt.IsZero() {
		o.CollectedAt = time.Now().UTC()
	}
	if strings.TrimSpace(o.OS) == "" {
		o.OS = runtime.GOOS
	}
	if strings.TrimSpace(o.Architecture) == "" {
		o.Architecture = runtime.GOARCH
	}
	o.EvidenceSchema = evidence.SchemaVersion
	accepted, issues, invalid, duplicate, truncated := sanitizeEvidence("overview", o.Evidence, seen, reliability.MaxProviderEvidence)
	provider.InvalidEvidence = invalid
	provider.DuplicateEvidence = duplicate
	provider.Truncated = truncated
	provider.DegradationReasons = append(provider.DegradationReasons, issues...)
	if (invalid > 0 || duplicate > 0 || truncated) && provider.State == StateComplete {
		provider.State = StateDegraded
	}
	if len(accepted) == 0 && provider.PanicContained {
		health := evidence.NewState("reliability.provider.overview.health", evidence.StateDegraded, "provider guard", o.CollectedAt, evidence.ConfidenceExact, "overview provider failed; assessment continues with explicit degraded core metadata")
		accepted = append(accepted, health)
		seen[health.Key] = struct{}{}
	}
	o.Evidence = accepted
	o.Degraded = reliability.LimitStrings(append(o.Degraded, provider.DegradationReasons...), reliability.MaxDegradationReasons)
	provider.Evidence = countEvidence(accepted)
	provider.DegradationReasons = reliability.LimitStrings(provider.DegradationReasons, reliability.MaxDegradationReasons)
	provider.Timing = timing(started, time.Now().UTC())
	return o, provider
}

func sanitizeEvidence(provider string, raw []evidence.Observation, seen map[string]struct{}, limit int) (accepted []evidence.Observation, issues []string, invalid, duplicate int, truncated bool) {
	if limit < 0 {
		limit = 0
	}
	ordered := append([]evidence.Observation(nil), raw...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Key != ordered[j].Key {
			return ordered[i].Key < ordered[j].Key
		}
		return ordered[i].Source < ordered[j].Source
	})
	local := make(map[string]struct{}, len(ordered))
	for i, observation := range ordered {
		if err := observation.Validate(); err != nil {
			invalid++
			issues = append(issues, fmt.Sprintf("provider %s invalid evidence %d quarantined: %v", provider, i, err))
			continue
		}
		if _, ok := local[observation.Key]; ok {
			duplicate++
			issues = append(issues, fmt.Sprintf("provider %s duplicate evidence key %q quarantined", provider, observation.Key))
			continue
		}
		if _, ok := seen[observation.Key]; ok {
			duplicate++
			issues = append(issues, fmt.Sprintf("provider %s cross-provider duplicate evidence key %q quarantined", provider, observation.Key))
			continue
		}
		local[observation.Key] = struct{}{}
		if len(accepted) >= limit {
			truncated = true
			continue
		}
		accepted = append(accepted, observation)
		seen[observation.Key] = struct{}{}
	}
	if truncated {
		issues = append(issues, fmt.Sprintf("provider %s evidence truncated at limit %d", provider, limit))
	}
	return accepted, reliability.LimitStrings(issues, reliability.MaxDegradationReasons), invalid, duplicate, truncated
}

func evaluateCategorySafe(ctx context.Context, job categoryJob, observations []evidence.Observation, assessedAt time.Time) (out categoryOutcome) {
	defer func() {
		if recovered := recover(); recovered != nil {
			at := time.Now().UTC()
			out = categoryOutcome{result: CategoryResult{
				Name: job.name, State: StateSkipped, Timing: timing(at, at), RuleCount: len(job.rules), RuleIDs: categoryRuleIDs(job.rules), NotEvaluatedRules: len(job.rules),
				Reason: fmt.Sprintf("category panic contained by guard (%T)", recovered),
			}}
		}
	}()
	return evaluateCategory(ctx, job, observations, assessedAt)
}

// ProviderUsable reports whether a typed provider completed with evidence that
// passed the boundary. PARTIAL providers are deliberately excluded.
func ProviderUsable(collection CollectionResult, name string) bool {
	for _, provider := range collection.Providers {
		if provider.Name == name {
			return provider.State == StateComplete || provider.State == StateDegraded
		}
	}
	return false
}

func groupRules(rules []assessment.Rule) []categoryJob {
	byCategory := make(map[string][]assessment.Rule)
	for _, r := range rules {
		name := strings.TrimSpace(r.Category)
		byCategory[name] = append(byCategory[name], r)
	}
	names := make([]string, 0, len(byCategory))
	for name := range byCategory {
		names = append(names, name)
	}
	sort.Strings(names)
	jobs := make([]categoryJob, 0, len(names))
	for _, name := range names {
		rules := append([]assessment.Rule(nil), byCategory[name]...)
		sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
		jobs = append(jobs, categoryJob{name: name, rules: rules})
	}
	return jobs
}

func evaluateCategory(ctx context.Context, job categoryJob, observations []evidence.Observation, assessedAt time.Time) categoryOutcome {
	started := time.Now().UTC()
	if err := ctx.Err(); err != nil {
		completed := time.Now().UTC()
		return categoryOutcome{result: CategoryResult{
			Name: job.name, State: StateSkipped, Timing: timing(started, completed), RuleCount: len(job.rules), RuleIDs: categoryRuleIDs(job.rules), NotEvaluatedRules: len(job.rules),
			Reason: "assessment deadline reached before category execution: " + err.Error(),
		}}
	}

	findings, err := assessment.EvaluateRules(job.rules, observations, assessedAt)
	completed := time.Now().UTC()
	if err != nil {
		return categoryOutcome{err: fmt.Errorf("evaluate category %q: %w", job.name, err)}
	}
	counts := countFindings(findings)
	degraded, reasons := categoryDegradation(findings)
	state := StateComplete
	if len(findings) > 0 && counts.NotApplicable == len(findings) {
		state = StateNotApplicable
	} else if counts.Unknown > 0 || degraded > 0 {
		state = StateDegraded
	}
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return categoryOutcome{
		result: CategoryResult{
			Name: job.name, State: state, Timing: timing(started, completed), RuleCount: len(job.rules), RuleIDs: categoryRuleIDs(job.rules), EvaluatedRules: len(job.rules),
			Findings: counts, FindingIDs: ids, DegradedEvidence: degraded, DegradationReasons: reasons,
		},
		findings: findings,
	}
}

func categoryRuleIDs(rules []assessment.Rule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}

func summarizeCollection(observations []evidence.Observation, degraded []string, providers []ProviderResult, started, completed time.Time) CollectionResult {
	counts := countEvidence(observations)
	reasons := make([]string, 0)
	seen := map[string]struct{}{}
	for _, o := range observations {
		if o.State == evidence.StateObserved || o.State == evidence.StateNotApplicable {
			continue
		}
		reason := o.Key + ": " + strings.TrimSpace(o.Reason)
		if _, ok := seen[reason]; !ok {
			seen[reason] = struct{}{}
			reasons = append(reasons, reason)
		}
	}
	for _, d := range degraded {
		reason := strings.TrimSpace(d)
		if reason == "" {
			continue
		}
		if _, ok := seen[reason]; !ok {
			seen[reason] = struct{}{}
			reasons = append(reasons, reason)
		}
	}
	reasons = reliability.LimitStrings(reasons, reliability.MaxDegradationReasons)
	state := StateComplete
	for _, provider := range providers {
		if provider.State == StatePartial || provider.State == StateSkipped {
			state = StatePartial
			break
		}
		if provider.State == StateDegraded && state == StateComplete {
			state = StateDegraded
		}
	}
	if state == StateComplete && (counts.Degraded+counts.Denied+counts.Unavailable+counts.Unsupported > 0 || len(degraded) > 0) {
		state = StateDegraded
	}
	return CollectionResult{State: state, Timing: timing(started, completed), Evidence: counts, Providers: append([]ProviderResult(nil), providers...), DegradationReasons: reasons}
}

func countEvidence(observations []evidence.Observation) EvidenceCounts {
	var c EvidenceCounts
	for _, o := range observations {
		c.Total++
		switch o.State {
		case evidence.StateObserved:
			c.Observed++
		case evidence.StateDegraded:
			c.Degraded++
		case evidence.StateDenied:
			c.Denied++
		case evidence.StateUnavailable:
			c.Unavailable++
		case evidence.StateUnsupported:
			c.Unsupported++
		case evidence.StateNotApplicable:
			c.NotApplicable++
		}
	}
	return c
}

func countFindings(findings []assessment.Finding) FindingCounts {
	var c FindingCounts
	for _, f := range findings {
		c.Total++
		switch f.Status {
		case assessment.StatusPass:
			c.Pass++
		case assessment.StatusWarn:
			c.Warn++
		case assessment.StatusFail:
			c.Fail++
		case assessment.StatusUnknown:
			c.Unknown++
		}
		if f.Applicability == assessment.NotApplicable {
			c.NotApplicable++
		}
		if f.Suppression == assessment.SuppressionSuppressed {
			c.Suppressed++
		}
	}
	return c
}

func categoryDegradation(findings []assessment.Finding) (int, []string) {
	seenEvidence := map[string]struct{}{}
	seenReason := map[string]struct{}{}
	reasons := make([]string, 0)
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.State == evidence.StateObserved || e.State == evidence.StateNotApplicable {
				continue
			}
			seenEvidence[e.Key] = struct{}{}
			reason := e.Key + ": " + strings.TrimSpace(e.Reason)
			if _, ok := seenReason[reason]; !ok {
				seenReason[reason] = struct{}{}
				reasons = append(reasons, reason)
			}
		}
		if f.Status == assessment.StatusUnknown && len(f.Evidence) == 0 {
			reason := f.RuleID + ": required evidence was not present in the normalized snapshot"
			if _, ok := seenReason[reason]; !ok {
				seenReason[reason] = struct{}{}
				reasons = append(reasons, reason)
			}
		}
	}
	sort.Strings(reasons)
	return len(seenEvidence), reasons
}

func summarize(categories []CategoryResult, findings []assessment.Finding, evidenceCounts EvidenceCounts) Summary {
	var cc CategoryCounts
	eval := EvaluationCoverage{Complete: true}
	reasonSet := map[string]struct{}{}
	for _, c := range categories {
		cc.Total++
		eval.SelectedRules += c.RuleCount
		eval.EvaluatedRules += c.EvaluatedRules
		eval.NotEvaluatedRules += c.NotEvaluatedRules
		if c.NotEvaluatedRules > 0 {
			eval.Complete = false
			reason := strings.TrimSpace(c.Reason)
			if reason == "" {
				reason = c.Name + ": selected rules were not evaluated"
			} else {
				reason = c.Name + ": " + reason
			}
			reasonSet[reason] = struct{}{}
		}
		switch c.State {
		case StateComplete:
			cc.Complete++
		case StateDegraded:
			cc.Degraded++
		case StateSkipped:
			cc.Skipped++
		case StateNotApplicable:
			cc.NotApplicable++
		}
	}
	if eval.SelectedRules == 0 {
		eval.Percent = 100
	} else {
		eval.Percent = (float64(eval.EvaluatedRules) / float64(eval.SelectedRules)) * 100
	}
	for reason := range reasonSet {
		eval.Reasons = append(eval.Reasons, reason)
	}
	sort.Strings(eval.Reasons)
	if eval.EvaluatedRules+eval.NotEvaluatedRules != eval.SelectedRules {
		eval.Complete = false
		eval.Reasons = append(eval.Reasons, "evaluation accounting mismatch")
	}
	return Summary{Categories: cc, Findings: countFindings(findings), Evidence: evidenceCounts, Evaluation: eval, UnknownAudit: evidencequality.AuditUnknownFindings(findings)}
}

func overallState(collection CollectionResult, categories CategoryCounts, findings FindingCounts, timedOut bool) State {
	if timedOut || categories.Skipped > 0 || collection.State == StatePartial {
		return StatePartial
	}
	if collection.State == StateDegraded || categories.Degraded > 0 || findings.Unknown > 0 {
		return StateDegraded
	}
	return StateComplete
}

// ApplySuppressionResult attaches policy state without changing raw
// finding status or evidence. Category and global finding counts are recomputed
// only to surface the number of suppressed findings.
func ApplySuppressionResult(in *Result, findings []assessment.Finding, report suppression.Report) error {
	if in == nil {
		return fmt.Errorf("scan result is required")
	}
	if report.Schema != suppression.SchemaVersion {
		return fmt.Errorf("suppression report schema %q is invalid", report.Schema)
	}
	if err := assessment.ValidateAll(findings); err != nil {
		return fmt.Errorf("suppression findings: %w", err)
	}
	byID := make(map[string]assessment.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	for i := range in.Categories {
		items := make([]assessment.Finding, 0, len(in.Categories[i].FindingIDs))
		for _, id := range in.Categories[i].FindingIDs {
			f, ok := byID[id]
			if !ok {
				return fmt.Errorf("category %q references missing finding %q after suppression", in.Categories[i].Name, id)
			}
			items = append(items, f)
		}
		in.Categories[i].Findings = countFindings(items)
	}
	in.Findings = append([]assessment.Finding(nil), findings...)
	in.Suppressions = report
	in.Summary = summarize(in.Categories, in.Findings, in.Collection.Evidence)
	return nil
}

func timing(started, completed time.Time) Timing {
	return Timing{StartedAt: started.UTC(), CompletedAt: completed.UTC(), DurationMS: float64(completed.Sub(started).Nanoseconds()) / float64(time.Millisecond)}
}
