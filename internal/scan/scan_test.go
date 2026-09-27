package scan

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/assessment"
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/overview"
	"github.com/Nikolov999/chimera/internal/reliability"
)

func TestRunUsesBoundedParallelCategoriesAndDeterministicOrdering(t *testing.T) {
	at := time.Now().UTC()
	collector := func(context.Context) overview.Overview {
		return overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at,
			OS:             "test",
			Architecture:   "test",
			Evidence: []evidence.Observation{
				evidence.NewObserved("test.value", "ok", "test collector", at, evidence.ConfidenceExact),
			},
		}
	}

	var active int32
	var maxActive int32
	mkRule := func(id, category string) assessment.Rule {
		return assessment.Rule{
			ID: id, Title: id, Category: category, Severity: assessment.SeverityInfo,
			AffectedObject: id, ExpectedState: "ok", Risk: "test risk", Remediation: "test remediation",
			Evaluate: func(idx assessment.Index) assessment.Evaluation {
				n := atomic.AddInt32(&active, 1)
				for {
					old := atomic.LoadInt32(&maxActive)
					if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&active, -1)
				return assessment.Evaluation{
					Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact,
					ObservedState: "ok", Applicability: assessment.Applicable, EvidenceKeys: []string{"test.value"},
				}
			},
		}
	}
	rules := []assessment.Rule{
		mkRule("CHM-TEST-Z", "zeta"),
		mkRule("CHM-TEST-A", "alpha"),
		mkRule("CHM-TEST-M", "middle"),
	}

	got, err := Run(context.Background(), 2, collector, rules)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkersUsed != 2 {
		t.Fatalf("workers used=%d want=2", got.WorkersUsed)
	}
	if atomic.LoadInt32(&maxActive) > 2 {
		t.Fatalf("observed %d concurrent categories with max-workers=2", maxActive)
	}
	if atomic.LoadInt32(&maxActive) < 2 {
		t.Fatalf("category execution was not parallel; max active=%d", maxActive)
	}
	if len(got.Categories) != 3 || got.Categories[0].Name != "alpha" || got.Categories[1].Name != "middle" || got.Categories[2].Name != "zeta" {
		t.Fatalf("categories are not deterministic: %#v", got.Categories)
	}
	if len(got.Findings) != 3 || got.Findings[0].RuleID != "CHM-TEST-A" || got.Findings[1].RuleID != "CHM-TEST-M" || got.Findings[2].RuleID != "CHM-TEST-Z" {
		t.Fatalf("findings are not deterministic: %#v", got.Findings)
	}
	if got.State != StateComplete || got.Summary.Categories.Complete != 3 {
		t.Fatalf("unexpected scan summary: state=%s summary=%#v", got.State, got.Summary)
	}
}

func TestRunReservesTimeForEvaluationAfterCollectionBudget(t *testing.T) {
	at := time.Now().UTC()
	collector := func(ctx context.Context) overview.Overview {
		<-ctx.Done()
		return overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at,
			OS:             "test",
			Architecture:   "test",
			Evidence: []evidence.Observation{
				evidence.NewObserved("test.value", "ok", "test collector", at, evidence.ConfidenceExact),
			},
		}
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-001", Title: "test", Category: "test", Severity: assessment.SeverityInfo,
		AffectedObject: "test.value", ExpectedState: "ok", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(idx assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "ok", Applicability: assessment.Applicable, EvidenceKeys: []string{"test.value"}}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := Run(ctx, 1, collector, []assessment.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got.TimedOut {
		t.Fatalf("hard command deadline should remain available for evaluation: %#v", got.Timing)
	}
	if got.State != StatePartial || got.Collection.State != StatePartial {
		t.Fatalf("collection budget exhaustion must remain partial: state=%s collection=%s", got.State, got.Collection.State)
	}
	if got.Summary.Categories.Complete != 1 || got.Summary.Categories.Skipped != 0 || got.Summary.Findings.Pass != 1 {
		t.Fatalf("reserved evaluation budget was not used: %#v", got.Summary)
	}
	if len(got.Collection.Providers) != 1 || got.Collection.Providers[0].State != StatePartial {
		t.Fatalf("overview collection budget state not retained: %#v", got.Collection.Providers)
	}
}

func TestCollectionDegradationIsExplicit(t *testing.T) {
	at := time.Now().UTC()
	collector := func(context.Context) overview.Overview {
		return overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at,
			OS:             "test",
			Architecture:   "test",
			Degraded:       []string{"provider: permission denied"},
			Evidence: []evidence.Observation{
				evidence.NewState("test.value", evidence.StateDenied, "test collector", at, evidence.ConfidenceHigh, "permission denied"),
			},
		}
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-002", Title: "test", Category: "test", Severity: assessment.SeverityLow,
		AffectedObject: "test.value", ExpectedState: "observed", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(idx assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusUnknown, Confidence: evidence.ConfidenceHigh, ObservedState: "DENIED", Applicability: assessment.Applicable, EvidenceKeys: []string{"test.value"}}
		},
	}
	got, err := Run(context.Background(), 4, collector, []assessment.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got.Collection.State != StateDegraded || got.Collection.Evidence.Denied != 1 {
		t.Fatalf("collection degradation not accounted: %#v", got.Collection)
	}
	if got.Categories[0].State != StateDegraded || got.Categories[0].DegradedEvidence != 1 {
		t.Fatalf("category degradation not accounted: %#v", got.Categories[0])
	}
	if got.State != StateDegraded || got.Summary.Findings.Unknown != 1 {
		t.Fatalf("overall degradation not accounted: %#v", got.Summary)
	}
}

func TestRunAccountsForNotApplicableCategory(t *testing.T) {
	at := time.Now().UTC()
	collector := func(context.Context) overview.Overview {
		return overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at,
			OS:             "test",
			Architecture:   "test",
			Evidence: []evidence.Observation{
				evidence.NewState("test.na", evidence.StateNotApplicable, "test collector", at, evidence.ConfidenceExact, "not applicable on test platform"),
			},
		}
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-003", Title: "test", Category: "platform-specific", Severity: assessment.SeverityInfo,
		AffectedObject: "test.na", ExpectedState: "not applicable", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(idx assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "NOT_APPLICABLE", Applicability: assessment.NotApplicable, EvidenceKeys: []string{"test.na"}}
		},
	}
	got, err := Run(context.Background(), 1, collector, []assessment.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got.Categories[0].State != StateNotApplicable || got.Categories[0].Findings.NotApplicable != 1 {
		t.Fatalf("not-applicable category accounting failed: %#v", got.Categories[0])
	}
	if got.Summary.Categories.NotApplicable != 1 || got.Summary.Findings.NotApplicable != 1 || got.Summary.Evidence.NotApplicable != 1 {
		t.Fatalf("not-applicable summary accounting failed: %#v", got.Summary)
	}
	if got.State != StateComplete {
		t.Fatalf("not-applicable-only category should not degrade scan, got %s", got.State)
	}
}

func TestRunNamedContainsProviderPanic(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	panicCollector := NamedEvidenceCollector{Name: "panic-provider", Collect: func(context.Context) ([]evidence.Observation, []string) {
		panic("provider failure")
	}}
	got, err := RunNamed(context.Background(), 1, overviewCollector, nil, panicCollector)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StatePartial || len(got.Collection.Providers) != 2 {
		t.Fatalf("panic was not contained as partial scan: state=%s providers=%#v", got.State, got.Collection.Providers)
	}
	p := got.Collection.Providers[1]
	if !p.PanicContained || p.State != StatePartial || ProviderUsable(got.Collection, "panic-provider") {
		t.Fatalf("unexpected panic provider state %#v", p)
	}
}

func TestRunNamedQuarantinesInvalidAndDuplicateEvidence(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	provider := NamedEvidenceCollector{Name: "corrupt", Collect: func(context.Context) ([]evidence.Observation, []string) {
		return []evidence.Observation{
			evidence.NewObserved("test.good", 1, "provider", at, evidence.ConfidenceExact),
			evidence.NewObserved("test.good", 2, "provider", at, evidence.ConfidenceExact),
			{Key: "test.invalid", State: evidence.StateObserved, Source: "provider", CollectedAt: at, Confidence: evidence.ConfidenceExact},
		}, nil
	}}
	got, err := RunNamed(context.Background(), 1, overviewCollector, nil, provider)
	if err != nil {
		t.Fatal(err)
	}
	p := got.Collection.Providers[1]
	if p.State != StateDegraded || p.InvalidEvidence != 1 || p.DuplicateEvidence != 1 || p.Evidence.Total != 1 {
		t.Fatalf("unexpected provider quarantine result %#v", p)
	}
	if !ProviderUsable(got.Collection, "corrupt") {
		t.Fatal("provider with preserved valid evidence should remain usable but degraded")
	}
	if got.Collection.Evidence.Total != 2 {
		t.Fatalf("accepted evidence total=%d want=2", got.Collection.Evidence.Total)
	}
}

func TestRunNamedContainsRulePanic(t *testing.T) {
	at := time.Now().UTC()
	collector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.value", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-PANIC", Title: "panic", Category: "panic", Severity: assessment.SeverityInfo,
		AffectedObject: "test.value", ExpectedState: "ok", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(assessment.Index) assessment.Evaluation { panic("rule failure") },
	}
	got, err := RunNamed(context.Background(), 1, collector, []assessment.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StatePartial || got.Summary.Categories.Skipped != 1 || len(got.Findings) != 0 {
		t.Fatalf("rule panic was not contained: state=%s summary=%#v", got.State, got.Summary)
	}
}

func TestRunNamedCollectorsExecuteIndependentProvidersConcurrently(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	started := make(chan string, 2)
	release := make(chan struct{})
	mk := func(name, key string) NamedEvidenceCollector {
		return NamedEvidenceCollector{Name: name, Collect: func(ctx context.Context) ([]evidence.Observation, []string) {
			started <- name
			select {
			case <-release:
			case <-ctx.Done():
			}
			return []evidence.Observation{evidence.NewObserved(key, "ok", name, at, evidence.ConfidenceExact)}, nil
		}}
	}
	done := make(chan error, 1)
	go func() {
		_, err := RunNamed(context.Background(), 2, overviewCollector, nil, mk("one", "test.one"), mk("two", "test.two"))
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			close(release)
			t.Fatal("independent collectors did not run concurrently")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunNamedCollectorDependenciesGateExecution(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	primaryStarted := make(chan struct{}, 1)
	dependentStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	primary := NamedEvidenceCollector{Name: "primary", Collect: func(ctx context.Context) ([]evidence.Observation, []string) {
		primaryStarted <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return []evidence.Observation{evidence.NewObserved("test.primary", "ok", "primary", at, evidence.ConfidenceExact)}, nil
	}}
	dependent := NamedEvidenceCollector{Name: "dependent", Dependencies: []string{"primary"}, Collect: func(context.Context) ([]evidence.Observation, []string) {
		dependentStarted <- struct{}{}
		return []evidence.Observation{evidence.NewObserved("test.dependent", "ok", "dependent", at, evidence.ConfidenceExact)}, nil
	}}
	done := make(chan error, 1)
	go func() {
		_, err := RunNamed(context.Background(), 2, overviewCollector, nil, primary, dependent)
		done <- err
	}()
	select {
	case <-primaryStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("primary collector did not start")
	}
	select {
	case <-dependentStarted:
		close(release)
		t.Fatal("dependent collector started before dependency completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-dependentStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dependent collector did not start after dependency completed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunNamedCollectionBudgetSkipsUnstartedProvidersAndStillEvaluates(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	slow := NamedEvidenceCollector{Name: "slow", Collect: func(ctx context.Context) ([]evidence.Observation, []string) {
		<-ctx.Done()
		return nil, nil
	}}
	var secondStarted int32
	second := NamedEvidenceCollector{Name: "second", Collect: func(context.Context) ([]evidence.Observation, []string) {
		atomic.StoreInt32(&secondStarted, 1)
		return []evidence.Observation{evidence.NewObserved("test.second", "ok", "second", at, evidence.ConfidenceExact)}, nil
	}}
	rule := assessment.Rule{
		ID: "CHM-TEST-BUDGET", Title: "budget", Category: "budget", Severity: assessment.SeverityInfo,
		AffectedObject: "test.base", ExpectedState: "ok", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "ok", Applicability: assessment.Applicable, EvidenceKeys: []string{"test.base"}}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	got, err := RunNamed(ctx, 1, overviewCollector, []assessment.Rule{rule}, slow, second)
	if err != nil {
		t.Fatal(err)
	}
	if got.TimedOut || got.Summary.Categories.Complete != 1 || got.Summary.Findings.Pass != 1 {
		t.Fatalf("hard deadline was not reserved for evaluation: timed_out=%t summary=%#v", got.TimedOut, got.Summary)
	}
	if atomic.LoadInt32(&secondStarted) != 0 {
		t.Fatal("collector started after the collection soft budget expired")
	}
	if len(got.Collection.Providers) != 3 || got.Collection.Providers[2].Name != "second" || got.Collection.Providers[2].State != StateSkipped {
		t.Fatalf("unstarted provider was not explicitly skipped: %#v", got.Collection.Providers)
	}
	if got.State != StatePartial {
		t.Fatalf("skipped collection must make the scan partial, got %s", got.State)
	}
}

func TestRunNamedReadyCollectorsRespectPriorityFix23(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test"}
	}
	started := make(chan string, 2)
	release := make(chan struct{})
	mk := func(name string, priority int) NamedEvidenceCollector {
		return NamedEvidenceCollector{Name: name, Priority: priority, Collect: func(ctx context.Context) ([]evidence.Observation, []string) {
			started <- name
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, nil
		}}
	}
	done := make(chan error, 1)
	go func() {
		_, err := RunNamed(context.Background(), 1, overviewCollector, nil, mk("optional", 50), mk("core", 10))
		done <- err
	}()
	select {
	case got := <-started:
		if got != "core" {
			close(release)
			t.Fatalf("first provider=%s want=core", got)
		}
	case <-time.After(500 * time.Millisecond):
		close(release)
		t.Fatal("priority provider did not start")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunNamedConcurrentMergePreservesDeclarationOrder(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test", Evidence: []evidence.Observation{
			evidence.NewObserved("test.base", "ok", "overview", at, evidence.ConfidenceExact),
		}}
	}
	first := NamedEvidenceCollector{Name: "first", Collect: func(context.Context) ([]evidence.Observation, []string) {
		time.Sleep(40 * time.Millisecond)
		return []evidence.Observation{evidence.NewObserved("test.shared", "first", "first", at, evidence.ConfidenceExact)}, nil
	}}
	second := NamedEvidenceCollector{Name: "second", Collect: func(context.Context) ([]evidence.Observation, []string) {
		return []evidence.Observation{evidence.NewObserved("test.shared", "second", "second", at, evidence.ConfidenceExact)}, nil
	}}
	got, err := RunNamed(context.Background(), 2, overviewCollector, nil, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Collection.Providers) != 3 {
		t.Fatalf("provider count=%d", len(got.Collection.Providers))
	}
	if got.Collection.Providers[1].Evidence.Total != 1 || got.Collection.Providers[2].DuplicateEvidence != 1 {
		t.Fatalf("declaration-order duplicate ownership changed: %#v", got.Collection.Providers)
	}
}

func TestRunNamedRejectsCollectorDependencyCycle(t *testing.T) {
	at := time.Now().UTC()
	overviewCollector := func(context.Context) overview.Overview {
		return overview.Overview{EvidenceSchema: evidence.SchemaVersion, CollectedAt: at, OS: "test", Architecture: "test"}
	}
	a := NamedEvidenceCollector{Name: "a", Dependencies: []string{"b"}, Collect: func(context.Context) ([]evidence.Observation, []string) { return nil, nil }}
	b := NamedEvidenceCollector{Name: "b", Dependencies: []string{"a"}, Collect: func(context.Context) ([]evidence.Observation, []string) { return nil, nil }}
	if _, err := RunNamed(context.Background(), 2, overviewCollector, nil, a, b); err == nil {
		t.Fatal("expected collector dependency cycle to be rejected")
	}
}

func TestRunRecordsNotEvaluatedRulesWhenHardDeadlineExpiresBeforeEvaluation(t *testing.T) {
	at := time.Now().UTC()
	collector := func(context.Context) overview.Overview {
		// Simulate a provider that does not return until after the hard command
		// deadline. The scan must preserve rule coverage instead of returning a
		// misleading zero-finding clean result.
		time.Sleep(20 * time.Millisecond)
		return overview.Overview{
			EvidenceSchema: evidence.SchemaVersion,
			CollectedAt:    at,
			OS:             "test",
			Architecture:   "test",
			Evidence: []evidence.Observation{
				evidence.NewObserved("test.value", "ok", "test collector", at, evidence.ConfidenceExact),
			},
		}
	}
	rule := assessment.Rule{
		ID: "CHM-TEST-NOT-EVAL", Title: "test", Category: "test", Severity: assessment.SeverityInfo,
		AffectedObject: "test.value", ExpectedState: "ok", Risk: "test risk", Remediation: "test remediation",
		Evaluate: func(idx assessment.Index) assessment.Evaluation {
			return assessment.Evaluation{Status: assessment.StatusPass, Confidence: evidence.ConfidenceExact, ObservedState: "ok", Applicability: assessment.Applicable, EvidenceKeys: []string{"test.value"}}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	got, err := Run(ctx, 1, collector, []assessment.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if !got.TimedOut || got.State != StatePartial {
		t.Fatalf("expected hard-timeout partial result, got timedOut=%t state=%s", got.TimedOut, got.State)
	}
	if got.Summary.Evaluation.SelectedRules != 1 || got.Summary.Evaluation.EvaluatedRules != 0 || got.Summary.Evaluation.NotEvaluatedRules != 1 || got.Summary.Evaluation.Complete {
		t.Fatalf("unexpected evaluation coverage: %#v", got.Summary.Evaluation)
	}
	if got.Summary.Findings.Total != 0 || len(got.Findings) != 0 {
		t.Fatalf("not-evaluated rule must not synthesize a finding: summary=%#v findings=%#v", got.Summary.Findings, got.Findings)
	}
	if len(got.Categories) != 1 || got.Categories[0].State != StateSkipped || got.Categories[0].NotEvaluatedRules != 1 || len(got.Categories[0].RuleIDs) != 1 {
		t.Fatalf("category did not preserve NOT_EVALUATED coverage: %#v", got.Categories)
	}
}

func TestFix44WindowsPowerShellLaneBoundsConcurrentCollectors(t *testing.T) {
	var active int32
	var maxActive int32
	collectors := make([]NamedEvidenceCollector, 0, 6)
	for i := 0; i < 6; i++ {
		collectors = append(collectors, NamedEvidenceCollector{
			Name:        "pwsh-" + string(rune('a'+i)),
			BudgetClass: reliability.ProviderBudgetMedium,
			Lane:        reliability.ProviderLanePowerShellCIM,
			Collect: func(context.Context) ([]evidence.Observation, []string) {
				n := atomic.AddInt32(&active, 1)
				for {
					old := atomic.LoadInt32(&maxActive)
					if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&active, -1)
				return nil, nil
			},
		})
	}
	out, err := runNamedEvidenceCollectorsForPlatform(context.Background(), 8, collectors, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(collectors) {
		t.Fatalf("outcomes=%d want=%d", len(out), len(collectors))
	}
	if got := atomic.LoadInt32(&maxActive); got > int32(reliability.WindowsPowerShellCIMLaneLimit) {
		t.Fatalf("PowerShell/CIM concurrency=%d exceeds lane limit=%d", got, reliability.WindowsPowerShellCIMLaneLimit)
	}
}

func TestFix44WindowsManagementAggregateCapAcrossExpensiveLanes(t *testing.T) {
	var active int32
	var maxActive int32
	collectors := make([]NamedEvidenceCollector, 0, 8)
	for i := 0; i < 8; i++ {
		lane := reliability.ProviderLanePowerShellCIM
		class := reliability.ProviderBudgetMedium
		if i%2 == 1 {
			lane = reliability.ProviderLaneHeavySecurity
			class = reliability.ProviderBudgetHeavy
		}
		collectors = append(collectors, NamedEvidenceCollector{
			Name:        "management-" + string(rune('a'+i)),
			BudgetClass: class,
			Lane:        lane,
			Collect: func(context.Context) ([]evidence.Observation, []string) {
				n := atomic.AddInt32(&active, 1)
				for {
					old := atomic.LoadInt32(&maxActive)
					if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&active, -1)
				return nil, nil
			},
		})
	}
	if _, err := runNamedEvidenceCollectorsForPlatform(context.Background(), 8, collectors, "windows"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&maxActive); got > int32(reliability.WindowsManagementLaneLimit) {
		t.Fatalf("Windows management concurrency=%d exceeds aggregate limit=%d", got, reliability.WindowsManagementLaneLimit)
	}
}

func TestFix44NativeLaneBypassesSaturatedManagementQueue(t *testing.T) {
	release := make(chan struct{})
	managementStarted := make(chan struct{}, 3)
	nativeStarted := make(chan struct{}, 1)
	mkManagement := func(name string, lane reliability.ProviderExecutionLane) NamedEvidenceCollector {
		return NamedEvidenceCollector{
			Name: name, Priority: 5, Lane: lane, BudgetClass: reliability.ProviderBudgetHeavy,
			Collect: func(ctx context.Context) ([]evidence.Observation, []string) {
				managementStarted <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
				return nil, nil
			},
		}
	}
	collectors := []NamedEvidenceCollector{
		mkManagement("heavy-a", reliability.ProviderLaneHeavySecurity),
		mkManagement("heavy-b", reliability.ProviderLaneHeavySecurity),
		mkManagement("pwsh-a", reliability.ProviderLanePowerShellCIM),
		mkManagement("pwsh-b", reliability.ProviderLanePowerShellCIM), // queued by management cap
		{
			Name: "native", Priority: 50, Lane: reliability.ProviderLaneNativeLight, BudgetClass: reliability.ProviderBudgetFast,
			Collect: func(context.Context) ([]evidence.Observation, []string) {
				nativeStarted <- struct{}{}
				return nil, nil
			},
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := runNamedEvidenceCollectorsForPlatform(context.Background(), 5, collectors, "windows")
		done <- err
	}()
	for i := 0; i < reliability.WindowsManagementLaneLimit; i++ {
		select {
		case <-managementStarted:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("management lane did not saturate")
		}
	}
	select {
	case <-nativeStarted:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("native collector was head-of-line blocked by saturated management lane")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFix44WindowsSchedulingTelemetryCapturesLaneQueueAndDeadline(t *testing.T) {
	collectors := []NamedEvidenceCollector{
		{Name: "pwsh-a", Lane: reliability.ProviderLanePowerShellCIM, BudgetClass: reliability.ProviderBudgetMedium, Collect: func(context.Context) ([]evidence.Observation, []string) {
			time.Sleep(30 * time.Millisecond)
			return nil, nil
		}},
		{Name: "pwsh-b", Lane: reliability.ProviderLanePowerShellCIM, BudgetClass: reliability.ProviderBudgetMedium, Collect: func(context.Context) ([]evidence.Observation, []string) {
			time.Sleep(30 * time.Millisecond)
			return nil, nil
		}},
		{Name: "pwsh-c", Lane: reliability.ProviderLanePowerShellCIM, BudgetClass: reliability.ProviderBudgetMedium, Collect: func(context.Context) ([]evidence.Observation, []string) { return nil, nil }},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := runNamedEvidenceCollectorsForPlatform(ctx, 8, collectors, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[2].provider.Scheduling == nil || out[2].provider.Budget == nil {
		t.Fatalf("missing Fix44 telemetry: %#v", out)
	}
	tel := out[2].provider.Scheduling
	if tel.Lane != string(reliability.ProviderLanePowerShellCIM) || tel.LaneLimit != reliability.WindowsPowerShellCIMLaneLimit {
		t.Fatalf("unexpected lane telemetry: %#v", tel)
	}
	if tel.QueueWaitMS < 5 {
		t.Fatalf("third PowerShell collector did not expose queue wait: %#v", tel)
	}
	if tel.ExecutionStartedAt == nil || tel.ExecutionStartedAt.IsZero() || tel.ExecutionDurationMS < 0 || tel.DeadlineAt == nil || tel.ParentRemainingAtStartMS <= 0 {
		t.Fatalf("incomplete scheduling timing telemetry: %#v", tel)
	}
}

func TestFix56WindowsQueueAgingRaisesAdmissionPriority(t *testing.T) {
	now := time.Now().UTC()
	node := collectorNode{priority: 20, readyAt: now.Add(-5 * reliability.WindowsQueueAgingInterval)}
	got := effectiveCollectorPriority(node, "windows", now)
	if got >= node.priority {
		t.Fatalf("aged Windows provider priority=%d want less than static=%d", got, node.priority)
	}
	if want := 15; got != want {
		t.Fatalf("aged Windows provider priority=%d want=%d", got, want)
	}
	if portable := effectiveCollectorPriority(node, "linux", now); portable != node.priority {
		t.Fatalf("non-Windows queue priority changed: got=%d want=%d", portable, node.priority)
	}
}

func TestFix56WindowsQueueAgingIsBounded(t *testing.T) {
	now := time.Now().UTC()
	node := collectorNode{priority: 20, readyAt: now.Add(-100 * reliability.WindowsQueueAgingInterval)}
	got := effectiveCollectorPriority(node, "windows", now)
	want := node.priority - reliability.WindowsQueueAgingMaxBoost
	if want < 1 {
		want = 1
	}
	if got != want {
		t.Fatalf("bounded aged priority=%d want=%d", got, want)
	}
}

func TestFix57WindowsStarvedCollectorIsSkippedBeforeExecution(t *testing.T) {
	started := false
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	out, err := runNamedEvidenceCollectorsForPlatform(ctx, 1, []NamedEvidenceCollector{{
		Name: "late-medium", Lane: reliability.ProviderLanePowerShellCIM, BudgetClass: reliability.ProviderBudgetMedium,
		Collect: func(context.Context) ([]evidence.Observation, []string) {
			started = true
			return nil, nil
		},
	}}, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("provider implementation started despite insufficient parent assessment budget")
	}
	if len(out) != 1 || out[0].provider.State != StateSkipped {
		t.Fatalf("unexpected skipped outcome: %#v", out)
	}
	if out[0].provider.Scheduling == nil || !out[0].provider.Scheduling.SkippedBeforeExecution || out[0].provider.Scheduling.AdmissionMinimumMS <= 0 {
		t.Fatalf("missing Fix57 pre-execution skip telemetry: %#v", out[0].provider.Scheduling)
	}
	if len(out[0].provider.DegradationReasons) == 0 || !strings.Contains(out[0].provider.DegradationReasons[0], "insufficient remaining assessment budget") {
		t.Fatalf("missing assessment-budget reason: %#v", out[0].provider.DegradationReasons)
	}
}

func TestFix57WindowsSchedulingTelemetryIncludesDependencyWait(t *testing.T) {
	collectors := []NamedEvidenceCollector{
		{Name: "parent", Priority: 1, Lane: reliability.ProviderLaneNativeLight, BudgetClass: reliability.ProviderBudgetFast, Collect: func(context.Context) ([]evidence.Observation, []string) {
			time.Sleep(20 * time.Millisecond)
			return nil, nil
		}},
		{Name: "child", Priority: 1, Dependencies: []string{"parent"}, Lane: reliability.ProviderLanePowerShellCIM, BudgetClass: reliability.ProviderBudgetMedium, Collect: func(context.Context) ([]evidence.Observation, []string) { return nil, nil }},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := runNamedEvidenceCollectorsForPlatform(ctx, 2, collectors, "windows")
	if err != nil {
		t.Fatal(err)
	}
	tel := out[1].provider.Scheduling
	if tel == nil || tel.ReadyAt == nil || tel.DependencyWaitMS < 10 || tel.ParentRemainingAtStartMS <= 0 || tel.AdmissionMinimumMS <= 0 {
		t.Fatalf("incomplete Fix57 critical-path telemetry: %#v", tel)
	}
}
