package scan

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

// collectorRawOutcome is intentionally unsanitized. Post-117 Fix 13 runs
// independent providers concurrently, then performs the accepted-evidence merge
// in declaration order so duplicate ownership and output remain deterministic.
type collectorRawOutcome struct {
	index        int
	name         string
	observations []evidence.Observation
	degraded     []string
	provider     ProviderResult
}

type collectorNode struct {
	index      int
	name       string
	priority   int
	collector  NamedEvidenceCollector
	remaining  int
	dependents []int
	readyAt    time.Time
	scheduled  bool
	done       bool
}

type collectorJob struct {
	index            int
	name             string
	collector        NamedEvidenceCollector
	schedulerStarted time.Time
	readyAt          time.Time
	lane             reliability.ProviderExecutionLane
	laneLimit        int
	managementLimit  int
}

// runNamedEvidenceCollectors executes the scheduler for the current platform.
func runNamedEvidenceCollectors(ctx context.Context, maxWorkers int, collectors []NamedEvidenceCollector) ([]collectorRawOutcome, error) {
	return runNamedEvidenceCollectorsForPlatform(ctx, maxWorkers, collectors, runtime.GOOS)
}

// runNamedEvidenceCollectorsForPlatform executes a bounded dependency graph.
// Dependencies are ordering dependencies, not success dependencies: a dependent
// provider may still consume degraded dependency evidence. Fix44 adds Windows
// execution-lane admission before a provider receives its child budget. Queueing
// therefore consumes the parent collection window, but never silently consumes a
// provider's own FAST/MEDIUM/HEAVY execution allowance.
func runNamedEvidenceCollectorsForPlatform(ctx context.Context, maxWorkers int, collectors []NamedEvidenceCollector, platform string) ([]collectorRawOutcome, error) {
	nodes, err := buildCollectorGraph(collectors)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}

	workers := reliability.BoundCollectionWorkers(maxWorkers, len(nodes))
	if workers < 1 {
		return nil, fmt.Errorf("collector worker pool is empty")
	}
	platform = strings.ToLower(strings.TrimSpace(platform))

	jobs := make(chan collectorJob, workers)
	completed := make(chan collectorRawOutcome, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				allowed, remaining, minimum := reliability.CollectorStartAllowed(ctx, platform, job.collector.BudgetClass)
				if !allowed {
					reason := ctx.Err()
					if reason == nil {
						reason = fmt.Errorf("insufficient remaining assessment budget before provider execution: remaining=%s minimum=%s", remaining.Round(time.Millisecond), minimum)
					}
					now := time.Now().UTC()
					out := skippedCollectorOutcome(job.index, job.name, reason)
					var deadline time.Time
					if d, ok := ctx.Deadline(); ok {
						deadline = d.UTC()
					}
					attachSchedulingTelemetry(&out.provider, platform, job, now, deadline, remaining)
					if out.provider.Scheduling != nil {
						out.provider.Scheduling.SkippedBeforeExecution = true
					}
					completed <- out
					continue
				}
				completed <- collectEvidenceRawSafe(ctx, job.index, job.name, job.collector, platform, job)
			}
		}()
	}

	ready := make([]int, 0, len(nodes))
	schedulerStarted := time.Now().UTC()
	readyNow := schedulerStarted
	for i := range nodes {
		if nodes[i].remaining == 0 {
			nodes[i].readyAt = readyNow
			ready = append(ready, i)
		}
	}
	sortReadyCollectors(ready, nodes)

	outcomes := make([]collectorRawOutcome, len(nodes))
	active := 0
	finished := 0
	budgetExpired := false
	laneActive := map[reliability.ProviderExecutionLane]int{}
	managementActive := 0

	laneFor := func(idx int) reliability.ProviderExecutionLane {
		return reliability.NormalizeExecutionLane(nodes[idx].collector.Lane)
	}
	canAdmit := func(idx int) bool {
		if platform != "windows" {
			return true
		}
		lane := laneFor(idx)
		limit := reliability.ExecutionLaneLimit(platform, lane, workers)
		if limit < 1 || laneActive[lane] >= limit {
			return false
		}
		if reliability.IsWindowsManagementLane(lane) {
			managementLimit := reliability.WindowsManagementLimit(platform, workers)
			if managementLimit < 1 || managementActive >= managementLimit {
				return false
			}
		}
		return true
	}
	admit := func(idx int) collectorJob {
		lane := laneFor(idx)
		laneLimit := reliability.ExecutionLaneLimit(platform, lane, workers)
		managementLimit := 0
		if platform == "windows" {
			laneActive[lane]++
			if reliability.IsWindowsManagementLane(lane) {
				managementActive++
				managementLimit = reliability.WindowsManagementLimit(platform, workers)
			}
		}
		return collectorJob{
			index:            nodes[idx].index,
			name:             nodes[idx].name,
			collector:        nodes[idx].collector,
			schedulerStarted: schedulerStarted,
			readyAt:          nodes[idx].readyAt,
			lane:             lane,
			laneLimit:        laneLimit,
			managementLimit:  managementLimit,
		}
	}
	release := func(idx int) {
		if platform != "windows" || idx < 0 || idx >= len(nodes) {
			return
		}
		lane := laneFor(idx)
		if laneActive[lane] > 0 {
			laneActive[lane]--
		}
		if reliability.IsWindowsManagementLane(lane) && managementActive > 0 {
			managementActive--
		}
	}

	// pickReady scans all currently admissible providers rather than blocking
	// behind one saturated lane. Fix56 also applies bounded Windows-only queue
	// aging so a provider that has been ready for several seconds cannot remain
	// indefinitely behind newly-ready management work. Static priority is still
	// the primary order and non-Windows behavior remains unchanged.
	pickReady := func() int {
		now := time.Now().UTC()
		bestPos := -1
		bestPriority := 0
		bestIndex := 0
		for pos := 0; pos < len(ready); {
			idx := ready[pos]
			if nodes[idx].scheduled || nodes[idx].done {
				ready = append(ready[:pos], ready[pos+1:]...)
				continue
			}
			if canAdmit(idx) {
				effective := effectiveCollectorPriority(nodes[idx], platform, now)
				if bestPos < 0 || effective < bestPriority || (effective == bestPriority && nodes[idx].index < bestIndex) {
					bestPos = pos
					bestPriority = effective
					bestIndex = nodes[idx].index
				}
			}
			pos++
		}
		if bestPos < 0 {
			return -1
		}
		idx := ready[bestPos]
		ready = append(ready[:bestPos], ready[bestPos+1:]...)
		return idx
	}

	scheduleReady := func() {
		for !budgetExpired && active < workers && len(ready) > 0 {
			if ctx.Err() != nil {
				budgetExpired = true
				break
			}
			idx := pickReady()
			if idx == -2 {
				continue
			}
			if idx < 0 {
				break // all ready providers are waiting on lane capacity
			}
			nodes[idx].scheduled = true
			active++
			jobs <- admit(idx)
		}
	}

	markPendingSkipped := func(reason error) {
		now := time.Now().UTC()
		for i := range nodes {
			if nodes[i].scheduled || nodes[i].done {
				continue
			}
			nodes[i].done = true
			out := skippedCollectorOutcome(nodes[i].index, nodes[i].name, reason)
			if platform == "windows" {
				lane := laneFor(i)
				wait := time.Duration(0)
				if !nodes[i].readyAt.IsZero() {
					wait = now.Sub(nodes[i].readyAt)
					if wait < 0 {
						wait = 0
					}
				}
				readyAt := nodes[i].readyAt.UTC()
				dependencyWait := time.Duration(0)
				if !nodes[i].readyAt.IsZero() && !schedulerStarted.IsZero() {
					dependencyWait = nodes[i].readyAt.Sub(schedulerStarted)
					if dependencyWait < 0 {
						dependencyWait = 0
					}
				}
				out.provider.Scheduling = &ProviderSchedulingTelemetry{
					Lane:             string(lane),
					LaneLimit:        reliability.ExecutionLaneLimit(platform, lane, workers),
					ReadyAt:          &readyAt,
					DependencyWaitMS: float64(dependencyWait) / float64(time.Millisecond),
					ManagementLimit: func() int {
						if reliability.IsWindowsManagementLane(lane) {
							return reliability.WindowsManagementLimit(platform, workers)
						}
						return 0
					}(),
					QueueWaitMS:            float64(wait) / float64(time.Millisecond),
					AdmissionMinimumMS:     float64(reliability.CollectorStartMinimumFor(platform, nodes[i].collector.BudgetClass)) / float64(time.Millisecond),
					SkippedBeforeExecution: true,
				}
			}
			outcomes[nodes[i].index] = out
			finished++
		}
	}

	scheduleReady()
	for finished < len(nodes) {
		if active == 0 {
			if budgetExpired || ctx.Err() != nil {
				if !budgetExpired {
					budgetExpired = true
				}
				markPendingSkipped(ctx.Err())
				break
			}
			// A validated DAG with unfinished nodes and no active/ready work should
			// be impossible; retain a defensive guard rather than deadlocking.
			if len(ready) == 0 {
				close(jobs)
				wg.Wait()
				return nil, fmt.Errorf("collector dependency scheduler stalled")
			}
			scheduleReady()
			if active == 0 {
				close(jobs)
				wg.Wait()
				return nil, fmt.Errorf("collector execution-lane scheduler stalled")
			}
			continue
		}

		if budgetExpired {
			out := <-completed
			active--
			nodeIdx := nodeIndexByOriginal(nodes, out.index)
			release(nodeIdx)
			if nodeIdx < 0 || nodes[nodeIdx].done {
				continue
			}
			nodes[nodeIdx].done = true
			outcomes[out.index] = out
			finished++
			continue
		}

		select {
		case out := <-completed:
			active--
			nodeIdx := nodeIndexByOriginal(nodes, out.index)
			release(nodeIdx)
			if nodeIdx < 0 || nodes[nodeIdx].done {
				continue
			}
			nodes[nodeIdx].done = true
			outcomes[out.index] = out
			finished++
			becameReadyAt := time.Now().UTC()
			for _, dependent := range nodes[nodeIdx].dependents {
				nodes[dependent].remaining--
				if nodes[dependent].remaining == 0 && !nodes[dependent].scheduled && !nodes[dependent].done {
					nodes[dependent].readyAt = becameReadyAt
					ready = append(ready, dependent)
				}
			}
			sortReadyCollectors(ready, nodes)
			scheduleReady()
		case <-ctx.Done():
			budgetExpired = true
			markPendingSkipped(ctx.Err())
		}
	}

	close(jobs)
	wg.Wait()
	return outcomes, nil
}

func effectiveCollectorPriority(node collectorNode, platform string, now time.Time) int {
	priority := node.priority
	if strings.ToLower(strings.TrimSpace(platform)) != "windows" || node.readyAt.IsZero() || now.IsZero() {
		return priority
	}
	wait := now.Sub(node.readyAt)
	if wait <= 0 || reliability.WindowsQueueAgingInterval <= 0 {
		return priority
	}
	boost := int(wait / reliability.WindowsQueueAgingInterval)
	if boost > reliability.WindowsQueueAgingMaxBoost {
		boost = reliability.WindowsQueueAgingMaxBoost
	}
	priority -= boost
	if priority < 1 {
		priority = 1
	}
	return priority
}

func collectorPriority(priority int) int {
	if priority <= 0 {
		return 100
	}
	return priority
}

func sortReadyCollectors(ready []int, nodes []collectorNode) {
	sort.SliceStable(ready, func(i, j int) bool {
		a, b := nodes[ready[i]], nodes[ready[j]]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		return a.index < b.index
	})
}

func buildCollectorGraph(collectors []NamedEvidenceCollector) ([]collectorNode, error) {
	nodes := make([]collectorNode, len(collectors))
	byName := make(map[string]int, len(collectors))
	for i, named := range collectors {
		name := strings.TrimSpace(named.Name)
		if name == "" {
			name = fmt.Sprintf("extra-%02d", i+1)
		}
		if named.Collect == nil {
			return nil, fmt.Errorf("evidence collector %q is nil", name)
		}
		if _, exists := byName[name]; exists {
			return nil, fmt.Errorf("duplicate evidence collector name %q", name)
		}
		byName[name] = i
		nodes[i] = collectorNode{index: i, name: name, priority: collectorPriority(named.Priority), collector: named}
	}

	for i := range nodes {
		seenDependency := map[string]struct{}{}
		for _, raw := range nodes[i].collector.Dependencies {
			dep := strings.TrimSpace(raw)
			if dep == "" {
				continue
			}
			if dep == nodes[i].name {
				return nil, fmt.Errorf("evidence collector %q cannot depend on itself", nodes[i].name)
			}
			if _, duplicate := seenDependency[dep]; duplicate {
				continue
			}
			seenDependency[dep] = struct{}{}
			depIdx, ok := byName[dep]
			if !ok {
				return nil, fmt.Errorf("evidence collector %q depends on unknown collector %q", nodes[i].name, dep)
			}
			nodes[i].remaining++
			nodes[depIdx].dependents = append(nodes[depIdx].dependents, i)
		}
	}

	// Validate acyclicity without mutating the runtime dependency counts.
	remaining := make([]int, len(nodes))
	queue := make([]int, 0, len(nodes))
	for i := range nodes {
		remaining[i] = nodes[i].remaining
		if remaining[i] == 0 {
			queue = append(queue, i)
		}
	}
	visited := 0
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		visited++
		for _, dependent := range nodes[i].dependents {
			remaining[dependent]--
			if remaining[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}
	if visited != len(nodes) {
		return nil, fmt.Errorf("evidence collector dependency graph contains a cycle")
	}
	return nodes, nil
}

func nodeIndexByOriginal(nodes []collectorNode, original int) int {
	if original >= 0 && original < len(nodes) && nodes[original].index == original {
		return original
	}
	for i := range nodes {
		if nodes[i].index == original {
			return i
		}
	}
	return -1
}

func collectEvidenceRawSafe(ctx context.Context, index int, name string, named NamedEvidenceCollector, platform string, job collectorJob) (out collectorRawOutcome) {
	started := time.Now().UTC()
	out = collectorRawOutcome{index: index, name: name, provider: ProviderResult{Name: name, State: StateComplete}}
	child, cancel, budget := reliability.CollectorContextFor(ctx, platform, named.BudgetClass)
	defer cancel()
	if platform == "windows" {
		out.provider.Budget = providerBudgetTelemetry(budget)
		var deadline time.Time
		if d, ok := child.Deadline(); ok {
			deadline = d.UTC()
		}
		attachSchedulingTelemetry(&out.provider, platform, job, started, deadline, budget.ParentRemaining)
	}

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				out.provider.PanicContained = true
				out.provider.State = StatePartial
				out.provider.DegradationReasons = append(out.provider.DegradationReasons, reliability.PanicReason(name, recovered))
			}
		}()
		out.observations, out.degraded = named.Collect(child)
		if named.Validate != nil {
			if err := named.Validate(); err != nil {
				out.provider.State = StatePartial
				out.provider.InvalidEvidence++
				out.provider.DegradationReasons = append(out.provider.DegradationReasons, fmt.Sprintf("provider %s typed inventory validation failed: %v", name, err))
				out.observations = nil
			}
		}
	}()

	if err := child.Err(); err != nil {
		if ctx.Err() != nil {
			out.provider.State = StatePartial
			out.provider.DegradationReasons = append(out.provider.DegradationReasons, fmt.Sprintf("provider %s stopped at the reserved collection budget: %v", name, err))
		} else {
			if out.provider.State == StateComplete {
				out.provider.State = StateDegraded
			}
			out.provider.DegradationReasons = append(out.provider.DegradationReasons, fmt.Sprintf("provider %s collector deadline reached: %v", name, err))
		}
	}
	out.provider.DegradationReasons = reliability.LimitStrings(out.provider.DegradationReasons, reliability.MaxDegradationReasons)
	out.degraded = reliability.LimitStrings(out.degraded, reliability.MaxDegradationReasons)
	completedAt := time.Now().UTC()
	out.provider.Timing = timing(started, completedAt)
	if out.provider.Scheduling != nil {
		out.provider.Scheduling.ExecutionDurationMS = float64(completedAt.Sub(started)) / float64(time.Millisecond)
	}
	return out
}

func attachSchedulingTelemetry(provider *ProviderResult, platform string, job collectorJob, started, deadline time.Time, parentRemaining time.Duration) {
	if provider == nil || platform != "windows" {
		return
	}
	queueWait := time.Duration(0)
	if !job.readyAt.IsZero() && !started.IsZero() {
		queueWait = started.Sub(job.readyAt)
		if queueWait < 0 {
			queueWait = 0
		}
	}
	dependencyWait := time.Duration(0)
	if !job.schedulerStarted.IsZero() && !job.readyAt.IsZero() {
		dependencyWait = job.readyAt.Sub(job.schedulerStarted)
		if dependencyWait < 0 {
			dependencyWait = 0
		}
	}
	telemetry := &ProviderSchedulingTelemetry{
		Lane:                     string(reliability.NormalizeExecutionLane(job.lane)),
		LaneLimit:                job.laneLimit,
		ManagementLimit:          job.managementLimit,
		DependencyWaitMS:         float64(dependencyWait) / float64(time.Millisecond),
		QueueWaitMS:              float64(queueWait) / float64(time.Millisecond),
		ParentRemainingAtStartMS: float64(parentRemaining) / float64(time.Millisecond),
		AdmissionMinimumMS:       float64(reliability.CollectorStartMinimumFor(platform, job.collector.BudgetClass)) / float64(time.Millisecond),
	}
	if !job.readyAt.IsZero() {
		r := job.readyAt.UTC()
		telemetry.ReadyAt = &r
	}
	if !started.IsZero() {
		s := started.UTC()
		telemetry.ExecutionStartedAt = &s
	}
	if !deadline.IsZero() {
		d := deadline.UTC()
		telemetry.DeadlineAt = &d
	}
	provider.Scheduling = telemetry
}

func skippedCollectorOutcome(index int, name string, reason error) collectorRawOutcome {
	at := time.Now().UTC()
	text := "reserved collection budget reached before provider execution"
	if reason != nil {
		text += ": " + reason.Error()
	}
	return collectorRawOutcome{
		index: index,
		name:  name,
		provider: ProviderResult{
			Name:               name,
			State:              StateSkipped,
			Timing:             timing(at, at),
			DegradationReasons: []string{text},
		},
	}
}

func finalizeCollectorOutcome(out collectorRawOutcome, seen map[string]struct{}, globalRemaining int) (observations []evidence.Observation, degraded []string, provider ProviderResult) {
	provider = out.provider
	degraded = append([]string(nil), out.degraded...)
	if provider.State == StateSkipped {
		return nil, degraded, provider
	}
	limit := reliability.MaxProviderEvidence
	if globalRemaining < limit {
		limit = globalRemaining
	}
	accepted, issues, invalid, duplicate, truncated := sanitizeEvidence(out.name, out.observations, seen, limit)
	provider.InvalidEvidence += invalid
	provider.DuplicateEvidence += duplicate
	provider.Truncated = truncated || len(out.observations) > limit
	provider.DegradationReasons = append(provider.DegradationReasons, issues...)
	if (provider.InvalidEvidence > 0 || duplicate > 0 || provider.Truncated || len(degraded) > 0) && provider.State == StateComplete {
		provider.State = StateDegraded
	}
	if len(out.observations) > 0 && len(accepted) == 0 && provider.State == StateDegraded {
		provider.State = StatePartial
	}
	if globalRemaining == 0 && len(out.observations) > 0 {
		provider.State = StatePartial
		provider.Truncated = true
		provider.DegradationReasons = append(provider.DegradationReasons, "global evidence budget exhausted before provider evidence could be accepted")
	}
	provider.Evidence = countEvidence(accepted)
	provider.DegradationReasons = reliability.LimitStrings(provider.DegradationReasons, reliability.MaxDegradationReasons)
	degraded = reliability.LimitStrings(degraded, reliability.MaxDegradationReasons)
	return accepted, degraded, provider
}
