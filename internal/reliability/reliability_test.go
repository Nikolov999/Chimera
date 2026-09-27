package reliability

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContractValid(t *testing.T) {
	if err := ValidateContract(); err != nil {
		t.Fatal(err)
	}
	if got := BoundWorkers(MaxWorkers+100, MaxWorkers+100); got != MaxWorkers {
		t.Fatalf("bounded workers=%d want=%d", got, MaxWorkers)
	}
}

func TestStableReadFileAndSizeLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := StableReadFile(p, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"ok":true}` {
		t.Fatalf("read=%q", got)
	}
	if _, err := StableReadFile(p, 2); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestCollectorContextHasBoundedDeadline(t *testing.T) {
	ctx, cancel := CollectorContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("collector context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > CollectorTimeout+time.Second {
		t.Fatalf("unexpected collector deadline %s", remaining)
	}
}

func TestLimitStringsDeterministicAndBounded(t *testing.T) {
	got := LimitStrings([]string{"z", "a", "z", "b", "c"}, 3)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || !strings.Contains(got[2], "omitted") {
		t.Fatalf("unexpected limited strings %#v", got)
	}
}

func TestCollectionContextReservesHardDeadlineTime(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelParent()
	ctx, cancel, reserve := CollectionContext(parent)
	defer cancel()
	if reserve <= 0 || reserve >= 500*time.Millisecond {
		t.Fatalf("unexpected evaluation reserve %s", reserve)
	}
	parentDeadline, _ := parent.Deadline()
	collectionDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("collection context has no soft deadline")
	}
	if !collectionDeadline.Before(parentDeadline) {
		t.Fatalf("collection deadline %s does not precede hard deadline %s", collectionDeadline, parentDeadline)
	}
	delta := parentDeadline.Sub(collectionDeadline)
	if delta < reserve-time.Millisecond || delta > reserve+time.Millisecond {
		t.Fatalf("deadline reserve delta=%s reserve=%s", delta, reserve)
	}
}

func TestBoundCollectionWorkersUsesIndependentCeiling(t *testing.T) {
	if got := BoundCollectionWorkers(MaxWorkers, MaxWorkers); got != MaxCollectionWorkers {
		t.Fatalf("collection workers=%d want=%d", got, MaxCollectionWorkers)
	}
}

func TestWindowsProviderBudgetClasses(t *testing.T) {
	if got := ProviderBudgetFor("windows", ProviderBudgetFast); got != WindowsFastCollectorTimeout {
		t.Fatalf("fast budget=%s want=%s", got, WindowsFastCollectorTimeout)
	}
	if got := ProviderBudgetFor("windows", ProviderBudgetMedium); got != WindowsMediumCollectorTimeout {
		t.Fatalf("medium budget=%s want=%s", got, WindowsMediumCollectorTimeout)
	}
	if got := ProviderBudgetFor("windows", ProviderBudgetHeavy); got != WindowsHeavyCollectorTimeout {
		t.Fatalf("heavy budget=%s want=%s", got, WindowsHeavyCollectorTimeout)
	}
	if !(WindowsFastCollectorTimeout < WindowsMediumCollectorTimeout && WindowsMediumCollectorTimeout < WindowsHeavyCollectorTimeout) {
		t.Fatalf("Windows budget classes are not ordered: fast=%s medium=%s heavy=%s", WindowsFastCollectorTimeout, WindowsMediumCollectorTimeout, WindowsHeavyCollectorTimeout)
	}
}

func TestNonWindowsBudgetClassesPreservePortableCollectorCeiling(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "freebsd"} {
		for _, class := range []ProviderBudgetClass{ProviderBudgetFast, ProviderBudgetMedium, ProviderBudgetHeavy} {
			if got := ProviderBudgetFor(platform, class); got != CollectorTimeout {
				t.Fatalf("%s/%s budget=%s want portable %s", platform, class, got, CollectorTimeout)
			}
		}
	}
}

func TestStageContextReservesParentCleanupTime(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelParent()
	parentDeadline, _ := parent.Deadline()
	child, cancelChild, decision := StageContext(parent, 10*time.Second, 500*time.Millisecond, ProviderBudgetHeavy)
	defer cancelChild()
	childDeadline, ok := child.Deadline()
	if !ok {
		t.Fatal("stage context has no deadline")
	}
	if !childDeadline.Before(parentDeadline) {
		t.Fatalf("child deadline %s must precede parent %s", childDeadline, parentDeadline)
	}
	if decision.Applied >= decision.ParentRemaining {
		t.Fatalf("applied=%s must be less than parent remaining=%s", decision.Applied, decision.ParentRemaining)
	}
	if !decision.CappedByParent {
		t.Fatalf("expected parent-capped decision: %#v", decision)
	}
	if decision.Reserve <= 0 {
		t.Fatalf("expected positive cleanup reserve: %#v", decision)
	}
}

func TestWindowsCollectorContextUsesRequestedClassAndParentCap(t *testing.T) {
	ctx, cancel, decision := CollectorContextFor(context.Background(), "windows", ProviderBudgetHeavy)
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("unbounded-parent Windows collector has no class deadline")
	}
	cancel()
	if decision.Class != ProviderBudgetHeavy || decision.Requested != WindowsHeavyCollectorTimeout || decision.Applied != WindowsHeavyCollectorTimeout {
		t.Fatalf("unexpected heavy decision %#v", decision)
	}

	parent, cancelParent := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelParent()
	child, cancelChild, capped := CollectorContextFor(parent, "windows", ProviderBudgetHeavy)
	defer cancelChild()
	if _, ok := child.Deadline(); !ok {
		t.Fatal("bounded Windows child has no deadline")
	}
	if !capped.CappedByParent || capped.Applied >= capped.ParentRemaining {
		t.Fatalf("Windows child did not preserve parent reserve: %#v", capped)
	}
}

func TestFix44WindowsExecutionLaneLimits(t *testing.T) {
	workers := MaxCollectionWorkers
	if got := ExecutionLaneLimit("windows", ProviderLanePowerShellCIM, workers); got != WindowsPowerShellCIMLaneLimit {
		t.Fatalf("powershell lane limit=%d want=%d", got, WindowsPowerShellCIMLaneLimit)
	}
	if got := ExecutionLaneLimit("windows", ProviderLaneHeavySecurity, workers); got != WindowsHeavySecurityLaneLimit {
		t.Fatalf("heavy lane limit=%d want=%d", got, WindowsHeavySecurityLaneLimit)
	}
	if got := ExecutionLaneLimit("windows", ProviderLaneNativeLight, workers); got != workers {
		t.Fatalf("native lane limit=%d want=%d", got, workers)
	}
	if got := WindowsManagementLimit("windows", workers); got != WindowsManagementLaneLimit {
		t.Fatalf("management limit=%d want=%d", got, WindowsManagementLaneLimit)
	}
	if got := ExecutionLaneLimit("linux", ProviderLanePowerShellCIM, workers); got != workers {
		t.Fatalf("non-Windows lane unexpectedly constrained: %d", got)
	}
}

func TestFix44ExecutionLaneLimitsRespectSmallWorkerPools(t *testing.T) {
	for _, workers := range []int{1, 2} {
		if got := ExecutionLaneLimit("windows", ProviderLanePowerShellCIM, workers); got != workers {
			t.Fatalf("workers=%d powershell lane=%d", workers, got)
		}
		if got := ExecutionLaneLimit("windows", ProviderLaneHeavySecurity, workers); got != workers {
			t.Fatalf("workers=%d heavy lane=%d", workers, got)
		}
		if got := WindowsManagementLimit("windows", workers); got != workers {
			t.Fatalf("workers=%d management lane=%d", workers, got)
		}
	}
}

func TestFix57WindowsCollectorAdmissionMinimums(t *testing.T) {
	if got := CollectorStartMinimumFor("windows", ProviderBudgetFast); got != WindowsFastCollectorMinimumStart {
		t.Fatalf("fast minimum=%s want=%s", got, WindowsFastCollectorMinimumStart)
	}
	if got := CollectorStartMinimumFor("windows", ProviderBudgetMedium); got != WindowsMediumCollectorMinimumStart {
		t.Fatalf("medium minimum=%s want=%s", got, WindowsMediumCollectorMinimumStart)
	}
	if got := CollectorStartMinimumFor("windows", ProviderBudgetHeavy); got != WindowsHeavyCollectorMinimumStart {
		t.Fatalf("heavy minimum=%s want=%s", got, WindowsHeavyCollectorMinimumStart)
	}
	if got := CollectorStartMinimumFor("linux", ProviderBudgetHeavy); got != 0 {
		t.Fatalf("portable collector gained admission minimum: %s", got)
	}
}

func TestFix57WindowsCollectorStartAllowedRejectsStarvedParent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	allowed, remaining, minimum := CollectorStartAllowed(ctx, "windows", ProviderBudgetMedium)
	if allowed {
		t.Fatalf("starved Windows collector was admitted: remaining=%s minimum=%s", remaining, minimum)
	}
	if minimum != WindowsMediumCollectorMinimumStart || remaining <= 0 {
		t.Fatalf("unexpected admission diagnostics remaining=%s minimum=%s", remaining, minimum)
	}
}

func TestFix57PortableCollectorStartAllowedPreservesBehavior(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	allowed, _, minimum := CollectorStartAllowed(ctx, "linux", ProviderBudgetHeavy)
	if !allowed || minimum != 0 {
		t.Fatalf("portable collector admission changed: allowed=%t minimum=%s", allowed, minimum)
	}
}
