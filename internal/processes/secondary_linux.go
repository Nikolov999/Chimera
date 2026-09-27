//go:build linux

package processes

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/reliability"
)

// collectConcurrentSecondary prevents one Linux /proc enrichment from starving
// the others. The base process list and trust join are already complete before
// these stages start; each secondary view gets an independent bounded child and
// completed evidence is retained even if a peer stage degrades.
func collectConcurrentSecondary(ctx context.Context, inv *Inventory) bool {
	if inv == nil {
		return true
	}
	const preferredBudget = 8 * time.Second
	type result struct {
		kind string
		path []PathPermissionContext
		mem  []ExecutionMemoryContext
		mods []LoadedModuleContext
		iso  []IsolationContext
		env  []RuntimeEnvironmentContext
		src  SourceStatus
	}
	ch := make(chan result, 5)
	var wg sync.WaitGroup
	launch := func(kind string, fn func(context.Context) result) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child, cancel, _ := reliability.StageContext(ctx, preferredBudget, 500*time.Millisecond, reliability.ProviderBudgetDefault)
			defer cancel()
			r := fn(child)
			r.kind = kind
			ch <- r
		}()
	}
	items := append([]Process(nil), inv.Processes...)
	launch("permissions", func(c context.Context) result {
		return result{path: collectPathPermissions(c, items, inv.Platform)}
	})
	launch("memory", func(c context.Context) result {
		v, src := collectExecutionMemory(c, items, inv.Platform)
		return result{mem: v, src: src}
	})
	launch("modules", func(c context.Context) result {
		v, src := collectLoadedModules(c, items, inv.Platform)
		return result{mods: v, src: src}
	})
	launch("isolation", func(c context.Context) result {
		v, src := collectIsolationPosture(c, items, inv.Platform)
		return result{iso: v, src: src}
	})
	launch("environment", func(c context.Context) result {
		v, src := collectRuntimeEnvironment(c, items, inv.Platform)
		return result{env: v, src: src}
	})
	go func() { wg.Wait(); close(ch) }()

	attach := func(src SourceStatus) {
		if src.ID == "" {
			return
		}
		inv.Sources = append(inv.Sources, src)
		if src.State != evidence.StateObserved && src.State != evidence.StateNotApplicable && src.State != evidence.StateUnsupported && strings.TrimSpace(src.Reason) != "" {
			inv.Degraded = append(inv.Degraded, src.ID+": "+strings.TrimSpace(src.Reason))
		}
	}
	for r := range ch {
		switch r.kind {
		case "permissions":
			inv.PathPermissions = r.path
		case "memory":
			inv.ExecutionMemory = r.mem
			attach(r.src)
		case "modules":
			inv.LoadedModules = r.mods
			attach(r.src)
		case "isolation":
			inv.IsolationPosture = r.iso
			attach(r.src)
		case "environment":
			inv.RuntimeEnvironment = r.env
			attach(r.src)
		}
	}
	return true
}
