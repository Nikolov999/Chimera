package processes

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestCountIsolationNamespacesAndApplySummary(t *testing.T) {
	items := normalize([]Process{{PID: 42, PPID: 1, Name: "agent", ExecutablePath: "/usr/bin/agent", SessionID: "1", CommandLine: CommandLineMetadata{Redacted: true}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}})
	c := IsolationContext{
		ProcessID: items[0].ID, PID: 42, Platform: "linux", State: "OBSERVED", IsolationState: "ISOLATED",
		PIDNamespace: true, MountNamespace: true, NetworkNamespace: true, Seccomp: "FILTER", NoNewPrivileges: true,
		AppContainer: "NOT_APPLICABLE", JobObject: "NOT_APPLICABLE", Sandbox: "PROFILED", Source: "test", Confidence: evidence.ConfidenceHigh,
	}
	c.NamespaceCount = countIsolationNamespaces(c)
	if c.NamespaceCount != 3 {
		t.Fatalf("namespace count = %d, want 3", c.NamespaceCount)
	}
	applyIsolationSummaries(items, []IsolationContext{c})
	got := items[0].Isolation
	if got.State != "ISOLATED" || !got.PIDNamespace || !got.MountNamespace || !got.NetworkNamespace || got.Seccomp != "FILTER" || !got.NoNewPrivileges || got.Sandbox != "PROFILED" {
		t.Fatalf("isolation summary not applied: %#v", got)
	}
}

func TestSummaryCountsIsolationPosture(t *testing.T) {
	items := []Process{{PID: 1, Name: "a"}, {PID: 2, Name: "b"}}
	isolation := []IsolationContext{
		{PID: 1, State: "OBSERVED", IsolationState: "ISOLATED", PIDNamespace: true, NamespaceCount: 1, Seccomp: "FILTER", NoNewPrivileges: true, CgroupScoped: true, ContainerHint: true, Sandbox: "ENFORCED"},
		{PID: 2, State: "UNKNOWN", IsolationState: "UNKNOWN", AppContainer: "TRUE", JobObject: "TRUE"},
	}
	s := summarize(items, nil, nil, nil, nil, isolation, nil)
	if s.IsolationObserved != 1 || s.IsolationUnknown != 1 || s.IsolationIsolated != 1 || s.NamespaceIsolated != 1 || s.SeccompFiltered != 1 || s.NoNewPrivileges != 1 || s.ContainerContexts != 1 || s.AppContainerContexts != 1 || s.JobObjectContexts != 1 || s.SandboxContexts != 1 {
		t.Fatalf("unexpected isolation summary: %#v", s)
	}
}
