//go:build linux

package processes

import (
	"context"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix64ExitedProcessDoesNotDegradeMemoryProvider(t *testing.T) {
	items := []Process{{PID: 999999999, PPID: 1, Name: "short-lived", ExecutablePath: "/usr/bin/short-lived"}}
	got, stats := collectExecutionMemoryPlatform(context.Background(), items)
	if len(got) != 1 {
		t.Fatalf("unexpected transient memory record count: %#v", got)
	}
	if stats.State != evidence.StateObserved || stats.Count != 1 || stats.Missing != 0 || stats.Denied != 0 {
		t.Fatalf("transient process exit must not degrade memory provider health: %#v", stats)
	}
	if got[0].State != "UNKNOWN" || got[0].Reason != "process exited before executable-memory enrichment completed" {
		t.Fatalf("unexpected transient executable-memory context: %#v", got[0])
	}
}
