//go:build linux

package processes

import (
	"context"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestLinuxLoadedLibraryCandidate(t *testing.T) {
	for _, path := range []string{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/opt/vendor/plugin.so", "/usr/lib/node_modules/addon.node"} {
		if !linuxLoadedLibraryCandidate(path) {
			t.Fatalf("expected library candidate: %s", path)
		}
	}
	for _, path := range []string{"/home/user/readme.txt", "/tmp/random.bin"} {
		if linuxLoadedLibraryCandidate(path) {
			t.Fatalf("unexpected library candidate: %s", path)
		}
	}
}

func TestFix65ExitedProcessDoesNotCreateModuleProviderGap(t *testing.T) {
	items := []Process{{
		ID: "proc-gone", PID: 999999999, PPID: 1, Name: "gone",
		CollectionSource: "Linux procfs", Confidence: evidence.ConfidenceHigh,
	}}
	got, stats := collectLoadedModulesPlatform(context.Background(), items)
	if len(got) != 1 {
		t.Fatalf("unexpected transient module record count: %#v", got)
	}
	if stats.State != evidence.StateObserved || stats.Count != 1 || stats.Missing != 0 || stats.Denied != 0 {
		t.Fatalf("transient process exit must be handled rather than counted as missing: %#v", stats)
	}
	if got[0].State != "UNKNOWN" || got[0].Reason != "process exited before loaded-module enrichment completed" || got[0].Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected lifecycle-aware module context: %#v", got[0])
	}
}
