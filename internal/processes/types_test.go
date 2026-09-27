package processes

import (
	"context"
	"github.com/Nikolov999/chimera/internal/evidence"
	"testing"
	"time"
)

func TestNormalizeDeterministicAndRedacted(t *testing.T) {
	in := []Process{{PID: 9, PPID: 1, Name: "z", CommandLine: CommandLineMetadata{Available: true, ArgumentCount: 2, ByteCount: 10}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}, {PID: 2, PPID: 1, Name: "a", CollectionSource: "test", Confidence: evidence.ConfidenceHigh}}
	out := normalize(in)
	if len(out) != 2 || out[0].PID != 2 || out[1].PID != 9 {
		t.Fatalf("unexpected order: %#v", out)
	}
	for _, p := range out {
		if !p.CommandLine.Redacted {
			t.Fatal("command line must remain redacted")
		}
		if p.ID == "" {
			t.Fatal("stable id missing")
		}
	}
}
func TestInventoryValidateRejectsRawCommandLineSurface(t *testing.T) {
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, CollectedAt: time.Now().UTC(), Processes: []Process{{ID: "x", PID: 1, Name: "x", CommandLine: CommandLineMetadata{Redacted: false}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}}}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
func TestCollectProducesValidEvidence(t *testing.T) {
	inv := Collect(context.Background())
	if err := inv.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestNormalizeRuntimePrivilegesBindsStableProcessID(t *testing.T) {
	items := normalize([]Process{{PID: 77, PPID: 1, Name: "agent", ExecutablePath: "/usr/bin/agent", SessionID: "1", CommandLine: CommandLineMetadata{Redacted: true}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}})
	ctx := []RuntimePrivilegeContext{{PID: 77, Platform: "linux", State: "EXCESS", AccountClass: "USER", PrivilegeSetState: "OBSERVED", HighImpactPrivileges: []string{"CAP_SYS_ADMIN", "CAP_SYS_ADMIN"}, Source: "test", Confidence: evidence.ConfidenceExact}}
	out := normalizeRuntimePrivileges(items, ctx, "linux")
	if len(out) != 1 || out[0].ProcessID != items[0].ID || len(out[0].HighImpactPrivileges) != 1 {
		t.Fatalf("runtime privilege normalization failed: %#v", out)
	}
}

func TestNormalizeExecutionMemoryBindsStableProcessIDAndJITContext(t *testing.T) {
	items := normalize([]Process{{PID: 91, PPID: 1, Name: "java", ExecutablePath: "/usr/bin/java", SessionID: "1", CommandLine: CommandLineMetadata{Redacted: true}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}})
	ctx := []ExecutionMemoryContext{{PID: 91, Platform: "linux", State: "OBSERVED", RegionsObserved: 4, ExecutableRegions: 2, WritableExecutableRegions: 1, Source: "test", Confidence: evidence.ConfidenceHigh}}
	out := normalizeExecutionMemory(items, ctx, "linux")
	if len(out) != 1 || out[0].ProcessID != items[0].ID || !out[0].JITLikeContext || len(out[0].JITBasis) == 0 {
		t.Fatalf("execution-memory normalization failed: %#v", out)
	}
	if len(out[0].Signals) == 0 || out[0].Signals[0] != "writable-executable-memory" {
		t.Fatalf("expected W+X signal: %#v", out[0].Signals)
	}
}
