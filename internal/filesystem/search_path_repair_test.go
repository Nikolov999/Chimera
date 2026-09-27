package filesystem

import (
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix17RepairSearchPathRecordKeepsUsablePartialRecord(t *testing.T) {
	in := []SearchPathRecord{{
		Path:  "/example/bin",
		State: evidence.StateObserved,
	}}
	out, degraded := repairSearchPathRecords(in, PermissionCapability{Model: "TEST_PERMISSIONS"})
	if len(out) != 1 {
		t.Fatalf("expected one retained record, got %d", len(out))
	}
	got := out[0]
	if got.State != evidence.StateDegraded {
		t.Fatalf("expected repaired record to be degraded, got %s", got.State)
	}
	if got.ID == "" || got.PermissionModel != "TEST_PERMISSIONS" || got.CollectionSource == "" || got.Confidence == "" {
		t.Fatalf("repaired record still incomplete: %#v", got)
	}
	if len(got.Contexts) == 0 || len(got.DiscoverySources) == 0 {
		t.Fatalf("expected fallback provenance, got %#v", got)
	}
	if len(degraded) == 0 || !strings.Contains(degraded[0], "degraded") {
		t.Fatalf("expected explicit degradation reason, got %#v", degraded)
	}
}

func TestFix17RepairSearchPathRecordQuarantinesMissingIdentity(t *testing.T) {
	out, degraded := repairSearchPathRecords([]SearchPathRecord{{State: evidence.StateObserved}}, PermissionCapability{Model: "TEST_PERMISSIONS"})
	if len(out) != 0 {
		t.Fatalf("record without path identity must be quarantined, got %#v", out)
	}
	if len(degraded) != 1 || !strings.Contains(degraded[0], "missing path identity") {
		t.Fatalf("expected quarantine reason, got %#v", degraded)
	}
}
