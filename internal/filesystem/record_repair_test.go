package filesystem

import (
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestRepairPlatformTempDirectoryRecordsRepairsIncompleteWindowsRow(t *testing.T) {
	in := []TempDirectoryRecord{{Path: `C:\\Users\\demo\\AppData\\Local\\Temp`, State: evidence.StateObserved}}
	out, degraded := repairTempDirectoryRecords(in, PermissionCapability{Model: "NTFS_DACL"})
	if len(out) != 1 || len(degraded) == 0 {
		t.Fatalf("expected one degraded retained record, got records=%d degraded=%v", len(out), degraded)
	}
	r := out[0]
	if r.ID == "" || r.Scope == "" || r.PermissionModel == "" || len(r.DiscoverySources) == 0 || r.CollectionSource == "" || r.Confidence == "" {
		t.Fatalf("repaired temp record remains incomplete: %#v", r)
	}
	if r.State != evidence.StateDegraded {
		t.Fatalf("expected DEGRADED state, got %s", r.State)
	}
}

func TestRepairPlatformTempDirectoryRecordsQuarantinesPathlessWindowsRow(t *testing.T) {
	out, degraded := repairTempDirectoryRecords([]TempDirectoryRecord{{State: evidence.StateObserved}}, PermissionCapability{Model: "NTFS_DACL"})
	if len(out) != 0 || len(degraded) != 1 || !strings.Contains(degraded[0], "missing path identity") {
		t.Fatalf("unexpected quarantine result: records=%#v degraded=%#v", out, degraded)
	}
}

func TestRepairPlatformExecutableRecordsRetainsUsableWindowsRow(t *testing.T) {
	in := []ExecutableRecord{{Path: `C:\\Program Files\\Example\\example.exe`, State: evidence.StateObserved}}
	out, degraded := repairExecutableRecords(in, PermissionCapability{Model: "NTFS_DACL"})
	if len(out) != 1 || len(degraded) == 0 {
		t.Fatalf("expected repaired executable row, got records=%d degraded=%v", len(out), degraded)
	}
	r := out[0]
	if r.ID == "" || r.Directory == "" || r.PermissionModel == "" || r.DiscoverySource == "" || r.CollectionSource == "" || r.Confidence == "" {
		t.Fatalf("repaired executable record remains incomplete: %#v", r)
	}
	if r.State != evidence.StateDegraded {
		t.Fatalf("expected DEGRADED state, got %s", r.State)
	}
}
