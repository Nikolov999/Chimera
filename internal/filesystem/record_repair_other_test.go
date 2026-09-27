//go:build !windows

package filesystem

import "testing"

func TestNonWindowsPlatformRepairDoesNotSynthesizeMissingFields(t *testing.T) {
	temp := []TempDirectoryRecord{{Path: "/tmp"}}
	got, degraded := repairPlatformTempDirectoryRecords(temp, PermissionCapability{Model: "POSIX_MODE"})
	if len(degraded) != 0 || len(got) != 1 {
		t.Fatalf("unexpected non-Windows repair result: %#v %#v", got, degraded)
	}
	if got[0].State != "" || got[0].PermissionModel != "" || got[0].CollectionSource != "" {
		t.Fatalf("non-Windows repair must not synthesize provider fields: %#v", got[0])
	}
}
