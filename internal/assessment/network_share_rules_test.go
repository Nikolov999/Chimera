package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
)

func TestPhase085MountedGuestShareFails(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	rec := fsinv.NetworkShareRecord{ID: "m1", Direction: fsinv.NetworkShareDirectionMounted, Protocol: fsinv.NetworkShareProtocolSMB, LocalPath: "/mnt/public", Remote: "//srv/public", AccessMode: fsinv.MountAccessReadWrite, Writable: true, AccessKnown: true, GuestAllowed: true, BroadAccess: true, BroadWrite: true, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("filesystem.source.network-mounted-shares", fsinv.SourceStatus{ID: "network-mounted-shares", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.network_share.m1", rec, "test", now, evidence.ConfidenceExact),
	})
	got := phase085Rule(t, "CHM-FS-017").Evaluate(idx)
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPhase085NFSBroadWriteFailsAndBroadReadWarns(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	src := evidence.NewObserved("filesystem.source.nfs-exports", fsinv.SourceStatus{ID: "nfs-exports", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh)
	write := fsinv.NetworkShareRecord{ID: "n1", Direction: fsinv.NetworkShareDirectionExported, Protocol: fsinv.NetworkShareProtocolNFS, LocalPath: "/srv/data", Remote: "*", AccessMode: fsinv.MountAccessReadWrite, Writable: true, AccessKnown: true, BroadAccess: true, BroadWrite: true, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	got := phase085Rule(t, "CHM-FS-018").Evaluate(NewIndex([]evidence.Observation{src, evidence.NewObserved("filesystem.network_share.n1", write, "test", now, evidence.ConfidenceHigh)}))
	if got.Status != StatusFail {
		t.Fatalf("broad write status=%s want FAIL: %#v", got.Status, got)
	}
	read := write
	read.ID = "n2"
	read.AccessMode = fsinv.MountAccessReadOnly
	read.Writable = false
	read.ReadOnly = true
	read.BroadWrite = false
	got = phase085Rule(t, "CHM-FS-018").Evaluate(NewIndex([]evidence.Observation{src, evidence.NewObserved("filesystem.network_share.n2", read, "test", now, evidence.ConfidenceHigh)}))
	if got.Status != StatusWarn {
		t.Fatalf("broad read status=%s want WARN: %#v", got.Status, got)
	}
}

func TestPhase085NFSIdentityBoundaryFails(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	rec := fsinv.NetworkShareRecord{ID: "n1", Direction: fsinv.NetworkShareDirectionExported, Protocol: fsinv.NetworkShareProtocolNFS, LocalPath: "/srv/root", Remote: "10.0.0.0/24", AccessMode: fsinv.MountAccessReadWrite, Writable: true, AccessKnown: true, DangerousOptions: []string{"no_root_squash"}, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("filesystem.source.nfs-exports", fsinv.SourceStatus{ID: "nfs-exports", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.network_share.n1", rec, "test", now, evidence.ConfidenceHigh),
	})
	got := phase085Rule(t, "CHM-FS-019").Evaluate(idx)
	if got.Status != StatusFail {
		t.Fatalf("status=%s want FAIL: %#v", got.Status, got)
	}
}

func TestPhase085MountedPermissionBypassFails(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	rec := fsinv.NetworkShareRecord{ID: "m1", Direction: fsinv.NetworkShareDirectionMounted, Protocol: fsinv.NetworkShareProtocolSMB, LocalPath: "/mnt/team", Remote: "//srv/team", AccessMode: fsinv.MountAccessReadWrite, Writable: true, AccessKnown: true, DangerousOptions: []string{"noperm"}, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("filesystem.source.network-mounted-shares", fsinv.SourceStatus{ID: "network-mounted-shares", State: evidence.StateObserved, Source: "test", ItemCount: 1}, "test", now, evidence.ConfidenceHigh),
		evidence.NewObserved("filesystem.network_share.m1", rec, "test", now, evidence.ConfidenceHigh),
	})
	got := phase085Rule(t, "CHM-FS-020").Evaluate(idx)
	if got.Status != StatusFail {
		t.Fatalf("status=%s want FAIL: %#v", got.Status, got)
	}
}

func TestPhase085NetworkShareRulesAreInCatalog(t *testing.T) {
	for _, id := range []string{"CHM-FS-017", "CHM-FS-018", "CHM-FS-019", "CHM-FS-020"} {
		_ = phase085Rule(t, id)
	}
}

func phase085Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range FilesystemRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s missing", id)
	return Rule{}
}
