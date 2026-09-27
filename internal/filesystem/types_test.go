package filesystem

import (
	"context"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestCollectValid(t *testing.T) {
	inv := Collect(context.Background())
	if err := inv.Validate(); err != nil {
		t.Fatalf("validate filesystem inventory: %v", err)
	}
	if inv.Schema != SchemaVersion || inv.CollectorVersion != CollectorVersion {
		t.Fatalf("unexpected contract: %#v", inv)
	}
	if inv.Summary.Paths == 0 {
		t.Fatal("expected filesystem path inventory")
	}
	if len(inv.Evidence) == 0 {
		t.Fatal("expected normalized evidence")
	}
	if len(inv.TempDirectories) == 0 {
		t.Fatal("expected filesystem inventory to retain temporary-directory security evidence")
	}

	if len(inv.MountBoundaries) == 0 {
		t.Fatal("expected mount/volume inventory")
	}
	for _, m := range inv.MountBoundaries {
		if m.AccessMode == "" || m.Classification == "" || m.EncryptionState == "" || m.BackingSource == "" {
			t.Fatalf("incomplete mount record: %#v", m)
		}
	}
	foundTempSource := false
	foundMountedShareSource := false
	foundNFSExportSource := false
	for _, o := range inv.Evidence {
		if o.Key == "filesystem.source.temporary-directory-security" {
			foundTempSource = true
		}
		if o.Key == "filesystem.source.network-mounted-shares" {
			foundMountedShareSource = true
		}
		if o.Key == "filesystem.source.nfs-exports" {
			foundNFSExportSource = true
		}
	}
	if !foundTempSource {
		t.Fatal("expected filesystem inventory to retain temporary-directory source evidence")
	}
	if !foundMountedShareSource || !foundNFSExportSource {
		t.Fatalf("expected network-share source evidence: mounted=%t nfs_exports=%t", foundMountedShareSource, foundNFSExportSource)
	}
	for _, sh := range inv.NetworkShares {
		if sh.ID == "" || sh.Direction == "" || sh.Protocol == "" || sh.AccessMode == "" || sh.State == "" || sh.CollectionSource == "" || sh.Confidence == "" {
			t.Fatalf("incomplete network-share record: %#v", sh)
		}
	}
}

func TestNormalizeCandidatesDeterministicAndUnique(t *testing.T) {
	got := normalizeCandidates([]candidate{{"root", "/tmp", "a"}, {"ROOT", "/tmp/", "b"}, {"TEMP", "/tmp", "c"}})
	if len(got) != 2 {
		t.Fatalf("expected kind-scoped dedupe, got %#v", got)
	}
	if got[0].Kind != "ROOT" || got[1].Kind != "TEMP" {
		t.Fatalf("expected deterministic kind order: %#v", got)
	}
}

func TestBuildEvidencePreservesUnavailablePathState(t *testing.T) {
	inv := Inventory{CollectedAt: Collect(context.Background()).CollectedAt, PermissionCapability: PermissionCapability{State: evidence.StateObserved, Model: "TEST", Source: "test"}, Summary: Summary{}, Paths: []PathRecord{{ID: "deadbeef", Kind: "ROOT", Path: "/definitely/missing", State: evidence.StateUnavailable, PermissionModel: "TEST", CollectionSource: "test", Confidence: evidence.ConfidenceHigh, Reason: "missing"}}}
	ev := buildEvidence(inv)
	found := false
	for _, o := range ev {
		if o.Key == "filesystem.path.deadbeef" {
			found = true
			if o.State != evidence.StateUnavailable {
				t.Fatalf("unexpected state %s", o.State)
			}
		}
	}
	if !found {
		t.Fatal("missing path evidence")
	}
}
