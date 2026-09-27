package storage

import (
	"context"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeAndValidateInventory(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Volumes:     []Volume{{MountPoint: "/", Device: "/dev/dm-0", Filesystem: "ext4", SystemVolume: true, Fixed: true, EncryptionProduct: "LUKS2/dm-crypt", EncryptionState: EncryptionEncrypted, ProtectionState: ProtectionEnabled, LockState: LockUnlocked, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}},
		SwapAreas:   []SwapArea{{Path: "/swapfile", Kind: "FILE", SizeBytes: 4096, Active: true, EncryptionState: EncryptionEncrypted, EncryptionProduct: "LUKS2/dm-crypt", State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}},
		Hibernation: HibernationPosture{SupportState: SupportYes, ConfigurationState: HibernationEnabled, ImagePath: "/swapfile", ExposureState: ExposureProtected, EncryptionState: EncryptionEncrypted, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact},
		Sources:     []SourceStatus{{ID: "test", State: evidence.StateObserved, Source: "test", ItemCount: 3}},
	}
	inv.Volumes = normalizeVolumes(inv.Volumes)
	inv.SwapAreas = normalizeSwapAreas(inv.SwapAreas)
	inv.Hibernation = normalizeHibernation(inv.Hibernation)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Summary = summarize(inv.Volumes, inv.SwapAreas, inv.Hibernation)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if inv.Summary.EncryptedVolumes != 1 || inv.Summary.SystemVolumes != 1 || inv.Summary.EncryptedSwapAreas != 1 || inv.Summary.HibernationExposure != ExposureProtected {
		t.Fatalf("unexpected summary: %+v", inv.Summary)
	}
	if len(inv.Evidence) != 5 {
		t.Fatalf("expected summary, source, volume, swap, and hibernation evidence; got %d", len(inv.Evidence))
	}
}

func TestCollectContract(t *testing.T) {
	inv := Collect(context.Background())
	if inv.Schema != SchemaVersion || inv.CollectorVersion != CollectorVersion {
		t.Fatalf("unexpected collector identity: %+v", inv)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("collect validate: %v", err)
	}
	if inv.Hibernation.ConfigurationState == "" || inv.Hibernation.ExposureState == "" {
		t.Fatalf("hibernation posture missing: %+v", inv.Hibernation)
	}
}
