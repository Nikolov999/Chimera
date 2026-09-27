//go:build linux

package storage

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseLinuxSwapsTreatsZramAsVolatile(t *testing.T) {
	raw := "Filename Type Size Used Priority\n/dev/zram0 partition 4096 1024 100\n"
	areas := parseLinuxSwaps(raw, nil)
	if len(areas) != 1 {
		t.Fatalf("areas=%d", len(areas))
	}
	if areas[0].EncryptionState != EncryptionNotApplicable || areas[0].EncryptionProduct != "zram" || areas[0].Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected zram posture: %+v", areas[0])
	}
}

func TestParseLinuxSwapsInheritsEncryptedContainingVolume(t *testing.T) {
	volumes := []Volume{{MountPoint: "/", Device: "/dev/mapper/cryptroot", EncryptionState: EncryptionEncrypted, EncryptionProduct: "LUKS2/dm-crypt", ProtectionState: ProtectionEnabled, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}}
	raw := "Filename Type Size Used Priority\n/swapfile file 8192 2048 -2\n"
	areas := parseLinuxSwaps(raw, volumes)
	if len(areas) != 1 {
		t.Fatalf("areas=%d", len(areas))
	}
	if areas[0].EncryptionState != EncryptionEncrypted || areas[0].EncryptionProduct != "LUKS2/dm-crypt" {
		t.Fatalf("unexpected swapfile posture: %+v", areas[0])
	}
	if areas[0].SizeBytes != 8192*1024 || areas[0].UsedBytes != 2048*1024 {
		t.Fatalf("unexpected swap sizing: %+v", areas[0])
	}
}
