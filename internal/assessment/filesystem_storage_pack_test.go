package assessment

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	stginv "github.com/Nikolov999/chimera/internal/storage"
)

func TestPhase086FilesystemStoragePackStableContract(t *testing.T) {
	rules := FilesystemStorageRulePack()
	if err := ValidateFilesystemStorageRulePack(rules); err != nil {
		t.Fatalf("ValidateFilesystemStorageRulePack: %v", err)
	}
	if got, want := len(rules), 24; got != want {
		t.Fatalf("rule count=%d want %d", got, want)
	}
	gotIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		gotIDs = append(gotIDs, rule.ID)
	}
	sort.Strings(gotIDs)
	if wantIDs := FilesystemStorageRuleIDs(); !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("stable ID inventory drift\ngot:  %v\nwant: %v", gotIDs, wantIDs)
	}
}

func TestPhase086ImplementedRulesUseFilesystemStoragePackExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, rule := range ImplementedRules() {
		counts[rule.ID]++
	}
	for _, id := range FilesystemStorageRuleIDs() {
		if counts[id] != 1 {
			t.Fatalf("implemented catalog contains %s %d time(s), want exactly 1", id, counts[id])
		}
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("rule set version=%q", RuleSetVersion)
	}
}

func TestPhase086PackRejectsStableIDAndCategoryDrift(t *testing.T) {
	rules := FilesystemStorageRulePack()
	missing := append([]Rule(nil), rules[1:]...)
	if err := ValidateFilesystemStorageRulePack(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing stable ID error=%v", err)
	}

	drifted := append([]Rule(nil), rules...)
	for i := range drifted {
		if strings.HasPrefix(drifted[i].ID, "CHM-STG-") {
			drifted[i].Category = "filesystem"
			break
		}
	}
	if err := ValidateFilesystemStorageRulePack(drifted); err == nil || !strings.Contains(err.Error(), "must use category storage") {
		t.Fatalf("category drift error=%v", err)
	}

	renumbered := append([]Rule(nil), rules...)
	renumbered[0].ID = "CHM-FS-999"
	if err := ValidateFilesystemStorageRulePack(renumbered); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("renumbered ID error=%v", err)
	}
}

func TestPhase086SystemVolumeEncryptionFailsUnencryptedOrInactiveProtection(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	for name, volume := range map[string]stginv.Volume{
		"unencrypted": {
			ID: "sys", MountPoint: "/", SystemVolume: true, Fixed: true,
			EncryptionState: stginv.EncryptionUnencrypted, ProtectionState: stginv.ProtectionDisabled,
			LockState: stginv.LockUnlocked, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
		},
		"protection-disabled": {
			ID: "sys", MountPoint: "/", SystemVolume: true, Fixed: true,
			EncryptionState: stginv.EncryptionEncrypted, ProtectionState: stginv.ProtectionDisabled,
			LockState: stginv.LockUnlocked, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
		},
	} {
		t.Run(name, func(t *testing.T) {
			idx := NewIndex([]evidence.Observation{evidence.NewObserved("storage.volume.sys", volume, "test", now, volume.Confidence)})
			got := phase086Rule(t, "CHM-STG-003").Evaluate(idx)
			if got.Status != StatusFail {
				t.Fatalf("status=%s observed=%s", got.Status, got.ObservedState)
			}
		})
	}
}

func TestPhase086SystemVolumeEncryptionPassesOnlyActiveProtection(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	volume := stginv.Volume{
		ID: "sys", MountPoint: "C:\\\\", SystemVolume: true, Fixed: true,
		EncryptionProduct: "BitLocker", EncryptionState: stginv.EncryptionEncrypted, ProtectionState: stginv.ProtectionEnabled,
		LockState: stginv.LockUnlocked, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact,
	}
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("storage.volume.sys", volume, "test", now, evidence.ConfidenceExact)})
	got := phase086Rule(t, "CHM-STG-003").Evaluate(idx)
	if got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("evaluation=%#v", got)
	}
}

func TestPhase086FixedDataVolumeEncryptionKeepsUnknownMetadataUnknown(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	volume := stginv.Volume{
		ID: "data", MountPoint: "/data", Fixed: true,
		EncryptionState: stginv.EncryptionUnknown, ProtectionState: stginv.ProtectionUnknown,
		LockState: stginv.LockUnknown, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceMedium,
		Reason: "block encryption metadata unavailable",
	}
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("storage.volume.data", volume, "test", now, evidence.ConfidenceMedium)})
	got := phase086Rule(t, "CHM-STG-004").Evaluate(idx)
	if got.Status != StatusUnknown {
		t.Fatalf("evaluation=%#v", got)
	}
}

func phase086Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, rule := range FilesystemStorageRulePack() {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}
