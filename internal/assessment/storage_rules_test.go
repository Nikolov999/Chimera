package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	stginv "github.com/Nikolov999/chimera/internal/storage"
)

func TestPhase084StorageRulesDetectUnencryptedSwap(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	area := stginv.SwapArea{ID: "swp-test", Path: "/swapfile", Kind: "FILE", Active: true, EncryptionState: stginv.EncryptionUnencrypted, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}
	obs := []evidence.Observation{evidence.NewObserved("storage.swap."+area.ID, area, "test", now, evidence.ConfidenceHigh)}
	findings, err := EvaluateRules(StorageRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusForStorageRule(findings, "CHM-STG-001"); got != StatusFail {
		t.Fatalf("CHM-STG-001 status=%s want FAIL", got)
	}
}

func TestPhase084StorageRulesIgnoreVolatileZramAsPersistentRisk(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	area := stginv.SwapArea{ID: "swp-zram", Path: "/dev/zram0", Kind: "PARTITION", Active: true, EncryptionState: stginv.EncryptionNotApplicable, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	obs := []evidence.Observation{evidence.NewObserved("storage.swap."+area.ID, area, "test", now, evidence.ConfidenceExact)}
	findings, err := EvaluateRules(StorageRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusForStorageRule(findings, "CHM-STG-001"); got != StatusPass {
		t.Fatalf("CHM-STG-001 status=%s want PASS", got)
	}
}

func TestPhase084StorageRulesDetectExposedHibernation(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	h := stginv.HibernationPosture{SupportState: stginv.SupportYes, ConfigurationState: stginv.HibernationEnabled, ExposureState: stginv.ExposureExposed, EncryptionState: stginv.EncryptionUnencrypted, ProtectionBasis: "unencrypted system volume", State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	obs := []evidence.Observation{evidence.NewObserved("storage.hibernation", h, "test", now, evidence.ConfidenceExact)}
	findings, err := EvaluateRules(StorageRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusForStorageRule(findings, "CHM-STG-002"); got != StatusFail {
		t.Fatalf("CHM-STG-002 status=%s want FAIL", got)
	}
}

func TestPhase084StorageRulesPassDisabledHibernation(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	h := stginv.HibernationPosture{SupportState: stginv.SupportYes, ConfigurationState: stginv.HibernationDisabled, ExposureState: stginv.ExposureNotApplicable, EncryptionState: stginv.EncryptionNotApplicable, State: evidence.StateObserved, CollectionSource: "test", Confidence: evidence.ConfidenceExact}
	obs := []evidence.Observation{evidence.NewObserved("storage.hibernation", h, "test", now, evidence.ConfidenceExact)}
	findings, err := EvaluateRules(StorageRules(), obs, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusForStorageRule(findings, "CHM-STG-002"); got != StatusPass {
		t.Fatalf("CHM-STG-002 status=%s want PASS", got)
	}
}

func TestImplementedRulesIncludesPhase084StorageRulesExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		counts[r.ID]++
	}
	for _, id := range []string{"CHM-STG-001", "CHM-STG-002"} {
		if counts[id] != 1 {
			t.Fatalf("%s count=%d want 1", id, counts[id])
		}
	}
	if RuleSetVersion != "chimera.rules/v1" {
		t.Fatalf("rule set version=%q", RuleSetVersion)
	}
}

func statusForStorageRule(findings []Finding, id string) Status {
	for _, f := range findings {
		if f.RuleID == id {
			return f.Status
		}
	}
	return ""
}
