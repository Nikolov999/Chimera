package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
)

func phase062SMBRule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range SMBSecurityRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing SMB rule %s", id)
	return Rule{}
}

func smbRuleIndex(obs ...evidence.Observation) Index {
	at := time.Date(2026, 8, 19, 11, 30, 0, 0, time.UTC)
	base := []evidence.Observation{evidence.NewObserved("smb_security.applicability", "APPLICABLE", "test", at, evidence.ConfidenceHigh)}
	base = append(base, obs...)
	return NewIndex(base)
}

func smbSettingObs(name, value string) evidence.Observation {
	at := time.Date(2026, 8, 19, 11, 30, 0, 0, time.UTC)
	s := remotemgmt.SMBSetting{Name: name, Scope: "server", State: evidence.StateObserved, Value: value, Source: "test", Confidence: evidence.ConfidenceHigh}
	return evidence.NewObserved("smb_security.setting.server."+name, s, "test", at, evidence.ConfidenceHigh)
}

func TestPhase062LegacySMB1Fails(t *testing.T) {
	got := phase062SMBRule(t, "CHM-NET-025").Evaluate(smbRuleIndex(smbSettingObs("smb1_enabled", "true")))
	if got.Status != StatusFail {
		t.Fatalf("SMB1 enabled should fail: %#v", got)
	}
}

func TestPhase062SambaSMB2MinimumPasses(t *testing.T) {
	got := phase062SMBRule(t, "CHM-NET-025").Evaluate(smbRuleIndex(smbSettingObs("min_protocol", "SMB2_10")))
	if got.Status != StatusPass {
		t.Fatalf("SMB2 minimum should pass: %#v", got)
	}
}

func TestPhase062SigningOptionalWarns(t *testing.T) {
	got := phase062SMBRule(t, "CHM-NET-026").Evaluate(smbRuleIndex(smbSettingObs("signing_required", "false"), smbSettingObs("signing_enabled", "true")))
	if got.Status != StatusWarn {
		t.Fatalf("optional signing should warn: %#v", got)
	}
}

func TestPhase062WritableGuestShareFails(t *testing.T) {
	at := time.Date(2026, 8, 19, 11, 30, 0, 0, time.UTC)
	sh := remotemgmt.SMBShare{ID: "smbs-test", Name: "public", Path: "/srv/public", State: evidence.StateObserved, GuestAllowed: true, Writable: true, WritableKnown: true, BroadRead: true, BroadWrite: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx := smbRuleIndex(
		evidence.NewObserved("smb_security.shares_inventory", map[string]any{"state": "OBSERVED", "count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("smb_security.share.smbs-test", sh, "test", at, evidence.ConfidenceHigh),
	)
	if got := phase062SMBRule(t, "CHM-NET-028").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("writable guest share should fail guest rule: %#v", got)
	}
	if got := phase062SMBRule(t, "CHM-NET-029").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("writable guest share should fail share rule: %#v", got)
	}
}

func TestPhase062AllSharesEncryptedPass(t *testing.T) {
	at := time.Date(2026, 8, 19, 11, 30, 0, 0, time.UTC)
	sh := remotemgmt.SMBShare{ID: "smbs-test", Name: "docs", Path: "/srv/docs", State: evidence.StateObserved, EncryptionRequired: true, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx := smbRuleIndex(
		smbSettingObs("encryption", "desired"),
		evidence.NewObserved("smb_security.shares_inventory", map[string]any{"state": "OBSERVED", "count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("smb_security.share.smbs-test", sh, "test", at, evidence.ConfidenceHigh),
	)
	if got := phase062SMBRule(t, "CHM-NET-027").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("all data shares encrypted should pass: %#v", got)
	}
}
