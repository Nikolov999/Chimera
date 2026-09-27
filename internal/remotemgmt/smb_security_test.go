package remotemgmt

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestSMBSecurityValidationNotApplicable(t *testing.T) {
	s := SMBSecurity{Schema: smbSecuritySchemaVersion, State: smbStateNotApplicable, Platform: "linux"}
	if err := validateSMBSecurity(s); err != nil {
		t.Fatalf("not-applicable SMB report should validate: %v", err)
	}
}

func TestNormalizeSMBSecuritySummary(t *testing.T) {
	s := SMBSecurity{
		Schema: smbSecuritySchemaVersion, State: smbStateComplete, Platform: "linux",
		ShareInventoryState: evidence.StateObserved, ShareInventorySource: "test",
		Settings: []SMBSetting{{Name: "signing", Scope: "server", State: evidence.StateObserved, Value: "mandatory", Source: "test", Confidence: evidence.ConfidenceHigh}},
		Shares:   []SMBShare{{Name: "public", Path: "/srv/public", State: evidence.StateObserved, GuestAllowed: true, Writable: true, WritableKnown: true, BroadRead: true, BroadWrite: true, AccessKnown: true, Source: "test", Confidence: evidence.ConfidenceHigh}},
	}
	s = normalizeSMBSecurity(s)
	if s.Summary.GuestShares != 1 || s.Summary.WritableGuestShares != 1 || s.Summary.BroadWriteShares != 1 {
		t.Fatalf("unexpected summary: %#v", s.Summary)
	}
	if err := validateSMBSecurity(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSMBSensitivePath(t *testing.T) {
	if !smbSensitivePath("/etc") || !smbSensitivePath(`/Windows/System32`) && !smbSensitivePath(`C:\Windows\System32`) {
		t.Fatal("expected sensitive system path classification")
	}
	if smbSensitivePath("/srv/team") {
		t.Fatal("ordinary data share path should not be classified as sensitive")
	}
}
