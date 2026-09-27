package overview

import (
	"strings"
	"testing"
)

func TestFinalizePrivilegeStandardContextAdvertisesOptionalDepth(t *testing.T) {
	p := finalizePrivilege(Privilege{
		Level: "standard-user", Elevated: false, Principal: "fixture",
		AdministrativeGroup: AdminGroupNotMember, ElevationState: "standard",
		CollectionTier: "standard", DetectionSource: "fixture",
	})
	if p.Schema != PrivilegeSchemaVersion {
		t.Fatalf("unexpected schema %q", p.Schema)
	}
	if !p.DeeperEvidenceAvailable || len(p.DeeperEvidence) == 0 {
		t.Fatalf("standard context did not advertise optional deeper evidence: %#v", p)
	}
	if !strings.Contains(strings.ToLower(p.ElevationNote), "deeper evidence available with elevation") {
		t.Fatalf("missing explicit elevation note: %q", p.ElevationNote)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("invalid privilege contract: %v", err)
	}
}

func TestFinalizePrivilegeElevatedContextDoesNotRequestMoreElevation(t *testing.T) {
	p := finalizePrivilege(Privilege{
		Level: "root", Elevated: true, Principal: "fixture",
		AdministrativeGroup: AdminGroupMember, ElevationState: "root",
		CollectionTier: "elevated", DetectionSource: "fixture",
	})
	if p.DeeperEvidenceAvailable || len(p.DeeperEvidence) != 0 {
		t.Fatalf("elevated context incorrectly advertised more elevation: %#v", p)
	}
	if !strings.Contains(strings.ToLower(p.ElevationNote), "remains read-only") {
		t.Fatalf("elevated safety note missing: %q", p.ElevationNote)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("invalid privilege contract: %v", err)
	}
}

func TestFinalizePrivilegeUnknownContextFailsClosed(t *testing.T) {
	p := finalizePrivilege(Privilege{Level: "unknown", Principal: "fixture", AdministrativeGroup: AdminGroupUnknown, CollectionTier: "unknown"})
	if p.DeeperEvidenceAvailable {
		t.Fatal("unknown privilege context must not assume elevation would improve evidence")
	}
	if !strings.Contains(strings.ToLower(p.ElevationNote), "could not be determined") {
		t.Fatalf("unexpected unknown-context note: %q", p.ElevationNote)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("invalid privilege contract: %v", err)
	}
}

func TestPrivilegeValidationRejectsContradictoryTier(t *testing.T) {
	p := finalizePrivilege(Privilege{Level: "root", Elevated: true, AdministrativeGroup: AdminGroupMember, CollectionTier: "standard"})
	// finalizePrivilege intentionally preserves an explicit tier so validation can
	// detect contradictory platform collector output.
	if err := p.Validate(); err == nil {
		t.Fatal("expected contradictory elevated/standard tier to fail validation")
	}
}
