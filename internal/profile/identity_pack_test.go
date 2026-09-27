package profile

import (
	"testing"

	"github.com/Nikolov999/chimera/internal/assessment"
)

func TestPhase073IdentityPackUsesProfileSeverityFloors(t *testing.T) {
	base := assessment.IdentityAuthenticationRulePack()
	server, err := Resolve("server")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(server, base)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, d := range applied.Decisions {
		if d.RuleID != "CHM-ID-029" {
			continue
		}
		found = true
		if d.BaseSeverity != assessment.SeverityLow || d.EffectiveSeverity != assessment.SeverityMedium || !d.Applicable {
			t.Fatalf("unexpected server identity profile decision: %#v", d)
		}
	}
	if !found {
		t.Fatal("CHM-ID-029 profile decision missing")
	}
}

func TestPhase073IdentityPackMinimalProfileIsNotApplicable(t *testing.T) {
	minimal, err := Resolve("minimal")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(minimal, assessment.IdentityAuthenticationRulePack())
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Decisions) != 43 {
		t.Fatalf("identity decision count=%d want 43", len(applied.Decisions))
	}
	for _, d := range applied.Decisions {
		if d.Applicable {
			t.Fatalf("minimal profile unexpectedly enables identity rule %s", d.RuleID)
		}
	}
}
