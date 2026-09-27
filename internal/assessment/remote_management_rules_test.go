package assessment

import (
	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/firewall"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
	"testing"
	"time"
)

func TestPhase060SSHAbsentFirewallFails(t *testing.T) {
	at := time.Now().UTC()
	s := remotemgmt.Surface{ID: "rms-test", Family: "SSH", Role: "REMOTE_ADMIN", ConfiguredState: "ENABLED", RuntimeState: "ACTIVE", ListenerState: "PRESENT", BindingState: "ALL_INTERFACES", FirewallCoverage: firewall.CoverageAbsent, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("remote_management.summary", remotemgmt.Summary{Surfaces: 1}, "test", at, evidence.ConfidenceHigh), evidence.NewObserved("remote_management.surface."+s.ID, s, "test", at, evidence.ConfidenceHigh)})
	got := phase060Rule(t, "CHM-NET-016").Evaluate(idx)
	if got.Status != StatusFail {
		t.Fatalf("got=%#v", got)
	}
}
func TestPhase060RDPFirewallPresentPasses(t *testing.T) {
	at := time.Now().UTC()
	s := remotemgmt.Surface{ID: "rms-test", Family: "RDP", Role: "REMOTE_DESKTOP", ConfiguredState: "ENABLED", RuntimeState: "ACTIVE", ListenerState: "PRESENT", BindingState: "EXTERNAL", FirewallCoverage: firewall.CoveragePresent, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("remote_management.summary", remotemgmt.Summary{Surfaces: 1}, "test", at, evidence.ConfidenceHigh), evidence.NewObserved("remote_management.surface."+s.ID, s, "test", at, evidence.ConfidenceHigh)})
	got := phase060Rule(t, "CHM-NET-017").Evaluate(idx)
	if got.Status != StatusPass {
		t.Fatalf("got=%#v", got)
	}
}
func TestPhase060HighSecurityEnabledWarns(t *testing.T) {
	at := time.Now().UTC()
	s := remotemgmt.Surface{ID: "rms-test", Family: "WINRM", Role: "REMOTE_ADMIN", ConfiguredState: "ENABLED", RuntimeState: "ACTIVE", ListenerState: "PRESENT", BindingState: "LOOPBACK_ONLY", FirewallCoverage: "NOT_APPLICABLE", Source: "test", Confidence: evidence.ConfidenceHigh}
	idx := NewIndex([]evidence.Observation{evidence.NewObserved("remote_management.summary", remotemgmt.Summary{Surfaces: 1}, "test", at, evidence.ConfidenceHigh), evidence.NewObserved("remote_management.surface."+s.ID, s, "test", at, evidence.ConfidenceHigh)})
	got := phase060Rule(t, "CHM-NET-018").EvaluateProfile("high-security", idx)
	if got.Status != StatusWarn {
		t.Fatalf("got=%#v", got)
	}
}
func phase060Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range RemoteManagementRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s missing", id)
	return Rule{}
}
