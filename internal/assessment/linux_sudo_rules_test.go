package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase069Index(state evidence.State, grants []accounts.SudoGrant, env []accounts.SudoEnvironmentIssue, paths []accounts.SudoPathIssue, cfg []accounts.SudoConfigPath) Index {
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	obs := []evidence.Observation{evidence.NewObserved("account.platform", "linux", "test", at, evidence.ConfidenceExact)}
	if state == evidence.StateObserved {
		obs = append(obs, evidence.NewObserved("account.sudo.provider", map[string]any{"state": "OBSERVED"}, "test", at, evidence.ConfidenceHigh))
	} else {
		obs = append(obs, evidence.NewState("account.sudo.provider", state, "test", at, evidence.ConfidenceLow, "degraded test provider"))
	}
	for _, grant := range grants {
		obs = append(obs, evidence.NewObserved("account.sudo.grant."+grant.ID, grant, "test", at, evidence.ConfidenceHigh))
	}
	for _, issue := range env {
		obs = append(obs, evidence.NewObserved("account.sudo.environment."+issue.ID, issue, "test", at, evidence.ConfidenceHigh))
	}
	for _, issue := range paths {
		obs = append(obs, evidence.NewObserved("account.sudo.path."+issue.ID, issue, "test", at, evidence.ConfidenceHigh))
	}
	for _, item := range cfg {
		obs = append(obs, evidence.NewObserved("account.sudo.config."+item.ID, item, "test", at, evidence.ConfidenceExact))
	}
	return NewIndex(obs)
}

func phase069Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range LinuxSudoRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestPhase069RuleCatalog(t *testing.T) {
	rules := LinuxSudoRules()
	if len(rules) != 5 {
		t.Fatalf("expected five rules, got %d", len(rules))
	}
	want := map[string]bool{"CHM-ID-021": false, "CHM-ID-022": false, "CHM-ID-023": false, "CHM-ID-024": false, "CHM-ID-025": false}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %s: %v", r.ID, err)
		}
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("unexpected rule %s", r.ID)
		}
		want[r.ID] = true
	}
	for id, ok := range want {
		if !ok {
			t.Fatalf("missing %s", id)
		}
	}
}

func TestPhase069BroadNOPASSWDFails(t *testing.T) {
	grant := accounts.SudoGrant{ID: "g1", Subjects: "alice", Hosts: "ALL", Source: "/etc/sudoers", Line: 10, Commands: []accounts.SudoCommand{{Spec: "ALL", NOPASSWD: true, Unrestricted: true}}}
	got := phase069Rule(t, "CHM-ID-021").Evaluate(phase069Index(evidence.StateObserved, []accounts.SudoGrant{grant}, nil, nil, nil))
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestPhase069UnrestrictedGrantWarns(t *testing.T) {
	grant := accounts.SudoGrant{ID: "g1", Subjects: "%sudo", Hosts: "ALL", Source: "/etc/sudoers", Line: 20, Commands: []accounts.SudoCommand{{Spec: "ALL", Unrestricted: true}}}
	got := phase069Rule(t, "CHM-ID-022").Evaluate(phase069Index(evidence.StateObserved, []accounts.SudoGrant{grant}, nil, nil, nil))
	if got.Status != StatusWarn {
		t.Fatalf("expected WARN, got %#v", got)
	}
}

func TestPhase069UnsafeEnvironmentFails(t *testing.T) {
	issue := accounts.SudoEnvironmentIssue{ID: "e1", Kind: "DANGEROUS_ENV_KEEP", Source: "/etc/sudoers", Line: 4, Detail: "test", Values: []string{"LD_PRELOAD"}}
	got := phase069Rule(t, "CHM-ID-023").Evaluate(phase069Index(evidence.StateObserved, nil, []accounts.SudoEnvironmentIssue{issue}, nil, nil))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestPhase069WritableReferenceFails(t *testing.T) {
	issue := accounts.SudoPathIssue{ID: "p1", Kind: "SCRIPT", Path: "/opt/admin.sh", Source: "/etc/sudoers", Line: 8, Reason: "target is world-writable"}
	got := phase069Rule(t, "CHM-ID-024").Evaluate(phase069Index(evidence.StateObserved, nil, nil, []accounts.SudoPathIssue{issue}, nil))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestPhase069InsecureConfigFails(t *testing.T) {
	item := accounts.SudoConfigPath{ID: "c1", Path: "/etc/sudoers.d/ops", Kind: "FILE", State: evidence.StateObserved, Mode: "0666", Insecure: true, InsecureBasis: []string{"world-writable"}, Source: "test", Confidence: evidence.ConfidenceExact}
	got := phase069Rule(t, "CHM-ID-025").Evaluate(phase069Index(evidence.StateObserved, nil, nil, nil, []accounts.SudoConfigPath{item}))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestPhase069DegradedProviderDoesNotProduceFalsePass(t *testing.T) {
	got := phase069Rule(t, "CHM-ID-021").Evaluate(phase069Index(evidence.StateDenied, nil, nil, nil, nil))
	if got.Status != StatusUnknown || got.Applicability != Applicable {
		t.Fatalf("expected UNKNOWN for denied sudoers content, got %#v", got)
	}
}

func TestPhase069NonLinuxNotApplicable(t *testing.T) {
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	idx := NewIndex([]evidence.Observation{
		evidence.NewObserved("account.platform", "windows", "test", at, evidence.ConfidenceExact),
		evidence.NewState("account.sudo.provider", evidence.StateNotApplicable, "test", at, evidence.ConfidenceExact, "not applicable"),
	})
	got := phase069Rule(t, "CHM-ID-025").Evaluate(idx)
	if got.Status != StatusPass || got.Applicability != NotApplicable {
		t.Fatalf("expected NOT_APPLICABLE, got %#v", got)
	}
}

func TestImplementedRulesIncludesPhase069Identities(t *testing.T) {
	want := map[string]bool{"CHM-ID-021": false, "CHM-ID-022": false, "CHM-ID-023": false, "CHM-ID-024": false, "CHM-ID-025": false}
	seen := map[string]struct{}{}
	for _, r := range ImplementedRules() {
		if _, dup := seen[r.ID]; dup {
			t.Fatalf("duplicate implemented rule id %s", r.ID)
		}
		seen[r.ID] = struct{}{}
		if _, ok := want[r.ID]; ok {
			want[r.ID] = true
		}
	}
	for id, ok := range want {
		if !ok {
			t.Fatalf("implemented catalog missing %s", id)
		}
	}
}
