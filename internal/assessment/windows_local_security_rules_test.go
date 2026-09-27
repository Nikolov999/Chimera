package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase067Index(platform string, values map[string]string, accts ...accounts.Account) Index {
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("account.platform", platform, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.count", len(accts), "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.policy.provider", map[string]any{"state": "OBSERVED"}, "test", at, evidence.ConfidenceHigh),
	}
	for k, v := range values {
		obs = append(obs, evidence.NewObserved("account.policy."+k, v, "test", at, evidence.ConfidenceExact))
	}
	for i, a := range accts {
		obs = append(obs, evidence.NewObserved("account.item.test-"+string(rune('a'+i)), a, "test", at, evidence.ConfidenceHigh))
	}
	return NewIndex(obs)
}

func phase067Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range WindowsLocalSecurityRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestWindowsLocalSecurityRulesContract(t *testing.T) {
	rules := WindowsLocalSecurityRules()
	if len(rules) != 9 {
		t.Fatalf("rule count=%d want 9", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestPhase067UACDisabledFails(t *testing.T) {
	got := phase067Rule(t, "CHM-ID-007").Evaluate(phase067Index("windows", map[string]string{"uac-enabled": "DISABLED"}))
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPhase067RemoteTokenFilteringDisabledFails(t *testing.T) {
	got := phase067Rule(t, "CHM-ID-011").Evaluate(phase067Index("windows", map[string]string{"remote-uac-filtering": "DISABLED"}))
	if got.Status != StatusFail {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPhase067GuestEnabledFails(t *testing.T) {
	guest := accounts.Account{Principal: `HOST\\Guest`, SID: "S-1-5-21-1-501", EnabledState: "ENABLED"}
	got := phase067Rule(t, "CHM-ID-012").Evaluate(phase067Index("windows", nil, guest))
	if got.Status != StatusFail {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPhase067BuiltinAdminDisabledPassesRegardlessOfApprovalMode(t *testing.T) {
	admin := accounts.Account{Principal: `HOST\\Administrator`, SID: "S-1-5-21-1-500", EnabledState: "DISABLED"}
	got := phase067Rule(t, "CHM-ID-010").Evaluate(phase067Index("windows", map[string]string{"builtin-admin-approval-mode": "DISABLED"}, admin))
	if got.Status != StatusPass {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPhase067AnonymousAccessComposite(t *testing.T) {
	idx := phase067Index("windows", map[string]string{
		"everyone-includes-anonymous": "DISABLED",
		"restrict-anonymous-sam":      "ENABLED",
		"restrict-anonymous":          "NO_SAM_ACCOUNT_ENUMERATION",
	})
	got := phase067Rule(t, "CHM-ID-014").Evaluate(idx)
	if got.Status != StatusPass {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
	idx = phase067Index("windows", map[string]string{
		"everyone-includes-anonymous": "ENABLED",
		"restrict-anonymous-sam":      "ENABLED",
		"restrict-anonymous":          "NO_SAM_ACCOUNT_ENUMERATION",
	})
	got = phase067Rule(t, "CHM-ID-014").Evaluate(idx)
	if got.Status != StatusFail {
		t.Fatalf("unexpected insecure evaluation: %#v", got)
	}
}

func TestPhase067NotApplicableOffWindows(t *testing.T) {
	got := phase067Rule(t, "CHM-ID-007").Evaluate(phase067Index("linux", nil))
	if got.Status != StatusPass || got.Applicability != NotApplicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}
