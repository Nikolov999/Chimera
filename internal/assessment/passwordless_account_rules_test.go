package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase066AccountIndex(platform string, at time.Time, accts ...accounts.Account) Index {
	obs := []evidence.Observation{
		evidence.NewObserved("account.platform", platform, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.count", len(accts), "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.summary", accounts.Summary{Accounts: len(accts)}, "test", at, evidence.ConfidenceHigh),
	}
	for i, a := range accts {
		if a.ID == "" {
			a.ID = "test-account"
		}
		if a.Principal == "" {
			a.Principal = a.Name
		}
		if a.CollectionSource == "" {
			a.CollectionSource = "test"
		}
		if a.Confidence == "" {
			a.Confidence = evidence.ConfidenceHigh
		}
		obs = append(obs, evidence.NewObserved("account.item.test-"+string(rune('a'+i)), a, "test", at, evidence.ConfidenceHigh))
	}
	return NewIndex(obs)
}

func phase066Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range PasswordlessAccountRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestPasswordlessAccountRulesContract(t *testing.T) {
	rules := PasswordlessAccountRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %s: %v", r.ID, err)
		}
		if r.Category != "identity" {
			t.Fatalf("unexpected category for %s: %s", r.ID, r.Category)
		}
	}
}

func TestEmptyPasswordRuleFailsForEnabledLoginCapableAccount(t *testing.T) {
	at := time.Now().UTC()
	a := accounts.Account{
		Name: "alice", Principal: "alice", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", AccountType: "HUMAN",
		Authentication: accounts.AuthenticationMetadata{State: "OBSERVED", PasswordState: "EMPTY", PasswordRequired: "UNKNOWN", Source: "test"},
	}
	got := phase066Rule(t, "CHM-ID-005").Evaluate(phase066AccountIndex("linux", at, a))
	if got.Status != StatusFail || got.Applicability != Applicable || got.Confidence != evidence.ConfidenceExact {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestEmptyPasswordRulePassesKnownNonEmptyAccounts(t *testing.T) {
	at := time.Now().UTC()
	a := accounts.Account{
		Name: "alice", Principal: "alice", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", AccountType: "HUMAN",
		Authentication: accounts.AuthenticationMetadata{State: "OBSERVED", PasswordState: "PASSWORD_SET", PasswordRequired: "UNKNOWN", Source: "test"},
	}
	got := phase066Rule(t, "CHM-ID-005").Evaluate(phase066AccountIndex("linux", at, a))
	if got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestEmptyPasswordRulePreservesUnknownState(t *testing.T) {
	at := time.Now().UTC()
	a := accounts.Account{
		Name: "alice", Principal: "alice", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", AccountType: "HUMAN",
		Authentication: accounts.AuthenticationMetadata{State: "UNAVAILABLE", PasswordState: "UNKNOWN", PasswordRequired: "UNKNOWN", Source: "test"},
	}
	got := phase066Rule(t, "CHM-ID-005").Evaluate(phase066AccountIndex("darwin", at, a))
	if got.Status != StatusUnknown || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPasswordRequiredRuleFailsOnWindowsFlag(t *testing.T) {
	at := time.Now().UTC()
	a := accounts.Account{
		Name: "localadmin", Principal: "HOST\\localadmin", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", AccountType: "HUMAN", Privileged: true,
		Authentication: accounts.AuthenticationMetadata{State: "OBSERVED", PasswordState: "UNKNOWN", PasswordRequired: "NO", Source: "Win32_UserAccount metadata"},
	}
	got := phase066Rule(t, "CHM-ID-006").Evaluate(phase066AccountIndex("windows", at, a))
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}

func TestPasswordRequiredRuleNotApplicableOutsideWindows(t *testing.T) {
	at := time.Now().UTC()
	a := accounts.Account{
		Name: "alice", Principal: "alice", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", AccountType: "HUMAN",
		Authentication: accounts.AuthenticationMetadata{State: "OBSERVED", PasswordState: "PASSWORD_SET", PasswordRequired: "UNKNOWN", Source: "test"},
	}
	got := phase066Rule(t, "CHM-ID-006").Evaluate(phase066AccountIndex("linux", at, a))
	if got.Status != StatusPass || got.Applicability != NotApplicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
}
