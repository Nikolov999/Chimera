package assessment

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase071BaseIndex() Index {
	at := time.Now().UTC()
	return Index{
		"account.platform":                                         evidence.NewObserved("account.platform", "darwin", "test", at, evidence.ConfidenceExact),
		"account.macos_authorization.provider":                     evidence.NewObserved("account.macos_authorization.provider", map[string]any{"state": "OBSERVED"}, "test", at, evidence.ConfidenceHigh),
		"account.macos_authorization.filevault":                    evidence.NewObserved("account.macos_authorization.filevault", "ENABLED", "test", at, evidence.ConfidenceExact),
		"account.macos_authorization.login.automatic-login":        evidence.NewObserved("account.macos_authorization.login.automatic-login", "DISABLED", "test", at, evidence.ConfidenceExact),
		"account.macos_authorization.login.guest-login":            evidence.NewObserved("account.macos_authorization.login.guest-login", "DISABLED", "test", at, evidence.ConfidenceExact),
		"account.macos_authorization.login.disable-fde-auto-login": evidence.NewObserved("account.macos_authorization.login.disable-fde-auto-login", "ENABLED", "test", at, evidence.ConfidenceExact),
	}
}

func phase071Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range MacOSAuthorizationRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestMacOSAuthorizationRulesContract(t *testing.T) {
	rules := MacOSAuthorizationRules()
	want := []string{"CHM-ID-032", "CHM-ID-033", "CHM-ID-034", "CHM-ID-035", "CHM-ID-036", "CHM-ID-037", "CHM-ID-038"}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, id := range want {
		if rules[i].ID != id {
			t.Fatalf("rule %d id=%s want=%s", i, rules[i].ID, id)
		}
		if err := rules[i].Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMacFileVaultAndLoginRules(t *testing.T) {
	idx := phase071BaseIndex()
	if got := phase071Rule(t, "CHM-ID-032").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("filevault=%#v", got)
	}
	idx["account.macos_authorization.login.automatic-login"] = evidence.NewObserved("account.macos_authorization.login.automatic-login", "ENABLED", "test", time.Now().UTC(), evidence.ConfidenceExact)
	if got := phase071Rule(t, "CHM-ID-033").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("automatic login=%#v", got)
	}
	if got := phase071Rule(t, "CHM-ID-034").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("guest login=%#v", got)
	}
	if got := phase071Rule(t, "CHM-ID-035").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("fde auto login=%#v", got)
	}
}

func TestMacAuthorizationRightAllowFails(t *testing.T) {
	idx := phase071BaseIndex()
	at := time.Now().UTC()
	right := accounts.MacOSAuthorizationRight{ID: "system-preferences", Name: "system.preferences", State: evidence.StateObserved, Class: "ALLOW", Source: "test", Confidence: evidence.ConfidenceHigh}
	idx["account.macos_authorization.right.system-preferences"] = evidence.NewObserved("account.macos_authorization.right.system-preferences", right, "test", at, evidence.ConfidenceHigh)
	if got := phase071Rule(t, "CHM-ID-036").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("authorization right=%#v", got)
	}
}

func TestMacFileVaultIdentityMappingWarnsOnOrphan(t *testing.T) {
	idx := phase071BaseIndex()
	at := time.Now().UTC()
	item := accounts.MacOSIdentityAuthorization{ID: "macos-auth-a", Principal: "oldadmin", EnabledState: "UNKNOWN", LoginCapability: "UNKNOWN", SecureToken: "UNKNOWN", SecureTokenEvidenceState: evidence.StateUnavailable, FileVaultAuthorized: "AUTHORIZED", FileVaultEvidenceState: evidence.StateObserved, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx["account.macos_authorization.identity.macos-auth-a"] = evidence.NewObserved("account.macos_authorization.identity.macos-auth-a", item, "test", at, evidence.ConfidenceHigh)
	if got := phase071Rule(t, "CHM-ID-037").Evaluate(idx); got.Status != StatusWarn {
		t.Fatalf("mapping=%#v", got)
	}
}

func TestMacAdminSecureTokenWarnsWhenDisabled(t *testing.T) {
	idx := phase071BaseIndex()
	at := time.Now().UTC()
	item := accounts.MacOSIdentityAuthorization{ID: "macos-auth-admin", Principal: "admin", UID: "501", Privileged: true, EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", SecureToken: "DISABLED", SecureTokenEvidenceState: evidence.StateObserved, FileVaultAuthorized: "AUTHORIZED", FileVaultEvidenceState: evidence.StateObserved, Source: "test", Confidence: evidence.ConfidenceHigh}
	idx["account.macos_authorization.identity.macos-auth-admin"] = evidence.NewObserved("account.macos_authorization.identity.macos-auth-admin", item, "test", at, evidence.ConfidenceHigh)
	if got := phase071Rule(t, "CHM-ID-038").Evaluate(idx); got.Status != StatusWarn {
		t.Fatalf("secure token=%#v", got)
	}
}

func TestMacOSAuthorizationRulesNotApplicableOnLinux(t *testing.T) {
	at := time.Now().UTC()
	idx := Index{
		"account.platform":                     evidence.NewObserved("account.platform", "linux", "test", at, evidence.ConfidenceExact),
		"account.macos_authorization.provider": evidence.NewState("account.macos_authorization.provider", evidence.StateNotApplicable, "test", at, evidence.ConfidenceExact, "not applicable"),
	}
	for _, r := range MacOSAuthorizationRules() {
		got := r.Evaluate(idx)
		if got.Status != StatusPass || got.Applicability != NotApplicable {
			t.Fatalf("%s got %#v", r.ID, got)
		}
	}
}

func TestImplementedRulesIncludesPhase071IdentitiesExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		if strings.HasPrefix(r.ID, "CHM-ID-") {
			counts[r.ID]++
		}
	}
	for _, id := range []string{"CHM-ID-032", "CHM-ID-033", "CHM-ID-034", "CHM-ID-035", "CHM-ID-036", "CHM-ID-037", "CHM-ID-038"} {
		if counts[id] != 1 {
			t.Fatalf("%s occurs %d times", id, counts[id])
		}
	}
}
