package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase065AccountIndex(platform string, at time.Time, accts ...accounts.Account) Index {
	obs := []evidence.Observation{
		evidence.NewObserved("account.platform", platform, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.count", len(accts), "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.inventory.summary", map[string]any{"accounts": len(accts)}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("account.source.test", map[string]any{"state": "OBSERVED", "item_count": len(accts)}, "test", at, evidence.ConfidenceHigh),
	}
	for i, a := range accts {
		obs = append(obs, evidence.NewObserved("account.item.test-"+string(rune('a'+i)), a, "test", at, evidence.ConfidenceHigh))
	}
	return NewIndex(obs)
}

func phase065Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range PrivilegedAccountRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestPhase065RuleCatalog(t *testing.T) {
	rules := PrivilegedAccountRules()
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	want := map[string]bool{"CHM-ID-001": false, "CHM-ID-002": false, "CHM-ID-003": false, "CHM-ID-004": false}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %s: %v", r.ID, err)
		}
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("unexpected rule id %s", r.ID)
		}
		want[r.ID] = true
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("missing %s", id)
		}
	}
}

func TestUnexpectedPrivilegedMembershipFlagsServiceAdminAndAlternateUIDZero(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	service := accounts.Account{Principal: "backupsvc", Name: "backupsvc", UID: "998", AccountType: "SERVICE", EnabledState: "ENABLED", LoginCapability: "LOGIN_DISABLED", Privileged: true, ServiceAccount: true, PrivilegeBasis: []string{"member of privileged group sudo"}}
	altRoot := accounts.Account{Principal: "opsroot", Name: "opsroot", UID: "0", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true, PrivilegeBasis: []string{"uid 0"}}
	got := phase065Rule(t, "CHM-ID-001").Evaluate(phase065AccountIndex("linux", at, service, altRoot))
	if got.Status != StatusFail || got.Confidence != evidence.ConfidenceHigh || got.Applicability != Applicable {
		t.Fatalf("unexpected evaluation: %#v", got)
	}
	if len(got.EvidenceKeys) != 2 {
		t.Fatalf("expected two account evidence keys, got %#v", got.EvidenceKeys)
	}
}

func TestUnexpectedPrivilegedMembershipAllowsCoreRootAndHumanAdmin(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	root := accounts.Account{Principal: "root", Name: "root", UID: "0", AccountType: "SYSTEM", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true, PrivilegeBasis: []string{"uid 0"}}
	admin := accounts.Account{Principal: "alice", Name: "alice", UID: "1000", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true, Groups: []string{"sudo"}, PrivilegeBasis: []string{"member of privileged group sudo"}}
	got := phase065Rule(t, "CHM-ID-001").Evaluate(phase065AccountIndex("linux", at, root, admin))
	if got.Status != StatusPass {
		t.Fatalf("expected PASS, got %#v", got)
	}
}

func TestDormantPrivilegedAccountUsesSnapshotCollectionTime(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	a := accounts.Account{Principal: `HOST\\Admin2`, Name: "Admin2", SID: "S-1-5-21-1-1001", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true, Authentication: accounts.AuthenticationMetadata{LastLogin: at.Add(-120 * 24 * time.Hour).Format(time.RFC3339)}}
	got := phase065Rule(t, "CHM-ID-002").Evaluate(phase065AccountIndex("windows", at, a))
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("expected stale privileged account failure, got %#v", got)
	}
}

func TestDormantPrivilegedAccountNotApplicableWithoutReliableProvider(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	a := accounts.Account{Principal: "alice", Name: "alice", UID: "1000", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true}
	got := phase065Rule(t, "CHM-ID-002").Evaluate(phase065AccountIndex("linux", at, a))
	if got.Status != StatusPass || got.Applicability != NotApplicable {
		t.Fatalf("expected NOT_APPLICABLE PASS, got %#v", got)
	}
}

func TestInteractiveServiceAccountRule(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	a := accounts.Account{Principal: "buildsvc", Name: "buildsvc", AccountType: "SERVICE", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", ServiceAccount: true}
	got := phase065Rule(t, "CHM-ID-003").Evaluate(phase065AccountIndex("windows", at, a))
	if got.Status != StatusFail || got.Applicability != Applicable {
		t.Fatalf("expected service interactive-login failure, got %#v", got)
	}
}

func TestDangerousDelegatedPrivilegeScope(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	a := accounts.Account{Principal: "dev", Name: "dev", UID: "1000", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Groups: []string{"docker"}}
	got := phase065Rule(t, "CHM-ID-004").Evaluate(phase065AccountIndex("linux", at, a))
	if got.Status != StatusWarn || got.Applicability != Applicable {
		t.Fatalf("expected high-impact delegated privilege warning, got %#v", got)
	}
}

func TestImplementedRulesIncludesPhase065Identities(t *testing.T) {
	want := map[string]bool{"CHM-ID-001": false, "CHM-ID-002": false, "CHM-ID-003": false, "CHM-ID-004": false}
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
	for id, present := range want {
		if !present {
			t.Fatalf("implemented catalog missing %s", id)
		}
	}
}

func TestPhase065RulesProduceValidFindings(t *testing.T) {
	at := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	a := accounts.Account{Principal: "svc", Name: "svc", UID: "998", AccountType: "SERVICE", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true, ServiceAccount: true, Groups: []string{"docker", "sudo"}, PrivilegeBasis: []string{"member of privileged group sudo"}}
	idx := phase065AccountIndex("linux", at, a)
	obs := make([]evidence.Observation, 0, len(idx))
	for _, o := range idx {
		obs = append(obs, o)
	}
	findings, err := EvaluateRules(PrivilegedAccountRules(), obs, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}
	if err := ValidateAll(findings); err != nil {
		t.Fatal(err)
	}
}
