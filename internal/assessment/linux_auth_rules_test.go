package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase070Index(state evidence.State, rules []accounts.LinuxPAMRule, lp accounts.LinuxLoginPolicy, tuning accounts.LinuxAuthTuning, cfg []accounts.LinuxAuthConfigPath) Index {
	at := time.Now().UTC()
	idx := Index{
		"account.platform": evidence.NewObserved("account.platform", "linux", "test", at, evidence.ConfidenceExact),
	}
	if state == evidence.StateObserved {
		idx["account.linux_auth.provider"] = evidence.NewObserved("account.linux_auth.provider", map[string]any{"state": "OBSERVED"}, "test", at, evidence.ConfidenceHigh)
		idx["account.linux_auth.tuning"] = evidence.NewObserved("account.linux_auth.tuning", tuning, "test", at, evidence.ConfidenceHigh)
	} else {
		idx["account.linux_auth.provider"] = evidence.NewState("account.linux_auth.provider", state, "test", at, evidence.ConfidenceLow, "provider unavailable")
	}
	for _, r := range rules {
		idx["account.linux_auth.pam."+r.ID] = evidence.NewObserved("account.linux_auth.pam."+r.ID, r, r.Source, at, evidence.ConfidenceHigh)
	}
	if lp.State == evidence.StateObserved {
		idx["account.linux_auth.login_policy"] = evidence.NewObserved("account.linux_auth.login_policy", lp, lp.Source, at, evidence.ConfidenceExact)
	}
	for _, c := range cfg {
		idx["account.linux_auth.config."+c.ID] = evidence.NewObserved("account.linux_auth.config."+c.ID, c, c.Source, at, evidence.ConfidenceExact)
	}
	return idx
}

func phase070Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range LinuxAuthenticationRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestLinuxAuthenticationRulesContract(t *testing.T) {
	rules := LinuxAuthenticationRules()
	if len(rules) != 6 {
		t.Fatalf("expected six rules, got %d", len(rules))
	}
	want := []string{"CHM-ID-026", "CHM-ID-027", "CHM-ID-028", "CHM-ID-029", "CHM-ID-030", "CHM-ID-031"}
	for i, id := range want {
		if rules[i].ID != id {
			t.Fatalf("rule %d id=%s want=%s", i, rules[i].ID, id)
		}
		if err := rules[i].Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxPAMBypassFailsOnNullOK(t *testing.T) {
	r := accounts.LinuxPAMRule{ID: "pam-rule-a", Service: "common-auth", Type: "auth", Control: "required", Module: "pam_unix.so", Source: "/etc/pam.d/common-auth", Line: 1, NullOK: true}
	got := phase070Rule(t, "CHM-ID-026").Evaluate(phase070Index(evidence.StateObserved, []accounts.LinuxPAMRule{r}, accounts.LinuxLoginPolicy{}, accounts.LinuxAuthTuning{}, nil))
	if got.Status != StatusFail {
		t.Fatalf("got %#v", got)
	}
}

func TestLinuxLockoutAndQualityPass(t *testing.T) {
	rs := []accounts.LinuxPAMRule{
		{ID: "pam-rule-a", Service: "common-auth", Type: "auth", Control: "required", Module: "pam_faillock.so", Source: "/etc/pam.d/common-auth", Line: 1, Deny: 4},
		{ID: "pam-rule-b", Service: "common-password", Type: "password", Control: "requisite", Module: "pam_pwquality.so", Source: "/etc/pam.d/common-password", Line: 1, MinLen: 14},
	}
	idx := phase070Index(evidence.StateObserved, rs, accounts.LinuxLoginPolicy{}, accounts.LinuxAuthTuning{FaillockDeny: 4, PwqualityMinLen: 14}, nil)
	if got := phase070Rule(t, "CHM-ID-027").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("lockout=%#v", got)
	}
	if got := phase070Rule(t, "CHM-ID-028").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("quality=%#v", got)
	}
}

func TestLinuxPasswordPolicyRules(t *testing.T) {
	lp := accounts.LinuxLoginPolicy{State: evidence.StateObserved, Source: "/etc/login.defs", Confidence: evidence.ConfidenceExact, MaxDays: 180, MinDays: 1, WarnAge: 14, EncryptMethod: "YESCRYPT"}
	idx := phase070Index(evidence.StateObserved, nil, lp, accounts.LinuxAuthTuning{}, nil)
	if got := phase070Rule(t, "CHM-ID-029").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("ageing=%#v", got)
	}
	if got := phase070Rule(t, "CHM-ID-030").Evaluate(idx); got.Status != StatusPass {
		t.Fatalf("hashing=%#v", got)
	}
}

func TestLinuxConfigIntegrityFailsOnWritablePath(t *testing.T) {
	cfg := accounts.LinuxAuthConfigPath{ID: "auth-config-a", Path: "/etc/pam.d/common-auth", Kind: "PAM_FILE", State: evidence.StateObserved, Mode: "-rw-rw-r--", UID: 0, Insecure: true, InsecureBasis: []string{"configuration is group/world writable"}, Source: "/etc/pam.d/common-auth", Confidence: evidence.ConfidenceExact}
	got := phase070Rule(t, "CHM-ID-031").Evaluate(phase070Index(evidence.StateObserved, nil, accounts.LinuxLoginPolicy{}, accounts.LinuxAuthTuning{}, []accounts.LinuxAuthConfigPath{cfg}))
	if got.Status != StatusFail {
		t.Fatalf("got %#v", got)
	}
}

func TestLinuxAuthenticationRulesDeniedRemainUnknown(t *testing.T) {
	got := phase070Rule(t, "CHM-ID-026").Evaluate(phase070Index(evidence.StateDenied, nil, accounts.LinuxLoginPolicy{}, accounts.LinuxAuthTuning{}, nil))
	if got.Status != StatusUnknown {
		t.Fatalf("got %#v", got)
	}
}
