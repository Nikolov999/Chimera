package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase068Index(platform, arch string, controls map[string]string) Index {
	at := time.Unix(1700000000, 0).UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("account.platform", platform, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.architecture", arch, "test", at, evidence.ConfidenceExact),
	}
	if platform == "windows" {
		obs = append(obs, evidence.NewObserved("account.credential_protection.provider", map[string]any{"state": "OBSERVED"}, "test", at, evidence.ConfidenceHigh))
	} else {
		obs = append(obs, evidence.NewState("account.credential_protection.provider", evidence.StateNotApplicable, "test", at, evidence.ConfidenceExact, "not applicable"))
	}
	for k, v := range controls {
		obs = append(obs, evidence.NewObserved("account.credential_protection."+k, v, "test", at, evidence.ConfidenceExact))
	}
	return NewIndex(obs)
}

func phase068Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range WindowsCredentialProtectionRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestWindowsCredentialProtectionRulesContract(t *testing.T) {
	rules := WindowsCredentialProtectionRules()
	if len(rules) != 5 {
		t.Fatalf("got %d rules want 5", len(rules))
	}
	want := []string{"CHM-ID-016", "CHM-ID-017", "CHM-ID-018", "CHM-ID-019", "CHM-ID-020"}
	for i, r := range rules {
		if r.ID != want[i] {
			t.Fatalf("rule %d id=%s want %s", i, r.ID, want[i])
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		if len(r.References) == 0 || r.References[0].URL == "" {
			t.Fatalf("%s missing authoritative reference", r.ID)
		}
	}
}

func TestPhase068LSAProtection(t *testing.T) {
	pass := phase068Rule(t, "CHM-ID-016").Evaluate(phase068Index("windows", "amd64", map[string]string{"lsa-protection-config": "ENABLED_WITHOUT_UEFI_LOCK"}))
	if pass.Status != StatusPass || pass.Applicability != Applicable {
		t.Fatalf("expected PASS/APPLICABLE: %#v", pass)
	}
	fail := phase068Rule(t, "CHM-ID-016").Evaluate(phase068Index("windows", "amd64", map[string]string{"lsa-protection-config": "DISABLED"}))
	if fail.Status != StatusFail {
		t.Fatalf("expected FAIL: %#v", fail)
	}
}

func TestPhase068CredentialGuardRuntime(t *testing.T) {
	idx := phase068Index("windows", "amd64", map[string]string{
		"credential-guard-runtime":      "RUNNING",
		"credential-guard-configured":   "CONFIGURED",
		"virtualization-based-security": "RUNNING",
	})
	got := phase068Rule(t, "CHM-ID-017").Evaluate(idx)
	if got.Status != StatusPass || got.Applicability != Applicable {
		t.Fatalf("expected PASS: %#v", got)
	}

	got = phase068Rule(t, "CHM-ID-017").Evaluate(phase068Index("windows", "386", map[string]string{"credential-guard-runtime": "NOT_RUNNING"}))
	if got.Applicability != NotApplicable {
		t.Fatalf("expected 32-bit not applicable: %#v", got)
	}
}

func TestPhase068WDigestAndLMHash(t *testing.T) {
	idx := phase068Index("windows", "amd64", map[string]string{
		"wdigest-credential-caching": "ENABLED",
		"lm-hash-storage":            "ENABLED",
	})
	if got := phase068Rule(t, "CHM-ID-018").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("expected WDigest FAIL: %#v", got)
	}
	if got := phase068Rule(t, "CHM-ID-020").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("expected LM hash FAIL: %#v", got)
	}
}

func TestPhase068CachedLogons(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]string
		status Status
		app    Applicability
	}{
		{"workgroup", map[string]string{"domain-membership": "WORKGROUP", "cached-logons-count": "COUNT_10"}, StatusPass, NotApplicable},
		{"tight", map[string]string{"domain-membership": "DOMAIN_JOINED", "cached-logons-count": "COUNT_2"}, StatusPass, Applicable},
		{"default", map[string]string{"domain-membership": "DOMAIN_JOINED", "cached-logons-count": "COUNT_10"}, StatusWarn, Applicable},
		{"broad", map[string]string{"domain-membership": "DOMAIN_JOINED", "cached-logons-count": "COUNT_25"}, StatusFail, Applicable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := phase068Rule(t, "CHM-ID-019").Evaluate(phase068Index("windows", "amd64", tc.values))
			if got.Status != tc.status || got.Applicability != tc.app {
				t.Fatalf("got %#v", got)
			}
		})
	}
}

func TestPhase068NonWindowsNotApplicable(t *testing.T) {
	got := phase068Rule(t, "CHM-ID-018").Evaluate(phase068Index("linux", "amd64", nil))
	if got.Applicability != NotApplicable || got.Status != StatusPass {
		t.Fatalf("expected not applicable: %#v", got)
	}
}
