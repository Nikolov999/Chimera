package accounts

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeDWORDPolicy(t *testing.T) {
	cases := []struct {
		id   string
		raw  int64
		want string
	}{
		{"uac-enabled", 1, "ENABLED"},
		{"uac-enabled", 0, "DISABLED"},
		{"remote-uac-filtering", 0, "ENABLED"},
		{"remote-uac-filtering", 1, "DISABLED"},
		{"admin-consent-prompt", 0, "ELEVATE_WITHOUT_PROMPTING"},
		{"admin-consent-prompt", 5, "PROMPT_CONSENT_NON_WINDOWS_BINARIES"},
		{"restrict-anonymous", 2, "NO_ACCESS_WITHOUT_EXPLICIT_ANONYMOUS_PERMISSIONS"},
	}
	for _, tc := range cases {
		if got := normalizeDWORDPolicy(tc.id, tc.raw); got != tc.want {
			t.Fatalf("normalizeDWORDPolicy(%q,%d)=%q want %q", tc.id, tc.raw, got, tc.want)
		}
	}
}

func TestSecurityPolicyEvidenceAndValidation(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "windows", Architecture: "amd64", CollectedAt: at,
		SecurityPolicy: SecurityPolicy{State: evidence.StateObserved, Source: "test", Controls: []SecurityControl{
			makeObservedSecurityControl("uac-enabled", "UAC", "test", 1),
			makeUnavailableSecurityControl("secure-desktop-prompt", "Secure desktop", "test", "missing", evidence.StateUnavailable),
		}},
	}
	inv.Groups = normalizeGroups(inv.Groups)
	inv.Accounts = normalizeAccounts(inv.Accounts, inv.Groups)
	inv.Sources = normalizeSources(inv.Sources)
	inv.SecurityPolicy = normalizeSecurityPolicy(inv.Platform, inv.SecurityPolicy)
	inv.CredentialProtection = normalizeCredentialProtection(inv.Platform, inv.CredentialProtection)
	inv.SudoPosture = normalizeSudoPosture(inv.Platform, inv.SudoPosture)
	inv.LinuxAuthPosture = normalizeLinuxAuthPosture(inv.Platform, inv.LinuxAuthPosture)
	inv.MacOSAuthorizationPosture = normalizeMacOSAuthorizationPosture(inv.Platform, inv.MacOSAuthorizationPosture)
	inv.SSHKeyPosture = normalizeSSHKeyPosture(inv.Platform, inv.SSHKeyPosture)
	inv.Summary = summarize(inv.Accounts, inv.Groups)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	foundObserved := false
	foundUnavailable := false
	for _, o := range inv.Evidence {
		switch o.Key {
		case "account.policy.uac-enabled":
			foundObserved = o.State == evidence.StateObserved && o.Value == "ENABLED"
		case "account.policy.secure-desktop-prompt":
			foundUnavailable = o.State == evidence.StateUnavailable
		}
	}
	if !foundObserved || !foundUnavailable {
		t.Fatalf("expected normalized policy evidence; observed=%v unavailable=%v", foundObserved, foundUnavailable)
	}
}

func TestWindowsSecurityPolicyDefaultsAreExplicitAndBounded(t *testing.T) {
	cases := []struct {
		id   string
		want int64
		ok   bool
	}{
		{"remote-uac-filtering", 0, true}, {"secure-desktop-prompt", 1, true}, {"unknown-control", 0, false},
	}
	for _, tc := range cases {
		got, ok := windowsSecurityPolicyDefault(tc.id)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("default %s=(%d,%v) want (%d,%v)", tc.id, got, ok, tc.want, tc.ok)
		}
	}
	c := makeDefaultSecurityControl("remote-uac-filtering", "Remote UAC", "HKLM\\...", 0)
	if c.State != evidence.StateObserved || c.Value != "ENABLED" || c.Confidence != evidence.ConfidenceHigh {
		t.Fatalf("default control=%#v", c)
	}
}
