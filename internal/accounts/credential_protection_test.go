package accounts

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestNormalizeCredentialProtectionValue(t *testing.T) {
	cases := []struct {
		id   string
		raw  int64
		want string
	}{
		{"lsa-protection-config", 1, "ENABLED_UEFI_LOCK"},
		{"lsa-protection-config", 2, "ENABLED_WITHOUT_UEFI_LOCK"},
		{"credential-guard-runtime", 1, "RUNNING"},
		{"credential-guard-configured", 0, "NOT_CONFIGURED"},
		{"virtualization-based-security", 2, "RUNNING"},
		{"wdigest-credential-caching", 0, "DISABLED"},
		{"lm-hash-storage", 1, "DISABLED"},
		{"domain-membership", 1, "DOMAIN_JOINED"},
		{"cached-logons-count", 10, "COUNT_10"},
	}
	for _, tc := range cases {
		if got := normalizeCredentialProtectionValue(tc.id, tc.raw); got != tc.want {
			t.Fatalf("normalizeCredentialProtectionValue(%q,%d)=%q want %q", tc.id, tc.raw, got, tc.want)
		}
	}
}

func TestCredentialProtectionEvidenceAndValidation(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "windows", Architecture: "amd64", CollectedAt: at,
		SecurityPolicy: SecurityPolicy{State: evidence.StateObserved, Source: "test"},
		CredentialProtection: CredentialProtection{State: evidence.StateObserved, Source: "test", Controls: []SecurityControl{
			makeObservedCredentialControl("credential-guard-runtime", "Credential Guard", "test", 1),
			makeObservedCredentialControl("cached-logons-count", "Cached logons", "test", 2),
			makeUnavailableCredentialControl("wdigest-credential-caching", "WDigest", "test", "missing", evidence.StateUnavailable),
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
	foundProvider := false
	foundRunning := false
	foundUnavailable := false
	for _, o := range inv.Evidence {
		switch o.Key {
		case "account.credential_protection.provider":
			foundProvider = o.State == evidence.StateObserved
		case "account.credential_protection.credential-guard-runtime":
			foundRunning = o.State == evidence.StateObserved && o.Value == "RUNNING"
		case "account.credential_protection.wdigest-credential-caching":
			foundUnavailable = o.State == evidence.StateUnavailable
		}
	}
	if !foundProvider || !foundRunning || !foundUnavailable {
		t.Fatalf("expected normalized credential-protection evidence; provider=%v running=%v unavailable=%v", foundProvider, foundRunning, foundUnavailable)
	}
}

func TestWindowsCredentialDefaultsDoNotInferModernPlatformControls(t *testing.T) {
	if got, ok := windowsCredentialProtectionDefault("wdigest-credential-caching"); !ok || got != 0 {
		t.Fatalf("wdigest default=(%d,%v)", got, ok)
	}
	if got, ok := windowsCredentialProtectionDefault("cached-logons-count"); !ok || got != 10 {
		t.Fatalf("cached-logons default=(%d,%v)", got, ok)
	}
	if _, ok := windowsCredentialProtectionDefault("credential-guard-lsa-config"); ok {
		t.Fatal("Credential Guard registry absence must not be inferred as disabled")
	}
	if _, ok := windowsCredentialProtectionDefault("lsa-protection-config"); ok {
		t.Fatal("RunAsPPL registry absence must not be inferred as disabled")
	}
}
