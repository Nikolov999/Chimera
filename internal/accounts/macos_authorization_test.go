package accounts

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseMacOSAuthorizationProviders(t *testing.T) {
	if got, ok := parseFileVaultStatus("FileVault is On.\n"); !ok || got != "ENABLED" {
		t.Fatalf("FileVault parse=%q ok=%v", got, ok)
	}
	if got, ok := parseSecureTokenStatus("Secure token is ENABLED for user demo"); !ok || got != "ENABLED" {
		t.Fatalf("SecureToken parse=%q ok=%v", got, ok)
	}
	if got, ok := parseBooleanPosture("1"); !ok || !got {
		t.Fatalf("boolean parse=%v ok=%v", got, ok)
	}
	users := parseFdesetupUsers("demo,11111111-1111-1111-1111-111111111111\nadmin,22222222-2222-2222-2222-222222222222\n")
	if _, ok := users["demo"]; !ok {
		t.Fatalf("fdesetup users missing demo: %#v", users)
	}
	if _, ok := users["admin"]; !ok {
		t.Fatalf("fdesetup users missing admin: %#v", users)
	}
}

func TestParseAuthorizationDBRight(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>class</key><string>rule</string>
<key>rule</key><array><string>authenticate-admin</string><string>authenticate-session-owner-or-admin</string></array>
</dict></plist>`
	got := parseAuthorizationDBRight("system.preferences", raw)
	if got.State != evidence.StateObserved || got.Class != "RULE" || len(got.Rules) != 2 {
		t.Fatalf("parsed right=%#v", got)
	}
	allow := parseAuthorizationDBRight("system.preferences.accounts", `<plist><dict><key>class</key><string>allow</string></dict></plist>`)
	if allow.State != evidence.StateObserved || allow.Class != "ALLOW" {
		t.Fatalf("allow right=%#v", allow)
	}
}

func TestMacOSAuthorizationNormalizationEvidenceAndValidation(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{
		Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion,
		Platform: "darwin", Architecture: "arm64", CollectedAt: at,
		Accounts: []Account{{
			Name: "admin", Principal: "admin", UID: "501", GID: "20", AccountType: "HUMAN", EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", Privileged: true,
			Authentication:   AuthenticationMetadata{State: "OBSERVED", PasswordState: "UNKNOWN", PasswordRequired: "UNKNOWN", PasswordExpires: "UNKNOWN", PasswordChangeable: "UNKNOWN", Source: "test"},
			CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
		}},
		MacOSAuthorizationPosture: MacOSAuthorizationPosture{
			State: evidence.StateObserved, Source: "test",
			FileVault: SecurityControl{ID: "filevault", Name: "FileVault disk encryption", State: evidence.StateObserved, Value: "ENABLED", Source: "fdesetup status", Confidence: evidence.ConfidenceExact},
			LoginControls: []SecurityControl{
				{ID: "guest-login", Name: "Guest login", State: evidence.StateObserved, Value: "DISABLED", Source: "defaults", Confidence: evidence.ConfidenceExact},
				{ID: "automatic-login", Name: "Automatic login", State: evidence.StateObserved, Value: "DISABLED", Source: "defaults", Confidence: evidence.ConfidenceExact},
			},
			Rights:     []MacOSAuthorizationRight{{ID: "system-preferences", Name: "system.preferences", State: evidence.StateObserved, Class: "RULE", Rules: []string{"authenticate-admin"}, Source: "security authorizationdb", Confidence: evidence.ConfidenceHigh}},
			Identities: []MacOSIdentityAuthorization{{Principal: "admin", UID: "501", Privileged: true, EnabledState: "ENABLED", LoginCapability: "LOGIN_CAPABLE", SecureToken: "ENABLED", SecureTokenEvidenceState: evidence.StateObserved, FileVaultAuthorized: "AUTHORIZED", FileVaultEvidenceState: evidence.StateObserved, Source: "test", Confidence: evidence.ConfidenceHigh}},
		},
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
	want := map[string]bool{
		"account.macos_authorization.provider":                 false,
		"account.macos_authorization.filevault":                false,
		"account.macos_authorization.login.automatic-login":    false,
		"account.macos_authorization.right.system-preferences": false,
	}
	identitySeen := false
	for _, o := range inv.Evidence {
		if _, ok := want[o.Key]; ok {
			want[o.Key] = true
		}
		if len(o.Key) > len("account.macos_authorization.identity.") && o.Key[:len("account.macos_authorization.identity.")] == "account.macos_authorization.identity." {
			identitySeen = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing evidence %s", key)
		}
	}
	if !identitySeen {
		t.Fatal("missing macOS identity relationship evidence")
	}
}

func TestMacOSAuthorizationNonDarwinNormalization(t *testing.T) {
	p := normalizeMacOSAuthorizationPosture("linux", MacOSAuthorizationPosture{})
	if p.State != evidence.StateNotApplicable || p.FileVault.State != evidence.StateUnavailable {
		t.Fatalf("unexpected non-darwin posture: %#v", p)
	}
	// The provider is not applicable; individual controls may remain unavailable
	// unless the platform collector supplied their explicit N/A state.
	if err := validateMacOSAuthorizationPosture("linux", p); err != nil {
		t.Fatal(err)
	}
}
