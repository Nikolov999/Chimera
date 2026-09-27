package accounts

import (
	"github.com/Nikolov999/chimera/internal/evidence"
	"testing"
	"time"
)

func TestNormalizeAndValidate(t *testing.T) {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at,
		Groups:               []Group{{Name: "sudo", GID: "27", Privileged: true, Members: []string{"alice"}, CollectionSource: "test", Confidence: evidence.ConfidenceExact}},
		Accounts:             []Account{{Name: "alice", Principal: "alice", UID: "1000", GID: "1000", AccountType: "human", EnabledState: "enabled", LoginCapability: "login_capable", Groups: []string{"sudo"}, Authentication: AuthenticationMetadata{State: "observed", PasswordState: "password_set", PasswordRequired: "unknown", PasswordExpires: "unknown", PasswordChangeable: "unknown", Source: "test"}, CollectionSource: "test", Confidence: evidence.ConfidenceHigh}},
		Sources:              []SourceStatus{{ID: "test", State: evidence.StateObserved, Source: "test", ItemCount: 1}},
		SecurityPolicy:       SecurityPolicy{State: evidence.StateNotApplicable, Source: "test", Reason: "not applicable on linux"},
		CredentialProtection: CredentialProtection{State: evidence.StateNotApplicable, Source: "test", Reason: "not applicable on linux"},
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
	if !inv.Accounts[0].Privileged {
		t.Fatal("privileged group membership not propagated")
	}
	if inv.Summary.Privileged != 1 || inv.Summary.Accounts != 1 || inv.Summary.Groups != 1 {
		t.Fatalf("unexpected summary: %#v", inv.Summary)
	}
}

func TestStableAccountID(t *testing.T) {
	a := Account{Name: "alice", Principal: "alice", UID: "1000"}
	b := stableAccountID(a)
	if b == "" || b != stableAccountID(a) {
		t.Fatal("account id is not stable")
	}
}
