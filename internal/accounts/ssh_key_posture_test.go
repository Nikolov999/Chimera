package accounts

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestSSHKeyPostureNormalizeSummarizeAndEvidence(t *testing.T) {
	at := time.Now().UTC()
	p := normalizeSSHKeyPosture("linux", SSHKeyPosture{State: evidence.StateObserved, Source: "test", Records: []SSHKeyPathRecord{
		{Principal: "root", AccountID: "acct-root", Privileged: true, Path: "/root/.ssh", Kind: "ssh_directory", State: evidence.StateObserved, Directory: true, OwnerID: "0", OwnerMatch: "match", Source: "test", Confidence: evidence.ConfidenceExact},
		{Principal: "root", AccountID: "acct-root", Privileged: true, Path: "/root/.ssh/authorized_keys", Kind: "authorized_keys", State: evidence.StateObserved, OwnerID: "0", OwnerMatch: "match", BroadWrite: true, Insecure: true, InsecureBasis: []string{"group-writable path"}, Source: "test", Confidence: evidence.ConfidenceExact},
		{Principal: "alice", AccountID: "acct-alice", Path: "/home/alice/.ssh/id_ed25519", Kind: "private_key_candidate", State: evidence.StateObserved, OwnerID: "1000", OwnerMatch: "match", BroadRead: true, Insecure: true, InsecureBasis: []string{"private-key candidate is group-readable"}, Source: "test", Confidence: evidence.ConfidenceExact},
	}})
	if p.Summary.AuthorizedKeysFiles != 1 || p.Summary.PrivilegedAuthorizedKeysFiles != 1 || p.Summary.InsecurePrivilegedAuthorizedKeys != 1 || p.Summary.InsecurePrivateKeyCandidates != 1 {
		t.Fatalf("unexpected SSH summary: %#v", p.Summary)
	}
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: "linux", Architecture: "amd64", CollectedAt: at,
		SecurityPolicy: normalizeSecurityPolicy("linux", SecurityPolicy{}), CredentialProtection: normalizeCredentialProtection("linux", CredentialProtection{}),
		SudoPosture: normalizeSudoPosture("linux", SudoPosture{}), LinuxAuthPosture: normalizeLinuxAuthPosture("linux", LinuxAuthPosture{}), MacOSAuthorizationPosture: normalizeMacOSAuthorizationPosture("linux", MacOSAuthorizationPosture{}), SSHKeyPosture: p,
	}
	inv.Summary = summarize(inv.Accounts, inv.Groups)
	inv.Evidence = buildEvidence(inv)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	provider, record := false, false
	for _, o := range inv.Evidence {
		if o.Key == "account.ssh_key.provider" && o.State == evidence.StateObserved {
			provider = true
		}
		if o.Key == "account.ssh_key.path."+p.Records[1].ID && o.State == evidence.StateObserved {
			record = true
		}
	}
	if !provider || !record {
		t.Fatalf("missing evidence provider=%v record=%v", provider, record)
	}
}

func TestSSHKeyPostureUnsupportedPlatform(t *testing.T) {
	p := normalizeSSHKeyPosture("plan9", SSHKeyPosture{})
	if p.State != evidence.StateNotApplicable || p.Reason == "" {
		t.Fatalf("unexpected unsupported posture: %#v", p)
	}
	if err := validateSSHKeyPosture("plan9", p); err != nil {
		t.Fatal(err)
	}
}

func TestSSHPrivateKeyCandidateNames(t *testing.T) {
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa_sk", "identity"} {
		if !isSSHPrivateKeyCandidateName(name) {
			t.Fatalf("expected %q to be recognized", name)
		}
	}
	for _, name := range []string{"id_ed25519.pub", "known_hosts", "config", "server.key"} {
		if isSSHPrivateKeyCandidateName(name) {
			t.Fatalf("did not expect %q to be recognized", name)
		}
	}
}
