package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/accounts"
	"github.com/Nikolov999/chimera/internal/evidence"
)

func phase072Index(state string, records ...accounts.SSHKeyPathRecord) Index {
	at := time.Now().UTC()
	obs := []evidence.Observation{
		evidence.NewObserved("account.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("account.ssh_key.provider", map[string]any{"state": state, "records": len(records)}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("account.ssh_key.summary", accounts.SSHKeyPostureSummary{}, "test", at, evidence.ConfidenceHigh),
	}
	for _, r := range records {
		obs = append(obs, evidence.NewObserved("account.ssh_key.path."+r.ID, r, "test", at, evidence.ConfidenceHigh))
	}
	return NewIndex(obs)
}

func phase072Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range SSHKeyPostureRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing rule %s", id)
	return Rule{}
}

func TestSSHKeyPostureRulesContract(t *testing.T) {
	rules := SSHKeyPostureRules()
	if len(rules) != 5 {
		t.Fatalf("rules=%d", len(rules))
	}
	want := []string{"CHM-ID-039", "CHM-ID-040", "CHM-ID-041", "CHM-ID-042", "CHM-ID-043"}
	for i, id := range want {
		if rules[i].ID != id {
			t.Fatalf("rule[%d]=%s want %s", i, rules[i].ID, id)
		}
		if err := rules[i].Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSHKeyRulesDetectWeakPathsAndPrivilegedAccess(t *testing.T) {
	auth := accounts.SSHKeyPathRecord{ID: "auth", Principal: "root", Privileged: true, Path: "/root/.ssh/authorized_keys", Kind: "AUTHORIZED_KEYS", State: evidence.StateObserved, OwnerMatch: "MATCH", BroadWrite: true, Insecure: true, InsecureBasis: []string{"group-writable path"}, Source: "test", Confidence: evidence.ConfidenceExact}
	dir := accounts.SSHKeyPathRecord{ID: "dir", Principal: "root", Privileged: true, Path: "/root/.ssh", Kind: "SSH_DIRECTORY", State: evidence.StateObserved, OwnerMatch: "MATCH", BroadWrite: true, Insecure: true, InsecureBasis: []string{"group-writable path"}, Source: "test", Confidence: evidence.ConfidenceExact}
	key := accounts.SSHKeyPathRecord{ID: "key", Principal: "alice", Path: "/home/alice/.ssh/id_ed25519", Kind: "PRIVATE_KEY_CANDIDATE", State: evidence.StateObserved, OwnerMatch: "MATCH", BroadRead: true, Insecure: true, InsecureBasis: []string{"private-key candidate is group-readable"}, Source: "test", Confidence: evidence.ConfidenceExact}
	idx := phase072Index("OBSERVED", auth, dir, key)
	if got := phase072Rule(t, "CHM-ID-039").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("directory status=%s", got.Status)
	}
	if got := phase072Rule(t, "CHM-ID-040").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("authorized_keys status=%s", got.Status)
	}
	if got := phase072Rule(t, "CHM-ID-041").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("private key status=%s", got.Status)
	}
	if got := phase072Rule(t, "CHM-ID-042").Evaluate(idx); got.Status != StatusWarn {
		t.Fatalf("privileged presence status=%s", got.Status)
	}
	if got := phase072Rule(t, "CHM-ID-043").Evaluate(idx); got.Status != StatusFail {
		t.Fatalf("privileged integrity status=%s", got.Status)
	}
}

func TestSSHKeyRulesPassCleanAndUnknownOnDegradedProvider(t *testing.T) {
	clean := accounts.SSHKeyPathRecord{ID: "auth", Principal: "alice", Path: "/home/alice/.ssh/authorized_keys", Kind: "AUTHORIZED_KEYS", State: evidence.StateObserved, OwnerMatch: "MATCH", Source: "test", Confidence: evidence.ConfidenceExact}
	if got := phase072Rule(t, "CHM-ID-040").Evaluate(phase072Index("OBSERVED", clean)); got.Status != StatusPass {
		t.Fatalf("clean status=%s", got.Status)
	}
	if got := phase072Rule(t, "CHM-ID-040").Evaluate(phase072Index("DEGRADED", clean)); got.Status != StatusUnknown {
		t.Fatalf("degraded status=%s", got.Status)
	}
}

func TestImplementedRulesIncludesPhase072ExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, r := range ImplementedRules() {
		counts[r.ID]++
	}
	for _, id := range []string{"CHM-ID-039", "CHM-ID-040", "CHM-ID-041", "CHM-ID-042", "CHM-ID-043"} {
		if counts[id] != 1 {
			t.Fatalf("%s count=%d", id, counts[id])
		}
	}
}
