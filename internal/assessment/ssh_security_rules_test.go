package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/remotemgmt"
)

func sshRuleIndex(obs ...evidence.Observation) Index {
	at := time.Unix(1700000000, 0).UTC()
	base := []evidence.Observation{evidence.NewObserved("ssh_security.applicability", "APPLICABLE", "test", at, evidence.ConfidenceHigh)}
	base = append(base, obs...)
	return NewIndex(base)
}

func sshSettingObs(name, value string) evidence.Observation {
	at := time.Unix(1700000000, 0).UTC()
	s := remotemgmt.SSHSetting{Name: name, State: evidence.StateObserved, Value: value, Source: "test", Confidence: evidence.ConfidenceHigh}
	return evidence.NewObserved("ssh_security.setting."+name, s, "test", at, evidence.ConfidenceHigh)
}

func phase061Rule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range SSHSecurityRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

func TestSSHRootLoginRuleFailsYes(t *testing.T) {
	got := phase061Rule(t, "CHM-NET-020").Evaluate(sshRuleIndex(sshSettingObs("permitrootlogin", "yes")))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestSSHPasswordRuleFailsEmptyPasswords(t *testing.T) {
	got := phase061Rule(t, "CHM-NET-021").Evaluate(sshRuleIndex(
		sshSettingObs("permitemptypasswords", "yes"),
		sshSettingObs("passwordauthentication", "no"),
	))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestSSHConfigPermissionRuleFailsBroadWrite(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	f := remotemgmt.SSHFilePosture{ID: "sshf-test", Path: "/etc/ssh/sshd_config", State: evidence.StateObserved, Exists: true, BroadlyWritable: true, TrustedOwner: true, PermissionBasis: "POSIX mode/uid/gid", Source: "test", Confidence: evidence.ConfidenceHigh}
	got := phase061Rule(t, "CHM-NET-022").Evaluate(sshRuleIndex(evidence.NewObserved("ssh_security.file.sshf-test", f, "test", at, evidence.ConfidenceHigh)))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestSSHForwardingRuleFailsGatewayPorts(t *testing.T) {
	got := phase061Rule(t, "CHM-NET-023").Evaluate(sshRuleIndex(sshSettingObs("gatewayports", "clientspecified")))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestSSHAlgorithmRuleFailsWeakChoice(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	a := remotemgmt.SSHAlgorithmPosture{Family: "ciphers", State: evidence.StateObserved, Values: []string{"aes256-gcm@openssh.com", "3des-cbc"}, Weak: []string{"3des-cbc"}, Source: "test", Confidence: evidence.ConfidenceHigh}
	got := phase061Rule(t, "CHM-NET-024").Evaluate(sshRuleIndex(evidence.NewObserved("ssh_security.algorithms.ciphers", a, "test", at, evidence.ConfidenceHigh)))
	if got.Status != StatusFail {
		t.Fatalf("expected FAIL, got %#v", got)
	}
}

func TestSSHRuleNotApplicable(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	idx := NewIndex([]evidence.Observation{evidence.NewState("ssh_security.applicability", evidence.StateNotApplicable, "test", at, evidence.ConfidenceHigh, "not detected")})
	got := phase061Rule(t, "CHM-NET-020").Evaluate(idx)
	if got.Applicability != NotApplicable || got.Status != StatusPass {
		t.Fatalf("unexpected result: %#v", got)
	}
}
