package remotemgmt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseSSHConfigIncludeAndMatchBoundary(t *testing.T) {
	dir := t.TempDir()
	incDir := filepath.Join(dir, "sshd_config.d")
	if err := os.MkdirAll(incDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(incDir, "10-hardening.conf")
	if err := os.WriteFile(inc, []byte("PasswordAuthentication no\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "sshd_config")
	cfg := "PermitRootLogin no\nInclude sshd_config.d/*.conf\nMatch User legacy\nPasswordAuthentication yes\nGatewayPorts yes\n"
	if err := os.WriteFile(root, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	got := parseSSHConfig(root)
	if got.MatchBlocks != 1 {
		t.Fatalf("expected one Match block, got %d", got.MatchBlocks)
	}
	if got.Settings["permitrootlogin"].Value != "no" {
		t.Fatalf("root login not parsed: %#v", got.Settings)
	}
	if got.Settings["passwordauthentication"].Value != "no" {
		t.Fatalf("included global value should win before Match: %#v", got.Settings)
	}
	if _, ok := got.Settings["gatewayports"]; ok {
		t.Fatalf("Match-scoped gatewayports must not be treated as global")
	}
	if len(got.Files) != 2 {
		t.Fatalf("expected root+include files, got %#v", got.Files)
	}
}

func TestAlgorithmsFromParsedRejectsRelativeModifierWithoutEffectiveResolution(t *testing.T) {
	parsed := sshParsedConfig{Settings: map[string]sshParsedValue{
		"ciphers": {Value: "-3des-cbc", Source: "/etc/ssh/sshd_config:1"},
	}}
	got := algorithmsFromParsed(parsed)
	var c SSHAlgorithmPosture
	found := false
	for _, a := range got {
		if a.Family == "ciphers" {
			c, found = a, true
			break
		}
	}
	if !found {
		t.Fatal("ciphers posture missing")
	}
	if c.State != evidence.StateUnavailable {
		t.Fatalf("relative modifier should be unresolved, got %#v", c)
	}
	if len(c.Weak) != 0 {
		t.Fatalf("removed weak cipher must not be reported as enabled: %#v", c)
	}
}

func TestWeakSSHAlgorithms(t *testing.T) {
	got := weakSSHAlgorithms("kexalgorithms", []string{"curve25519-sha256", "diffie-hellman-group1-sha1"})
	if len(got) != 1 || got[0] != "diffie-hellman-group1-sha1" {
		t.Fatalf("unexpected weak set: %#v", got)
	}
}

func TestSSHSecurityValidationNotApplicable(t *testing.T) {
	s := SSHSecurity{Schema: sshSecuritySchemaVersion, State: sshStateNotApplicable}
	if err := validateSSHSecurity(s); err != nil {
		t.Fatalf("not-applicable report should validate: %v", err)
	}
}
