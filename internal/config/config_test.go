package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/reliability"
)

func TestExplicitConfigOverridesDefaults(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	data := []byte(`{"timeout":"7s","profile":"server","severity":"HIGH","max_workers":3,"offline":true}`)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options.Timeout != 7*time.Second || got.Options.Profile != "server" || got.Options.Severity != "HIGH" || got.Options.MaxWorkers != 3 || !got.Options.Offline {
		t.Fatalf("unexpected options: %+v", got.Options)
	}
	if len(got.Sources) == 0 {
		t.Fatal("expected config source")
	}
}

func TestUnknownConfigKeyFailsClosed(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	if err := os.WriteFile(p, []byte(`{"not_a_real_key":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected unknown-key error")
	}
}

func TestPhase032ConfigCannotEnableNetworkRefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chimera.json")
	if err := os.WriteFile(path, []byte(`{"refresh_intelligence":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected configuration-driven refresh to fail closed")
	} else if !strings.Contains(err.Error(), "cannot be enabled from configuration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPhase110CustomProfilesLoadAndValidate(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	data := []byte(`{
  "profile":"prod-web",
  "custom_profiles":[{
    "name":"prod-web",
    "extends":"server",
    "description":"Production web host",
    "disabled_rules":["CHM-CTR-023"],
    "severity_overrides":{"CHM-NET-008":"HIGH"},
    "environment":{"environment":"production","role":"web"},
    "service_policy_mode":"required",
    "port_policy_mode":"required",
    "expected_services":[{"name":"sshd","state":"RUNNING","required":true}],
    "expected_ports":[{"protocol":"TCP","port":22,"binding":"EXTERNAL","required":false}],
    "allowed_exceptions":[{"kind":"port","match":"tcp/443","reason":"approved ingress"}]
  }]
}`)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options.Profile != "prod-web" || len(got.Profiles) != 1 || got.Profiles[0].Name != "prod-web" {
		t.Fatalf("unexpected custom-profile config: %#v", got)
	}
}

func TestPhase110InvalidCustomProfileFailsClosed(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	if err := os.WriteFile(p, []byte(`{"custom_profiles":[{"name":"bad","extends":"server","disabled_rules":["CHM-NOT-REAL"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected invalid custom profile to fail")
	}
}

func TestPhase111SuppressionsLoadValidateAndRecordSource(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	data := []byte(`{
  "suppressions":[{
    "id":"SEC-1234",
    "rule_id":"CHM-NET-008",
    "reason":"Temporary approved exception during firewall migration",
    "owner":"security-platform",
    "created_at":"2026-08-20T06:00:00Z",
    "expires_at":"2026-09-20T06:00:00Z",
    "metadata":{"ticket":"SEC-1234","environment":"production"}
  }]
}`)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Suppressions) != 1 {
		t.Fatalf("expected one suppression, got %#v", got.Suppressions)
	}
	s := got.Suppressions[0]
	if s.ID != "SEC-1234" || s.RuleID != "CHM-NET-008" || s.Owner != "security-platform" || s.Source == "" {
		t.Fatalf("unexpected suppression: %#v", s)
	}
}

func TestPhase111InvalidSuppressionFailsClosed(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "chimera.json")
	if err := os.WriteFile(p, []byte(`{"suppressions":[{"rule_id":"CHM-NET-008","reason":"missing owner and expiry","created_at":"2026-08-20T06:00:00Z"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected invalid suppression to fail closed")
	}
}

func TestDefaultTimeoutForGOOSFix57(t *testing.T) {
	if got := defaultTimeoutForGOOS("windows"); got != reliability.WindowsNormalAssessmentTimeout {
		t.Fatalf("windows default timeout=%s want=%s", got, reliability.WindowsNormalAssessmentTimeout)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := defaultTimeoutForGOOS(goos); got != 30*time.Second {
			t.Fatalf("%s default timeout=%s want=30s", goos, got)
		}
	}
}
