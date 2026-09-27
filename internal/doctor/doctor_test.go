package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/intelligence"
)

func TestRunProducesPhase008Contract(t *testing.T) {
	r := Run(context.Background(), Options{})
	if r.Schema != SchemaVersion {
		t.Fatalf("schema=%q", r.Schema)
	}
	if r.Platform != runtime.GOOS || r.Architecture != runtime.GOARCH {
		t.Fatalf("unexpected platform %s/%s", r.Platform, r.Architecture)
	}
	if len(r.Collectors) == 0 || len(r.Permissions) == 0 || len(r.PlatformChecks) == 0 || len(r.RulePacks) == 0 {
		t.Fatalf("missing doctor check groups: %#v", r)
	}
	if r.Summary.Total == 0 {
		t.Fatal("summary did not account for checks")
	}
	if supportedPlatform(runtime.GOOS) && !r.Supported {
		t.Fatal("supported current platform reported unsupported")
	}
}

func TestConfiguredIntelligenceFreshness(t *testing.T) {
	t.Setenv(intelligence.EnvDirectory, "")
	builtin, err := intelligence.Load()
	if err != nil {
		t.Fatal(err)
	}
	store := builtin.Store
	store.Version = "test-local-store"
	store.RetrievedAt = time.Now().UTC().Add(-31 * 24 * time.Hour)
	for i := range store.Sources {
		store.Sources[i].RetrievedAt = store.RetrievedAt
	}
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(intelligence.EnvDirectory, dir)
	h := checkIntelligence(Options{Offline: true}, time.Now().UTC())
	if h.State != StateWarn || h.Freshness != "STALE" || h.Mode != "offline-local-pinned" || h.Version != "test-local-store" || len(h.Digest) != 64 {
		t.Fatalf("unexpected intelligence health: %#v", h)
	}
}

func TestSummaryAndOverallState(t *testing.T) {
	s := summarize([]Check{{State: StatePass}, {State: StateWarn}, {State: StateNotApplicable}})
	if s.Total != 3 || s.Pass != 1 || s.Warn != 1 || s.NotApplicable != 1 {
		t.Fatalf("unexpected summary: %#v", s)
	}
	if got := overallState(s, true); got != "DEGRADED" {
		t.Fatalf("state=%q", got)
	}
	s.Fail = 1
	if got := overallState(s, true); got != "UNHEALTHY" {
		t.Fatalf("state=%q", got)
	}
	if got := overallState(s, false); got != "UNSUPPORTED" {
		t.Fatalf("state=%q", got)
	}
}

func TestPhase105EnterpriseRuleAndEngineHealth(t *testing.T) {
	checks := rulePackChecks()
	if len(checks) != 17 {
		t.Fatalf("rule pack check count=%d", len(checks))
	}
	byID := make(map[string]Check, len(checks))
	for _, check := range checks {
		byID[check.ID] = check
	}
	release := byID["release.v1"]
	if release.State != StatePass || !release.Required || release.Source != "chimera.public-contract/v1" {
		t.Fatalf("unexpected release health: %#v", release)
	}
	reliability := byID["runtime.phase116"]
	if reliability.State != StatePass || !reliability.Required || reliability.Source != "reliability/phase116-v1" {
		t.Fatalf("unexpected reliability health: %#v", reliability)
	}
	engine := byID["rules.engine-v2"]
	if engine.State != StatePass || !engine.Required || engine.Source != "chimera.rule-engine/v2-phase106" {
		t.Fatalf("unexpected declarative rule-engine health: %#v", engine)
	}
	service := byID["rules.service-scheduler"]
	if service.State != StatePass || !service.Required || service.Source != "chimera.rules/service-scheduler-v1-phase051" {
		t.Fatalf("unexpected service/scheduler rule pack health: %#v", service)
	}
	network := byID["rules.network-firewall"]
	if network.State != StatePass || !network.Required || network.Source != "chimera.rules/network-firewall-v1-phase063" {
		t.Fatalf("unexpected network/firewall rule pack health: %#v", network)
	}
	identity := byID["rules.identity-authentication"]
	if identity.State != StatePass || !identity.Required || identity.Source != "chimera.rules/identity-authentication-v1-phase073" {
		t.Fatalf("unexpected identity/authentication rule pack health: %#v", identity)
	}
	filesystemStorage := byID["rules.filesystem-storage"]
	if filesystemStorage.State != StatePass || !filesystemStorage.Required || filesystemStorage.Source != "chimera.rules/filesystem-storage-v1-phase086" {
		t.Fatalf("unexpected filesystem/storage rule pack health: %#v", filesystemStorage)
	}
	persistenceSecrets := byID["rules.persistence-secrets"]
	if persistenceSecrets.State != StatePass || !persistenceSecrets.Required || persistenceSecrets.Source != "chimera.rules/persistence-secrets-v1-phase104" {
		t.Fatalf("unexpected persistence/secret-storage rule pack health: %#v", persistenceSecrets)
	}
	crossDomain := byID["rules.cross-domain"]
	if crossDomain.State != StatePass || !crossDomain.Required || crossDomain.Source != "chimera.rules/cross-domain-v1-phase107" {
		t.Fatalf("unexpected cross-domain rule pack health: %#v", crossDomain)
	}
	enterpriseProfiles := byID["profiles.enterprise"]
	if enterpriseProfiles.State != StatePass || !enterpriseProfiles.Required || enterpriseProfiles.Source != "chimera.enterprise-policy/v1-phase110" {
		t.Fatalf("unexpected enterprise-profile health: %#v", enterpriseProfiles)
	}
	cisInspired := byID["baseline.cis-inspired"]
	if cisInspired.State != StatePass || !cisInspired.Required || cisInspired.Source != "chimera.control-map/cis-inspired-v1-phase109" {
		t.Fatalf("unexpected CIS-inspired mapping health: %#v", cisInspired)
	}
	suppressions := byID["findings.suppressions"]
	if suppressions.State != StatePass || !suppressions.Required || suppressions.Source != "chimera.suppression/v1" {
		t.Fatalf("unexpected suppression-engine health: %#v", suppressions)
	}
	diffEngine := byID["assessment.diff"]
	if diffEngine.State != StatePass || !diffEngine.Required || diffEngine.Source != "chimera.assessment-diff/v1" {
		t.Fatalf("unexpected assessment-diff health: %#v", diffEngine)
	}
	priorityEngine := byID["assessment.prioritization"]
	if priorityEngine.State != StatePass || !priorityEngine.Required || priorityEngine.Source != "risk-priority/post117-fix04-v1" {
		t.Fatalf("unexpected risk-prioritization health: %#v", priorityEngine)
	}
	remediationEngine := byID["assessment.remediation"]
	if remediationEngine.State != StatePass || !remediationEngine.Required || remediationEngine.Source != "remediation/phase114-v1" {
		t.Fatalf("unexpected remediation-view health: %#v", remediationEngine)
	}
	reportingEngine := byID["assessment.reporting"]
	if reportingEngine.State != StatePass || !reportingEngine.Required || reportingEngine.Source != "report/phase115-v1+export/phase115-v1" {
		t.Fatalf("unexpected report/export health: %#v", reportingEngine)
	}
	baselineEngine := byID["baseline.engine"]
	if baselineEngine.State != StatePass || !baselineEngine.Required || baselineEngine.Source != "chimera.baseline-engine/v2-phase109" {
		t.Fatalf("unexpected baseline engine health: %#v", baselineEngine)
	}
}
