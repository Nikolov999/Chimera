package intelligence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestBuiltinStoreLoadsAndValidates(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.Schema != SchemaVersion || loaded.Metadata.Version != BuiltinVersion {
		t.Fatalf("unexpected metadata: %#v", loaded.Metadata)
	}
	if loaded.Metadata.State != "PINNED_BUILTIN" || loaded.Metadata.SourceCount < 1 || loaded.Metadata.ProductCount < 1 || loaded.Metadata.VulnerabilityCount < 1 || loaded.Metadata.LifecycleCount < 1 {
		t.Fatalf("incomplete built-in intelligence metadata: %#v", loaded.Metadata)
	}
	if loaded.Metadata.DigestAlgorithm != "sha256" || len(loaded.Metadata.Digest) != 64 {
		t.Fatalf("unexpected digest: %#v", loaded.Metadata)
	}
}

func TestConfiguredLocalStoreOverridesBuiltin(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	raw, err := json.MarshalIndent(builtin.Store, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDirectory, dir)
	local, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if local.Metadata.State != "PINNED_LOCAL" || local.Metadata.Path == "" {
		t.Fatalf("configured store not identified as local: %#v", local.Metadata)
	}
	if local.Metadata.Digest != builtin.Metadata.Digest {
		t.Fatalf("equivalent stores produced different canonical digests: %s != %s", local.Metadata.Digest, builtin.Metadata.Digest)
	}
}

func TestConfiguredStoreFailsClosedOnUnknownField(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"schema":"chimera.intelligence/v1","version":"x","retrieved_at":"2026-08-18T00:00:00Z","sources":[],"products":[],"vulnerabilities":[],"unexpected":true}`)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDirectory, dir)
	if _, err := Load(); err == nil {
		t.Fatal("expected configured store with unknown field to fail closed")
	}
}

func TestConfiguredStoreRejectsMalformedCPEAndPURL(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Store)
	}{
		{name: "cpe", mutate: func(s *Store) { s.Products[0].CPEs = []string{"cpe:2.3:a:too-short"} }},
		{name: "purl", mutate: func(s *Store) { s.Products[0].PURLs = []string{"pkg:maven"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := builtin.Store
			store.Products = append([]ProductMapping(nil), builtin.Store.Products...)
			tc.mutate(&store)
			raw, err := json.MarshalIndent(store, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvDirectory, dir)
			if _, err := Load(); err == nil {
				t.Fatalf("expected malformed %s identity to fail closed", tc.name)
			}
		})
	}
}

func TestConfiguredStoreRejectsMalformedLifecycleRecords(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*LifecycleRecord)
	}{
		{name: "target-kind", mutate: func(r *LifecycleRecord) { r.TargetKinds = []string{"remote-service"} }},
		{name: "post-support-status", mutate: func(r *LifecycleRecord) { r.StatusAfterEnd = "SUPPORTED" }},
		{name: "source", mutate: func(r *LifecycleRecord) { r.SourceID = "missing-source" }},
		{name: "reference", mutate: func(r *LifecycleRecord) { r.Reference = "file:///tmp/not-authoritative" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := builtin.Store
			store.Lifecycles = append([]LifecycleRecord(nil), builtin.Store.Lifecycles...)
			if len(store.Lifecycles) == 0 {
				t.Fatal("built-in lifecycle catalog is empty")
			}
			tc.mutate(&store.Lifecycles[0])
			raw, err := json.MarshalIndent(store, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvDirectory, dir)
			if _, err := Load(); err == nil {
				t.Fatalf("expected malformed lifecycle %s to fail closed", tc.name)
			}
		})
	}
}

func TestPhase031OfflineSessionPinsCurrentBuiltin(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	now := time.Date(2026, 8, 18, 21, 0, 0, 0, time.UTC)
	s := Open(LoadOptions{Offline: true, Now: now})
	if err := s.Error(); err != nil {
		t.Fatal(err)
	}
	if s.Status.Schema != AssessmentSchemaVersion || s.Status.Mode != "OFFLINE_PINNED" || s.Status.State != "READY" || s.Status.Freshness != "CURRENT" {
		t.Fatalf("unexpected offline session status: %#v", s.Status)
	}
	if !s.Status.Available || !s.Status.ReadOnly || s.Status.NetworkAccess {
		t.Fatalf("unsafe/offline contract mismatch: %#v", s.Status)
	}
	if s.Status.SnapshotDigest != s.Loaded.Metadata.Digest || len(s.Status.SnapshotDigest) != 64 {
		t.Fatalf("snapshot was not pinned to loaded digest: %#v", s.Status)
	}
	if err := evidence.ValidateAll(s.Evidence); err != nil {
		t.Fatalf("invalid evidence: %v", err)
	}
}

func TestPhase031StaleConfiguredSnapshotIsUsableButDegraded(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 21, 0, 0, 0, time.UTC)
	store := builtin.Store
	store.Version = "stale-test"
	store.RetrievedAt = now.Add(-31 * 24 * time.Hour)
	for i := range store.Sources {
		store.Sources[i].RetrievedAt = store.RetrievedAt
	}
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDirectory, dir)
	s := Open(LoadOptions{Offline: true, Now: now})
	if err := s.Error(); err != nil {
		t.Fatal(err)
	}
	if s.Status.State != "STALE" || s.Status.Freshness != "STALE" || len(s.DegradationReasons()) != 1 {
		t.Fatalf("stale snapshot not degraded explicitly: %#v", s.Status)
	}
}

func TestPhase031InvalidConfiguredSnapshotDoesNotFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"schema":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDirectory, dir)
	s := Open(LoadOptions{Offline: true, Now: time.Date(2026, 8, 18, 21, 0, 0, 0, time.UTC)})
	if s.Error() == nil || s.Status.State != "MISSING" || s.Status.Available || s.Status.NetworkAccess {
		t.Fatalf("invalid configured snapshot did not fail closed: %#v err=%v", s.Status, s.Error())
	}
	if len(s.Evidence) == 0 || s.Evidence[0].State != evidence.StateUnavailable {
		t.Fatalf("missing intelligence is not explicit normalized evidence: %#v", s.Evidence)
	}
}

func TestPost117BuiltinIntelligenceBreadth(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.ProductCount < 20 {
		t.Fatalf("post-117 product catalog regressed: %d", loaded.Metadata.ProductCount)
	}
	if loaded.Metadata.VulnerabilityCount < 179 {
		t.Fatalf("post-117 vulnerability catalog regressed: %d", loaded.Metadata.VulnerabilityCount)
	}
	if loaded.Metadata.SourceCount < 24 {
		t.Fatalf("post-117 provenance source catalog regressed: %d", loaded.Metadata.SourceCount)
	}
	if loaded.Metadata.LifecycleCount < 55 {
		t.Fatalf("post-117 lifecycle catalog regressed: %d", loaded.Metadata.LifecycleCount)
	}
	requiredProducts := map[string]bool{
		"apache-httpd-native":           false,
		"nginx-native":                  false,
		"openssl-runtime":               false,
		"python-runtime":                false,
		"nodejs-runtime":                false,
		"curl-tool-native":              false,
		"libcurl-native":                false,
		"rsync-native":                  false,
		"openssh-portable-native":       false,
		"postgresql-server-native":      false,
		"postgresql-client-native":      false,
		"git-native":                    false,
		"go-runtime":                    false,
		"php-runtime":                   false,
		"dotnet-runtime":                false,
		"dotnet-aspnetcore-runtime":     false,
		"dotnet-windowsdesktop-runtime": false,
		"dotnet-sdk":                    false,
	}
	for _, p := range loaded.Store.Products {
		if _, ok := requiredProducts[p.ID]; ok {
			requiredProducts[p.ID] = true
		}
	}
	for id, ok := range requiredProducts {
		if !ok {
			t.Fatalf("required curated product mapping %q is missing", id)
		}
	}
	requiredCVEs := map[string]bool{
		"CVE-2026-29167": false,
		"CVE-2026-42533": false,
		"CVE-2024-9143":  false,
		"CVE-2021-44228": false,
		"CVE-2024-3094":  false,
		"CVE-2026-12064": false,
		"CVE-2026-43618": false,
		"CVE-2024-6387":  false,
		"CVE-2024-10979": false,
		"CVE-2024-32002": false,
		"CVE-2024-50349": false,
		"CVE-2026-58043": false,
		"CVE-2026-48933": false,
		"CVE-2025-48384": false,
		"CVE-2025-48385": false,
		"CVE-2026-42505": false,
		"CVE-2026-42501": false,
		"CVE-2026-27143": false,
		"CVE-2025-4517":  false,
		"CVE-2025-4330":  false,
		"CVE-2025-4138":  false,
		"CVE-2024-12718": false,
		"CVE-2025-4435":  false,
		"CVE-2026-17543": false,
		"CVE-2026-17544": false,
		"CVE-2026-7260":  false,
		"CVE-2026-14355": false,
		"CVE-2026-12184": false,
		"CVE-2026-6722":  false,
		"CVE-2026-7261":  false,
		"CVE-2026-6735":  false,
		"CVE-2026-6104":  false,
		"CVE-2026-62871": false,
		"CVE-2026-62886": false,
		"CVE-2026-62897": false,
		"CVE-2026-62898": false,
		"CVE-2026-62899": false,
		"CVE-2026-62901": false,
		"CVE-2026-62902": false,
		"CVE-2026-62909": false,
		"CVE-2026-70354": false,
	}
	for _, v := range loaded.Store.Vulnerabilities {
		if _, ok := requiredCVEs[v.ID]; ok {
			requiredCVEs[v.ID] = true
		}
	}
	for id, ok := range requiredCVEs {
		if !ok {
			t.Fatalf("required curated vulnerability %q is missing", id)
		}
	}

	requiredLifecycle := map[string]bool{
		"debian-11-lts-eos":            false,
		"windows-11-24h2-home-pro-eos": false,
		"nodejs-22-eos":                false,
		"dotnet-8-eos":                 false,
		"openssl-3-4-eos":              false,
		"php-8-2-eos":                  false,
		"postgresql-14-upstream-eos":   false,
	}
	for _, r := range loaded.Store.Lifecycles {
		if _, ok := requiredLifecycle[r.ID]; ok {
			requiredLifecycle[r.ID] = true
		}
	}
	for id, ok := range requiredLifecycle {
		if !ok {
			t.Fatalf("required curated lifecycle record %q is missing", id)
		}
	}
}

func TestPost117Fix12ConfiguredStoreRejectsUnknownAffectedPlatform(t *testing.T) {
	t.Setenv(EnvDirectory, "")
	builtin, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	store := builtin.Store
	store.Vulnerabilities = append([]Vulnerability(nil), builtin.Store.Vulnerabilities...)
	if len(store.Vulnerabilities) == 0 || len(store.Vulnerabilities[0].Affected) == 0 {
		t.Fatal("built-in vulnerability catalog is empty")
	}
	store.Vulnerabilities[0].Affected = append([]AffectedProduct(nil), store.Vulnerabilities[0].Affected...)
	store.Vulnerabilities[0].Affected[0].Platforms = []string{"solaris"}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDirectory, dir)
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown affected platform to fail closed")
	}
}
