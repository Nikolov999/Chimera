package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectMetadataDoesNotReadContentByItself(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	secret := "CHIMERA_TEST_SECRET=do-not-emit"
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	rec, keep := inspectMetadata(candidate{Kind: "ENVIRONMENT_FILE", Scope: "USER", Path: path, Source: "test"})
	if !keep || !rec.Exists || rec.ContentInspected {
		t.Fatalf("unexpected record: %#v", rec)
	}
	if rec.CollectionSource == "" || rec.PermissionState == "" {
		t.Fatalf("metadata incomplete: %#v", rec)
	}
	if rec.Reason == secret || rec.Path == secret {
		t.Fatalf("secret value leaked into record: %#v", rec)
	}
}

func TestPhase101InventoryValidationAllowsRedactedContentInspection(t *testing.T) {
	inv := Collect(context.Background())
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	if inv.Summary.ContentInspected != inv.PlaintextRisk.InspectedFiles {
		t.Fatalf("inspection summary mismatch: %#v %#v", inv.Summary, inv.PlaintextRisk)
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "secret_value_raw") {
		t.Fatal("unexpected raw-secret field in inventory")
	}
}

func TestInventoryValidationRejectsUnredactedIndicatorMetadata(t *testing.T) {
	inv := Collect(context.Background())
	if len(inv.Records) == 0 {
		t.Skip("no secret-storage records observable on test host")
	}
	inv.Records[0].SecretIndicators = []SecretIndicator{{Type: "SENSITIVE_ASSIGNMENT", Line: 1}}
	inv.Records[0].SecretIndicatorCount = 1
	inv.Records[0].RedactionApplied = false
	if err := inv.Validate(); err == nil {
		t.Fatal("expected redaction invariant failure")
	}
}

func TestExpandCandidatesIsBoundedAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.env", "b.env", "c.env"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, degraded := expandCandidates([]candidate{{Kind: "ENVIRONMENT_FILE", Scope: "APPLICATION", Path: filepath.Join(dir, "*.env"), Source: "test"}})
	if len(degraded) != 0 || len(got) != 3 {
		t.Fatalf("unexpected expansion: %#v %#v", got, degraded)
	}
	if got[0].Path > got[1].Path || got[1].Path > got[2].Path {
		t.Fatalf("not sorted: %#v", got)
	}
}

func TestPhase102UserPrivateKeyGroupReadIsExposed(t *testing.T) {
	r := Record{
		ID: "u", Kind: "PRIVATE_KEY", Scope: "USER", Path: "/home/u/.ssh/id_ed25519",
		State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE",
		WorldReadable: "FALSE", GroupReadable: "TRUE", WorldWritable: "FALSE", GroupWritable: "FALSE",
		BroadlyAccessible: "TRUE", BroadlyWritable: "FALSE", OwnerID: "1000",
	}
	p := classifyPrivateKeyPermission(r)
	if p.ReadPosture != PrivateKeyPostureExposed || p.WritePosture != PrivateKeyPostureRestricted || p.OwnerPosture != PrivateKeyPostureNotApplicable {
		t.Fatalf("unexpected user private-key posture: %#v", p)
	}
}

func TestPhase102SystemPrivateKeyTrustedGroupReadRequiresReview(t *testing.T) {
	r := Record{
		ID: "s", Kind: "PRIVATE_KEY", Scope: "SYSTEM", Path: "/etc/ssl/private/server.key",
		State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE",
		WorldReadable: "FALSE", GroupReadable: "TRUE", WorldWritable: "FALSE", GroupWritable: "FALSE",
		BroadlyAccessible: "TRUE", BroadlyWritable: "FALSE", OwnerID: "0",
	}
	p := classifyPrivateKeyPermission(r)
	if p.ReadPosture != PrivateKeyPostureReview || p.OwnerPosture != PrivateKeyPostureExpected {
		t.Fatalf("unexpected system private-key posture: %#v", p)
	}
}

func TestPhase102PrivateKeyPermissionSummaryValidation(t *testing.T) {
	records := []Record{
		{ID: "u", Kind: "PRIVATE_KEY", Scope: "USER", Path: "/home/u/.ssh/id_ed25519", State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", WorldReadable: "FALSE", GroupReadable: "FALSE", WorldWritable: "FALSE", GroupWritable: "FALSE", OwnerID: "1000"},
		{ID: "s", Kind: "PRIVATE_KEY", Scope: "SYSTEM", Path: "/etc/ssh/ssh_host_ed25519_key", State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", WorldReadable: "FALSE", GroupReadable: "FALSE", WorldWritable: "FALSE", GroupWritable: "FALSE", OwnerID: "0"},
	}
	s := buildPrivateKeyPermissionSummary(records)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.AssessmentState != PrivateKeyAssessmentComplete || s.Keys != 2 || s.ReadRestricted != 2 || s.WriteRestricted != 2 || s.SystemOwnerExpected != 1 {
		t.Fatalf("unexpected private-key summary: %#v", s)
	}
}

func TestPhase103CredentialFilePostureClassifiesProvidersAndPermissions(t *testing.T) {
	rows := []Record{
		{ID: "aws", Kind: "CLOUD_CONFIG", Scope: "USER", Path: "/home/u/.aws/credentials", State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", BroadlyAccessible: "TRUE", BroadlyWritable: "FALSE"},
		{ID: "git", Kind: "DEVELOPER_CREDENTIAL", Scope: "USER", Path: "/home/u/.gitconfig", State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", BroadlyAccessible: "TRUE", BroadlyWritable: "TRUE"},
		{ID: "pip", Kind: "DEVELOPER_CREDENTIAL", Scope: "USER", Path: "/home/u/.config/pip/pip.conf", State: "OBSERVED", PermissionState: "OBSERVED", PermissionModel: "POSIX_MODE", BroadlyAccessible: "FALSE", BroadlyWritable: "FALSE"},
	}
	s := buildCredentialFilePostureSummary(rows)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.AssessmentState != CredentialAssessmentComplete || s.Files != 3 || s.CredentialBearing != 2 || s.ConfigurationOnly != 1 {
		t.Fatalf("unexpected credential summary: %#v", s)
	}
	if s.ReadExposed != 1 || s.ReadNotApplicable != 1 || s.WriteExposed != 1 || s.WriteRestricted != 2 {
		t.Fatalf("unexpected access counters: %#v", s)
	}
	providers := map[string]bool{}
	for _, p := range s.Providers {
		providers[p.Provider] = true
	}
	for _, provider := range []string{"AWS", "GIT", "PIP"} {
		if !providers[provider] {
			t.Fatalf("provider %s missing from %#v", provider, s.Providers)
		}
	}
}

func TestPhase103CredentialFilePostureKeepsUnknownPermissionState(t *testing.T) {
	r := Record{ID: "kube", Kind: "ORCHESTRATION_CONFIG", Scope: "USER", Path: "/home/u/.kube/config", State: "OBSERVED", PermissionState: "UNKNOWN", PermissionModel: "POSIX_MODE", BroadlyAccessible: "UNKNOWN", BroadlyWritable: "UNKNOWN"}
	s := buildCredentialFilePostureSummary([]Record{r})
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.AssessmentState != CredentialAssessmentDegraded || s.ReadUnknown != 1 || s.WriteUnknown != 1 || s.UnknownPosture != 1 {
		t.Fatalf("unknown permission posture was not preserved: %#v", s)
	}
}

func TestPhase103CredentialDescriptorCoversRoadmapFamilies(t *testing.T) {
	paths := map[string]string{
		"/home/u/.aws/credentials":                                    "AWS",
		"/home/u/.azure/msal_token_cache.bin":                         "AZURE",
		"/home/u/.config/gcloud/application_default_credentials.json": "GCP",
		"/home/u/.kube/config":                                        "KUBERNETES",
		"/home/u/.git-credentials":                                    "GIT",
		"/home/u/.npmrc":                                              "NPM",
		"/home/u/.config/pip/pip.conf":                                "PIP",
	}
	for path, want := range paths {
		d, ok := credentialDescriptorForRecord(Record{Path: path})
		if !ok || d.Provider != want {
			t.Fatalf("descriptor for %s = %#v ok=%t; want provider %s", path, d, ok, want)
		}
	}
}
