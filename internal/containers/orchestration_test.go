package containers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestParseKubeconfigStructureRedactsCredentialValues(t *testing.T) {
	raw := `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
users:
- user:
    token: super-secret-token-value
    client-key-data: very-secret-key-data
    client-key: ./client.key
`
	got, err := parseKubeconfigStructure("/tmp/kube/config", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 1 || got.Servers[0] != "https://127.0.0.1:6443" || got.LocalServerCount != 1 {
		t.Fatalf("unexpected server posture: %#v", got)
	}
	if len(got.EmbeddedCredentialKinds) != 2 || len(got.CredentialReferences) != 1 || got.CredentialReferences[0].Kind != "CLIENT_KEY" {
		t.Fatalf("unexpected redacted structure: %#v", got)
	}
	text := strings.Join(got.EmbeddedCredentialKinds, " ") + strings.Join(got.Servers, " ") + got.CredentialReferences[0].Path
	if strings.Contains(text, "super-secret") || strings.Contains(text, "very-secret") {
		t.Fatal("credential value leaked into parsed posture")
	}
}

func TestInspectKubeconfigAndCredentialPathPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics are intentionally unresolved on Windows")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyPath, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config")
	cfg := "apiVersion: v1\nclusters:\n- cluster:\n    server: https://localhost:6443\nusers:\n- user:\n    client-key: ./client.key\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, refs, ok := inspectKubeconfig(kubeconfigCandidate{Path: cfgPath, Scope: "USER"})
	if !ok || rec.State != evidence.StateObserved || rec.PermissionAssessmentState != "OBSERVED" || rec.WorldReadableState != "FALSE" || rec.GroupReadableState != "FALSE" {
		t.Fatalf("unexpected kubeconfig posture: %#v", rec)
	}
	if rec.StructureAssessmentState != "OBSERVED" || rec.LocalServerEndpointCount != 1 || len(refs) != 1 {
		t.Fatalf("unexpected structure posture: %#v refs=%#v", rec, refs)
	}
	cred := inspectCredentialPath(rec.ID, refs[0])
	if cred.State != evidence.StateObserved || cred.PermissionAssessmentState != "OBSERVED" || cred.WorldReadableState != "FALSE" || cred.GroupReadableState != "FALSE" {
		t.Fatalf("unexpected credential posture: %#v", cred)
	}
}

func TestNormalizeKubernetesPostureApplicability(t *testing.T) {
	p := normalizeKubernetesPosture(KubernetesPosture{ID: "kubernetes", State: evidence.StateObserved, InstallationState: "present", Applicability: "mixed", CollectionSource: "test", Confidence: evidence.ConfidenceHigh})
	if p.InstallationState != "PRESENT" || p.Applicability != "MIXED" {
		t.Fatalf("unexpected normalized posture: %#v", p)
	}
}
