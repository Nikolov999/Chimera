package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase101DetectsIndicatorsWithoutRetainingValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	secret := "super-secret-value-12345"
	body := "APP_MODE=prod\nDB_PASSWORD=" + secret + "\nNORMAL_VALUE=hello\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r, keep := inspectMetadata(candidate{Kind: "ENVIRONMENT_FILE", Scope: "APPLICATION", Path: path, Source: "test"})
	if !keep {
		t.Fatal("expected metadata record")
	}
	records := []Record{r}
	if degraded := inspectContentPosture(context.Background(), records); len(degraded) != 0 {
		t.Fatalf("unexpected degradation: %#v", degraded)
	}
	got := records[0]
	if !got.ContentInspected || got.SecretIndicatorState != "DETECTED" || got.SecretIndicatorCount != 1 || !got.RedactionApplied {
		t.Fatalf("unexpected content posture: %#v", got)
	}
	if got.SecretIndicators[0].Type != "SENSITIVE_ASSIGNMENT" || got.SecretIndicators[0].Line != 2 {
		t.Fatalf("unexpected indicator metadata: %#v", got.SecretIndicators)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "DB_PASSWORD="+secret) {
		t.Fatalf("secret value leaked into serialized record: %s", raw)
	}
}

func TestPhase101RecognizesCommonTokenShapesWithoutEmittingToken(t *testing.T) {
	token := "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
	inds := detectSecretIndicators([]byte("token = " + token + "\n"))
	if len(inds) < 1 {
		t.Fatal("expected token indicator")
	}
	raw, err := json.Marshal(inds)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatalf("token leaked into indicator metadata: %s", raw)
	}
}

func TestPhase101SkipsPlaceholderAssignments(t *testing.T) {
	inds := detectSecretIndicators([]byte("PASSWORD=${PASSWORD}\nCLIENT_SECRET=<redacted>\nTOKEN=changeme\n"))
	if len(inds) != 0 {
		t.Fatalf("placeholders should not be treated as material secret values: %#v", inds)
	}
}

func TestPhase101SkipsBinaryCredentialStoreContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	if err := os.WriteFile(path, []byte{0, 1, 2, 3, 4}, 0600); err != nil {
		t.Fatal(err)
	}
	r, keep := inspectMetadata(candidate{Kind: "CREDENTIAL_STORE", Scope: "USER", Path: path, Source: "test"})
	if !keep {
		t.Fatal("expected metadata record")
	}
	records := []Record{r}
	inspectContentPosture(context.Background(), records)
	if records[0].ContentInspected || records[0].SecretIndicatorState != "SKIPPED" {
		t.Fatalf("credential store must remain outside plaintext inspection: %#v", records[0])
	}
}

func TestPhase101PlaintextRiskSummaryContainsOnlyRedactedMetadata(t *testing.T) {
	r := Record{
		ID: "abc", Kind: "ENVIRONMENT_FILE", Scope: "USER", Path: "/tmp/.env", Exists: true,
		State: "OBSERVED", PermissionState: "OBSERVED", BroadlyAccessible: "TRUE",
		ContentInspected: true, ContentInspectionState: "OBSERVED", SecretIndicatorState: "DETECTED",
		SecretIndicatorCount: 2, SecretIndicators: []SecretIndicator{{Type: "SENSITIVE_ASSIGNMENT", Line: 1}, {Type: "API_TOKEN", Line: 2}}, RedactionApplied: true,
	}
	s := buildPlaintextRiskSummary([]Record{r})
	if s.FilesWithIndicators != 1 || s.IndicatorCount != 2 || s.BroadlyAccessibleWithIndicators != 1 || len(s.Records) != 1 {
		t.Fatalf("unexpected risk summary: %#v", s)
	}
}

func TestPhase101DetectsEmbeddedServiceEnvironmentAssignment(t *testing.T) {
	inds := detectSecretIndicators([]byte(`Environment="DB_PASSWORD=not-a-placeholder"` + "\n"))
	found := false
	for _, ind := range inds {
		if ind.Type == "SENSITIVE_ASSIGNMENT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected embedded sensitive assignment indicator: %#v", inds)
	}
}
