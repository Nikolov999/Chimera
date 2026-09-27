package secrets

import (
	"context"
	"testing"
	"time"
)

func TestWindowsSecretStageBudgetsAreBounded(t *testing.T) {
	for _, stage := range []string{secretStagePermissions, secretStageContent} {
		budget := windowsSecretStageBudgets[stage]
		if budget <= 0 || budget > 10*time.Second {
			t.Fatalf("unexpected %s budget %s", stage, budget)
		}
	}
}

func TestSecretEnrichmentStageContextPortableContract(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	child, done, _ := secretEnrichmentStageContext(parent, secretStageContent)
	defer done()
	if child == nil {
		t.Fatal("nil stage context")
	}
}
