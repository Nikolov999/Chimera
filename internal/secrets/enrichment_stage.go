package secrets

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/reliability"
)

const (
	secretStagePermissions = "PERMISSION_ENRICHMENT"
	secretStageContent     = "PLAINTEXT_CONTENT_ENRICHMENT"
)

var windowsSecretStageBudgets = map[string]time.Duration{
	secretStagePermissions: 6 * time.Second,
	secretStageContent:     8 * time.Second,
}

// secretEnrichmentStageContext keeps metadata inventory independent from
// secondary ACL/content enrichment. Non-Windows platforms retain their existing
// collector context because the live release issue is Windows-specific.
func secretEnrichmentStageContext(parent context.Context, stage string) (context.Context, context.CancelFunc, reliability.BudgetDecision) {
	if parent == nil {
		parent = context.Background()
	}
	if runtime.GOOS != "windows" {
		return parent, func() {}, reliability.BudgetDecision{}
	}
	stage = strings.ToUpper(strings.TrimSpace(stage))
	preferred := windowsSecretStageBudgets[stage]
	if preferred <= 0 {
		preferred = 5 * time.Second
	}
	return reliability.StageContext(parent, preferred, 500*time.Millisecond, reliability.ProviderBudgetMedium)
}
