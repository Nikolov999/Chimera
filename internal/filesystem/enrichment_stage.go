package filesystem

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/reliability"
)

const (
	filesystemStageExecutable = "EXECUTABLE_DACL"
	filesystemStageSearchPath = "SEARCH_PATH_DACL"
	filesystemStageSensitive  = "SENSITIVE_FILE_DACL"
	filesystemStageTemp       = "TEMP_DIRECTORY_DACL"
	filesystemStageACL        = "ACL_BOUNDARIES"
)

var windowsFilesystemStageBudgets = map[string]time.Duration{
	filesystemStageExecutable: 8 * time.Second,
	filesystemStageSearchPath: 4 * time.Second,
	filesystemStageSensitive:  6 * time.Second,
	filesystemStageTemp:       4 * time.Second,
	filesystemStageACL:        8 * time.Second,
}

// filesystemEnrichmentStageContext prevents one optional Windows ACL enrichment
// from consuming the entire filesystem collector budget. Linux/macOS preserve
// their established collector behavior and receive the parent context unchanged.
func filesystemEnrichmentStageContext(parent context.Context, stage string) (context.Context, context.CancelFunc, reliability.BudgetDecision) {
	if parent == nil {
		parent = context.Background()
	}
	if runtime.GOOS != "windows" {
		return parent, func() {}, reliability.BudgetDecision{}
	}
	stage = strings.ToUpper(strings.TrimSpace(stage))
	preferred := windowsFilesystemStageBudgets[stage]
	if preferred <= 0 {
		preferred = 5 * time.Second
	}
	return reliability.StageContext(parent, preferred, 500*time.Millisecond, reliability.ProviderBudgetHeavy)
}
