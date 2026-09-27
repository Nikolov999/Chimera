//go:build linux

package filesystem

import (
	"context"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/reliability"
)

const filesystemStagePrivilegedLinux = "PRIVILEGED_FILES"

var linuxFilesystemStageBudgets = map[string]time.Duration{
	filesystemStageExecutable:      4 * time.Second,
	filesystemStageSearchPath:      2 * time.Second,
	filesystemStagePrivilegedLinux: 5 * time.Second,
	filesystemStageSensitive:       2 * time.Second,
	filesystemStageTemp:            1500 * time.Millisecond,
	filesystemStageACL:             2500 * time.Millisecond,
}

// unixFilesystemStageContext is compiled only into Linux. It prevents one
// expensive enrichment from consuming the complete 20s provider budget while
// leaving the frozen Fix59 Windows source and stage helper untouched.
func unixFilesystemStageContext(parent context.Context, stage string) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	preferred := linuxFilesystemStageBudgets[strings.ToUpper(strings.TrimSpace(stage))]
	if preferred <= 0 {
		return parent, func() {}
	}
	ctx, cancel, _ := reliability.StageContext(parent, preferred, 350*time.Millisecond, reliability.ProviderBudgetHeavy)
	return ctx, cancel
}
