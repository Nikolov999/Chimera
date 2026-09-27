//go:build !linux && !windows && !darwin

package software

import (
	"context"
	"runtime"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformInfrastructureActivity(context.Context) ([]infrastructureActivity, []SourceStatus) {
	return nil, []SourceStatus{{ID: "infrastructure-activity", State: evidence.StateUnsupported, Source: "platform process/service metadata", Reason: "activity inventory is unsupported on " + runtime.GOOS}}
}
