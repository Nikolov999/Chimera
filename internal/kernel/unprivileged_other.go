//go:build !linux && !windows && !darwin

package kernel

import (
	"context"
	"runtime"
)

func collectUnprivilegedFeatures(ctx context.Context, _ Inventory) []UnprivilegedFeatureAssessment {
	_ = ctx
	return phase015PlatformNotApplicable(runtime.GOOS)
}
