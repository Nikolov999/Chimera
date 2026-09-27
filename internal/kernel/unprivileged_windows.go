//go:build windows

package kernel

import "context"

func collectUnprivilegedFeatures(ctx context.Context, _ Inventory) []UnprivilegedFeatureAssessment {
	_ = ctx
	return phase015PlatformNotApplicable("windows")
}
