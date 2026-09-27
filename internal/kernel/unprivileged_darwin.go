//go:build darwin

package kernel

import "context"

func collectUnprivilegedFeatures(ctx context.Context, _ Inventory) []UnprivilegedFeatureAssessment {
	_ = ctx
	return phase015DarwinApplicability()
}

func phase015DarwinApplicability() []UnprivilegedFeatureAssessment {
	return phase015PlatformNotApplicable("darwin")
}
