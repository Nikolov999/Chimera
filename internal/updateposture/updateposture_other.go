//go:build !linux && !windows && !darwin

package updateposture

import "context"

func collectPlatform(_ context.Context, r *Result) {
	r.State = StateUnsupported
	r.Limitations = append(r.Limitations, "update posture is unsupported on this platform")
}
