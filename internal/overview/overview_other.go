//go:build !linux && !windows && !darwin

package overview

import "context"

func collectPlatform(ctx context.Context, o *Overview) {
	_ = ctx
	o.Kernel = "unsupported"
	o.Privilege = Privilege{Level: "unknown", Principal: o.CurrentUser, Detail: "platform collector unavailable"}
	o.SecurityControls = []Control{{Name: "Platform security controls", State: "unsupported"}}
	o.Degraded = append(o.Degraded, "platform-specific overview collector unsupported")
}
